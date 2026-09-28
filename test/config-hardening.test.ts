/**
 * 配置装载加固的回归测试（G-1 / G-2 / G-5）。
 *
 * 背景：文档推荐的密钥生成方式是 `crypto.randomBytes(32).toString('base64url')`。
 * 若占位符检测把真实随机密钥误判为占位符，服务会**直接起不来**（fail-closed 用错了地方），
 * 一次部署要填 4 个值，任何千分之几的误报都会放大成可感知的上线失败率。
 * 因此这里把「随机密钥零误拒」固化为不可回退的回归测试。
 *
 *   G-1 占位符检测误报：删除 3 字符 marker、短 marker 改整串/整词匹配，随机密钥零误拒
 *   G-2 重复模式弱密钥：'abcdefgh'.repeat(4) 这类能被字符种类阈值放行的弱密钥被拒绝
 *   G-5 非字符串绑定：toBool / toInt 收到布尔等非字符串值不再抛 TypeError 导致全局 500
 *
 * 采样使用**固定种子**的伪随机（mulberry32），因此结果可复现、CI 不会随机变红。
 */

import { describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { isRepeatedChunk, loadConfig, looksLikePlaceholder } from '../src/config.js';
import { AppError } from '../src/errors.js';
import { TEST_ENV, createFakeKv } from './helpers.js';
import type { Env, ExecutionContextLike } from '../src/types.js';

const ctx: ExecutionContextLike = { waitUntil: () => {} };
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';

/** mulberry32：固定种子的 32 位伪随机，输出 [0,1) */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeBytes(rnd: () => number, n: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < n; i++) out.push(Math.floor(rnd() * 256));
  return out;
}

/** 等价于 Node 的 Buffer/randomBytes(32).toString('base64url')（43 字符、无填充） */
function toBase64Url(bytes: number[]): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    out += B64URL[b0 >> 2] as string;
    out += B64URL[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)] as string;
    if (b1 === undefined) break;
    const b2 = bytes[i + 2];
    out += B64URL[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)] as string;
    if (b2 === undefined) break;
    out += B64URL[b2 & 63] as string;
  }
  return out;
}

function toHex(bytes: number[]): string {
  let out = '';
  for (const b of bytes) out += (HEX[b >> 4] as string) + (HEX[b & 15] as string);
  return out;
}

/** `npm run gen-secret` 产出的形态：32 字节 -> base64url */
function genBase64Url(rnd: () => number): string {
  return toBase64Url(makeBytes(rnd, 32));
}

/** 另一种常见形态：32 字节 -> hex（64 字符） */
function genHex(rnd: () => number): string {
  return toHex(makeBytes(rnd, 32));
}

/** 新版 GitHub OAuth App 的 Client ID 形态：Ov23li + 14 个 base62 字符 */
function genClientId(rnd: () => number): string {
  let out = 'Ov23li';
  for (let i = 0; i < 14; i++) out += BASE62[Math.floor(rnd() * 62)] as string;
  return out;
}

/** 旧版 Client ID 形态：Iv1. + 16 个 hex */
function genIv1(rnd: () => number): string {
  let out = 'Iv1.';
  for (let i = 0; i < 16; i++) out += HEX[Math.floor(rnd() * 16)] as string;
  return out;
}

/** 一个随机 Secret 会在哪些校验点被拒（用于采样时分类计数） */
function rejectReasons(value: string): { placeholder: boolean; repeat: boolean; lowDistinct: boolean } {
  const normalized = value.trim().toLowerCase();
  return {
    placeholder: looksLikePlaceholder(value),
    repeat: isRepeatedChunk(normalized),
    lowDistinct: new Set(normalized).size < 8,
  };
}

const SAMPLE_SIZE = 200_000;

describe('G-1 占位符检测不得误拒真实随机密钥', () => {
  it('过短的 3 字符 marker 已移除（实测误拒率 ~1.2e-3，不可接受）', () => {
    // 这两个 marker 曾在 20 万次 base64url 采样里各命中 ~240 次
    expect(looksLikePlaceholder('xxx')).toBe(false);
    expect(looksLikePlaceholder('tbd')).toBe(false);
    // 但作为独立词元 / 整串仍应被其它规则识别（此处 'xxx' 已彻底移除，属于已知取舍）
    expect(looksLikePlaceholder('replace_with_xxx')).toBe(true);
  });

  it('短 marker 只在整串相等或独立词元位置命中（不在随机串内部误命中）', () => {
    // 整串相等
    expect(looksLikePlaceholder('todo')).toBe(true);
    expect(looksLikePlaceholder('xxxx')).toBe(true);
    // 独立词元（模板常见形态）
    expect(looksLikePlaceholder('dummy-secret')).toBe(true);
    expect(looksLikePlaceholder('fixme_later')).toBe(true);
    expect(looksLikePlaceholder('abc123')).toBe(true);
    // 落在连续字母数字内部 -> 不命中（这正是随机密钥的形态）
    expect(looksLikePlaceholder('atodokx')).toBe(false);
    expect(looksLikePlaceholder('xfixmey')).toBe(false);
    expect(looksLikePlaceholder('zdummy1')).toBe(false);
  });

  it(`固定种子 ${SAMPLE_SIZE.toLocaleString('en-US')} 次/组采样：base64url / hex / client-id 形态单密钥误拒均为 0`, () => {
    const groups: Array<[string, (rnd: () => number) => string, number]> = [
      ['base64url(43)', genBase64Url, 0x5eed_1001],
      ['hex(64)', genHex, 0x5eed_1002],
      ['clientid(Ov23li)', genClientId, 0x5eed_1003],
      ['clientid(Iv1.)', genIv1, 0x5eed_1004],
    ];

    const report: string[] = [];
    for (const [name, gen, seed] of groups) {
      const rnd = mulberry32(seed);
      let placeholder = 0;
      let repeat = 0;
      let lowDistinct = 0;
      for (let i = 0; i < SAMPLE_SIZE; i++) {
        const reasons = rejectReasons(gen(rnd));
        if (reasons.placeholder) placeholder++;
        if (reasons.repeat) repeat++;
        if (reasons.lowDistinct) lowDistinct++;
      }
      report.push(`${name}: placeholder=${placeholder} repeat=${repeat} lowDistinct=${lowDistinct}`);
      expect(placeholder, `${name} 占位符误拒`).toBe(0);
      expect(repeat, `${name} 重复模式误拒`).toBe(0);
      expect(lowDistinct, `${name} 字符种类误拒`).toBe(0);
    }
    console.log(`[G-1 采样 N=${SAMPLE_SIZE}/组] ${report.join(' | ')}`);
  }, 180_000);

  it('固定种子随机密钥全部通过 loadConfig（覆盖完整校验链）', () => {
    const rnd = mulberry32(0xc0ffee);
    for (let i = 0; i < 300; i++) {
      const env: Env = {
        ...TEST_ENV,
        OAUTH_KV: createFakeKv(),
        GITHUB_CLIENT_ID: genClientId(rnd),
        GITHUB_CLIENT_SECRET: genBase64Url(rnd),
        COOKIE_SECRET: genBase64Url(rnd),
        CALLBACK_SIGNING_SECRET: genHex(rnd),
      };
      expect(() => loadConfig(env, new URL('https://proxy.test/')), `第 ${i} 组`).not.toThrow();
    }
  });
});

describe('G-2 重复模式弱密钥被拒绝', () => {
  it('字符种类刚好达标的重复模式被识别', () => {
    expect(isRepeatedChunk('abcdefgh'.repeat(4))).toBe(true);
    expect(isRepeatedChunk('qwertyui'.repeat(4))).toBe(true);
    expect(isRepeatedChunk('0123456789abcdef'.repeat(2))).toBe(true);
    // 非重复串不应命中
    expect(isRepeatedChunk('abcdefghijklmnop')).toBe(false);
  });

  it('三类重复模式密钥被 loadConfig 拒绝（此前可绕过字符种类阈值）', () => {
    for (const weak of [
      'abcdefgh'.repeat(4),
      'qwertyui'.repeat(4),
      '0123456789abcdef'.repeat(2),
    ]) {
      expect(new Set(weak).size, `${weak} 应能通过字符种类阈值`).toBeGreaterThanOrEqual(8);
      let thrown: unknown = null;
      try {
        loadConfig({ ...TEST_ENV, OAUTH_KV: createFakeKv(), COOKIE_SECRET: weak }, new URL('https://proxy.test/'));
      } catch (error) {
        thrown = error;
      }
      expect(thrown, weak).toBeInstanceOf(AppError);
      expect((thrown as AppError).code).toBe('server_misconfigured');
      expect(JSON.stringify((thrown as AppError).detail)).toContain('重复模式');
    }
  });

  it('随机密钥不受重复模式规则影响', () => {
    const rnd = mulberry32(0x1234_5678);
    for (let i = 0; i < 5000; i++) {
      expect(isRepeatedChunk(genBase64Url(rnd))).toBe(false);
      expect(isRepeatedChunk(genHex(rnd))).toBe(false);
    }
  });
});

describe('G-5 非字符串绑定安全降级（不抛 TypeError）', () => {
  it('ALLOW_UNBOUND_STATE 绑定为布尔 true 时按真值解析，不抛错', () => {
    const config = loadConfig(
      { ...TEST_ENV, OAUTH_KV: createFakeKv(), ALLOW_UNBOUND_STATE: true as unknown as string },
      new URL('https://proxy.test/'),
    );
    expect(config.allowUnboundState).toBe(true);
  });

  it('ALLOW_INSECURE_REDIRECTS 绑定为数字 1 / 布尔 false 时分别按 true / false 解析', () => {
    const on = loadConfig(
      { ...TEST_ENV, OAUTH_KV: createFakeKv(), ALLOW_INSECURE_REDIRECTS: 1 as unknown as string },
      new URL('https://proxy.test/'),
    );
    expect(on.allowInsecureRedirects).toBe(true);

    const off = loadConfig(
      { ...TEST_ENV, OAUTH_KV: createFakeKv(), ALLOW_INSECURE_REDIRECTS: false as unknown as string },
      new URL('https://proxy.test/'),
    );
    expect(off.allowInsecureRedirects).toBe(false);
  });

  it('数值绑定为非字符串时回退默认值而非抛错', () => {
    const config = loadConfig(
      {
        ...TEST_ENV,
        OAUTH_KV: createFakeKv(),
        STATE_TTL_SECONDS: 600 as unknown as string,
        RATE_LIMIT_PER_MINUTE: true as unknown as string,
      },
      new URL('https://proxy.test/'),
    );
    expect(config.stateTtlSeconds).toBe(600);
    expect(config.rateLimitPerMinute).toBe(60); // 非数字字符串 -> 回退默认值
  });

  it('绑定为布尔时请求不再因 TypeError 全局 500（/health 正常 200）', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/health'),
      { ...TEST_ENV, OAUTH_KV: createFakeKv(), ALLOW_UNBOUND_STATE: true as unknown as string },
      ctx,
    );
    expect(response.status).toBe(200);
  });
});
