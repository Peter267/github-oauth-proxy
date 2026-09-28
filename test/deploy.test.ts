/**
 * 纯网页部署路径的回归测试。
 *
 * 一键部署后的默认形态是「代码已上线、配置还没填」，这条路径上任何一步静默失败
 * 都会让用户拿着一个看似正常、实则不安全或不工作的服务，因此这里把三件事固化下来：
 *
 *   D-01 模板占位符密钥必须被主动拒绝（否则等于公开密钥上线）
 *   D-02 配置缺失时首页降级为浏览器内配置引导页，而不是无操作性的错误页
 *   D-03 引导页只暴露配置项名称，绝不泄露密钥值
 */

import { afterEach, describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { loadConfig, findMissingSecrets, findPlaceholderSecrets, looksLikePlaceholder } from '../src/config.js';
import { AppError } from '../src/errors.js';
import { TEST_ENV, createFakeKv } from './helpers.js';
import type { Env, ExecutionContextLike } from '../src/types.js';

const ctx: ExecutionContextLike = { waitUntil: () => {} };

function env(overrides: Partial<Env> = {}): Env {
  return { ...TEST_ENV, OAUTH_KV: createFakeKv(), ...overrides };
}

function captureConfigError(source: Env): AppError {
  try {
    loadConfig(source, new URL('https://proxy.test/'));
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    return error as AppError;
  }
  throw new Error('预期 loadConfig 抛错，但没有');
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('D-01 占位符密钥拒绝', () => {
  it('识别仓库模板里的占位符指纹', () => {
    expect(looksLikePlaceholder('replace_with_your_github_client_id')).toBe(true);
    expect(looksLikePlaceholder('REPLACE_WITH_32_BYTE_RANDOM_STRING')).toBe(true);
    expect(looksLikePlaceholder('Ov23liXXXXXXXXXXXXXX')).toBe(true);
    expect(looksLikePlaceholder('please-change-me-before-deploy')).toBe(true);
    expect(looksLikePlaceholder('5f2c9a1e7b4d8f0a3c6e9b2d5a8f1c4e7b0d3a6f9c2e5b8d1a4f7c0e3b6d9a2f')).toBe(false);
    expect(looksLikePlaceholder('Ov23liAb3dEf9Gh1jK')).toBe(false);
  });

  it('仍是占位符的 Secret 会让配置装载快速失败', () => {
    const error = captureConfigError(
      env({ COOKIE_SECRET: 'replace_with_32_byte_random_string' }),
    );
    expect(error.code).toBe('server_misconfigured');
    expect(error.message).toContain('占位符');
    expect(JSON.stringify(error.detail)).toContain('COOKIE_SECRET');
  });

  it('占位符检测不被长度校验掩盖（占位符长度是"合法"的）', () => {
    const placeholder = 'replace_with_32_byte_random_string';
    expect(placeholder.length).toBeGreaterThanOrEqual(16);
    const error = captureConfigError(
      env({ COOKIE_SECRET: placeholder, GITHUB_CLIENT_SECRET: '5f2c9a1e7b4d8f0a3c6e9b2d5a8f1c4e7b0d3a6f9' }),
    );
    expect(error.message).toContain('占位符');
    expect(JSON.stringify(error.detail)).not.toContain('GITHUB_CLIENT_SECRET');
  });

  it('空值与占位符分别归类，互不混淆', () => {
    expect(findMissingSecrets(env({ GITHUB_CLIENT_ID: '' }))).toContain('GITHUB_CLIENT_ID');
    expect(findPlaceholderSecrets(env({ GITHUB_CLIENT_ID: '' }))).toEqual([]);
    // 模板 client id 的 8 连 X（'xxxxxxxx' 指纹）；4 连 X 已因误报率过高改为整串/整词匹配
    expect(findMissingSecrets(env({ GITHUB_CLIENT_ID: 'Ov23liXXXXXXXX' }))).toEqual([]);
    expect(findPlaceholderSecrets(env({ GITHUB_CLIENT_ID: 'Ov23liXXXXXXXX' }))).toEqual(['GITHUB_CLIENT_ID']);
  });

  it('真实密钥可以通过校验', () => {
    const config = loadConfig(env(), new URL('https://proxy.test/'));
    expect(config.githubClientSecret).toBe(TEST_ENV.GITHUB_CLIENT_SECRET);
  });
});

describe('D-02 首次部署配置引导页', () => {
  it('缺少 Secret 时 GET / 返回 503 引导页而非错误页', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/'),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );

    expect(response.status).toBe(503);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    const html = await response.text();
    expect(html).toContain('待配置');
    expect(html).toContain('GITHUB_CLIENT_SECRET');
    // 直接给出可复制到 GitHub OAuth App 的回调地址
    expect(html).toContain('https://proxy.test/callback');
    expect(html).toContain('data-copy="callback-url"');
  });

  it('占位符未替换时引导页明确点出"占位符"', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/'),
      env({ COOKIE_SECRET: 'replace_with_32_byte_random_string' }),
      ctx,
    );

    expect(response.status).toBe(503);
    const html = await response.text();
    expect(html).toContain('占位符');
    expect(html).toContain('COOKIE_SECRET');
  });

  it('缺少 OAUTH_KV 绑定时引导页提示绑定缺失', async () => {
    const bare: Env = { ...TEST_ENV };
    delete (bare as Partial<Env>).OAUTH_KV;
    const response = await worker.fetch(new Request('https://proxy.test/'), bare, ctx);

    expect(response.status).toBe(503);
    expect(await response.text()).toContain('OAUTH_KV');
  });

  it('GET /setup 与 GET / 等价', async () => {
    const ok = await worker.fetch(new Request('https://proxy.test/setup'), env(), ctx);
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain('GitHub OAuth 中转');

    const broken = await worker.fetch(
      new Request('https://proxy.test/setup'),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );
    expect(broken.status).toBe(503);
  });

  it('JSON 请求不被引导页拦截，仍返回结构化错误（供脚本与探针判断）', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/', { headers: { Accept: 'application/json' } }),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );

    expect(response.status).toBe(500);
    const body = (await response.json()) as { ok: boolean; error: { code: string } };
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('server_misconfigured');
  });

  it('非首页路由不受引导页影响，/health 仍报 500', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/health'),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );
    expect(response.status).toBe(500);
  });
});

describe('D-03 引导页不泄露密钥', () => {
  it('引导页只暴露配置项名称，绝不出现密钥值', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/'),
      env({ COOKIE_SECRET: '' }),
      ctx,
    );
    const html = await response.text();

    for (const secret of [
      TEST_ENV.GITHUB_CLIENT_ID,
      TEST_ENV.GITHUB_CLIENT_SECRET,
      TEST_ENV.CALLBACK_SIGNING_SECRET,
    ]) {
      expect(html).not.toContain(secret);
    }
  });

  it('配置就绪时首页展示回调地址但不展示任何密钥', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/'), env(), ctx);
    expect(response.status).toBe(200);
    const html = await response.text();

    expect(html).toContain('https://proxy.test/callback');
    expect(html).not.toContain(TEST_ENV.GITHUB_CLIENT_SECRET);
    expect(html).not.toContain(TEST_ENV.COOKIE_SECRET);
  });
});

describe('D-04 占位符 / 弱密钥检测召回与健壮性（FIX-5）', () => {
  it('此前漏报的占位符变体现在都能被识别', () => {
    // 注：'xxx' / 'tbd' 是 3 字符子串，实测单个 base64url 密钥误拒率 ~1.2e-3，
    // 已按 G-1 移除（回归见 test/config-hardening.test.ts）；
    // 'dummy-secret' / 'fixme_later' 走「独立词元」匹配，'abc123' 走整词匹配。
    const missed = [
      'REPLACE_ME',
      'replace-me-now',
      'insert_secret_here',
      'sample_secret_value',
      'dummy-secret',
      'put_your_secret_here',
      'fixme_later',
      'abc123',
      'db_password_2024',
    ];
    for (const value of missed) {
      expect(looksLikePlaceholder(value), value).toBe(true);
    }
  });

  it('零宽字符与全角变体无法绕过占位符检测', () => {
    // 在关键字内部插入零宽空格（U+200B）
    expect(looksLikePlaceholder('re\u200Bplace_with_yo\u200Bur_github_x')).toBe(true);
    // 全角字母经 NFKC 归一化后与半角等价
    expect(looksLikePlaceholder('ｒｅｐｌａｃｅ_with_x')).toBe(true);
    // BOM 前缀 + 软连字符（U+00AD）后缀
    expect(looksLikePlaceholder('\uFEFFreplace_me\u00AD')).toBe(true);
  });

  it('长度达标的纯数字弱口令被识别', () => {
    expect(looksLikePlaceholder('123456')).toBe(true);
    expect(looksLikePlaceholder('0123456789012345')).toBe(true);
  });

  it('长度达标的占位符仍被 loadConfig 拒绝（不回退既有行为）', () => {
    expect('insert_secret_here'.length).toBeGreaterThanOrEqual(16);
    expect('sample_secret_value'.length).toBeGreaterThanOrEqual(16);
    for (const placeholder of ['insert_secret_here', 'sample_secret_value', 'REPLACE_ME_ABCDEFGH']) {
      const error = captureConfigError(env({ COOKIE_SECRET: placeholder }));
      expect(error.code).toBe('server_misconfigured');
      expect(error.message).toContain('占位符');
    }
  });

  it('非字符串 / 纯空白 Secret 被显式拒绝，并指出字段名与实际类型', () => {
    const numeric = captureConfigError(env({ COOKIE_SECRET: 123 as unknown as string }));
    expect(numeric.code).toBe('server_misconfigured');
    expect(numeric.message).toContain('非法');
    expect(JSON.stringify(numeric.detail)).toContain('COOKIE_SECRET');
    expect(JSON.stringify(numeric.detail)).toContain('number');

    const object = captureConfigError(env({ COOKIE_SECRET: {} as unknown as string }));
    expect(JSON.stringify(object.detail)).toContain('COOKIE_SECRET');
    expect(JSON.stringify(object.detail)).toContain('object');

    const blank = captureConfigError(env({ GITHUB_CLIENT_ID: '   ' }));
    expect(JSON.stringify(blank.detail)).toContain('GITHUB_CLIENT_ID');
    expect(JSON.stringify(blank.detail)).toContain('空白');
  });

  it('GITHUB_CLIENT_ID 也受最小长度约束（此前完全没有长度校验）', () => {
    const error = captureConfigError(env({ GITHUB_CLIENT_ID: 'Ov23liAB' }));
    expect(error.code).toBe('server_misconfigured');
    expect(error.message).toContain('强度');
    expect(JSON.stringify(error.detail)).toContain('GITHUB_CLIENT_ID');
  });

  it('长度达标但熵极低的密钥被拒（去重后字符种类下限）', () => {
    const error = captureConfigError(env({ COOKIE_SECRET: 'a'.repeat(32) }));
    expect(error.code).toBe('server_misconfigured');
    expect(JSON.stringify(error.detail)).toContain('字符种类');
  });

  it('COOKIE_SECRET 与 CALLBACK_SIGNING_SECRET 相同被拒（DEPLOY.md 的强制约束）', () => {
    const shared = 'shared-secret-value-0123456789abcdef';
    const error = captureConfigError(
      env({ COOKIE_SECRET: shared, CALLBACK_SIGNING_SECRET: shared }),
    );
    expect(error.code).toBe('server_misconfigured');
    expect(error.message).toContain('不能相同');
  });

  it('真实随机 hex 密钥不被误拒（检测不能变成误报机器）', () => {
    const config = loadConfig(
      env({
        GITHUB_CLIENT_SECRET: '5f2c9a1e7b4d8f0a3c6e9b2d5a8f1c4e',
        COOKIE_SECRET: 'b7e1c4a9d2f5b8e1c4a7d0f3b6e9c2a5d8f1b4e7c0a3d6f9',
        CALLBACK_SIGNING_SECRET: '9d2f5b8e1c4a7d0f3b6e9c2a5d8f1b4e7c0a3d6f9b2e5c8a1d4f7',
      }),
      new URL('https://proxy.test/'),
    );
    expect(config.cookieSecret).toBe('b7e1c4a9d2f5b8e1c4a7d0f3b6e9c2a5d8f1b4e7c0a3d6f9');
  });
});

describe('D-05 引导页必须点名「取值非法」的 Secret', () => {
  // 这类取值既不算「缺失」也不算「占位符」；若引导页不点名，
  // 用户只会看到一个不说任何问题的「待配置」页而无从下手。
  it('纯空白密钥时引导页点名该字段并说明原因', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/'),
      env({ COOKIE_SECRET: '   ' }),
      ctx,
    );

    expect(response.status).toBe(503);
    const html = await response.text();
    expect(html).toContain('COOKIE_SECRET');
    expect(html).toContain('空白');
  });

  it('非字符串类型密钥时引导页报出实际类型', async () => {
    const broken = env();
    (broken as unknown as Record<string, unknown>).COOKIE_SECRET = 123;

    const response = await worker.fetch(new Request('https://proxy.test/'), broken, ctx);

    expect(response.status).toBe(503);
    const html = await response.text();
    expect(html).toContain('COOKIE_SECRET');
    expect(html).toContain('number');
  });
});
