/**
 * 安全回归测试集（deep scan 修复配套）。
 *
 * 每个用例对应一项经「验证」阶段确认的安全发现，均在修复前失败、修复后通过，
 * 用于把已验证的漏洞固化为不可回退的回归测试。
 *
 *   S-01 白名单通配符跨越 host/path 边界导致白名单绕过（OAuth token 外泄 / 开放重定向）
 *   S-02 CALLBACK_SIGNING_SECRET 缺少最小长度校验
 *   S-03 /health?deep=1 未鉴权且无限流，可被用于资源放大
 *   S-04 回传业务服务器的出站请求未禁止跟随重定向
 *   S-05 回调侧未对 state 记录中的 redirect_uri 做二次白名单校验（纵深防御）
 */

import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { AppError } from '../src/errors.js';
import { isUrlAllowed } from '../src/validation.js';
import { handleAuthorize } from '../src/handlers/authorize.js';
import { handleCallback } from '../src/handlers/callback.js';
import { handleHealth } from '../src/handlers/health.js';
import {
  TEST_ENV,
  cookiePair,
  createFakeKv,
  jsonResponse,
  stubFetch,
  testConfig,
  type FetchStub,
} from './helpers.js';
import type { Env } from '../src/types.js';

const CALLBACK_URI = 'https://api.example.com/auth/github/callback';
const COOKIE_NAME = 'gh_oauth_state';

let stub: FetchStub | null = null;
afterEach(() => {
  stub?.restore();
  stub = null;
});

function githubStub(): FetchStub {
  return stubFetch([
    {
      match: (url) => url.includes('access_token'),
      respond: () => jsonResponse({ access_token: 'gho_test_token', token_type: 'bearer', scope: 'read:user' }),
    },
    { match: (url) => url.endsWith('/user/emails'), respond: () => jsonResponse([]) },
    { match: (url) => url.endsWith('/user'), respond: () => jsonResponse({ id: 1, login: 'octocat' }) },
    { match: (url) => url.startsWith('https://api.example.com/'), respond: () => jsonResponse({ ok: true }) },
  ]);
}

async function startFlow(query: string, config = testConfig()) {
  const response = await handleAuthorize(
    new Request(`https://proxy.test/authorize?${query}`, {
      headers: { Origin: 'https://www.example.com', Accept: 'text/html' },
    }),
    config,
    'rid-authorize',
  );
  const location = response.headers.get('Location') ?? '';
  const nonce = location ? new URL(location).searchParams.get('state') ?? '' : '';
  return { nonce, setCookie: response.headers.get('Set-Cookie'), response, config };
}

describe('S-01 白名单通配符不得跨越 host/path 边界', () => {
  const patterns = ['https://*.example.net/*'];

  it('攻击者域名 + 路径内嵌白名单后缀不再被判为允许', () => {
    expect(isUrlAllowed(new URL('https://attacker.com/a.example.net/x'), patterns)).toBe(false);
    expect(isUrlAllowed(new URL('https://attacker.com/x.example.net/x'), patterns)).toBe(false);
    expect(isUrlAllowed(new URL('https://attacker.com/x'), patterns)).toBe(false);
  });

  it('合法子域仍被放行', () => {
    expect(isUrlAllowed(new URL('https://a.example.net/deep/path'), patterns)).toBe(true);
  });

  it('/authorize 端到端：恶意 redirect_uri 返回 400 redirect_uri_not_allowed', async () => {
    const response = await handleAuthorize(
      new Request(
        `https://proxy.test/authorize?redirect_uri=${encodeURIComponent('https://attacker.com/a.example.net/x')}`,
      ),
      testConfig({ ALLOWED_CALLBACK_URIS: 'https://*.example.net/*' }),
      'rid-wild-bypass',
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('redirect_uri_not_allowed');
  });

  it('/authorize 端到端：合法子域 redirect_uri 仍然 302', async () => {
    const response = await handleAuthorize(
      new Request(
        `https://proxy.test/authorize?redirect_uri=${encodeURIComponent('https://a.example.net/cb')}`,
      ),
      testConfig({ ALLOWED_CALLBACK_URIS: 'https://*.example.net/*' }),
      'rid-wild-ok',
    );
    expect(response.status).toBe(302);
  });

  it('success_redirect 通配绕过被忽略，不会跳转到攻击者站点', async () => {
    stub = githubStub();
    const { nonce, setCookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}` +
        `&success_redirect=${encodeURIComponent('https://attacker.com/a.example.net/x')}`,
      testConfig({ ALLOWED_REDIRECT_ORIGINS: 'https://*.example.net/*' }),
    );
    const cookie = cookiePair(setCookie, COOKIE_NAME);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, { headers: { Cookie: cookie } }),
      config,
      'rid-wild-redirect',
    );

    const location = response.headers.get('Location');
    expect(location ?? '').not.toContain('attacker.com');
    expect(response.status).toBe(200);
  });
});

describe('S-02 密钥强度校验', () => {
  it('CALLBACK_SIGNING_SECRET 过短时快速失败', () => {
    const bad: Env = { ...TEST_ENV, OAUTH_KV: createFakeKv(), CALLBACK_SIGNING_SECRET: 'short' };
    let thrown: unknown = null;
    try {
      loadConfig(bad, new URL('https://proxy.test/'));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AppError);
    expect((thrown as AppError).code).toBe('server_misconfigured');
  });
});

describe('S-03 /health?deep=1 限流', () => {
  it('超过阈值后深度探测返回 429', async () => {
    stub = stubFetch([{ match: () => true, respond: () => jsonResponse({ resources: {} }) }]);
    const config = testConfig({
      OAUTH_KV: createFakeKv(),
      RATE_LIMIT_KV: createFakeKv(),
      RATE_LIMIT_PER_MINUTE: '1',
    });
    const make = () =>
      new Request('https://proxy.test/health?deep=1', {
        headers: { 'CF-Connecting-IP': '198.51.100.7', Accept: 'application/json' },
      });

    expect((await handleHealth(make(), config, 'rid-h1')).status).toBe(200);
    expect((await handleHealth(make(), config, 'rid-h2')).status).toBe(429);
  });
});

describe('S-04 回传请求禁止跟随重定向', () => {
  it('对业务服务器的出站请求使用 redirect: error', async () => {
    stub = githubStub();
    const { nonce, setCookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
    );
    const cookie = cookiePair(setCookie, COOKIE_NAME);
    await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, { headers: { Cookie: cookie } }),
      config,
      'rid-redirect',
    );

    const delivery = stub.calls.find((call) => call.url.startsWith('https://api.example.com/'));
    expect(delivery).toBeDefined();
    expect(delivery?.redirect).toBe('error');
  });
});

describe('S-05 回调侧二次校验回传白名单', () => {
  it('被投毒的 state 记录中的非白名单 redirect_uri 被拒绝，且不发生任何出站请求', async () => {
    stub = stubFetch([]); // 任何出站请求都会抛错，确保校验先于出站
    const kv = createFakeKv();
    const nonce = 'poisoned-nonce';
    await kv.put(
      `oauth:state:${nonce}`,
      JSON.stringify({
        redirect_uri: 'https://evil.com/steal',
        business_state: null,
        scope: 'read:user',
        success_redirect: null,
        error_redirect: null,
        cookie_bound: false,
        created_at: Date.now(),
        request_id: 'poisoned',
        origin_fp: null,
      }),
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`),
      testConfig({ OAUTH_KV: kv }),
      'rid-poison',
    );

    expect(response.status).toBe(400);
    expect(await response.text()).toContain('redirect_uri_not_allowed');
    expect(stub.calls.length).toBe(0);
  });
});
