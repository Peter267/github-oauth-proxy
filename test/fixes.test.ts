/**
 * 红队确认缺陷的回归测试（FIX-1 ~ FIX-4）。
 *
 * 每个用例都对应一项经独立复核确认的缺陷，修复前失败、修复后通过：
 *
 *   FIX-1 /callback 失败跳转曾回落到未校验的 config.errorRedirect（开放重定向 + state 外泄）
 *   FIX-2 JSON 模式曾整体关闭 state Cookie 绑定（login-CSRF）
 *   FIX-3 /callback 成功页曾漏设安全响应头（nosniff / X-Frame-Options / Pragma）
 *   FIX-4 /callback 成功分支曾忽略 Accept 头，与失败分支内容协商口径不一致
 */

import { afterEach, describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { handleAuthorize } from '../src/handlers/authorize.js';
import { handleCallback } from '../src/handlers/callback.js';
import {
  TEST_ENV,
  cookiePair,
  createFakeKv,
  jsonResponse,
  stubFetch,
  testConfig,
  type FetchStub,
} from './helpers.js';
import type { Env, ExecutionContextLike } from '../src/types.js';

const CALLBACK_URI = 'https://api.example.com/auth/github/callback';
const COOKIE_NAME = 'gh_oauth_state';

const ctx: ExecutionContextLike = { waitUntil: () => {} };

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
    { match: (url) => url.endsWith('/user'), respond: () => jsonResponse({ id: 1, login: 'octocat', name: 'The Octocat' }) },
    { match: (url) => url.startsWith('https://api.example.com/'), respond: () => jsonResponse({ ok: true }) },
  ]);
}

/** 从 /authorize 响应里取出一次性 nonce 与绑定 Cookie */
function extractAuth(response: Response): { nonce: string; cookie: string } {
  const location = response.headers.get('Location') ?? '';
  const nonce = location ? new URL(location).searchParams.get('state') ?? '' : '';
  return { nonce, cookie: cookiePair(response.headers.get('Set-Cookie'), COOKIE_NAME) };
}

async function startFlow(query: string, config = testConfig()): Promise<{ response: Response; nonce: string; cookie: string }> {
  const response = await handleAuthorize(
    new Request(`https://proxy.test/authorize?${query}`, {
      headers: { Origin: 'https://www.example.com', Accept: 'text/html' },
    }),
    config,
    'rid-authorize',
  );
  return { response, ...extractAuth(response) };
}

describe('FIX-1 失败跳转必须经过白名单校验', () => {
  it('ERROR_REDIRECT 配成白名单外地址时，失败回调不会 302 到该地址', async () => {
    const config = testConfig({ ERROR_REDIRECT: 'https://evil.example.com/err' });
    const { nonce, cookie } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}&state=biz-1`,
      config,
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?error=access_denied&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-fix1-evil',
    );

    // 未通过白名单校验的默认跳转在 /authorize 阶段即被丢弃，回调只能渲染内置结果页
    expect(response.headers.get('Location') ?? '').not.toContain('evil.example.com');
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('biz-1');
  });

  it('ERROR_REDIRECT 在白名单内时行为不变（仍正常回跳并带回业务 state）', async () => {
    const config = testConfig({ ERROR_REDIRECT: 'https://www.example.com/login/failed' });
    const { nonce, cookie } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}&state=biz-2`,
      config,
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?error=access_denied&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-fix1-ok',
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') as string);
    expect(location.origin + location.pathname).toBe('https://www.example.com/login/failed');
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe('biz-2');
  });
});

describe('FIX-2 JSON 模式默认必须绑定 state Cookie', () => {
  function jsonAuthorize(config: ReturnType<typeof testConfig>) {
    return handleAuthorize(
      new Request(
        `https://proxy.test/authorize?format=json&redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
        { headers: { Origin: 'https://www.example.com' } },
      ),
      config,
      'rid-json-authorize',
    );
  }

  it('默认配置下 JSON 模式的 cookie_bound 为 true，且仍下发 Set-Cookie', async () => {
    const kv = createFakeKv();
    const config = testConfig({ OAUTH_KV: kv });
    const response = await jsonAuthorize(config);

    expect(response.status).toBe(200);
    const body = (await response.json()) as { state: string };
    const record = (await kv.get(`oauth:state:${body.state}`, 'json')) as { cookie_bound: boolean };
    expect(record.cookie_bound).toBe(true);
    // 未下发 Cookie 的话默认绑定会让回调必然失败，因此 JSON 模式也必须 Set-Cookie
    expect(response.headers.get('Set-Cookie')).toContain(COOKIE_NAME);
  });

  it('JSON 模式无 Cookie 的回调被拒（403）且不发生任何出站投递', async () => {
    stub = stubFetch([]); // 任何出站请求都会抛错，确保在投递前就被拦下
    const config = testConfig({ OAUTH_KV: createFakeKv() });
    const auth = await jsonAuthorize(config);
    const body = (await auth.json()) as { state: string };

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${body.state}`),
      config,
      'rid-json-nocookie',
    );

    expect(response.status).toBe(403);
    expect(stub.calls.length).toBe(0);
  });

  it('JSON 模式带正确 Cookie 的回调可以通过', async () => {
    stub = githubStub();
    const config = testConfig({ OAUTH_KV: createFakeKv() });
    const auth = await jsonAuthorize(config);
    const cookie = cookiePair(auth.headers.get('Set-Cookie'), COOKIE_NAME);
    const body = (await auth.json()) as { state: string };

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${body.state}`, { headers: { Cookie: cookie } }),
      config,
      'rid-json-cookie',
    );

    expect(response.status).toBe(200);
    expect(stub.calls.some((call) => call.url.startsWith('https://api.example.com/'))).toBe(true);
  });

  it('ALLOW_UNBOUND_STATE=true 时才恢复旧行为（无 Cookie 也能通过）', async () => {
    stub = githubStub();
    const kv = createFakeKv();
    const config = testConfig({ OAUTH_KV: kv, ALLOW_UNBOUND_STATE: 'true' });
    expect(config.allowUnboundState).toBe(true);

    const auth = await jsonAuthorize(config);
    const body = (await auth.json()) as { state: string };
    const record = (await kv.get(`oauth:state:${body.state}`, 'json')) as { cookie_bound: boolean };
    expect(record.cookie_bound).toBe(false);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${body.state}`),
      config,
      'rid-json-unbound',
    );
    expect(response.status).toBe(200);
  });

  it('开启降级开关时首页给出显式的 login-CSRF 告警', async () => {
    const env: Env = { ...TEST_ENV, OAUTH_KV: createFakeKv(), ALLOW_UNBOUND_STATE: 'true' };
    const response = await worker.fetch(new Request('https://proxy.test/'), env, ctx);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain('ALLOW_UNBOUND_STATE');
  });
});

describe('FIX-3 成功页统一下发安全响应头', () => {
  it('完整 /authorize → /callback 成功页包含 nosniff / X-Frame-Options / no-store', async () => {
    stub = githubStub();
    const config = testConfig();
    const { nonce, cookie } = await startFlow(`redirect_uri=${encodeURIComponent(CALLBACK_URI)}`, config);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, { headers: { Cookie: cookie } }),
      config,
      'rid-fix3',
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
  });
});

describe('FIX-4 callback 成功分支与全站内容协商一致', () => {
  it('带 Accept: application/json 的成功回调返回 JSON，且不含 access_token', async () => {
    stub = githubStub();
    const config = testConfig();
    const { nonce, cookie } = await startFlow(`redirect_uri=${encodeURIComponent(CALLBACK_URI)}`, config);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, {
        headers: { Cookie: cookie, Accept: 'application/json' },
      }),
      config,
      'rid-fix4-json',
    );

    expect(response.headers.get('Content-Type')).toContain('application/json');
    const text = await response.text();
    const body = JSON.parse(text) as { ok: boolean };
    expect(body.ok).toBe(true);
    expect(text).not.toContain('gho_test_token');
  });

  it('浏览器式 Accept: text/html... 仍返回 HTML 成功页', async () => {
    stub = githubStub();
    const config = testConfig();
    const { nonce, cookie } = await startFlow(`redirect_uri=${encodeURIComponent(CALLBACK_URI)}`, config);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, {
        headers: { Cookie: cookie, Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9' },
      }),
      config,
      'rid-fix4-html',
    );

    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(await response.text()).toContain('octocat');
  });
});
