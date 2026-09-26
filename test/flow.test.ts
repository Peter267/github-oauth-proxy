/**
 * 端到端流程测试（直接调用 handler，配合 fetch 桩）：
 *   /authorize -> GitHub 授权页 -> /callback -> 换 token -> 拉用户 -> 回传业务服务器
 * 覆盖：一次性 state、Cookie 绑定、白名单、来源校验、HMAC 签名、成功/失败跳转。
 */

import { afterEach, describe, expect, it } from 'vitest';
import { handleAuthorize } from '../src/handlers/authorize.js';
import { handleCallback } from '../src/handlers/callback.js';
import { hmacSha256Hex } from '../src/crypto.js';
import {
  TEST_ENV,
  cookiePair,
  createFakeKv,
  jsonResponse,
  stubFetch,
  testConfig,
  type FetchStub,
} from './helpers.js';

const CALLBACK_URI = 'https://api.example.com/auth/github/callback';
const COOKIE_NAME = 'gh_oauth_state';
const SIGNING_SECRET = TEST_ENV.CALLBACK_SIGNING_SECRET as string;

let stub: FetchStub | null = null;

afterEach(() => {
  stub?.restore();
  stub = null;
});

function githubStub(overrides: { tokenPayload?: Record<string, unknown> } = {}): FetchStub {
  return stubFetch([
    {
      match: (url) => url.startsWith('https://github.com/login/oauth/access_token'),
      respond: () =>
        jsonResponse(
          overrides.tokenPayload ?? {
            access_token: 'gho_test_token',
            token_type: 'bearer',
            scope: 'read:user user:email',
          },
        ),
    },
    {
      match: (url) => url.endsWith('/user/emails'),
      respond: () => jsonResponse([{ email: 'octo@example.com', primary: true, verified: true }]),
    },
    {
      match: (url) => url.endsWith('/user'),
      respond: () =>
        jsonResponse({
          id: 583231,
          login: 'octocat',
          name: 'The Octocat',
          email: null,
          avatar_url: 'https://avatars.githubusercontent.com/u/583231',
          html_url: 'https://github.com/octocat',
          created_at: '2011-01-25T18:44:36Z',
        }),
    },
    {
      match: (url) => url.startsWith('https://api.example.com/'),
      respond: () => jsonResponse({ ok: true }),
    },
  ]);
}

async function startFlow(
  query: string,
  config = testConfig(),
): Promise<{ nonce: string; cookie: string; response: Response; config: ReturnType<typeof testConfig> }> {
  const request = new Request(`https://proxy.test/authorize?${query}`, {
    headers: { Origin: 'https://www.example.com', Accept: 'text/html' },
  });
  const response = await handleAuthorize(request, config, 'rid-authorize');
  const location = response.headers.get('Location') ?? '';
  let nonce = '';
  if (location) nonce = new URL(location).searchParams.get('state') ?? '';
  return {
    nonce,
    cookie: cookiePair(response.headers.get('Set-Cookie'), COOKIE_NAME),
    response,
    config,
  };
}

describe('授权码流程（happy path）', () => {
  it('跳转到 GitHub 授权页并携带一次性 state', async () => {
    const { response, nonce, cookie } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}&state=opaque-1&scope=read:user%20user:email`,
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') as string);
    expect(location.origin + location.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(location.searchParams.get('client_id')).toBe(TEST_ENV.GITHUB_CLIENT_ID);
    expect(location.searchParams.get('redirect_uri')).toBe('https://proxy.test/callback');
    expect(location.searchParams.get('scope')).toBe('read:user user:email');
    expect(location.searchParams.get('state')).toBe(nonce);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Cookie 经过 AES-GCM 加密，不回显 nonce 明文
    expect(cookie.startsWith(`${COOKIE_NAME}=`)).toBe(true);
    expect(response.headers.get('Set-Cookie')).toContain('HttpOnly');
    expect(response.headers.get('Set-Cookie')).toContain('SameSite=Lax');
    expect(response.headers.get('Set-Cookie')).toContain('Secure');
  });

  it('回调换取 token、拉取用户并签名回传业务服务器', async () => {
    stub = githubStub();
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}&state=opaque-1`,
    );

    const callbackRequest = new Request(
      `https://proxy.test/callback?code=the_auth_code&state=${nonce}`,
      { headers: { Cookie: cookie } },
    );
    const response = await handleCallback(callbackRequest, config, 'rid-callback');

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(await response.text()).toContain('octocat');

    // ---- 校验回传报文 ----
    const delivery = stub.calls.find((call) => call.url.startsWith('https://api.example.com/'));
    expect(delivery).toBeDefined();
    expect(delivery?.method).toBe('POST');
    expect(delivery?.url).toBe(CALLBACK_URI);
    expect(delivery?.headers['content-type']).toContain('application/json');
    expect(delivery?.headers['idempotency-key']).toBe('rid-callback');

    const timestamp = delivery?.headers['x-gh-proxy-timestamp'] as string;
    const expectedSignature = await hmacSha256Hex(SIGNING_SECRET, `${timestamp}.${delivery?.body}`);
    expect(delivery?.headers['x-gh-proxy-signature']).toBe(`sha256=${expectedSignature}`);

    const payload = JSON.parse(delivery?.body as string) as Record<string, any>;
    expect(payload.event).toBe('oauth.callback');
    expect(payload.provider).toBe('github');
    expect(payload.state).toBe('opaque-1');
    expect(payload.token.access_token).toBe('gho_test_token');
    expect(payload.user.login).toBe('octocat');
    expect(payload.user.id).toBe(583231);
    // /user 未返回邮箱时回落到 /user/emails 的主邮箱
    expect(payload.user.email).toBe('octo@example.com');

    // ---- 换 token 请求体包含正确参数，且 secret 不出现在 URL ----
    const tokenCall = stub.calls.find((call) => call.url.includes('access_token'));
    expect(tokenCall?.url).not.toContain(TEST_ENV.GITHUB_CLIENT_SECRET as string);
    expect(JSON.parse(tokenCall?.body as string)).toMatchObject({
      code: 'the_auth_code',
      redirect_uri: 'https://proxy.test/callback',
      client_id: TEST_ENV.GITHUB_CLIENT_ID,
    });
  });

  it('配置了 success_redirect 时 302 带结果参数回跳', async () => {
    stub = githubStub();
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}&state=opaque-2` +
        `&success_redirect=${encodeURIComponent('https://www.example.com/login/success')}`,
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-callback',
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') as string);
    expect(location.origin + location.pathname).toBe('https://www.example.com/login/success');
    expect(location.searchParams.get('status')).toBe('ok');
    expect(location.searchParams.get('state')).toBe('opaque-2');
  });
});

describe('state 与 CSRF 防护', () => {
  it('state 只能使用一次（重放返回 403）', async () => {
    stub = githubStub();
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
    );

    const first = await handleCallback(
      new Request(`https://proxy.test/callback?code=c1&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-1',
    );
    expect(first.status).toBe(200);

    const replay = await handleCallback(
      new Request(`https://proxy.test/callback?code=c1&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-2',
    );
    expect(replay.status).toBe(403);
    expect(await replay.text()).toContain('state_expired');
  });

  it('缺少绑定 Cookie 时拒绝（双提交校验）', async () => {
    stub = githubStub();
    const { nonce, config } = await startFlow(`redirect_uri=${encodeURIComponent(CALLBACK_URI)}`);

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`),
      config,
      'rid-3',
    );
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('state_mismatch');
  });

  it('伪造 state（未在我方签发）被拒绝', async () => {
    const config = testConfig();
    const response = await handleCallback(
      new Request('https://proxy.test/callback?code=c&state=forged-nonce'),
      config,
      'rid-4',
    );
    expect(response.status).toBe(403);
  });

  it('缺少 state 参数返回 400', async () => {
    const config = testConfig();
    const response = await handleCallback(
      new Request('https://proxy.test/callback?code=c'),
      config,
      'rid-5',
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('state_missing');
  });
});

describe('白名单与来源校验', () => {
  it('redirect_uri 不在白名单时拒绝', async () => {
    const { response } = await startFlow(
      `redirect_uri=${encodeURIComponent('https://evil.com/steal')}`,
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('redirect_uri_not_allowed');
  });

  it('前缀通配白名单条目可用', async () => {
    const { response } = await startFlow(
      `redirect_uri=${encodeURIComponent('https://api.example.com/v2/auth/anything')}`,
    );
    expect(response.status).toBe(302);
  });

  it('来源不在白名单时拒绝', async () => {
    const config = testConfig();
    const request = new Request(
      `https://proxy.test/authorize?redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
      { headers: { Origin: 'https://evil.com' } },
    );
    const response = await handleAuthorize(request, config, 'rid-origin');
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('origin_not_allowed');
  });

  it('缺少 redirect_uri 返回 400 结构化错误', async () => {
    const config = testConfig();
    const request = new Request('https://proxy.test/authorize', {
      headers: { Accept: 'application/json' },
    });
    const response = await handleAuthorize(request, config, 'rid-missing');
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: { code: string }; request_id: string };
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('invalid_request');
    expect(body.request_id).toBe('rid-missing');
  });

  it('JSON 模式返回 authorize_url 且不带浏览器 Cookie 绑定', async () => {
    const config = testConfig();
    const request = new Request(
      `https://proxy.test/authorize?format=json&redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
      { headers: { Origin: 'https://www.example.com' } },
    );
    const response = await handleAuthorize(request, config, 'rid-json');
    expect(response.status).toBe(200);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://www.example.com');
    const body = (await response.json()) as { ok: boolean; authorize_url: string; state: string };
    expect(body.ok).toBe(true);
    expect(body.authorize_url).toContain('https://github.com/login/oauth/authorize');
    expect(body.state).toBe(new URL(body.authorize_url).searchParams.get('state'));
  });
});

describe('GitHub 异常处理', () => {
  it('用户取消授权 -> access_denied 并回跳 error_redirect', async () => {
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}` +
        `&error_redirect=${encodeURIComponent('https://www.example.com/login/failed')}`,
    );

    const response = await handleCallback(
      new Request(
        `https://proxy.test/callback?error=access_denied&error_description=user+denied&state=${nonce}`,
        { headers: { Cookie: cookie } },
      ),
      config,
      'rid-denied',
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location') as string);
    expect(location.origin + location.pathname).toBe('https://www.example.com/login/failed');
    expect(location.searchParams.get('error')).toBe('access_denied');
  });

  it('GitHub 返回 bad_verification_code -> invalid_code 400', async () => {
    stub = stubFetch([
      {
        match: (url) => url.includes('access_token'),
        respond: () => jsonResponse({ error: 'bad_verification_code', error_description: 'expired' }),
      },
    ]);
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=stale&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-bad-code',
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('invalid_code');
  });

  it('GitHub 5xx -> upstream_unavailable 503', async () => {
    stub = stubFetch([
      {
        match: (url) => url.includes('access_token'),
        respond: () => new Response('upstream boom', { status: 502 }),
      },
    ]);
    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
    );

    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-5xx',
    );
    expect(response.status).toBe(503);
  });

  it('业务服务器回传失败（4xx）-> delivery_failed 502', async () => {
    const stubLocal = stubFetch([
      {
        match: (url) => url.includes('access_token'),
        respond: () => jsonResponse({ access_token: 't', token_type: 'bearer', scope: 'read:user' }),
      },
      { match: (url) => url.endsWith('/user'), respond: () => jsonResponse({ id: 1, login: 'a' }) },
      {
        match: (url) => url.startsWith('https://api.example.com/'),
        respond: () => new Response('unauthorized', { status: 401 }),
      },
    ]);
    stub = stubLocal;

    const { nonce, cookie, config } = await startFlow(
      `redirect_uri=${encodeURIComponent(CALLBACK_URI)}`,
    );
    const response = await handleCallback(
      new Request(`https://proxy.test/callback?code=c&state=${nonce}`, {
        headers: { Cookie: cookie },
      }),
      config,
      'rid-deliver',
    );
    expect(response.status).toBe(502);
    expect(await response.text()).toContain('delivery_failed');
    // 4xx 不做重试
    expect(stubLocal.calls.filter((call) => call.url.startsWith('https://api.example.com/')).length).toBe(1);
  });
});

describe('限流', () => {
  it('超过阈值返回 429 且带 Retry-After', async () => {
    const rateKv = createFakeKv();
    const config = testConfig({
      OAUTH_KV: createFakeKv(),
      RATE_LIMIT_KV: rateKv,
      RATE_LIMIT_PER_MINUTE: '2',
    });

    const make = () =>
      handleAuthorize(
        new Request(
          `https://proxy.test/authorize?redirect_uri=${encodeURIComponent(CALLBACK_URI)}&format=json`,
          { headers: { 'CF-Connecting-IP': '198.51.100.9' } },
        ),
        config,
        'rid-rate',
      );

    expect((await make()).status).toBe(200);
    expect((await make()).status).toBe(200);
    const limited = await make();
    expect(limited.status).toBe(429);
    expect(limited.headers.get('Retry-After')).toBe('60');
  });
});
