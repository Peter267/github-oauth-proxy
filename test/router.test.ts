/**
 * 路由层测试：入口装配、配置缺失快速失败、CORS 预检、404、健康检查。
 */

import { afterEach, describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { TEST_ENV, createFakeKv } from './helpers.js';
import type { Env, ExecutionContextLike } from '../src/types.js';

const ctx: ExecutionContextLike = { waitUntil: () => {} };

function env(overrides: Partial<Env> = {}): Env {
  return { ...TEST_ENV, OAUTH_KV: createFakeKv(), ...overrides };
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('Worker 入口', () => {
  it('GET / 返回服务说明页', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/'), env(), ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(response.headers.get('X-Request-Id')).toBeTruthy();
    const html = await response.text();
    expect(html).toContain('GitHub OAuth 中转');
  });

  it('GET /health 返回结构化健康信息', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/health'), env(), ctx);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      service: string;
      checks: Record<string, { ok: boolean }>;
      config_summary: Record<string, unknown>;
    };
    expect(body.ok).toBe(true);
    expect(body.service).toBe('github-oauth-proxy');
    expect(body.checks.kv_read?.ok).toBe(true);
    expect(body.config_summary.callback_allowlist).toBe(2);
  });

  it('GET /health?deep=1 探测 GitHub 可达性', async () => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ resources: {} }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;

    const response = await worker.fetch(new Request('https://proxy.test/health?deep=1'), env(), ctx);
    const body = (await response.json()) as { ok: boolean; checks: Record<string, { ok: boolean }> };
    expect(body.checks.kv_round_trip?.ok).toBe(true);
    expect(body.checks.github_api?.ok).toBe(true);
    expect(body.ok).toBe(true);
  });

  it('缺少 Secrets 时返回 500 server_misconfigured 且不泄露细节', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/health', { headers: { Accept: 'application/json' } }),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );
    expect(response.status).toBe(500);
    const body = (await response.json()) as { ok: boolean; error: { code: string; detail?: unknown } };
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('server_misconfigured');
    expect(JSON.stringify(body.error.detail)).toContain('GITHUB_CLIENT_SECRET');
  });

  it('未知路由返回 404 结构化错误', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/nope', { headers: { Accept: 'application/json' } }),
      env(),
      ctx,
    );
    expect(response.status).toBe(404);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe('not_found');
  });

  it('尾斜杠路由等价', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/health/'), env(), ctx);
    expect(response.status).toBe(200);
  });

  it('OPTIONS 预检放行白名单内来源，拒绝其他来源', async () => {
    const ok = await worker.fetch(
      new Request('https://proxy.test/authorize', {
        method: 'OPTIONS',
        headers: { Origin: 'https://www.example.com' },
      }),
      env(),
      ctx,
    );
    expect(ok.status).toBe(204);
    expect(ok.headers.get('Access-Control-Allow-Origin')).toBe('https://www.example.com');

    const bad = await worker.fetch(
      new Request('https://proxy.test/authorize', {
        method: 'OPTIONS',
        headers: { Origin: 'https://evil.com', Accept: 'application/json' },
      }),
      env(),
      ctx,
    );
    expect(bad.status).toBe(403);
  });

  it('/authorize 只接受 GET / POST', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/authorize', { method: 'DELETE', headers: { Accept: 'application/json' } }),
      env(),
      ctx,
    );
    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('GET, POST');
  });

  it('/callback 只接受 GET', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/callback', { method: 'POST', headers: { Accept: 'application/json' } }),
      env(),
      ctx,
    );
    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('GET');
  });

  it('响应统一带安全头', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/health'), env(), ctx);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
  });
});

describe('G-4 production 下 bootstrap 失败不得泄露 detail', () => {
  const brokenProduction = (): Env =>
    env({ ENVIRONMENT: 'production', GITHUB_CLIENT_SECRET: '' });

  it('JSON 响应不含 detail（缺 GITHUB_CLIENT_SECRET 时）', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/health', { headers: { Accept: 'application/json' } }),
      brokenProduction(),
      ctx,
    );
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).toContain('server_misconfigured');
    expect(text).not.toContain('detail');
    expect(text).not.toContain('GITHUB_CLIENT_SECRET');
    expect(text).not.toContain('hint');
  });

  it('HTML 错误页不含 detail（缺 GITHUB_CLIENT_SECRET 时）', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/health'),
      brokenProduction(),
      ctx,
    );
    expect(response.status).toBe(500);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    const html = await response.text();
    expect(html).not.toContain('GITHUB_CLIENT_SECRET');
    expect(html).not.toContain('wrangler secret put');
  });

  it('未知路由同样是 production 不暴露 detail', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/nope', { headers: { Accept: 'application/json' } }),
      env({ ENVIRONMENT: 'production' }),
      ctx,
    );
    expect(response.status).toBe(404);
    const text = await response.text();
    expect(text).not.toContain('detail');
    expect(text).not.toContain('routes');
  });

  it('非 production（test）仍保留 detail，便于自检与联调', async () => {
    const json = await worker.fetch(
      new Request('https://proxy.test/health', { headers: { Accept: 'application/json' } }),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );
    expect(await json.text()).toContain('GITHUB_CLIENT_SECRET');

    // 首页/引导页是刻意的首次部署引导，无论环境都点名缺失项（保持既有契约）
    const setup = await worker.fetch(new Request('https://proxy.test/'), brokenProduction(), ctx);
    expect(setup.status).toBe(503);
    expect(await setup.text()).toContain('GITHUB_CLIENT_SECRET');
  });
});

describe('G-6 所有响应分支统一下发安全头', () => {
  function assertSecurityHeaders(response: Response): void {
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
    expect(response.headers.get('Cache-Control')).toContain('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
    expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
  }

  it('首页（200）带齐安全头', async () => {
    const response = await worker.fetch(new Request('https://proxy.test/'), env(), ctx);
    expect(response.status).toBe(200);
    assertSecurityHeaders(response);
    expect(response.headers.get('X-Proxy-Version')).toBeTruthy();
  });

  it('配置引导页（503）带齐安全头', async () => {
    const response = await worker.fetch(
      new Request('https://proxy.test/'),
      env({ GITHUB_CLIENT_SECRET: '' }),
      ctx,
    );
    expect(response.status).toBe(503);
    assertSecurityHeaders(response);
  });

  it('/authorize?format=json 的 JSON 分支带齐安全头', async () => {
    const response = await worker.fetch(
      new Request(
        `https://proxy.test/authorize?format=json&redirect_uri=${encodeURIComponent(
          'https://api.example.com/auth/github/callback',
        )}`,
        { headers: { Origin: 'https://www.example.com' } },
      ),
      env(),
      ctx,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('application/json');
    assertSecurityHeaders(response);
    expect(response.headers.get('Set-Cookie')).toContain('gh_oauth_state');
    expect(response.headers.get('X-Proxy-Version')).toBeTruthy();
  });
});
