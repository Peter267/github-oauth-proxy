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
