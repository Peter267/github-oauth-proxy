/**
 * 测试辅助：内存版 KV、测试用配置、可控的 fetch 桩。
 */

import { loadConfig, type Config } from '../src/config.js';
import type { Env, KVNamespace } from '../src/types.js';

export interface FakeKv extends KVNamespace {
  store: Map<string, string>;
  puts: number;
}

export function createFakeKv(): FakeKv {
  const store = new Map<string, string>();
  const kv: FakeKv = {
    store,
    puts: 0,
    get: (async (key: string, type?: 'text' | 'json'): Promise<unknown> => {
      const value = store.get(key);
      if (value === undefined) return null;
      if (type === 'json') {
        try {
          return JSON.parse(value) as unknown;
        } catch {
          return null;
        }
      }
      return value;
    }) as unknown as KVNamespace['get'],
    async put(key: string, value: string): Promise<void> {
      kv.puts += 1;
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
  };
  return kv;
}

export const TEST_ENV: Env = {
  GITHUB_CLIENT_ID: 'Ov23liTESTCLIENTID0000',
  GITHUB_CLIENT_SECRET: 'test-client-secret-value',
  COOKIE_SECRET: 'test-cookie-secret-value-0123456789',
  CALLBACK_SIGNING_SECRET: 'test-signing-secret-value-0123456789',
  OAUTH_KV: createFakeKv(),
  PUBLIC_BASE_URL: 'https://proxy.test',
  ALLOWED_CALLBACK_URIS:
    'https://api.example.com/auth/github/callback,https://api.example.com/v2/auth/*',
  ALLOWED_CALLBACK_ORIGINS: 'https://www.example.com',
  ALLOWED_REDIRECT_ORIGINS: 'https://www.example.com',
  DEFAULT_SCOPE: 'read:user user:email',
  STATE_TTL_SECONDS: '600',
  RATE_LIMIT_PER_MINUTE: '1000',
  UPSTREAM_TIMEOUT_MS: '5000',
  UPSTREAM_RETRIES: '0',
  DELIVERY_METHOD: 'POST',
  ALLOW_INSECURE_REDIRECTS: 'false',
  ENVIRONMENT: 'test',
  VERSION: '0.0.0-test',
  LOG_LEVEL: 'error',
};

export function testConfig(overrides: Partial<Env> = {}): Config {
  const env: Env = { ...TEST_ENV, OAUTH_KV: createFakeKv(), ...overrides };
  if (overrides.OAUTH_KV) env.OAUTH_KV = overrides.OAUTH_KV;
  return loadConfig(env, new URL('https://proxy.test/authorize'));
}

export interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  /** fetch init.redirect（用于断言出站请求不跟随重定向） */
  redirect: string | null;
}

export interface FetchStub {
  calls: RecordedCall[];
  restore(): void;
}

/**
 * 安装 fetch 桩：
 *  - 命中 routes 的按 handler 返回
 *  - 未命中的抛错，避免测试静默走真实网络
 */
export function stubFetch(
  routes: Array<{
    match: (url: string, call: RecordedCall) => boolean;
    respond: (call: RecordedCall) => Response | Promise<Response>;
  }>,
): FetchStub {
  const calls: RecordedCall[] = [];
  const original = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const headers: Record<string, string> = {};
    new Headers(init?.headers as HeadersInit | undefined).forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    const call: RecordedCall = {
      url,
      method: (init?.method || 'GET').toUpperCase(),
      headers,
      body: typeof init?.body === 'string' ? init.body : null,
      redirect: typeof init?.redirect === 'string' ? init.redirect : null,
    };
    calls.push(call);

    for (const route of routes) {
      if (route.match(url, call)) return await route.respond(call);
    }
    throw new Error(`unstubbed fetch: ${call.method} ${url}`);
  }) as typeof fetch;

  return {
    calls,
    restore() {
      globalThis.fetch = original;
    },
  };
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

/** 从 Set-Cookie 里抽出 name=value 对，用于构造后续回调请求的 Cookie 头 */
export function cookiePair(setCookie: string | null, name: string): string {
  if (!setCookie) return '';
  for (const segment of setCookie.split(';')) {
    const trimmed = segment.trim();
    if (trimmed.startsWith(`${name}=`)) return trimmed;
  }
  return '';
}
