/**
 * 运行时类型定义。
 *
 * 这里刻意不依赖 @cloudflare/workers-types / @types/node，
 * 只声明本服务用到的极小子集，保证在任意环境下 `tsc --noEmit` 都能通过。
 */

/** Workers KV 的最小可用子集 */
export interface KVNamespace {
  get(key: string, type: 'text'): Promise<string | null>;
  get(key: string, type: 'json'): Promise<unknown>;
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number; expiration?: number },
  ): Promise<void>;
  delete(key: string): Promise<void>;
}

/** Worker 环境变量 / 绑定（vars + secrets + kv_namespaces） */
export interface Env {
  // ---- Secrets（必须通过 wrangler secret put 注入，禁止硬编码）----
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  COOKIE_SECRET: string;
  CALLBACK_SIGNING_SECRET: string;

  // ---- 绑定 ----
  OAUTH_KV: KVNamespace;
  RATE_LIMIT_KV?: KVNamespace;

  // ---- 普通变量 ----
  PUBLIC_BASE_URL?: string;
  ALLOWED_CALLBACK_URIS?: string;
  ALLOWED_CALLBACK_ORIGINS?: string;
  ALLOWED_REDIRECT_ORIGINS?: string;
  DEFAULT_SCOPE?: string;
  ALLOWED_SCOPES?: string;
  SUCCESS_REDIRECT?: string;
  ERROR_REDIRECT?: string;
  STATE_TTL_SECONDS?: string;
  RATE_LIMIT_PER_MINUTE?: string;
  UPSTREAM_TIMEOUT_MS?: string;
  UPSTREAM_RETRIES?: string;
  DELIVERY_METHOD?: string;
  DELIVERY_TIMEOUT_MS?: string;
  ALLOW_INSECURE_REDIRECTS?: string;
  /** "true" 时才允许 JSON 模式跳过 state Cookie 绑定（默认 false，即必须绑定） */
  ALLOW_UNBOUND_STATE?: string;
  ENVIRONMENT?: string;
  VERSION?: string;
  LOG_LEVEL?: string;
}

/** ExecutionContext 的最小子集 */
export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException?(): void;
}

export type DeliveryMethod = 'POST' | 'GET';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
