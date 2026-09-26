/**
 * 配置装载与校验。
 *
 * 设计原则：
 * 1. 所有敏感信息（Client ID/Secret、签名密钥）只从 Secrets 读取，代码里没有任何默认值；
 * 2. 配置错误快速失败（fail fast），返回 server_misconfigured 而不是带病运行；
 * 3. 配置对象在单次请求内构造，无跨请求可变状态（Workers 单 isolate 并发安全）。
 */

import { AppError } from './errors.js';
import type { DeliveryMethod, Env, LogLevel, KVNamespace } from './types.js';

export interface Config {
  // 凭据
  githubClientId: string;
  githubClientSecret: string;
  cookieSecret: string;
  signingSecret: string;

  // 地址
  baseUrl: string;
  callbackUrl: string;
  userAgent: string;

  // 白名单
  allowedCallbackUris: string[];
  allowedCallbackOrigins: string[];
  allowedRedirectOrigins: string[];
  allowedScopes: string[];

  // scope / 跳转
  defaultScope: string;
  successRedirect: string | null;
  errorRedirect: string | null;

  // 行为参数
  stateTtlSeconds: number;
  rateLimitPerMinute: number;
  upstreamTimeoutMs: number;
  upstreamRetries: number;
  deliveryMethod: DeliveryMethod;
  deliveryTimeoutMs: number;
  allowInsecureRedirects: boolean;

  // 元信息
  environment: string;
  version: string;
  logLevel: LogLevel;

  // 绑定
  kv: KVNamespace;
  rateLimitKv: KVNamespace | null;
}

function splitList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function toInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function toBool(raw: string | undefined, fallback = false): boolean {
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase());
}

/**
 * @param env        Worker 绑定
 * @param requestUrl 当前请求 URL，用于在未配置 PUBLIC_BASE_URL 时推断 Worker 自身地址
 */
export function loadConfig(env: Env, requestUrl: URL): Config {
  const missing: string[] = [];
  if (!env.GITHUB_CLIENT_ID) missing.push('GITHUB_CLIENT_ID');
  if (!env.GITHUB_CLIENT_SECRET) missing.push('GITHUB_CLIENT_SECRET');
  if (!env.COOKIE_SECRET) missing.push('COOKIE_SECRET');
  if (!env.CALLBACK_SIGNING_SECRET) missing.push('CALLBACK_SIGNING_SECRET');
  if (!env.OAUTH_KV) missing.push('OAUTH_KV(binding)');

  if (missing.length > 0) {
    throw new AppError('server_misconfigured', '服务端配置缺失', {
      detail: {
        missing,
        hint: '请执行 npx wrangler secret put <NAME> 注入密钥，并确认 wrangler.toml 中已绑定 OAUTH_KV',
      },
      expose: true,
      redirectable: false,
    });
  }

  // 密钥强度：三个密钥都必须达到最小长度，避免弱密钥导致 Cookie 可伪造 / 签名可爆破
  const weakSecrets: string[] = [];
  if (env.GITHUB_CLIENT_SECRET.length < 16) weakSecrets.push('GITHUB_CLIENT_SECRET(>=16)');
  if (env.COOKIE_SECRET.length < 16) weakSecrets.push('COOKIE_SECRET(>=16)');
  if (env.CALLBACK_SIGNING_SECRET.length < 32) weakSecrets.push('CALLBACK_SIGNING_SECRET(>=32)');
  if (weakSecrets.length > 0) {
    throw new AppError('server_misconfigured', '密钥强度不足', {
      detail: {
        weak: weakSecrets,
        hint: '请用 npm run gen-secret 生成 32 字节随机串后 wrangler secret put',
      },
      redirectable: false,
    });
  }

  const baseUrl = (env.PUBLIC_BASE_URL || requestUrl.origin).replace(/\/+$/, '');
  const deliveryMethod: DeliveryMethod =
    (env.DELIVERY_METHOD || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';

  return {
    githubClientId: env.GITHUB_CLIENT_ID,
    githubClientSecret: env.GITHUB_CLIENT_SECRET,
    cookieSecret: env.COOKIE_SECRET,
    signingSecret: env.CALLBACK_SIGNING_SECRET,

    baseUrl,
    callbackUrl: `${baseUrl}/callback`,
    userAgent: `github-oauth-proxy/${env.VERSION || '1.0.0'} (+${baseUrl})`,

    allowedCallbackUris: splitList(env.ALLOWED_CALLBACK_URIS),
    allowedCallbackOrigins: splitList(env.ALLOWED_CALLBACK_ORIGINS),
    allowedRedirectOrigins: splitList(env.ALLOWED_REDIRECT_ORIGINS),
    allowedScopes: splitList(env.ALLOWED_SCOPES),

    defaultScope: (env.DEFAULT_SCOPE || 'read:user user:email').trim(),
    successRedirect: env.SUCCESS_REDIRECT?.trim() || null,
    errorRedirect: env.ERROR_REDIRECT?.trim() || null,

    stateTtlSeconds: toInt(env.STATE_TTL_SECONDS, 600, 60, 3600),
    rateLimitPerMinute: toInt(env.RATE_LIMIT_PER_MINUTE, 60, 0, 100000),
    upstreamTimeoutMs: toInt(env.UPSTREAM_TIMEOUT_MS, 8000, 1000, 30000),
    upstreamRetries: toInt(env.UPSTREAM_RETRIES, 2, 0, 5),
    deliveryMethod,
    deliveryTimeoutMs: toInt(env.DELIVERY_TIMEOUT_MS, 8000, 1000, 30000),
    allowInsecureRedirects: toBool(env.ALLOW_INSECURE_REDIRECTS, false),

    environment: env.ENVIRONMENT || 'production',
    version: env.VERSION || '1.0.0',
    logLevel: (env.LOG_LEVEL as LogLevel) || 'info',

    kv: env.OAUTH_KV,
    rateLimitKv: env.RATE_LIMIT_KV ?? null,
  };
}
