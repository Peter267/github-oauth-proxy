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

/**
 * 占位符指纹清单。
 *
 * 一键部署时，仓库模板里的示例值会被原样预填到 Cloudflare 的部署表单；
 * 若用户没有替换就直接上线，服务会带着「公开可知」的密钥运行
 * （state Cookie 可被伪造、回传业务服务器的报文可被伪造），属于静默的高危配置错误。
 * 因此这里主动识别并拒绝，把「忘了改」变成启动即失败的显式提示。
 */
const PLACEHOLDER_MARKERS = [
  'replace_with',
  'replace-with',
  'replacewith',
  'changeme',
  'change_me',
  'change-me',
  'your_',
  'your-',
  'placeholder',
  'xxxx',
  'todo',
  'example.com',
];

/** Secret 名称与 Env 字段的映射（顺序即展示顺序） */
const SECRET_FIELDS: Array<[string, keyof Env]> = [
  ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_ID'],
  ['GITHUB_CLIENT_SECRET', 'GITHUB_CLIENT_SECRET'],
  ['COOKIE_SECRET', 'COOKIE_SECRET'],
  ['CALLBACK_SIGNING_SECRET', 'CALLBACK_SIGNING_SECRET'],
];

export function looksLikePlaceholder(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return PLACEHOLDER_MARKERS.some((marker) => normalized.includes(marker));
}

/** 尚未注入（空值）的 Secret 名称；供快速失败与配置引导页复用 */
export function findMissingSecrets(env: Env): string[] {
  return SECRET_FIELDS.filter(([, field]) => !env[field]).map(([name]) => name);
}

/** 仍是模板占位符的 Secret 名称；供快速失败与配置引导页复用 */
export function findPlaceholderSecrets(env: Env): string[] {
  return SECRET_FIELDS.filter(([, field]) => {
    const value = env[field];
    return typeof value === 'string' && value.length > 0 && looksLikePlaceholder(value);
  }).map(([name]) => name);
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
  const missing = findMissingSecrets(env);
  if (!env.OAUTH_KV) missing.push('OAUTH_KV(binding)');

  if (missing.length > 0) {
    throw new AppError('server_misconfigured', '服务端配置缺失', {
      detail: {
        missing,
        hint: '网页部署请在 Cloudflare 控制台 Settings → Variables and Secrets 补齐（见 DEPLOY.md）；命令行部署请执行 npx wrangler secret put <NAME>，并确认已绑定 OAUTH_KV',
      },
      expose: true,
      redirectable: false,
    });
  }

  // 占位符检测必须在强度检测之前：模板示例值往往"长度合法"，却等于公开密钥
  const placeholders = findPlaceholderSecrets(env);
  if (placeholders.length > 0) {
    throw new AppError('server_misconfigured', '检测到未替换的占位符密钥', {
      detail: {
        placeholders,
        hint: '这些值仍是公开仓库里的示例模板，任何读到源码的人都能用它伪造 state Cookie 与回传签名。请替换为真实值；随机密钥可用 npm run gen-secret 生成，或纯浏览器执行 crypto.getRandomValues(new Uint8Array(32))',
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
