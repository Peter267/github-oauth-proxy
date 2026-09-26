/**
 * GitHub 上游交互：授权页 URL 构造、code 换 token、拉取用户信息。
 *
 * 关键点：
 * - 全部请求带超时（AbortController），避免 Workers 挂在慢连接上；
 * - 幂等请求（token 交换 / 用户信息）做有限次退避重试，覆盖跨境链路抖动；
 * - 429 尊重 Retry-After；
 * - 日志绝不打印 client_secret / code / access_token 原文。
 */

import { AppError } from './errors.js';
import { logger } from './logger.js';
import type { Config } from './config.js';

export const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
export const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
export const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_API_VERSION = '2022-11-28';

export interface TokenResult {
  accessToken: string;
  tokenType: string;
  scope: string;
}

export interface GithubUser {
  id: number;
  login: string;
  name?: string | null;
  email?: string | null;
  avatar_url?: string | null;
  html_url?: string | null;
  company?: string | null;
  location?: string | null;
  blog?: string | null;
  bio?: string | null;
  type?: string | null;
  site_admin?: boolean | null;
  created_at?: string | null;
  two_factor_authentication?: boolean | null;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// 授权页
// ---------------------------------------------------------------------------

export interface AuthorizeUrlParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  allowSignup?: boolean;
  login?: string | null;
}

export function buildAuthorizeUrl(params: AuthorizeUrlParams): string {
  const url = new URL(GITHUB_AUTHORIZE_URL);
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);
  url.searchParams.set('allow_signup', params.allowSignup === false ? 'false' : 'true');
  if (params.login) url.searchParams.set('login', params.login);
  return url.toString();
}

// ---------------------------------------------------------------------------
// 通用带重试请求
// ---------------------------------------------------------------------------

interface RetryOptions {
  method: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
  retries: number;
  /** 日志事件名前缀 */
  event: string;
  requestId: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(attempt: number): number {
  return Math.min(200 * 2 ** attempt, 2000);
}

function parseRetryAfter(raw: string | null): number {
  if (!raw) return 1000;
  const seconds = Number.parseInt(raw, 10);
  if (Number.isFinite(seconds)) return Math.min(Math.max(seconds, 0) * 1000, 5000);
  const date = Date.parse(raw);
  if (Number.isFinite(date)) return Math.min(Math.max(date - Date.now(), 0), 5000);
  return 1000;
}

/** URL 脱敏：日志里只保留 origin + path，剥掉 query（可能含 code） */
function safeUrl(raw: string): string {
  try {
    const url = new URL(raw);
    return `${url.origin}${url.pathname}`;
  } catch {
    return raw;
  }
}

async function fetchWithRetry(target: string, options: RetryOptions): Promise<Response> {
  let lastError: unknown = null;

  for (let attempt = 0; attempt <= options.retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    const startedAt = Date.now();

    try {
      const response = await fetch(target, {
        method: options.method,
        headers: options.headers,
        body: options.body,
        signal: controller.signal,
      });
      const durationMs = Date.now() - startedAt;

      logger.debug(`${options.event}.response`, {
        request_id: options.requestId,
        target: safeUrl(target),
        status: response.status,
        duration_ms: durationMs,
        attempt,
      });

      if (response.status === 429) {
        const waitMs = parseRetryAfter(response.headers.get('Retry-After'));
        logger.warn(`${options.event}.rate_limited`, {
          request_id: options.requestId,
          target: safeUrl(target),
          wait_ms: waitMs,
          attempt,
        });
        if (attempt < options.retries) {
          await sleep(waitMs);
          continue;
        }
        return response;
      }

      if (response.status >= 500 && attempt < options.retries) {
        await sleep(backoffMs(attempt));
        continue;
      }

      return response;
    } catch (error) {
      lastError = error;
      const aborted =
        error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError');
      logger.warn(`${options.event}.network_error`, {
        request_id: options.requestId,
        target: safeUrl(target),
        attempt,
        timeout: aborted,
        error: error instanceof Error ? error.message : String(error),
      });
      if (attempt < options.retries) {
        await sleep(backoffMs(attempt));
        continue;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  const aborted =
    lastError instanceof Error && (lastError.name === 'AbortError' || lastError.name === 'TimeoutError');
  throw new AppError(aborted ? 'upstream_timeout' : 'upstream_unavailable', undefined, {
    detail: { upstream: safeUrl(target), timeout_ms: options.timeoutMs },
    cause: lastError,
  });
}

// ---------------------------------------------------------------------------
// code -> access_token
// ---------------------------------------------------------------------------

/** GitHub 返回的 OAuth 错误码 -> 本服务错误码 */
function mapGithubOauthError(code: string): { errorCode: 'invalid_code' | 'token_exchange_failed' | 'server_misconfigured'; message: string } {
  switch (code) {
    case 'bad_verification_code':
      return { errorCode: 'invalid_code', message: 'GitHub 授权码无效、已过期或已被使用' };
    case 'incorrect_client_credentials':
      return { errorCode: 'server_misconfigured', message: 'GITHUB_CLIENT_ID / SECRET 配置错误' };
    case 'redirect_uri_mismatch':
      return { errorCode: 'server_misconfigured', message: 'redirect_uri 与 GitHub OAuth App 配置不一致' };
    default:
      return { errorCode: 'token_exchange_failed', message: `GitHub 返回错误: ${code}` };
  }
}

export async function exchangeCodeForToken(
  config: Config,
  code: string,
  requestId: string,
): Promise<TokenResult> {
  const response = await fetchWithRetry(GITHUB_TOKEN_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'User-Agent': config.userAgent,
    },
    body: JSON.stringify({
      client_id: config.githubClientId,
      client_secret: config.githubClientSecret,
      code,
      // redirect_uri 必须与 /authorize 时使用的完全一致，否则 GitHub 会拒绝
      redirect_uri: config.callbackUrl,
    }),
    timeoutMs: config.upstreamTimeoutMs,
    retries: config.upstreamRetries,
    event: 'github.token',
    requestId,
  });

  if (response.status === 429) {
    throw new AppError('upstream_rate_limited', undefined, {
      detail: { retry_after_ms: parseRetryAfter(response.headers.get('Retry-After')) },
    });
  }
  if (response.status >= 500) {
    throw new AppError('upstream_unavailable', undefined, {
      detail: { upstream_status: response.status },
    });
  }

  let payload: Record<string, unknown>;
  try {
    payload = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new AppError('token_exchange_failed', 'GitHub 返回了非 JSON 响应', {
      detail: { upstream_status: response.status },
    });
  }

  const oauthError = typeof payload.error === 'string' ? payload.error : null;
  if (oauthError) {
    const mapped = mapGithubOauthError(oauthError);
    logger.warn('github.token.oauth_error', {
      request_id: requestId,
      github_error: oauthError,
      github_error_description:
        typeof payload.error_description === 'string' ? payload.error_description : undefined,
    });
    throw new AppError(mapped.errorCode, mapped.message, {
      detail: {
        github_error: oauthError,
        github_error_description: payload.error_description,
        github_error_uri: payload.error_uri,
      },
    });
  }

  const accessToken = typeof payload.access_token === 'string' ? payload.access_token : null;
  if (!accessToken) {
    throw new AppError('token_exchange_failed', 'GitHub 响应中缺少 access_token', {
      detail: { upstream_status: response.status },
    });
  }

  return {
    accessToken,
    tokenType: typeof payload.token_type === 'string' ? payload.token_type : 'bearer',
    scope: typeof payload.scope === 'string' ? payload.scope : '',
  };
}

// ---------------------------------------------------------------------------
// 用户信息
// ---------------------------------------------------------------------------

function githubApiHeaders(config: Config, token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': config.userAgent,
  };
}

export async function fetchGithubUser(
  config: Config,
  token: string,
  requestId: string,
): Promise<GithubUser> {
  const response = await fetchWithRetry(`${GITHUB_API_BASE}/user`, {
    method: 'GET',
    headers: githubApiHeaders(config, token),
    timeoutMs: config.upstreamTimeoutMs,
    retries: config.upstreamRetries,
    event: 'github.user',
    requestId,
  });

  if (response.status === 401) {
    throw new AppError('user_fetch_failed', 'access_token 无效或权限不足', {
      detail: { upstream_status: 401 },
    });
  }
  if (response.status === 403) {
    const remaining = response.headers.get('X-RateLimit-Remaining');
    if (remaining === '0') {
      throw new AppError('upstream_rate_limited', undefined, {
        detail: {
          reset_at: response.headers.get('X-RateLimit-Reset'),
          retry_after_ms: parseRetryAfter(response.headers.get('Retry-After')),
        },
      });
    }
    throw new AppError('user_fetch_failed', 'GitHub 拒绝了该请求', { detail: { upstream_status: 403 } });
  }
  if (!response.ok) {
    throw new AppError('user_fetch_failed', undefined, { detail: { upstream_status: response.status } });
  }

  try {
    return (await response.json()) as GithubUser;
  } catch (error) {
    throw new AppError('user_fetch_failed', '解析 GitHub 用户信息失败', { cause: error });
  }
}

/**
 * 拉取主邮箱（需 user:email scope）。
 * 该接口失败不影响主流程：GitHub 的 /user 在部分场景下 email 为 null，
 * 但缺少邮箱不应导致登录整体失败。
 */
export async function fetchPrimaryEmail(
  config: Config,
  token: string,
  requestId: string,
): Promise<string | null> {
  try {
    const response = await fetchWithRetry(`${GITHUB_API_BASE}/user/emails`, {
      method: 'GET',
      headers: githubApiHeaders(config, token),
      timeoutMs: config.upstreamTimeoutMs,
      retries: 0,
      event: 'github.emails',
      requestId,
    });
    if (!response.ok) return null;
    const list = (await response.json()) as Array<{
      email?: string;
      primary?: boolean;
      verified?: boolean;
    }>;
    if (!Array.isArray(list)) return null;
    const primary = list.find((item) => item.primary && item.verified);
    const verified = list.find((item) => item.verified);
    return primary?.email ?? verified?.email ?? list[0]?.email ?? null;
  } catch (error) {
    logger.debug('github.emails.skipped', {
      request_id: requestId,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}
