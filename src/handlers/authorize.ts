/**
 * GET|POST /authorize —— 发起授权。
 *
 * 职责：
 *  1. 校验请求来源（Origin / Referer 白名单）
 *  2. 校验 redirect_uri 是否在回调白名单内（防开放重定向、防把 token 送到攻击者域名）
 *  3. 校验可选的成功 / 失败跳转地址
 *  4. 生成本次授权的一次性 state（KV + 加密 Cookie）并跳转到 GitHub 授权页
 *
 * 加 `?format=json`（或 Accept: application/json）时返回 JSON：
 *   { ok:true, authorize_url, state, expires_in } —— 供 SPA 自行控制跳转时机。
 */

import { AppError } from '../errors.js';
import { fingerprint } from '../crypto.js';
import { logger } from '../logger.js';
import { checkRateLimit, clientIp } from '../ratelimit.js';
import { buildAuthorizeUrl } from '../github.js';
import { createState } from '../state.js';
import {
  assertCallbackUriAllowed,
  assertBrowserRedirectAllowed,
  assertOriginAllowed,
  normalizeBusinessState,
  normalizeScope,
  normalizeUrl,
} from '../validation.js';
import {
  applySecurityHeaders,
  buildRedirectWithResult,
  errorResponse,
  jsonResponse,
  methodNotAllowed,
  redirectResponse,
  wantsJson,
} from '../responses.js';
import type { Config } from '../config.js';

/** 读取参数：GET query / POST form / POST JSON 三种来源统一 */
async function readParams(request: Request): Promise<URLSearchParams> {
  const url = new URL(request.url);
  if (request.method !== 'POST') return url.searchParams;

  const contentType = (request.headers.get('Content-Type') || '').toLowerCase();
  if (contentType.includes('application/json')) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new AppError('invalid_request', '请求体不是合法 JSON', { detail: { field: 'body' } });
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new AppError('invalid_request', '请求体必须是 JSON 对象', { detail: { field: 'body' } });
    }
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
      if (value === null || value === undefined) continue;
      params.set(key, typeof value === 'string' ? value : JSON.stringify(value));
    }
    return params;
  }

  const text = await request.text();
  return new URLSearchParams(text);
}

/** 解析并校验浏览器跳转地址；不合法时记日志并忽略（而不是让整个登录失败） */
function resolveBrowserRedirect(
  raw: string | null,
  fallback: string | null,
  config: Config,
  requestId: string,
  field: string,
): string | null {
  const candidate = (raw && raw.trim()) || fallback;
  if (!candidate) return null;
  try {
    const url = normalizeUrl(candidate, config.allowInsecureRedirects);
    assertBrowserRedirectAllowed(url, config.allowedRedirectOrigins, config.baseUrl);
    return url.toString();
  } catch (error) {
    logger.warn('authorize.redirect_ignored', {
      request_id: requestId,
      field,
      value: candidate.slice(0, 200),
      reason: error instanceof AppError ? error.code : 'invalid_url',
    });
    return null;
  }
}

export async function handleAuthorize(
  request: Request,
  config: Config,
  requestId: string,
): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return methodNotAllowed(request, ['GET', 'POST'], requestId, config);
  }

  const params = await readParams(request);
  const jsonMode = wantsJson(request);

  // ---- 限流 ----
  const rate = await checkRateLimit(config, request, 'authorize');
  if (!rate.allowed) {
    logger.warn('authorize.rate_limited', {
      request_id: requestId,
      ip_fp: rate.fingerprint,
      limit: rate.limit,
    });
    return errorResponse(
      request,
      new AppError('rate_limited', undefined, {
        detail: { limit_per_minute: rate.limit, retry_after_seconds: 60 },
      }),
      requestId,
      config,
      { 'Retry-After': '60' },
    );
  }

  // ---- 失败跳转地址（先解析，保证后续任何校验失败都能优雅回跳前台）----
  const errorRedirect = resolveBrowserRedirect(
    params.get('error_redirect'),
    config.errorRedirect,
    config,
    requestId,
    'error_redirect',
  );

  const businessStateRaw = params.get('state');

  try {
    // ---- 来源校验 ----
    assertOriginAllowed(request, config.allowedCallbackOrigins, config.baseUrl);

    // ---- redirect_uri 白名单 ----
    const redirectUriRaw = params.get('redirect_uri');
    if (!redirectUriRaw) {
      throw new AppError('invalid_request', '缺少必需参数 redirect_uri', {
        detail: { required: ['redirect_uri'], optional: ['state', 'scope', 'success_redirect', 'error_redirect', 'format'] },
      });
    }
    const redirectUri = normalizeUrl(redirectUriRaw, config.allowInsecureRedirects);
    assertCallbackUriAllowed(redirectUri, config.allowedCallbackUris);

    // ---- 其他参数 ----
    const successRedirect = resolveBrowserRedirect(
      params.get('success_redirect'),
      config.successRedirect,
      config,
      requestId,
      'success_redirect',
    );
    const scope = normalizeScope(params.get('scope'), config.defaultScope, config.allowedScopes);
    const businessState = normalizeBusinessState(businessStateRaw);

    // ---- 生成一次性 state ----
    const ipFp = await fingerprint(clientIp(request), 16);
    const { nonce, setCookie } = await createState(config, {
      redirect_uri: redirectUri.toString(),
      business_state: businessState,
      scope,
      success_redirect: successRedirect,
      error_redirect: errorRedirect,
      // 默认连 JSON 模式也必须绑定 Cookie：仅靠 KV 的一次性 nonce 挡不住 login-CSRF
      // （攻击者用自己的 nonce 诱导受害者浏览器带着受害者 code 回调，即可把 token
      // 投递给业务服务器并顶掉受害者会话）。JSON 模式同样会下发 Set-Cookie，
      // 只要前端调用 /authorize 时带 credentials，回调即可正常通过校验。
      // 仅当显式设置 ALLOW_UNBOUND_STATE=true 时才恢复「不绑」的旧行为 ——
      // 那不是免费的兼容开关，而是主动接受 login-CSRF 风险的降级。
      cookie_bound: !(jsonMode && config.allowUnboundState),
      created_at: Date.now(),
      request_id: requestId,
      origin_fp: ipFp,
    });

    const authorizeUrl = buildAuthorizeUrl({
      clientId: config.githubClientId,
      redirectUri: config.callbackUrl,
      scope,
      state: nonce,
      allowSignup: params.get('allow_signup') !== 'false',
      login: params.get('login'),
    });

    logger.info('authorize.created', {
      request_id: requestId,
      redirect_uri: redirectUri.origin + redirectUri.pathname,
      scope,
      has_state: Boolean(businessState),
      json_mode: jsonMode,
      callback_allowlist_hit: true,
      ip_fp: ipFp,
      client_ip: clientIp(request) !== 'unknown' ? undefined : 'unknown',
    });

    if (jsonMode) {
      const corsHeaders = buildCorsHeaders(request, config);
      // 统一走 applySecurityHeaders：此前这里手写头清单，漏掉了 nosniff / X-Frame-Options / Pragma。
      const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
      applySecurityHeaders(headers, requestId, config);
      for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
      if (setCookie) headers.append('Set-Cookie', setCookie);

      return new Response(
        JSON.stringify(
          {
            ok: true,
            authorize_url: authorizeUrl,
            state: nonce,
            scope,
            expires_in: config.stateTtlSeconds,
            callback_url: config.callbackUrl,
            request_id: requestId,
          },
          null,
          2,
        ),
        { status: 200, headers },
      );
    }

    return redirectResponse(authorizeUrl, requestId, 302, {
      'Set-Cookie': setCookie,
    });
  } catch (error) {
    const appError = error instanceof AppError ? error : new AppError('internal_error', String(error), { expose: false });
    logger[appError.status >= 500 ? 'error' : 'warn']('authorize.failed', {
      request_id: requestId,
      error_code: appError.code,
      error_message: appError.message,
      detail: appError.detail,
    });

    if (appError.redirectable && errorRedirect) {
      return redirectResponse(
        buildRedirectWithResult(errorRedirect, {
          status: 'error',
          error: appError.code,
          error_description: appError.message,
          state: businessStateRaw,
          request_id: requestId,
        }),
        requestId,
        302,
      );
    }
    return errorResponse(request, appError, requestId, config);
  }
}

/** JSON 模式下的 CORS 支持：仅回显白名单内的 Origin */
export function buildCorsHeaders(request: Request, config: Config): Record<string, string> {
  const origin = request.headers.get('Origin');
  if (!origin) return {};
  const allowed =
    config.allowedCallbackOrigins.some((item) => item.replace(/\/+$/, '') === origin) ||
    origin === new URL(config.baseUrl).origin;
  if (!allowed) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}
