/**
 * GET /callback —— GitHub 回调，完成授权码交换并回传业务服务器。
 *
 * 流程：
 *   1. 限流
 *   2. 取出并销毁一次性 state（KV），校验加密 Cookie 绑定
 *   3. 处理 GitHub 侧返回的 error（用户拒绝授权等）
 *   4. code -> access_token（POST https://github.com/login/oauth/access_token）
 *   5. 拉取用户资料（GET https://api.github.com/user，按 scope 尝试 /user/emails）
 *   6. HMAC 签名后 POST 给业务服务器（redirect_uri）
 *   7. 302 到 success_redirect，或渲染内置成功页
 *
 * 任何一步失败都会带上 record.error_redirect（若已配置且在白名单内）优雅回跳。
 */

import { AppError, isAppError } from '../errors.js';
import { fingerprint } from '../crypto.js';
import { logger } from '../logger.js';
import { checkRateLimit } from '../ratelimit.js';
import { exchangeCodeForToken, fetchGithubUser, fetchPrimaryEmail } from '../github.js';
import { clearStateCookie, consumeState, readStateCookie, type StateRecord } from '../state.js';
import { assertCallbackUriAllowed } from '../validation.js';
import { deliverToBusinessServer, type DeliveryPayload, type DeliveryUserInfo } from '../deliver.js';
import {
  buildRedirectWithResult,
  errorResponse,
  jsonResponse,
  methodNotAllowed,
  redirectResponse,
} from '../responses.js';
import { renderSuccessPage } from '../pages.js';
import type { Config } from '../config.js';

export async function handleCallback(
  request: Request,
  config: Config,
  requestId: string,
): Promise<Response> {
  if (request.method !== 'GET') {
    return methodNotAllowed(request, ['GET'], requestId, config);
  }

  const url = new URL(request.url);
  const startedAt = Date.now();
  let record: StateRecord | null = null;

  const rate = await checkRateLimit(config, request, 'callback');
  if (!rate.allowed) {
    logger.warn('callback.rate_limited', {
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
      { 'Retry-After': '60', 'Set-Cookie': clearStateCookie(config) },
    );
  }

  try {
    // ---- 1. 一次性 state ----
    const nonce = url.searchParams.get('state');
    if (!nonce) {
      throw new AppError('state_missing', undefined, { detail: { param: 'state' }, redirectable: false });
    }

    record = await consumeState(config, nonce);
    if (!record) {
      logger.warn('callback.state_invalid', { request_id: requestId, ip_fp: rate.fingerprint });
      throw new AppError('state_expired', undefined, { redirectable: false });
    }

    // ---- 2. Cookie 绑定校验（双提交）----
    if (record.cookie_bound) {
      const cookie = await readStateCookie(config, request);
      if (!cookie || cookie.n !== nonce) {
        logger.warn('callback.state_mismatch', {
          request_id: requestId,
          session_request_id: record.request_id,
          cookie_present: Boolean(cookie),
          ip_fp: rate.fingerprint,
        });
        throw new AppError('state_mismatch', undefined, { redirectable: false });
      }
    }

    // ---- 2.5 回传地址二次校验（纵深防御）----
    // redirect_uri 在 /authorize 阶段已过白名单，但这里再校验一次，
    // 确保即使 KV 记录被投毒或历史数据越权，也绝不会把签名报文发往白名单之外。
    let deliveryTarget: URL;
    try {
      deliveryTarget = new URL(record.redirect_uri);
    } catch {
      throw new AppError('redirect_uri_not_allowed', '回调地址格式非法', { redirectable: false });
    }
    assertCallbackUriAllowed(deliveryTarget, config.allowedCallbackUris);

    // ---- 3. GitHub 侧错误（用户拒绝 / 参数不匹配）----
    const githubError = url.searchParams.get('error');
    if (githubError) {
      const description = url.searchParams.get('error_description');
      logger.warn('callback.github_error', {
        request_id: requestId,
        github_error: githubError,
        github_error_description: description,
      });
      const code =
        githubError === 'access_denied' ? 'access_denied' : githubError === 'redirect_uri_mismatch' ? 'server_misconfigured' : 'token_exchange_failed';
      throw new AppError(code, code === 'access_denied' ? undefined : `GitHub 返回错误: ${githubError}`, {
        detail: { github_error: githubError, github_error_description: description },
      });
    }

    // ---- 4. 授权码 ----
    const code = url.searchParams.get('code');
    if (!code) {
      throw new AppError('invalid_request', '缺少必需参数 code', { detail: { param: 'code' } });
    }
    if (code.length > 128) {
      throw new AppError('invalid_code', 'code 长度异常', { detail: { length: code.length } });
    }

    // ---- 5. 换取 access_token ----
    const token = await exchangeCodeForToken(config, code, requestId);
    const tokenFp = await fingerprint(token.accessToken);

    // ---- 6. 用户信息 ----
    const user = await fetchGithubUser(config, token.accessToken, requestId);
    const email =
      typeof user.email === 'string' && user.email
        ? user.email
        : await fetchPrimaryEmail(config, token.accessToken, requestId);

    // ---- 7. 回传业务服务器 ----
    const issuedAt = new Date().toISOString();
    const payload: DeliveryPayload = {
      event: 'oauth.callback',
      provider: 'github',
      request_id: requestId,
      issued_at: issuedAt,
      state: record.business_state,
      scope: token.scope || record.scope,
      token: {
        access_token: token.accessToken,
        token_type: token.tokenType,
        scope: token.scope || record.scope,
        obtained_at: issuedAt,
      },
      user: buildUserInfo(user, email),
    };

    const delivery = await deliverToBusinessServer(config, record.redirect_uri, payload, requestId);
    const durationMs = Date.now() - startedAt;

    // ---- 8. 审计日志（不含 token / code 原文）----
    logger.info('callback.success', {
      request_id: requestId,
      session_request_id: record.request_id,
      github_user_id: user.id,
      github_login: user.login,
      scope: payload.scope,
      email_present: Boolean(email),
      token_fp: tokenFp,
      delivery_status: delivery.status,
      delivery_attempt: delivery.attempt,
      delivery_target: safeOrigin(record.redirect_uri),
      duration_ms: durationMs,
      ip_fp: rate.fingerprint,
    });

    return buildSuccessResponse(request, config, record, payload, requestId, user.login, user.name ?? null, user.avatar_url ?? null);
  } catch (error) {
    const appError = isAppError(error) ? error : new AppError('internal_error', String(error), { expose: false });

    logger[appError.status >= 500 ? 'error' : 'warn']('callback.failed', {
      request_id: requestId,
      session_request_id: record?.request_id,
      error_code: appError.code,
      error_message: appError.message,
      detail: appError.detail,
      duration_ms: Date.now() - startedAt,
      ip_fp: rate.fingerprint,
    });

    const errorRedirect = record?.error_redirect ?? config.errorRedirect;
    if (appError.redirectable && errorRedirect) {
      return redirectResponse(
        buildRedirectWithResult(errorRedirect, {
          status: 'error',
          error: appError.code,
          error_description: appError.expose ? appError.message : '服务内部错误',
          state: record?.business_state ?? null,
          request_id: requestId,
        }),
        requestId,
        302,
        { 'Set-Cookie': clearStateCookie(config) },
      );
    }

    return errorResponse(request, appError, requestId, config, {
      'Set-Cookie': clearStateCookie(config),
    });
  }
}

function buildUserInfo(
  user: Awaited<ReturnType<typeof fetchGithubUser>>,
  email: string | null,
): DeliveryUserInfo {
  return {
    id: user.id,
    login: user.login,
    name: user.name ?? null,
    email: email ?? null,
    avatar_url: user.avatar_url ?? null,
    html_url: user.html_url ?? null,
    company: user.company ?? null,
    location: user.location ?? null,
    blog: user.blog ?? null,
    bio: user.bio ?? null,
    type: user.type ?? null,
    site_admin: user.site_admin ?? false,
    github_created_at: user.created_at ?? null,
  };
}

function buildSuccessResponse(
  request: Request,
  config: Config,
  record: StateRecord,
  payload: DeliveryPayload,
  requestId: string,
  login: string,
  name: string | null,
  avatarUrl: string | null,
): Response {
  const setCookie = { 'Set-Cookie': clearStateCookie(config) };

  if (record.success_redirect) {
    return redirectResponse(
      buildRedirectWithResult(record.success_redirect, {
        status: 'ok',
        state: record.business_state,
        request_id: requestId,
      }),
      requestId,
      302,
      setCookie,
    );
  }

  if (wantsJsonCallback(request)) {
    // 刻意不回传 access_token 给浏览器：它只应出现在服务端到服务端的签名报文里
    return jsonResponse(
      {
        ok: true,
        user: { login, name, avatar_url: avatarUrl },
        scope: payload.scope,
        state: record.business_state,
        delivered_to: safeOrigin(record.redirect_uri),
        request_id: requestId,
      },
      200,
      requestId,
      { 'Set-Cookie': clearStateCookie(config) },
    );
  }

  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8' });
  headers.set('Set-Cookie', clearStateCookie(config));
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Request-Id', requestId);
  headers.set('X-Proxy-Version', config.version);

  return new Response(
    renderSuccessPage({ login, name, avatarUrl, requestId, state: record.business_state }),
    { status: 200, headers },
  );
}

function wantsJsonCallback(request: Request): boolean {
  return new URL(request.url).searchParams.get('format') === 'json';
}

function safeOrigin(target: string): string {
  try {
    return new URL(target).origin;
  } catch {
    return 'invalid';
  }
}
