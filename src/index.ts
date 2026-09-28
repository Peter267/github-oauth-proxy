/**
 * GitHub OAuth 中转（Proxy）—— Worker 入口与路由。
 *
 * 路由表：
 *   GET  /            -> 服务说明页（含配置自检）；配置未就绪时降级为分步配置引导页
 *   GET  /setup       -> 同 /
 *   GET  /health      -> 健康检查（?deep=1 深检查）
 *   GET  /authorize   -> 发起授权（重定向到 GitHub），?format=json 返回授权 URL
 *   POST /authorize   -> 同上（表单 / JSON 入参）
 *   GET  /callback    -> GitHub 回调，完成换取与回传
 *
 * 统一约定：
 *   - 所有响应带 X-Request-Id，日志与响应体里的 request_id 一致，便于端到端排查；
 *   - 所有错误返回结构化 JSON（浏览器场景返回 HTML 错误页），error.code 见 README 错误码表。
 */

import { AppError, toAppError } from './errors.js';
import {
  loadConfig,
  findMissingSecrets,
  findPlaceholderSecrets,
  type Config,
} from './config.js';
import { logger, newRequestId, setLogLevel } from './logger.js';
import { errorResponse, rawErrorResponse, wantsJson } from './responses.js';
import { renderLandingPage, type LandingInfo, type SetupState } from './pages.js';
import { handleAuthorize, buildCorsHeaders } from './handlers/authorize.js';
import { handleCallback } from './handlers/callback.js';
import { handleHealth } from './handlers/health.js';
import type { Env, ExecutionContextLike } from './types.js';

function normalizePath(pathname: string): string {
  if (pathname.length > 1 && pathname.endsWith('/')) return pathname.replace(/\/+$/, '');
  return pathname;
}

const SETUP_HINT =
  '空值与模板占位符都会被主动拒绝，这是刻意的 fail-closed 设计：宁可启动即失败，也不要带着公开可知的密钥对外服务。';

function buildSetupState(env: Env): SetupState {
  return {
    missing: findMissingSecrets(env),
    placeholders: findPlaceholderSecrets(env),
    kvMissing: !env.OAUTH_KV,
    hint: SETUP_HINT,
  };
}

/**
 * 配置尚未就绪时，把首页降级为「浏览器内分步引导页」。
 *
 * 一键部署后的默认形态就是「代码已上线、配置还没填」，此时抛错误页对纯网页用户
 * 毫无可操作性；这里改为直接渲染缺失项 + GitHub 回调地址 + 控制台操作路径，
 * 让整个上线过程不需要打开终端即可完成。
 */
function renderSetupLanding(env: Env, url: URL, requestId: string): Response {
  const baseUrl = (env.PUBLIC_BASE_URL || url.origin).replace(/\/+$/, '');
  const info: LandingInfo = {
    version: env.VERSION || '1.0.0',
    environment: env.ENVIRONMENT || 'production',
    baseUrl,
    callbackUrl: `${baseUrl}/callback`,
    successRedirect: null,
    errorRedirect: null,
    scope: (env.DEFAULT_SCOPE || 'read:user user:email').trim(),
    stateTtlSeconds: 600,
    rateLimitPerMinute: 60,
    upstreamTimeoutMs: 8000,
    callbackAllowlistCount: 0,
    rateLimitKvBound: Boolean(env.RATE_LIMIT_KV),
    kvBound: Boolean(env.OAUTH_KV),
    issues: [],
    setup: buildSetupState(env),
  };

  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Request-Id': requestId,
    'X-Proxy-Version': info.version,
  });
  // 503 是诚实的语义：服务已部署但尚不可用。人类看到引导页，探针看到 503。
  return new Response(renderLandingPage(info), { status: 503, headers });
}

function collectConfigIssues(config: Config): string[] {
  const issues: string[] = [];
  if (config.allowedCallbackUris.length === 0) {
    issues.push('• ALLOWED_CALLBACK_URIS 未配置：/authorize 会拒绝所有请求');
  }
  if (config.allowedCallbackOrigins.length === 0) {
    issues.push('• ALLOWED_CALLBACK_ORIGINS 未配置：不校验请求来源（建议至少配置业务前端域名）');
  }
  if (config.allowedRedirectOrigins.length === 0 && (config.successRedirect || config.errorRedirect)) {
    issues.push('• 配置了默认跳转但 ALLOWED_REDIRECT_ORIGINS 为空：默认跳转会被忽略');
  }
  if (!config.rateLimitKv) {
    issues.push('• 未绑定 RATE_LIMIT_KV：仅退化为不限流，建议在生产环境绑定');
  }
  if (config.allowInsecureRedirects) {
    issues.push('• ALLOW_INSECURE_REDIRECTS=true：允许 http 跳转，仅应在联调环境开启');
  }
  if (config.environment === 'production' && config.baseUrl.startsWith('http://')) {
    issues.push('• 生产环境 PUBLIC_BASE_URL 使用了 http://，GitHub 会拒绝非 https 回调');
  }
  return issues;
}

function renderLanding(config: Config, requestId: string): Response {
  const info: LandingInfo = {
    version: config.version,
    environment: config.environment,
    baseUrl: config.baseUrl,
    callbackUrl: config.callbackUrl,
    successRedirect: config.successRedirect,
    errorRedirect: config.errorRedirect,
    scope: config.defaultScope,
    stateTtlSeconds: config.stateTtlSeconds,
    rateLimitPerMinute: config.rateLimitPerMinute,
    upstreamTimeoutMs: config.upstreamTimeoutMs,
    callbackAllowlistCount: config.allowedCallbackUris.length,
    rateLimitKvBound: Boolean(config.rateLimitKv),
    kvBound: Boolean(config.kv),
    issues: collectConfigIssues(config),
    setup: null,
  };

  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Request-Id': requestId,
    'X-Proxy-Version': config.version,
  });
  return new Response(renderLandingPage(info), { status: 200, headers });
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContextLike,
  ): Promise<Response> {
    const requestId = newRequestId();
    const startedAt = Date.now();
    const url = new URL(request.url);
    const path = normalizePath(url.pathname);

    let config: Config;
    try {
      setLogLevel(env.LOG_LEVEL);
      config = loadConfig(env, url);
    } catch (error) {
      const appError = toAppError(error);
      logger.error('bootstrap.failed', {
        request_id: requestId,
        error_code: appError.code,
        error_message: appError.message,
        detail: appError.detail,
        path,
      });

      // 首页降级为配置引导页；其它路由（含 /health、/authorize）依旧返回结构化错误，
      // 避免把「未就绪」伪装成可用状态。
      if (
        appError.code === 'server_misconfigured' &&
        (path === '/' || path === '/setup') &&
        !wantsJson(request)
      ) {
        return renderSetupLanding(env, url, requestId);
      }

      return errorResponse(request, appError, requestId);
    }

    try {
      // ---- CORS 预检（供 SPA 以 format=json 调用 /authorize）----
      if (request.method === 'OPTIONS') {
        const cors = buildCorsHeaders(request, config);
        if (Object.keys(cors).length === 0) {
          return errorResponse(
            request,
            new AppError('origin_not_allowed', '预检请求来源不在白名单内', { redirectable: false }),
            requestId,
            config,
          );
        }
        const headers = new Headers(cors);
        headers.set('X-Request-Id', requestId);
        return new Response(null, { status: 204, headers });
      }

      let response: Response;

      switch (path) {
        case '/':
        case '/setup':
          response = renderLanding(config, requestId);
          break;
        case '/health':
          response = await handleHealth(request, config, requestId);
          break;
        case '/authorize':
          response = await handleAuthorize(request, config, requestId);
          break;
        case '/callback':
          response = await handleCallback(request, config, requestId);
          break;
        case '/favicon.ico':
          return new Response(null, { status: 204, headers: { 'X-Request-Id': requestId } });
        default:
          response = errorResponse(
            request,
            new AppError('not_found', `未知路由: ${path}`, {
              detail: { routes: ['GET /', 'GET /setup', 'GET /health', 'GET|POST /authorize', 'GET /callback'] },
              redirectable: false,
            }),
            requestId,
            config,
          );
      }

      logger.info('http.request', {
        request_id: requestId,
        method: request.method,
        path,
        status: response.status,
        duration_ms: Date.now() - startedAt,
        environment: config.environment,
        colo: request.headers.get('CF-Ray')?.split('-')[1] ?? null,
      });

      // 保证任何分支都带上 request id
      if (!response.headers.has('X-Request-Id')) {
        const cloned = new Headers(response.headers);
        cloned.set('X-Request-Id', requestId);
        return new Response(response.body, { status: response.status, headers: cloned });
      }
      return response;
    } catch (error) {
      const appError = toAppError(error);
      logger.error('http.unhandled_error', {
        request_id: requestId,
        path,
        method: request.method,
        error_code: appError.code,
        error_message: appError.message,
        stack: appError.cause instanceof Error ? appError.cause.stack : undefined,
        duration_ms: Date.now() - startedAt,
      });
      try {
        return errorResponse(request, appError, requestId, config);
      } catch {
        return rawErrorResponse('internal_error', '服务内部错误', 500, requestId);
      }
    }
  },
};
