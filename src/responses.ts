/**
 * 统一响应构造：安全响应头、结构化 JSON、302 跳转、内容协商（JSON / HTML）。
 */

import { AppError, ERROR_MESSAGE, type ErrorCode } from './errors.js';
import type { Config } from './config.js';
import { escapeHtml } from './pages.js';

export const SECURITY_HEADERS: Record<string, string> = {
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Pragma': 'no-cache',
};

export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

function applyCommonHeaders(headers: Headers, requestId: string, config?: Config): void {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  headers.set('X-Request-Id', requestId);
  if (config) headers.set('X-Proxy-Version', config.version);
}

export function jsonResponse(
  body: unknown,
  status: number,
  requestId: string,
  extraHeaders: Record<string, string> = {},
): Response {
  const headers = new Headers({ 'Content-Type': JSON_CONTENT_TYPE });
  applyCommonHeaders(headers, requestId);
  for (const [key, value] of Object.entries(extraHeaders)) headers.set(key, value);
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

export function redirectResponse(
  location: string,
  requestId: string,
  status = 302,
  extraHeaders: Record<string, string> = {},
): Response {
  const headers = new Headers({ Location: location });
  applyCommonHeaders(headers, requestId);
  for (const [key, value] of Object.entries(extraHeaders)) headers.set(key, value);
  return new Response(null, { status, headers });
}

export function htmlResponse(html: string, status: number, requestId: string): Response {
  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8' });
  applyCommonHeaders(headers, requestId);
  return new Response(html, { status, headers });
}

/** 是否希望拿到 JSON（SPA / 服务端调用）而非 HTML 错误页 */
export function wantsJson(request: Request): boolean {
  const url = new URL(request.url);
  if (url.searchParams.get('format') === 'json') return true;
  const accept = request.headers.get('Accept') || '';
  if (accept.includes('application/json')) return true;
  return false;
}

function renderErrorPage(error: AppError, requestId: string, config?: Config): string {
  const status = error.status;
  const detail = config?.environment === 'production' ? undefined : error.detail;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>登录失败 · ${status}</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#f6f7f9; color:#1f2328;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; }
  .card { width:min(560px,92vw); background:#fff; border:1px solid #d8dee4; border-radius:12px;
          padding:32px 34px; box-shadow:0 8px 28px rgba(27,31,36,.08); }
  .badge { display:inline-block; font-size:12px; font-weight:600; letter-spacing:.04em;
           color:#b42318; background:#fef3f2; border:1px solid #fecdca; border-radius:999px;
           padding:3px 10px; margin-bottom:14px; }
  h1 { font-size:20px; margin:0 0 10px; }
  p { margin:0 0 12px; line-height:1.65; color:#57606a; font-size:14px; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px;
         background:#f6f8fa; border:1px solid #d8dee4; border-radius:6px; padding:2px 6px; color:#1f2328; }
  pre { background:#f6f8fa; border:1px solid #d8dee4; border-radius:8px; padding:12px;
        overflow:auto; font-size:12.5px; color:#1f2328; }
  .meta { margin-top:16px; padding-top:14px; border-top:1px solid #eaeef2; font-size:12px; color:#8b949e; }
</style>
</head>
<body>
  <main class="card">
    <span class="badge">登录失败</span>
    <h1>${escapeHtml(ERROR_MESSAGE[error.code] || '登录过程中出现问题')}</h1>
    <p>${escapeHtml(error.expose ? error.message : '服务内部错误，请稍后重试或联系管理员。')}</p>
    <p>错误码：<code>${escapeHtml(error.code)}</code></p>
    ${detail ? `<pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre>` : ''}
    <div class="meta">request_id: <code>${escapeHtml(requestId)}</code></div>
  </main>
</body>
</html>`;
}

/** 渲染错误：JSON 请求返回结构化 JSON，浏览器请求返回 HTML 错误页 */
export function errorResponse(
  request: Request,
  error: AppError,
  requestId: string,
  config?: Config,
  extraHeaders: Record<string, string> = {},
): Response {
  if (wantsJson(request)) {
    return jsonResponse(error.toJSON(requestId), error.status, requestId, extraHeaders);
  }
  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8' });
  applyCommonHeaders(headers, requestId, config);
  for (const [key, value] of Object.entries(extraHeaders)) headers.set(key, value);
  return new Response(renderErrorPage(error, requestId, config), { status: error.status, headers });
}

/**
 * 把错误写入跳转地址的 query（error_redirect 场景）。
 */
export function buildRedirectWithResult(
  base: string,
  params: Record<string, string | null | undefined>,
): string {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    return base;
  }
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') continue;
    url.searchParams.set(key, value);
  }
  return url.toString();
}

export function methodNotAllowed(
  request: Request,
  allow: string[],
  requestId: string,
  config: Config,
): Response {
  const error = new AppError('method_not_allowed', `仅支持 ${allow.join(' / ')}`, {
    detail: { allow, method: request.method },
    redirectable: false,
  });
  return errorResponse(request, error, requestId, config, { Allow: allow.join(', ') });
}

export function notFound(request: Request, requestId: string, config: Config): Response {
  return errorResponse(
    request,
    new AppError('not_found', `未知路由: ${new URL(request.url).pathname}`, {
      detail: { routes: ['GET /', 'GET /health', 'GET|POST /authorize', 'GET /callback'] },
      redirectable: false,
    }),
    requestId,
    config,
  );
}

export function rawErrorResponse(code: ErrorCode, message: string, status: number, requestId: string): Response {
  const headers = new Headers({ 'Content-Type': JSON_CONTENT_TYPE });
  applyCommonHeaders(headers, requestId);
  return new Response(
    JSON.stringify(
      {
        ok: false,
        error: { code, message },
        request_id: requestId,
        timestamp: new Date().toISOString(),
      },
      null,
      2,
    ),
    { status, headers },
  );
}
