/**
 * 结构化错误定义。
 *
 * 所有对外可见的错误都通过 AppError 抛出，统一由 responses.ts 渲染成
 * 结构化 JSON（或 HTML），保证「错误码 + 可读信息 + request_id」三件套齐全。
 */

export type ErrorCode =
  // 客户端 / 协议层
  | 'invalid_request'
  | 'method_not_allowed'
  | 'not_found'
  | 'rate_limited'
  | 'origin_not_allowed'
  | 'redirect_uri_not_allowed'
  // state / CSRF
  | 'state_missing'
  | 'state_expired'
  | 'state_mismatch'
  // GitHub 交互
  | 'access_denied'
  | 'invalid_code'
  | 'token_exchange_failed'
  | 'user_fetch_failed'
  | 'upstream_timeout'
  | 'upstream_unavailable'
  | 'upstream_rate_limited'
  // 回传业务服务器
  | 'delivery_failed'
  // 服务端
  | 'server_misconfigured'
  | 'internal_error';

/** 错误码 -> HTTP 状态码 */
export const ERROR_STATUS: Record<ErrorCode, number> = {
  invalid_request: 400,
  method_not_allowed: 405,
  not_found: 404,
  rate_limited: 429,
  origin_not_allowed: 403,
  redirect_uri_not_allowed: 400,

  state_missing: 400,
  state_expired: 403,
  state_mismatch: 403,

  access_denied: 401,
  invalid_code: 400,
  token_exchange_failed: 502,
  user_fetch_failed: 502,
  upstream_timeout: 504,
  upstream_unavailable: 503,
  upstream_rate_limited: 429,

  delivery_failed: 502,

  server_misconfigured: 500,
  internal_error: 500,
};

/** 错误码 -> 面向用户的简短中文描述 */
export const ERROR_MESSAGE: Record<ErrorCode, string> = {
  invalid_request: '请求参数不合法',
  method_not_allowed: '不支持的请求方法',
  not_found: '接口不存在',
  rate_limited: '请求过于频繁，请稍后重试',
  origin_not_allowed: '请求来源不在白名单内',
  redirect_uri_not_allowed: 'redirect_uri 不在回调白名单内',

  state_missing: '缺少 state 参数',
  state_expired: 'state 无效或已过期（可能已使用过，或登录超时）',
  state_mismatch: 'state 与浏览器 Cookie 不匹配，疑似 CSRF',

  access_denied: '用户取消了 GitHub 授权',
  invalid_code: 'GitHub 授权码无效或已过期',
  token_exchange_failed: 'GitHub 换取 access_token 失败',
  user_fetch_failed: '获取 GitHub 用户信息失败',
  upstream_timeout: '访问 GitHub 超时',
  upstream_unavailable: 'GitHub 服务暂时不可用',
  upstream_rate_limited: 'GitHub 接口触发限流',

  delivery_failed: '授权结果回传业务服务器失败',

  server_misconfigured: '服务端配置缺失',
  internal_error: '服务内部错误',
};

export interface AppErrorOptions {
  /** 额外的诊断信息，会以 detail 字段返回（不含敏感数据） */
  detail?: unknown;
  /** 是否把 message 暴露给终端用户（默认除 5xx 外均为 true） */
  expose?: boolean;
  /** 覆盖默认 HTTP 状态码 */
  status?: number;
  /** 原始异常，仅用于日志 */
  cause?: unknown;
  /** 是否允许跳转到 error_redirect（参数校验类错误一般也允许） */
  redirectable?: boolean;
}

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly detail?: unknown;
  readonly expose: boolean;
  readonly redirectable: boolean;
  override readonly cause?: unknown;

  constructor(code: ErrorCode, message?: string, options: AppErrorOptions = {}) {
    const status = options.status ?? ERROR_STATUS[code] ?? 500;
    super(message ?? ERROR_MESSAGE[code] ?? code);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.detail = options.detail;
    this.expose = options.expose ?? status < 500;
    this.redirectable = options.redirectable ?? true;
    this.cause = options.cause;
  }

  toJSON(requestId: string): Record<string, unknown> {
    const body: Record<string, unknown> = {
      ok: false,
      error: {
        code: this.code,
        message: this.expose ? this.message : ERROR_MESSAGE[this.code],
      },
      request_id: requestId,
      timestamp: new Date().toISOString(),
    };
    if (this.detail !== undefined && this.expose) {
      (body.error as Record<string, unknown>).detail = this.detail;
    }
    return body;
  }
}

export function isAppError(value: unknown): value is AppError {
  return value instanceof AppError;
}

export function toAppError(value: unknown): AppError {
  if (isAppError(value)) return value;
  if (value instanceof Error) {
    if (value.name === 'AbortError' || value.name === 'TimeoutError') {
      return new AppError('upstream_timeout', ERROR_MESSAGE.upstream_timeout, { cause: value });
    }
    return new AppError('internal_error', value.message, { cause: value, expose: false });
  }
  return new AppError('internal_error', String(value), { expose: false });
}
