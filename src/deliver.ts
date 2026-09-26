/**
 * 授权结果回传业务服务器。
 *
 * 安全模型：
 * - 走服务端到服务端（Worker -> 业务服务器）的 HTTPS 请求，浏览器不接触 access_token；
 * - 报文用 HMAC-SHA256 签名，签名覆盖 `timestamp + "." + rawBody`，业务侧验签 + 校验时间窗，
 *   从而保证「请求确实来自本 Worker 且未被篡改、未被重放」；
 * - 4xx 不做重试（业务侧语义性拒绝），5xx / 网络异常做退避重试，避免跨境抖动丢单。
 */

import { hmacSha256Hex } from './crypto.js';
import { AppError } from './errors.js';
import { logger } from './logger.js';
import { truncate } from './validation.js';
import type { Config } from './config.js';

export interface DeliveryTokenInfo {
  access_token: string;
  token_type: string;
  scope: string;
  obtained_at: string;
}

export interface DeliveryUserInfo {
  id: number | string;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string | null;
  html_url: string | null;
  [key: string]: unknown;
}

export interface DeliveryPayload {
  event: 'oauth.callback';
  provider: 'github';
  request_id: string;
  issued_at: string;
  /** 业务方在 /authorize 时传入的 state，原样带回用于关联会话 */
  state: string | null;
  scope: string;
  token: DeliveryTokenInfo;
  user: DeliveryUserInfo;
}

export interface DeliveryResult {
  ok: boolean;
  status: number | null;
  attempt: number;
  error?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postOnce(
  config: Config,
  target: string,
  payload: DeliveryPayload,
  requestId: string,
  attempt: number,
): Promise<{ ok: boolean; status: number | null; retryable: boolean; error?: string }> {
  const rawBody = JSON.stringify(payload);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = await hmacSha256Hex(config.signingSecret, `${timestamp}.${rawBody}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.deliveryTimeoutMs);
  const startedAt = Date.now();

  try {
    let response: Response;
    if (config.deliveryMethod === 'GET') {
      const url = new URL(target);
      url.searchParams.set('payload', rawBody);
      url.searchParams.set('signature', `sha256=${signature}`);
      url.searchParams.set('timestamp', timestamp);
      response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': config.userAgent,
          'X-GH-Proxy-Event': payload.event,
          'X-GH-Proxy-Timestamp': timestamp,
          'X-GH-Proxy-Signature': `sha256=${signature}`,
          'X-GH-Proxy-Request-Id': requestId,
        },
        // 禁止跟随重定向：否则业务端点返回 3xx 时，携带 token/签名的请求会被续发到 Location 指向的地址
        redirect: 'error',
        signal: controller.signal,
      });
    } else {
      response = await fetch(target, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          Accept: 'application/json',
          'User-Agent': config.userAgent,
          'Idempotency-Key': requestId,
          'X-GH-Proxy-Event': payload.event,
          'X-GH-Proxy-Timestamp': timestamp,
          'X-GH-Proxy-Signature': `sha256=${signature}`,
          'X-GH-Proxy-Request-Id': requestId,
          'X-GH-Proxy-Delivery-Attempt': String(attempt + 1),
        },
        body: rawBody,
        // 禁止跟随重定向：否则业务端点返回 3xx 时，携带 token/签名的请求会被续发到 Location 指向的地址
        redirect: 'error',
        signal: controller.signal,
      });
    }

    const durationMs = Date.now() - startedAt;
    const ok = response.status >= 200 && response.status < 300;
    let snippet = '';
    if (!ok) {
      try {
        snippet = truncate(await response.text(), 300);
      } catch {
        snippet = '';
      }
    }

    logger[ok ? 'info' : 'warn']('delivery.response', {
      request_id: requestId,
      target_origin: safeOrigin(target),
      status: response.status,
      duration_ms: durationMs,
      attempt: attempt + 1,
      body_snippet: snippet || undefined,
    });

    // 4xx（除 408/429）视为业务侧明确拒绝，重试无意义
    const retryable =
      !ok &&
      (response.status >= 500 || response.status === 408 || response.status === 429);
    return {
      ok,
      status: response.status,
      retryable,
      error: ok ? undefined : `upstream_status_${response.status}${snippet ? `: ${snippet}` : ''}`,
    };
  } catch (error) {
    const aborted =
      error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError');
    logger.warn('delivery.network_error', {
      request_id: requestId,
      target_origin: safeOrigin(target),
      attempt: attempt + 1,
      timeout: aborted,
      error: error instanceof Error ? error.message : String(error),
    });
    return {
      ok: false,
      status: null,
      retryable: true,
      error: aborted ? 'delivery_timeout' : 'delivery_network_error',
    };
  } finally {
    clearTimeout(timer);
  }
}

function safeOrigin(target: string): string {
  try {
    return new URL(target).origin;
  } catch {
    return 'invalid';
  }
}

export async function deliverToBusinessServer(
  config: Config,
  target: string,
  payload: DeliveryPayload,
  requestId: string,
): Promise<DeliveryResult> {
  const maxAttempts = 1 + Math.max(0, Math.min(config.upstreamRetries, 3));
  let lastResult: { status: number | null; error?: string } = { status: null, error: 'not_executed' };

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const result = await postOnce(config, target, payload, requestId, attempt);
    if (result.ok) {
      return { ok: true, status: result.status, attempt: attempt + 1 };
    }
    lastResult = { status: result.status, error: result.error };
    if (!result.retryable) break;
    if (attempt < maxAttempts - 1) await sleep(Math.min(200 * 2 ** attempt, 1500));
  }

  logger.error('delivery.failed', {
    request_id: requestId,
    target_origin: safeOrigin(target),
    status: lastResult.status,
    error: lastResult.error,
  });

  throw new AppError('delivery_failed', '授权结果回传业务服务器失败', {
    detail: {
      status: lastResult.status,
      reason: lastResult.error,
      target_origin: safeOrigin(target),
    },
  });
}
