/**
 * GET /health —— 健康检查。
 *
 * 默认（浅检查）：验证 Worker 存活 + KV 绑定可读，适合做探针，成本极低。
 * `?deep=1`（深检查）：额外做一次 KV 写-读-删往返，并探测 GitHub API 可达性与延迟，
 *                     适合上线后首次联通性验证；不要放进高频探针。
 */

import { AppError } from '../errors.js';
import { checkRateLimit } from '../ratelimit.js';
import { errorResponse, jsonResponse } from '../responses.js';
import type { Config } from '../config.js';

const HEALTH_KEY = 'health:probe';

interface CheckResult {
  ok: boolean;
  latency_ms: number;
  detail?: string;
}

async function checkKvRead(config: Config): Promise<CheckResult> {
  const startedAt = Date.now();
  try {
    await config.kv.get(HEALTH_KEY, 'text');
    return { ok: true, latency_ms: Date.now() - startedAt };
  } catch (error) {
    return {
      ok: false,
      latency_ms: Date.now() - startedAt,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

async function checkKvRoundTrip(config: Config): Promise<CheckResult> {
  const startedAt = Date.now();
  const value = `probe-${Date.now()}`;
  try {
    await config.kv.put(HEALTH_KEY, value, { expirationTtl: 60 });
    const readBack = await config.kv.get(HEALTH_KEY, 'text');
    await config.kv.delete(HEALTH_KEY);
    if (readBack !== value) {
      return { ok: false, latency_ms: Date.now() - startedAt, detail: 'value_mismatch' };
    }
    return { ok: true, latency_ms: Date.now() - startedAt };
  } catch (error) {
    return {
      ok: false,
      latency_ms: Date.now() - startedAt,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

async function checkGithubReachable(): Promise<CheckResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch('https://api.github.com/rate_limit', {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'github-oauth-proxy/health' },
      signal: controller.signal,
    });
    return { ok: response.ok, latency_ms: Date.now() - startedAt, detail: `http_${response.status}` };
  } catch (error) {
    const aborted = error instanceof Error && error.name === 'AbortError';
    return {
      ok: false,
      latency_ms: Date.now() - startedAt,
      detail: aborted ? 'timeout' : 'network_error',
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function handleHealth(
  request: Request,
  config: Config,
  requestId: string,
): Promise<Response> {
  const deep = new URL(request.url).searchParams.get('deep') === '1';

  // 深检查会写 KV 并外呼 GitHub（资源放大面），因此只对 deep 做限流；
  // 浅检查仍是廉价的探针，不受限流影响。
  if (deep) {
    const rate = await checkRateLimit(config, request, 'health_deep');
    if (!rate.allowed) {
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
  }

  const checks: Record<string, CheckResult> = {
    kv_read: await checkKvRead(config),
  };

  if (deep) {
    checks.kv_round_trip = await checkKvRoundTrip(config);
    checks.github_api = await checkGithubReachable();
    if (config.rateLimitKv) checks.rate_limit_kv = await checkKvRead({ ...config, kv: config.rateLimitKv });
  }

  const ok = Object.values(checks).every((item) => item.ok);

  return jsonResponse(
    {
      ok,
      service: 'github-oauth-proxy',
      version: config.version,
      environment: config.environment,
      time: new Date().toISOString(),
      request_id: requestId,
      checks,
      config_summary: {
        worker_base_url: config.baseUrl,
        github_callback_url: config.callbackUrl,
        callback_allowlist: config.allowedCallbackUris.length,
        origin_allowlist: config.allowedCallbackOrigins.length,
        redirect_allowlist: config.allowedRedirectOrigins.length,
        default_scope: config.defaultScope,
        state_ttl_seconds: config.stateTtlSeconds,
        rate_limit_per_minute: config.rateLimitPerMinute,
        upstream_timeout_ms: config.upstreamTimeoutMs,
        delivery_method: config.deliveryMethod,
        rate_limit_kv_bound: Boolean(config.rateLimitKv),
      },
    },
    ok ? 200 : 503,
    requestId,
  );
}
