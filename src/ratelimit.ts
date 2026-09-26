/**
 * 轻量限流：基于 KV 的固定窗口计数器（按 IP + 路由维度）。
 *
 * 说明与取舍：
 * - KV 是最终一致的，因此这是「近似限流」，用于挡住脚本刷量与突发风暴，
 *   真正的强一致限流请在 Cloudflare 侧配置 Rate limiting rules（Dashboard 或
 *   `[[unsafe.bindings]]` 中的 rate limiting），两者叠加使用效果最好。
 * - 未绑定 RATE_LIMIT_KV 时退化为不限流，不阻塞主流程。
 * - 限流键中的 IP 经过哈希处理，日志与 KV 里都不落明文 IP（隐私友好）。
 */

import { fingerprint } from './crypto.js';
import type { Config } from './config.js';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  fingerprint: string | null;
}

const WINDOW_SECONDS = 60;

export function clientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Real-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0]?.trim() ||
    'unknown'
  );
}

export async function checkRateLimit(
  config: Config,
  request: Request,
  bucket: string,
): Promise<RateLimitResult> {
  const limit = config.rateLimitPerMinute;
  const kv = config.rateLimitKv;
  const ip = clientIp(request);
  const ipFp = await fingerprint(ip, 16);

  if (!kv || limit <= 0) {
    return { allowed: true, limit, remaining: limit, resetAt: 0, fingerprint: ipFp };
  }

  const windowIndex = Math.floor(Date.now() / (WINDOW_SECONDS * 1000));
  const key = `rl:${bucket}:${ipFp}:${windowIndex}`;
  const resetAt = (windowIndex + 1) * WINDOW_SECONDS * 1000;

  let current = 0;
  try {
    const raw = await kv.get(key, 'text');
    current = raw ? Number.parseInt(raw, 10) || 0 : 0;
  } catch {
    // KV 读取异常不应影响登录可用性
    return { allowed: true, limit, remaining: limit, resetAt, fingerprint: ipFp };
  }

  if (current >= limit) {
    return { allowed: false, limit, remaining: 0, resetAt, fingerprint: ipFp };
  }

  try {
    await kv.put(key, String(current + 1), { expirationTtl: WINDOW_SECONDS * 2 });
  } catch {
    /* 计数写失败时放行，保证可用性优先 */
  }

  return { allowed: true, limit, remaining: Math.max(limit - current - 1, 0), resetAt, fingerprint: ipFp };
}
