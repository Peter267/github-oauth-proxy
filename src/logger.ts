/**
 * 可观测日志：统一输出单行 JSON，方便 Workers Logs / Logpush / 日志平台结构化检索。
 *
 * 约定字段：
 *   ts / level / event / request_id / route / ...自定义字段
 *
 * 铁律：禁止把 client_secret、access_token、code、Cookie 原文写进日志。
 *      需要标记 token 时使用 `token_fp`（SHA-256 前 12 位）。
 */

import type { LogLevel } from './types.js';

const LEVEL_WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let currentLevel: LogLevel = 'info';

export function setLogLevel(level: string | undefined): void {
  if (level === 'debug' || level === 'info' || level === 'warn' || level === 'error') {
    currentLevel = level;
  }
}

/** 生成并返回一个请求级 trace id（同时写回响应头 X-Request-Id） */
export function newRequestId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  }
}

export function log(
  level: LogLevel,
  event: string,
  fields: Record<string, unknown> = {},
): void {
  if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[currentLevel]) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...fields,
  });
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export const logger = {
  debug: (event: string, fields?: Record<string, unknown>) => log('debug', event, fields),
  info: (event: string, fields?: Record<string, unknown>) => log('info', event, fields),
  warn: (event: string, fields?: Record<string, unknown>) => log('warn', event, fields),
  error: (event: string, fields?: Record<string, unknown>) => log('error', event, fields),
};
