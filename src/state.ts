/**
 * 一次性 state（防 CSRF）与加密 Cookie 管理。
 *
 * 双保险设计：
 *   1) 服务端（Workers KV）：`oauth:state:<nonce>` 保存本次授权的上下文，读取即删除（一次性），
 *      并设置 expirationTtl，天然过期。攻击者无法猜出 256bit 的 nonce，因此无法伪造 state。
 *   2) 浏览器（加密 Cookie）：AES-256-GCM 加密的 {nonce, requestId, issuedAt}，
 *      值可被服务端解密验证 —— 形成「双提交」绑定，确保回调来自同一浏览器。
 *
 * 这样即使 Cookie 被剥离（SameSite/隐私模式），KV 的一次性校验仍然生效；
 * 即使 KV 因最终一致性出现短暂残留，Cookie 绑定也仍能挡住跨站重放。
 */

import { decryptJson, encryptJson, randomToken } from './crypto.js';
import type { Config } from './config.js';

export const STATE_PREFIX = 'oauth:state:';
export const STATE_COOKIE = 'gh_oauth_state';
const COOKIE_AAD = 'gh-oauth-proxy/state-cookie/v1';

export interface StateRecord {
  /** 业务服务器接收授权结果的地址（已在 /authorize 阶段通过白名单校验） */
  redirect_uri: string;
  /** 业务方自带的 state，原样回传 */
  business_state: string | null;
  /** 规整后的 GitHub scope */
  scope: string;
  success_redirect: string | null;
  error_redirect: string | null;
  /** 是否要求回调时必须携带匹配的 Cookie */
  cookie_bound: boolean;
  created_at: number;
  /** 会话内 trace id，贯穿 authorize -> callback -> 回传业务服务器 */
  request_id: string;
  /** 发起授权的来源指纹（IP/UA 哈希），仅用于审计 */
  origin_fp: string | null;
}

interface StateCookiePayload {
  n: string; // nonce
  r: string; // request_id
  t: number; // issued_at (ms)
}

export interface CreatedState {
  nonce: string;
  setCookie: string;
}

/** 生成 state 并落库 */
export async function createState(config: Config, record: StateRecord): Promise<CreatedState> {
  const nonce = randomToken(32);
  await config.kv.put(`${STATE_PREFIX}${nonce}`, JSON.stringify(record), {
    expirationTtl: config.stateTtlSeconds,
  });

  const payload: StateCookiePayload = {
    n: nonce,
    r: record.request_id,
    t: record.created_at,
  };
  const cookieValue = await encryptJson(config.cookieSecret, payload, COOKIE_AAD);
  const setCookie = serializeCookie(STATE_COOKIE, cookieValue, {
    maxAge: config.stateTtlSeconds,
    secure: isSecureContext(config.baseUrl),
  });
  return { nonce, setCookie };
}

/**
 * 读取并立即销毁 state（一次性）。
 * KV 删除是最终一致的，因此不把它当作唯一屏障 —— Cookie 绑定会补上这一环。
 */
export async function consumeState(config: Config, nonce: string): Promise<StateRecord | null> {
  const key = `${STATE_PREFIX}${nonce}`;
  const raw = await config.kv.get(key, 'json');
  if (raw === null) return null;

  // 先删再解析，尽可能缩短重放窗口
  await config.kv.delete(key);

  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Partial<StateRecord>;
  if (typeof record.redirect_uri !== 'string' || typeof record.created_at !== 'number') return null;

  // 双保险：不仅依赖 KV 的 expirationTtl，读出来再判一次
  if (Date.now() - record.created_at > config.stateTtlSeconds * 1000) return null;

  return record as StateRecord;
}

/** 从 Cookie 中解出并校验 state 绑定（解密失败 / 内容不符 -> null） */
export async function readStateCookie(
  config: Config,
  request: Request,
): Promise<StateCookiePayload | null> {
  const cookieValue = parseCookie(request.headers.get('Cookie'), STATE_COOKIE);
  if (!cookieValue) return null;
  const payload = await decryptJson<StateCookiePayload>(config.cookieSecret, cookieValue, COOKIE_AAD);
  if (!payload || typeof payload.n !== 'string' || typeof payload.r !== 'string') return null;
  if (typeof payload.t !== 'number') return null;
  if (Date.now() - payload.t > config.stateTtlSeconds * 1000) return null;
  return payload;
}

export function clearStateCookie(config: Config): string {
  return serializeCookie(STATE_COOKIE, '', {
    maxAge: 0,
    secure: isSecureContext(config.baseUrl),
  });
}

// ---------------------------------------------------------------------------
// Cookie 工具
// ---------------------------------------------------------------------------

interface CookieOptions {
  maxAge: number;
  secure: boolean;
}

function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [
    `${name}=${value}`,
    'Path=/',
    // Lax：GitHub 回调是顶级 GET 导航，Cookie 会被带上；同时阻断跨站 POST 携带
    'SameSite=Lax',
    'HttpOnly',
    `Max-Age=${options.maxAge}`,
  ];
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

function isSecureContext(baseUrl: string): boolean {
  try {
    const url = new URL(baseUrl);
    return url.protocol === 'https:';
  } catch {
    return true;
  }
}

function parseCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const segment of header.split(';')) {
    const index = segment.indexOf('=');
    if (index === -1) continue;
    const key = segment.slice(0, index).trim();
    if (key !== name) continue;
    return segment.slice(index + 1).trim();
  }
  return null;
}
