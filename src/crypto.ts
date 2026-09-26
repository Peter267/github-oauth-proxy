/**
 * 加密原语：全部基于 WebCrypto（Workers 原生支持，无需任何依赖）。
 *
 * - encryptJson / decryptJson：AES-256-GCM，用于加密 state Cookie（防篡改 + 防读取）
 * - hmacSha256Hex：用于对回传业务服务器的报文签名
 * - fingerprint：单向指纹，用于日志中标记 token 而不泄露原文
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** 密钥派生参数：改这里等于让所有历史签发数据失效（可作为密钥轮换手段） */
const HKDF_SALT = 'gh-oauth-proxy/v1/aes-gcm-salt';
const HKDF_INFO = 'gh-oauth-proxy/v1/state-cookie';

// ---------------------------------------------------------------------------
// Base64URL
// ---------------------------------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** 生成 URL 安全的随机串（默认 32 字节 = 256 bit 熵） */
export function randomToken(byteLength = 32): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

// ---------------------------------------------------------------------------
// 哈希 / HMAC
// ---------------------------------------------------------------------------

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === 'string' ? encoder.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return toHex(new Uint8Array(digest));
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message) as BufferSource);
  return toHex(new Uint8Array(signature));
}

/** 日志友好的短指纹，例如 ip 指纹、token 指纹（不可逆） */
export async function fingerprint(value: string, length = 12): Promise<string> {
  return (await sha256Hex(value)).slice(0, length);
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return out;
}

// ---------------------------------------------------------------------------
// 常量时间比较
// ---------------------------------------------------------------------------

export function constantTimeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------------------------------------------------------------------------
// AES-256-GCM（加密 Cookie）
// ---------------------------------------------------------------------------

async function deriveAesKey(secret: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret) as BufferSource,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(HKDF_SALT) as BufferSource,
      info: encoder.encode(HKDF_INFO) as BufferSource,
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * 加密任意 JSON 为 `iv.ciphertext`（Base64URL）。
 * aad 参与认证，可用于绑定用途（例如 'state-cookie'）。
 */
export async function encryptJson(
  secret: string,
  value: unknown,
  aad: string,
): Promise<string> {
  const key = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: encoder.encode(aad) as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ciphertext))}`;
}

/** 解密失败（被篡改 / 密钥不匹配 / 格式错误）一律返回 null，由调用方决定如何处置 */
export async function decryptJson<T>(
  secret: string,
  packed: string,
  aad: string,
): Promise<T | null> {
  const parts = packed.split('.');
  if (parts.length !== 2) return null;
  const [ivPart, ctPart] = parts as [string, string];
  try {
    const key = await deriveAesKey(secret);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromBase64Url(ivPart) as BufferSource,
        additionalData: encoder.encode(aad) as BufferSource,
      },
      key,
      fromBase64Url(ctPart) as BufferSource,
    );
    return JSON.parse(decoder.decode(plaintext)) as T;
  } catch {
    return null;
  }
}
