import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  decryptJson,
  encryptJson,
  fingerprint,
  hmacSha256Hex,
  randomToken,
} from '../src/crypto.js';

describe('加密原语', () => {
  it('AES-GCM 加解密往返一致', async () => {
    const secret = 'unit-test-secret-key-0123456789';
    const payload = { n: 'nonce-abc', r: 'req-1', t: Date.now() };
    const packed = await encryptJson(secret, payload, 'aad-v1');
    expect(packed).toContain('.');
    const decoded = await decryptJson<typeof payload>(secret, packed, 'aad-v1');
    expect(decoded).toEqual(payload);
  });

  it('密文被篡改时解密返回 null', async () => {
    const secret = 'unit-test-secret-key-0123456789';
    const packed = await encryptJson(secret, { a: 1 }, 'aad-v1');
    const [iv, ct] = packed.split('.') as [string, string];
    const flipped = `${ct.slice(0, -2)}${ct.slice(-2) === 'AA' ? 'BB' : 'AA'}`;
    expect(await decryptJson(secret, `${iv}.${flipped}`, 'aad-v1')).toBeNull();
  });

  it('AAD 不匹配时解密失败（防跨用途复用）', async () => {
    const secret = 'unit-test-secret-key-0123456789';
    const packed = await encryptJson(secret, { a: 1 }, 'aad-v1');
    expect(await decryptJson(secret, packed, 'aad-v2')).toBeNull();
  });

  it('不同密钥无法解密', async () => {
    const packed = await encryptJson('key-a-0123456789abcdef', { a: 1 }, 'x');
    expect(await decryptJson('key-b-0123456789abcdef', packed, 'x')).toBeNull();
  });

  it('HMAC 稳定且随内容变化', async () => {
    const a = await hmacSha256Hex('secret', '1700000000.{"a":1}');
    const b = await hmacSha256Hex('secret', '1700000000.{"a":1}');
    const c = await hmacSha256Hex('secret', '1700000001.{"a":1}');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('randomToken 具备足够熵且每次不同', () => {
    const values = new Set(Array.from({ length: 50 }, () => randomToken(32)));
    expect(values.size).toBe(50);
    expect(randomToken(32)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('fingerprint 不可逆且长度可控', async () => {
    const fp = await fingerprint('203.0.113.7', 16);
    expect(fp).toHaveLength(16);
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    expect(fp).not.toContain('203.0.113.7');
  });

  it('constantTimeEqual 语义正确', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
  });
});
