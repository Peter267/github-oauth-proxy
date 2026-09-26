import { describe, expect, it } from 'vitest';
import {
  assertOriginAllowed,
  isUrlAllowed,
  normalizeBusinessState,
  normalizeScope,
  normalizeUrl,
} from '../src/validation.js';
import { AppError } from '../src/errors.js';

describe('normalizeUrl', () => {
  it('接受 https 地址', () => {
    expect(normalizeUrl('https://api.example.com/cb', false).href).toBe('https://api.example.com/cb');
  });

  it('默认拒绝 http，本地地址例外', () => {
    expect(() => normalizeUrl('http://api.example.com/cb', false)).toThrowError(AppError);
    expect(normalizeUrl('http://127.0.0.1:8080/cb', false).hostname).toBe('127.0.0.1');
    expect(normalizeUrl('http://api.example.com/cb', true).protocol).toBe('http:');
  });

  it('拒绝危险协议与内嵌凭证', () => {
    expect(() => normalizeUrl('javascript:alert(1)', true)).toThrowError(AppError);
    expect(() => normalizeUrl('https://user:pass@evil.com/cb', false)).toThrowError(AppError);
  });

  it('剥离 hash，避免绕过前缀匹配', () => {
    expect(normalizeUrl('https://api.example.com/cb#@evil.com', false).hash).toBe('');
  });
});

describe('isUrlAllowed 白名单语义', () => {
  const patterns = [
    'https://api.example.com',
    'https://api.example.com/auth/github/callback',
    'https://*.example.net/*',
  ];

  it('仅 origin 的条目放行该 origin 下任意路径', () => {
    expect(isUrlAllowed(new URL('https://api.example.com/anything/here'), patterns)).toBe(true);
  });

  it('带路径的条目为精确匹配（忽略 query 与末尾斜杠）', () => {
    expect(isUrlAllowed(new URL('https://api.example.com/auth/github/callback?x=1'), patterns)).toBe(true);
    expect(isUrlAllowed(new URL('https://api.example.com/auth/github/callback/'), patterns)).toBe(true);
    expect(isUrlAllowed(new URL('https://api.example.com/auth/github/other'), patterns)).toBe(true); // 被第一条 origin 规则放行
  });

  it('不同 origin 一律拒绝', () => {
    expect(isUrlAllowed(new URL('https://evil.com/auth/github/callback'), patterns)).toBe(false);
    expect(isUrlAllowed(new URL('https://api.example.com.evil.com/cb'), patterns)).toBe(false);
  });

  it('前缀通配条目生效', () => {
    expect(isUrlAllowed(new URL('https://a.example.net/deep/path'), patterns)).toBe(true);
  });

  it('通配符为整串锚定，不会放行相似域名', () => {
    expect(isUrlAllowed(new URL('https://a.example.net.evil.com/x'), patterns)).toBe(false);
    expect(isUrlAllowed(new URL('https://evil.com/?u=https://a.example.net/'), patterns)).toBe(false);
  });

  it('路径前缀通配命中与不命中', () => {
    const globs = ['https://api.example.com/auth/*'];
    expect(isUrlAllowed(new URL('https://api.example.com/auth/github/callback'), globs)).toBe(true);
    expect(isUrlAllowed(new URL('https://api.example.com/other'), globs)).toBe(false);
  });
});

describe('normalizeScope', () => {
  it('去重并规整分隔符', () => {
    expect(normalizeScope('read:user,user:email read:user', 'read:user', [])).toBe('read:user user:email');
  });

  it('配置了 ALLOWED_SCOPES 时拒绝越权 scope', () => {
    expect(() => normalizeScope('repo', 'read:user', ['read:user'])).toThrowError(AppError);
  });

  it('拒绝非法字符与空值', () => {
    expect(() => normalizeScope('read user;rm -rf', 'read:user', [])).toThrowError(AppError);
    expect(() => normalizeScope('', '', [])).toThrowError(AppError);
  });
});

describe('normalizeBusinessState', () => {
  it('接受 URL 安全字符', () => {
    expect(normalizeBusinessState('abc-123_XYZ.~')).toBe('abc-123_XYZ.~');
  });

  it('拒绝超长与非法字符', () => {
    expect(() => normalizeBusinessState('a'.repeat(600))).toThrowError(AppError);
    expect(() => normalizeBusinessState('<script>')).toThrowError(AppError);
  });

  it('空值返回 null', () => {
    expect(normalizeBusinessState(null)).toBeNull();
    expect(normalizeBusinessState('   ')).toBeNull();
  });
});

describe('assertOriginAllowed', () => {
  const allow = ['https://www.example.com'];

  it('白名单内的 Origin 放行', () => {
    const request = new Request('https://proxy.test/authorize', {
      headers: { Origin: 'https://www.example.com' },
    });
    expect(() => assertOriginAllowed(request, allow, 'https://proxy.test')).not.toThrow();
  });

  it('白名单外的 Origin 拒绝', () => {
    const request = new Request('https://proxy.test/authorize', {
      headers: { Origin: 'https://evil.com' },
    });
    expect(() => assertOriginAllowed(request, allow, 'https://proxy.test')).toThrowError(AppError);
  });

  it('缺少 Origin 时回退 Referer', () => {
    const ok = new Request('https://proxy.test/authorize', {
      headers: { Referer: 'https://www.example.com/login' },
    });
    expect(() => assertOriginAllowed(ok, allow, 'https://proxy.test')).not.toThrow();

    const bad = new Request('https://proxy.test/authorize', {
      headers: { Referer: 'https://evil.com/login' },
    });
    expect(() => assertOriginAllowed(bad, allow, 'https://proxy.test')).toThrowError(AppError);
  });

  it('未配置白名单时不做校验', () => {
    const request = new Request('https://proxy.test/authorize', {
      headers: { Origin: 'https://evil.com' },
    });
    expect(() => assertOriginAllowed(request, [], 'https://proxy.test')).not.toThrow();
  });
});
