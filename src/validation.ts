/**
 * 输入校验：URL 合法性、白名单匹配、scope 规整、来源校验。
 * 这是防「开放重定向 / SSRF 式回传 / 越权 scope」的第一道闸门。
 */

import { AppError } from './errors.js';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/**
 * 解析并规范化一个待跳转 URL。
 * 拒绝：非 http(s) 协议、内嵌用户名密码、非法格式。
 */
export function normalizeUrl(raw: string, allowInsecure: boolean): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new AppError('invalid_request', `URL 格式不合法: ${truncate(raw, 120)}`, {
      detail: { field: 'url' },
    });
  }

  const isHttp = url.protocol === 'https:';
  const isLocalHttp = url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname);
  const isDevHttp = url.protocol === 'http:' && allowInsecure;

  if (!isHttp && !isLocalHttp && !isDevHttp) {
    throw new AppError('invalid_request', 'URL 必须使用 https:// 协议', {
      detail: { field: 'url', protocol: url.protocol },
    });
  }
  if (url.username || url.password) {
    throw new AppError('invalid_request', 'URL 不允许内嵌用户名或密码', {
      detail: { field: 'url' },
    });
  }
  // 去掉 hash，避免被用作绕过白名单前缀匹配的载体
  url.hash = '';
  return url;
}

function stripTrailingSlash(path: string): string {
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

function originPathKey(url: URL): string {
  return `${url.protocol}//${url.host}${stripTrailingSlash(url.pathname)}`;
}

/**
 * 把含 `*` 的白名单条目编译成锚定的正则。
 *
 * `wildcard` 决定 `*` 展开为哪种字符类：host 段与 path 段必须使用不同的通配强度，
 * 否则同一个 `.*` 会跨越 host/path 边界 —— 例如 `https://*.example.com/*`
 * 会错误命中 `https://attacker.com/x.example.com/y`（把攻击者域名塞进 path）。
 */
function globToRegExp(pattern: string, wildcard: string): RegExp {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, wildcard);
  return new RegExp(`^${escaped}$`);
}

/** host 段通配：只允许主机标签字符，禁止吞掉 `:`/`@`/`/`，杜绝跨越 host/path 边界 */
const HOST_WILDCARD = '[^/:@]+';
/** path 段通配：保持文档语义，`*` 匹配任意字符（含 `/`）实现前缀匹配 */
const PATH_WILDCARD = '.*';

/**
 * 白名单匹配规则（语义明确、可预期）：
 *
 *   1. `https://api.example.com`           -> 仅 origin（path 为空或 "/"），放行该 origin 下任意路径
 *   2. `https://api.example.com/auth/gh`   -> origin + 路径精确匹配（忽略 query 与末尾斜杠）
 *   3. `https://api.example.com/auth/*`    -> 通配符匹配（`*` 匹配任意字符，整串锚定）
 *   4. `https://*.example.com/*`           -> 通配符可出现在主机名中，便于放行多子域
 *
 * 通配符按 origin 段与 path 段分别匹配（忽略 query）：origin 段的 `*` 只匹配主机标签字符，
 * 不允许跨越 `/`，因此无法用「攻击者域名 + 路径内嵌白名单后缀」绕过；
 * path 段的 `*` 才匹配任意字符。
 * 非法条目会被静默忽略（且不应阻塞服务），保证配置里多写一条注释不会导致线上 500。
 */
export function isUrlAllowed(target: URL, patterns: string[]): boolean {
  const targetKey = originPathKey(target);

  for (const rawPattern of patterns) {
    const pattern = rawPattern.trim();
    if (!pattern) continue;

    if (pattern.includes('*')) {
      // 把条目拆成 origin 段与 path 段分别匹配：
      //  - origin 段的 `*` 只能匹配主机标签字符，不能吞掉 host 与 path 之间的 `/`
      //  - path 段的 `*` 才按文档语义匹配任意字符
      // 这样既保留「通配符可出现在主机名中」的能力，又不会把攻击者域名 +
      // 路径内嵌白名单后缀（如 https://attacker.com/x.example.com/y）误判为命中。
      const parts = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]*)(\/[\s\S]*)?$/.exec(pattern);
      if (!parts) continue; // 非法条目（如 scheme 也含 `*`）直接跳过，fail-closed
      const originPattern = parts[1] as string;
      const rawPathPattern = parts[2] ?? '/';

      let originRe: RegExp;
      try {
        originRe = globToRegExp(originPattern, HOST_WILDCARD);
      } catch {
        continue;
      }
      if (!originRe.test(target.origin)) continue;

      const pathPattern = stripTrailingSlash(rawPathPattern);
      // 仅 origin（无路径或根路径）：放行该 origin 下任意路径
      if (pathPattern === '' || pathPattern === '/') return true;

      let pathRe: RegExp;
      try {
        pathRe = globToRegExp(pathPattern, PATH_WILDCARD);
      } catch {
        continue;
      }
      // 只对 origin + path 匹配（忽略 query），避免 `*` 吞掉 query 造成误放行
      if (pathRe.test(stripTrailingSlash(target.pathname))) return true;
      continue;
    }

    let patternUrl: URL;
    try {
      patternUrl = new URL(pattern);
    } catch {
      continue;
    }

    const pathIsRoot = patternUrl.pathname === '' || patternUrl.pathname === '/';
    if (pathIsRoot) {
      if (patternUrl.origin === target.origin) return true;
    } else if (patternUrl.origin === target.origin && originPathKey(patternUrl) === targetKey) {
      return true;
    }
  }
  return false;
}

/** 校验 redirect_uri（业务服务器接收结果的地址） */
export function assertCallbackUriAllowed(url: URL, allowed: string[]): void {
  if (allowed.length === 0) {
    throw new AppError('server_misconfigured', '未配置 ALLOWED_CALLBACK_URIS，拒绝所有回调', {
      detail: { hint: '请在 wrangler.toml 的 [vars] 中配置 ALLOWED_CALLBACK_URIS' },
      redirectable: false,
    });
  }
  if (!isUrlAllowed(url, allowed)) {
    throw new AppError('redirect_uri_not_allowed', 'redirect_uri 不在回调白名单内', {
      detail: { redirect_uri: url.href },
    });
  }
}

/** 校验 success_redirect / error_redirect 这类「跳转前台」的地址 */
export function assertBrowserRedirectAllowed(url: URL, allowed: string[], baseUrl: string): void {
  if (url.origin === new URL(baseUrl).origin) return; // 总是允许回跳 Worker 自身
  if (allowed.length > 0 && isUrlAllowed(url, allowed)) return;
  throw new AppError('redirect_uri_not_allowed', '跳转地址不在白名单内', {
    detail: { redirect_uri: url.href, hint: '需加入 ALLOWED_REDIRECT_ORIGINS' },
  });
}

/**
 * 校验请求来源合法性。
 * 浏览器顶级导航可能不带 Origin（此时退化为 Referer）；两者都没有时不阻断。
 */
export function assertOriginAllowed(request: Request, allowed: string[], baseUrl: string): void {
  if (allowed.length === 0) return;

  const rawOrigin = request.headers.get('Origin');
  let origin = rawOrigin;
  if (!origin) {
    const referer = request.headers.get('Referer');
    if (referer) {
      try {
        origin = new URL(referer).origin;
      } catch {
        origin = null;
      }
    }
  }
  if (!origin) return; // 无来源信息（如服务端对服务端调用），交给上层其他校验

  const selfOrigin = new URL(baseUrl).origin;
  if (origin === selfOrigin) return;
  if (allowed.some((item) => item.replace(/\/+$/, '') === origin)) return;

  throw new AppError('origin_not_allowed', '请求来源不在白名单内', {
    detail: { origin },
  });
}

const SCOPE_PATTERN = /^[a-z0-9_:.-]+$/i;

/** 规整 scope：去重、限长、字符校验，并在配置了 ALLOWED_SCOPES 时做子集校验 */
export function normalizeScope(raw: string | null | undefined, fallback: string, allowed: string[]): string {
  const source = (raw && raw.trim()) || fallback;
  const items = source
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);

  const scopes: string[] = [];
  for (const item of items) {
    if (!SCOPE_PATTERN.test(item)) {
      throw new AppError('invalid_request', `scope 含非法字符: ${truncate(item, 40)}`, {
        detail: { field: 'scope' },
      });
    }
    if (!scopes.includes(item)) scopes.push(item);
  }

  if (scopes.length === 0) {
    throw new AppError('invalid_request', 'scope 不能为空', { detail: { field: 'scope' } });
  }
  if (scopes.length > 8) {
    throw new AppError('invalid_request', 'scope 数量过多（最多 8 个）', {
      detail: { field: 'scope' },
    });
  }
  if (allowed.length > 0) {
    const illegal = scopes.filter((scope) => !allowed.includes(scope));
    if (illegal.length > 0) {
      throw new AppError('invalid_request', 'scope 不在允许范围内', {
        detail: { field: 'scope', illegal, allowed },
      });
    }
  }
  return scopes.join(' ');
}

/** 业务方自带的 state，原样回传，做长度限制与字符白名单 */
export function normalizeBusinessState(raw: string | null, maxLength = 512): string | null {
  if (!raw) return null;
  const value = raw.trim();
  if (value.length === 0) return null;
  if (value.length > maxLength) {
    throw new AppError('invalid_request', `state 长度超过 ${maxLength}`, {
      detail: { field: 'state' },
    });
  }
  if (!/^[A-Za-z0-9._~+/=-]+$/.test(value)) {
    throw new AppError('invalid_request', 'state 含非法字符', { detail: { field: 'state' } });
  }
  return value;
}

export function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
}
