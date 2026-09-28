/**
 * 配置装载与校验。
 *
 * 设计原则：
 * 1. 所有敏感信息（Client ID/Secret、签名密钥）只从 Secrets 读取，代码里没有任何默认值；
 * 2. 配置错误快速失败（fail fast），返回 server_misconfigured 而不是带病运行；
 * 3. 配置对象在单次请求内构造，无跨请求可变状态（Workers 单 isolate 并发安全）。
 */

import { AppError } from './errors.js';
import type { DeliveryMethod, Env, LogLevel, KVNamespace } from './types.js';

export interface Config {
  // 凭据
  githubClientId: string;
  githubClientSecret: string;
  cookieSecret: string;
  signingSecret: string;

  // 地址
  baseUrl: string;
  callbackUrl: string;
  userAgent: string;

  // 白名单
  allowedCallbackUris: string[];
  allowedCallbackOrigins: string[];
  allowedRedirectOrigins: string[];
  allowedScopes: string[];

  // scope / 跳转
  defaultScope: string;
  successRedirect: string | null;
  errorRedirect: string | null;

  // 行为参数
  stateTtlSeconds: number;
  rateLimitPerMinute: number;
  upstreamTimeoutMs: number;
  upstreamRetries: number;
  deliveryMethod: DeliveryMethod;
  deliveryTimeoutMs: number;
  allowInsecureRedirects: boolean;
  /** JSON 模式是否允许跳过 state Cookie 绑定（默认 false；置 true 会引入 login-CSRF 风险） */
  allowUnboundState: boolean;

  // 元信息
  environment: string;
  version: string;
  logLevel: LogLevel;

  // 绑定
  kv: KVNamespace;
  rateLimitKv: KVNamespace | null;
}

/**
 * 占位符指纹清单（子串匹配）。
 *
 * 一键部署时，仓库模板里的示例值会被原样预填到 Cloudflare 的部署表单；
 * 若用户没有替换就直接上线，服务会带着「公开可知」的密钥运行
 * （state Cookie 可被伪造、回传业务服务器的报文可被伪造），属于静默的高危配置错误。
 * 因此这里主动识别并拒绝，把「忘了改」变成启动即失败的显式提示。
 *
 * ⚠️ 误报即「真实随机密钥被拒、服务起不来」，因此本清单**只收录长度 ≥ 7 的指纹**：
 * 归一化会先做 lower-case，使 base64url 里每个字母的有效出现概率翻倍到 1/32，
 * 一个 7 字符的全字母指纹在 43 字符随机串中的出现概率仍低至 ~1e-9/密钥，
 * 而 3~4 字符指纹（如 'xxx' / 'tbd' / 'todo' / 'xxxx'）会高达 1e-3~1e-5/密钥 ——
 * 实测单个 base64url 密钥被拒 0.24%，一次部署 4 个值即 ~0.8% 直接不可用。
 * 短指纹改由 PLACEHOLDER_TOKEN_MARKERS（整词匹配）与 PURE_WEAK_VALUES（整串相等）承接。
 */
const PLACEHOLDER_MARKERS = [
  'replace_with',
  'replace-with',
  'replacewith',
  'replace_me',
  'replace-me',
  'replaceme',
  'changeme',
  'change_me',
  'change-me',
  'placeholder',
  'insert_',
  'sample_',
  'secret_here',
  'put_your',
  'password',
  'example.com',
  // 模板 client id 形态（如 Ov23liXXXXXXXXXXXXXX）：8 连 x 在随机 base64url 中概率 ~1e-11，
  // 是 'xxxx'（4 字符子串，误报率 ~5e-5）的「更严格匹配方式」。
  'xxxxxxxx',
];

/**
 * 短占位符指纹（≤6 字符）：只有当它作为**独立词元**出现（前后为非字母数字或串首尾）时才命中。
 *
 * 这些词在真实模板里总是以 `dummy-secret` / `fixme_later` 这类分隔形式出现，
 * 而高熵随机串是连续字母数字，几乎不可能把它们切成独立词元 —— 兼顾识别率与零误报。
 */
const PLACEHOLDER_TOKEN_MARKERS = new Set(['dummy', 'fixme', 'abc123']);

/** 按「非字母数字」切词；用于短指纹的整词匹配（在归一化后的值上执行） */
function tokenizeSecretValue(normalized: string): string[] {
  return normalized.split(/[^a-z0-9]+/).filter((token) => token.length > 0);
}

/**
 * 长度可能达标、整体却是弱口令的值。
 *
 * 这里用**整体相等**而非子串匹配：`123456` 作为子串会命中 `...0123456789`
 * 这类「随机串里恰好含连续数字」的合法密钥（测试夹具与真实 hex 密钥都可能发生），
 * 把检测变成误报机器。纯数字口令另由 looksLikePlaceholder 的纯数字规则兜住。
 */
const PURE_WEAK_VALUES = new Set([
  '123456',
  '1234567',
  '12345678',
  '123456789',
  '1234567890',
  'password',
  'passw0rd',
  'qwerty',
  'letmein',
  'changeme',
  // 过短的模板词改为「整串恰好相等」才命中：作为子串会大量误伤真实随机密钥。
  // （这些值本就过不了最小长度校验，保留在此只为语义完整与直接可读。）
  'todo',
  'xxxx',
  'your',
]);

/**
 * 不可见 / 易混淆码位：零宽空格与连接符、BOM、软连字符、蒙古文元音分隔符。
 *
 * 攻击面是「re<ZWSP>place_with_x」这类值与模板肉眼无法区分，却会绕过占位符匹配；
 * 因此所有匹配与长度判断前都必须先剥离它们。
 */
const INVISIBLE_CODEPOINTS = /[\u200B-\u200F\u2060\uFEFF\u00AD\u180E]/g;

/** 归一化：剥离不可见码位 → NFKC（全角转半角等）→ 去首尾空白 → 小写 */
function normalizeSecretValue(value: string): string {
  return value.replace(INVISIBLE_CODEPOINTS, '').normalize('NFKC').trim().toLowerCase();
}

/** 去重后的字符种类数，用于识别「长度达标但熵极低」的密钥（如 32 个相同字符） */
const MIN_DISTINCT_CHARS = 8;

function distinctCharCount(value: string): number {
  return new Set(value.replace(INVISIBLE_CODEPOINTS, '')).size;
}

/** 重复片段的最大长度；`abcdefgh`.repeat(4) 命中的是 8，而超过 16 的片段本身已接近随机 */
const MAX_REPEAT_CHUNK = 16;

/**
 * 整串是否由某个更短片段整数次重复构成（如 'abcdefgh'.repeat(4)）。
 *
 * 这类值去重后字符种类（8）刚好卡在 MIN_DISTINCT_CHARS 下限之上，能绕过字符种类校验，
 * 但熵依然极低（模式可枚举）。逐字符比对而非正则回溯，避免病态输入拖慢启动。
 *
 * 零误报：长度为质数（如 43 字符的 base64url）时不存在 1 < size < len 的因子，
 * 只可能全体同字符（已被字符种类校验覆盖）；64 字符 hex 的可行周期为 1/2/4/8/16/32，
 * 命中概率 ≤ (1/16)^62，实际为 0。因此随机密钥不会被误判。
 */
export function isRepeatedChunk(value: string, maxChunk = MAX_REPEAT_CHUNK): boolean {
  const length = value.length;
  const limit = Math.min(maxChunk, length >> 1);
  for (let size = 1; size <= limit; size++) {
    if (length % size !== 0) continue;
    if (value.slice(0, size).repeat(length / size) === value) return true;
  }
  return false;
}

/** Secret 名称与 Env 字段的映射（顺序即展示顺序） */
const SECRET_FIELDS: Array<[string, keyof Env]> = [
  ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_ID'],
  ['GITHUB_CLIENT_SECRET', 'GITHUB_CLIENT_SECRET'],
  ['COOKIE_SECRET', 'COOKIE_SECRET'],
  ['CALLBACK_SIGNING_SECRET', 'CALLBACK_SIGNING_SECRET'],
];

export function looksLikePlaceholder(value: string): boolean {
  const normalized = normalizeSecretValue(value);
  if (normalized.length === 0) return false;
  if (PURE_WEAK_VALUES.has(normalized)) return true;
  if (/^[0-9]+$/.test(normalized)) return true; // 纯数字口令（含 123456 / 000000…）
  if (PLACEHOLDER_MARKERS.some((marker) => normalized.includes(marker))) return true;
  // 短指纹只在「独立词元」位置命中，避免 'todo' / 'dummy' 这类短串落在随机密钥内部造成误报
  const tokens = tokenizeSecretValue(normalized);
  return tokens.some((token) => PLACEHOLDER_TOKEN_MARKERS.has(token));
}

/** 类型非法 / 剔除不可见字符后为空的 Secret */
export interface InvalidSecret {
  name: string;
  /** 实际 typeof，供运维直接定位是写错类型还是留了空白 */
  type: string;
  reason: 'not_string' | 'blank';
}

/**
 * 找出会「绕过全部既有校验」的 Secret 取值。
 *
 * `findMissingSecrets` 只判真值：数字 0、空对象这类值既非空、又非字符串，
 * 于是既不进 missing、也不进 placeholder，且 `(123).length === undefined`
 * 让长度校验静默失效 —— 结果带病上线。这里把这些情况显式挑出来。
 */
export function findInvalidSecrets(env: Env): InvalidSecret[] {
  const invalid: InvalidSecret[] = [];
  for (const [name, field] of SECRET_FIELDS) {
    const value = env[field] as unknown;
    if (typeof value !== 'string') {
      // null / undefined 语义上属于「缺失」，交给 findMissingSecrets 归类
      if (value !== null && value !== undefined) {
        invalid.push({ name, type: typeof value, reason: 'not_string' });
      }
      continue;
    }
    if (value.length > 0 && normalizeSecretValue(value).length === 0) {
      // 纯空白或只含不可见字符：非空但不可用
      invalid.push({ name, type: 'string', reason: 'blank' });
    }
  }
  return invalid;
}

/** 尚未注入（空值）的 Secret 名称；供快速失败与配置引导页复用 */
export function findMissingSecrets(env: Env): string[] {
  return SECRET_FIELDS.filter(([, field]) => !env[field]).map(([name]) => name);
}

/** 仍是模板占位符的 Secret 名称；供快速失败与配置引导页复用 */
export function findPlaceholderSecrets(env: Env): string[] {
  return SECRET_FIELDS.filter(([, field]) => {
    const value = env[field];
    return typeof value === 'string' && value.length > 0 && looksLikePlaceholder(value);
  }).map(([name]) => name);
}

function splitList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * 数值绑定解析：非字符串绑定（布尔 / 数字 / 对象）不做假设，统一 `String()` 后解析，
 * 解析不出数字即回退默认值 —— 绝不能因为运维把变量误绑成布尔而让整个 Worker 抛错 500。
 */
function toInt(raw: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

/** 布尔绑定解析：同样对非字符串安全，`String(true) === 'true'` 依旧按真值处理 */
function toBool(raw: unknown, fallback = false): boolean {
  if (raw === undefined || raw === null || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(raw).trim().toLowerCase());
}

/**
 * @param env        Worker 绑定
 * @param requestUrl 当前请求 URL，用于在未配置 PUBLIC_BASE_URL 时推断 Worker 自身地址
 */
export function loadConfig(env: Env, requestUrl: URL): Config {
  const missing = findMissingSecrets(env);
  if (!env.OAUTH_KV) missing.push('OAUTH_KV(binding)');

  if (missing.length > 0) {
    throw new AppError('server_misconfigured', '服务端配置缺失', {
      detail: {
        missing,
        hint: '网页部署请在 Cloudflare 控制台 Settings → Variables and Secrets 补齐（见 DEPLOY.md）；命令行部署请执行 npx wrangler secret put <NAME>，并确认已绑定 OAUTH_KV',
      },
      expose: true,
      redirectable: false,
    });
  }

  // 类型 / 空白校验必须在占位符与强度校验之前：非字符串值会让后续所有
  // `.length` / `.includes` 判断静默失效，是最容易被漏掉的一类坏配置。
  const invalid = findInvalidSecrets(env);
  if (invalid.length > 0) {
    throw new AppError('server_misconfigured', '检测到非法 Secret 取值', {
      detail: {
        invalid: invalid.map((item) => ({
          name: item.name,
          actual_type: item.type,
          reason:
            item.reason === 'not_string'
              ? `必须是字符串，当前为 ${item.type}`
              : '剔除空白 / 不可见字符后为空',
        })),
        hint: 'Secrets 只能是非空字符串；数字、对象或纯空白值无法被正确注入，请用 wrangler secret put <NAME> 重新写入。',
      },
      expose: true,
      redirectable: false,
    });
  }

  // 占位符检测必须在强度检测之前：模板示例值往往"长度合法"，却等于公开密钥
  const placeholders = findPlaceholderSecrets(env);
  if (placeholders.length > 0) {
    throw new AppError('server_misconfigured', '检测到未替换的占位符密钥', {
      detail: {
        placeholders,
        hint: '这些值仍是公开仓库里的示例模板，任何读到源码的人都能用它伪造 state Cookie 与回传签名。请替换为真实值；随机密钥可用 npm run gen-secret 生成，或纯浏览器执行 crypto.getRandomValues(new Uint8Array(32))',
      },
      expose: true,
      redirectable: false,
    });
  }

  // 密钥强度：长度 + 熵（去重后的字符种类）双重校验。
  // 只看长度会放过 "a".repeat(32) 这类可被瞬间爆破的密钥，因此补一道熵下限。
  const weakSecrets: string[] = [];
  const lengthRules: Array<[string, string, number]> = [
    ['GITHUB_CLIENT_ID', env.GITHUB_CLIENT_ID, 10],
    ['GITHUB_CLIENT_SECRET', env.GITHUB_CLIENT_SECRET, 16],
    ['COOKIE_SECRET', env.COOKIE_SECRET, 16],
    ['CALLBACK_SIGNING_SECRET', env.CALLBACK_SIGNING_SECRET, 32],
  ];
  for (const [name, value, min] of lengthRules) {
    if (normalizeSecretValue(value).length < min) weakSecrets.push(`${name}(>=${min})`);
  }
  const entropyRules: Array<[string, string]> = [
    ['GITHUB_CLIENT_SECRET', env.GITHUB_CLIENT_SECRET],
    ['COOKIE_SECRET', env.COOKIE_SECRET],
    ['CALLBACK_SIGNING_SECRET', env.CALLBACK_SIGNING_SECRET],
  ];
  for (const [name, value] of entropyRules) {
    if (distinctCharCount(value) < MIN_DISTINCT_CHARS) {
      weakSecrets.push(`${name}(字符种类>=${MIN_DISTINCT_CHARS})`);
    } else if (isRepeatedChunk(normalizeSecretValue(value))) {
      // 字符种类达标但整串是重复模式（如 'abcdefgh'.repeat(4)）：单纯提高字符种类阈值会
      // 误伤真实随机密钥（32 字符 hex 的期望去重字符数仅 ~13.9），因此改用这条零误报规则。
      weakSecrets.push(`${name}(重复模式)`);
    }
  }
  if (weakSecrets.length > 0) {
    throw new AppError('server_misconfigured', '密钥强度不足', {
      detail: {
        weak: weakSecrets,
        hint: '请用 npm run gen-secret 生成 32 字节随机串后 wrangler secret put',
      },
      redirectable: false,
    });
  }

  // DEPLOY.md 明确要求两者不同：Cookie 加密与回传签名共用密钥，
  // 任一泄露都会同时击穿「浏览器绑定」与「报文可信」两条防线。
  if (env.COOKIE_SECRET === env.CALLBACK_SIGNING_SECRET) {
    throw new AppError('server_misconfigured', 'COOKIE_SECRET 与 CALLBACK_SIGNING_SECRET 不能相同', {
      detail: {
        fields: ['COOKIE_SECRET', 'CALLBACK_SIGNING_SECRET'],
        hint: '两者用途不同（state Cookie 加密 vs 回传报文 HMAC 签名），请分别用 npm run gen-secret 生成不同的随机串。',
      },
      expose: true,
      redirectable: false,
    });
  }

  const baseUrl = (env.PUBLIC_BASE_URL || requestUrl.origin).replace(/\/+$/, '');
  const deliveryMethod: DeliveryMethod =
    (env.DELIVERY_METHOD || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';

  return {
    githubClientId: env.GITHUB_CLIENT_ID,
    githubClientSecret: env.GITHUB_CLIENT_SECRET,
    cookieSecret: env.COOKIE_SECRET,
    signingSecret: env.CALLBACK_SIGNING_SECRET,

    baseUrl,
    callbackUrl: `${baseUrl}/callback`,
    userAgent: `github-oauth-proxy/${env.VERSION || '1.0.0'} (+${baseUrl})`,

    allowedCallbackUris: splitList(env.ALLOWED_CALLBACK_URIS),
    allowedCallbackOrigins: splitList(env.ALLOWED_CALLBACK_ORIGINS),
    allowedRedirectOrigins: splitList(env.ALLOWED_REDIRECT_ORIGINS),
    allowedScopes: splitList(env.ALLOWED_SCOPES),

    defaultScope: (env.DEFAULT_SCOPE || 'read:user user:email').trim(),
    successRedirect: env.SUCCESS_REDIRECT?.trim() || null,
    errorRedirect: env.ERROR_REDIRECT?.trim() || null,

    stateTtlSeconds: toInt(env.STATE_TTL_SECONDS, 600, 60, 3600),
    rateLimitPerMinute: toInt(env.RATE_LIMIT_PER_MINUTE, 60, 0, 100000),
    upstreamTimeoutMs: toInt(env.UPSTREAM_TIMEOUT_MS, 8000, 1000, 30000),
    upstreamRetries: toInt(env.UPSTREAM_RETRIES, 2, 0, 5),
    deliveryMethod,
    deliveryTimeoutMs: toInt(env.DELIVERY_TIMEOUT_MS, 8000, 1000, 30000),
    allowInsecureRedirects: toBool(env.ALLOW_INSECURE_REDIRECTS, false),
    allowUnboundState: toBool(env.ALLOW_UNBOUND_STATE, false),

    environment: env.ENVIRONMENT || 'production',
    version: env.VERSION || '1.0.0',
    logLevel: (env.LOG_LEVEL as LogLevel) || 'info',

    kv: env.OAUTH_KV,
    rateLimitKv: env.RATE_LIMIT_KV ?? null,
  };
}
