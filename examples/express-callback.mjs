/**
 * 业务服务器对接示例：Node.js + Express
 *
 * 展示两件事：
 *   1) GET  /login/github          —— 把用户重定向到 OAuth 中转 Worker
 *   2) POST /auth/github/callback  —— 接收 Worker 的签名回传，验签后建立自己的会话
 *
 * 依赖：express、express-session
 *   npm i express express-session
 *
 * 环境变量：
 *   PROXY_BASE_URL           = https://gh-oauth.example.workers.dev
 *   CALLBACK_SIGNING_SECRET  = 与 Worker 端 CALLBACK_SIGNING_SECRET 完全一致
 *   SESSION_SECRET           = 你自己的会话密钥
 */

import crypto from 'node:crypto';
import express from 'express';
import session from 'express-session';

const PROXY_BASE_URL = process.env.PROXY_BASE_URL || 'https://gh-oauth.example.workers.dev';
const CALLBACK_SIGNING_SECRET = process.env.CALLBACK_SIGNING_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const MY_CALLBACK_URI = 'https://api.example.com/auth/github/callback';
const MAX_SKEW_SECONDS = 300;

if (!CALLBACK_SIGNING_SECRET) {
  throw new Error('缺少环境变量 CALLBACK_SIGNING_SECRET');
}

// 不要为会话密钥设置任何默认值：弱/可预测的 session secret 会导致会话伪造与账号接管。
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('请设置长度 >= 32 的环境变量 SESSION_SECRET（真实随机串）');
}

const app = express();

// ★ 关键：留存原始 body 字节，验签必须基于它，而不是 JSON.stringify(req.body)
app.use(
  express.json({
    limit: '256kb',
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  }),
);

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
  }),
);

// ---------------------------------------------------------------------------
// 1. 发起登录
// ---------------------------------------------------------------------------

app.get('/login/github', (req, res) => {
  // 业务自己的防 CSRF state：随机、一次性、存在会话里
  const state = crypto.randomBytes(32).toString('base64url');
  req.session.oauthState = state;

  const url = new URL('/authorize', PROXY_BASE_URL);
  url.searchParams.set('redirect_uri', MY_CALLBACK_URI);
  url.searchParams.set('state', state);
  url.searchParams.set('scope', 'read:user user:email');
  url.searchParams.set('success_redirect', 'https://www.example.com/login/success');
  url.searchParams.set('error_redirect', 'https://www.example.com/login/failed');

  req.session.save(() => res.redirect(url.toString()));
});

// ---------------------------------------------------------------------------
// 2. 验签
// ---------------------------------------------------------------------------

function constantTimeEqual(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyProxySignature(req) {
  const timestamp = req.get('X-GH-Proxy-Timestamp');
  const signature = (req.get('X-GH-Proxy-Signature') || '').replace(/^sha256=/, '');
  if (!timestamp || !signature) return { ok: false, reason: 'missing_signature' };

  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(skew)) return { ok: false, reason: 'bad_timestamp' };
  if (skew > MAX_SKEW_SECONDS) return { ok: false, reason: 'timestamp_expired' };

  const expected = crypto
    .createHmac('sha256', CALLBACK_SIGNING_SECRET)
    .update(`${timestamp}.${req.rawBody ?? ''}`, 'utf8')
    .digest('hex');

  if (!constantTimeEqual(expected, signature)) return { ok: false, reason: 'invalid_signature' };
  return { ok: true };
}

// 幂等表：生产环境请换成 Redis SETNX / 数据库唯一索引，并设置 TTL
const processedRequestIds = new Map();
function markProcessed(requestId) {
  const now = Date.now();
  for (const [key, ts] of processedRequestIds) {
    if (now - ts > 10 * 60 * 1000) processedRequestIds.delete(key);
  }
  if (processedRequestIds.has(requestId)) return false;
  processedRequestIds.set(requestId, now);
  return true;
}

// ---------------------------------------------------------------------------
// 3. 接收回传
// ---------------------------------------------------------------------------

app.post('/auth/github/callback', async (req, res) => {
  // 3.1 验签（必须在读取任何业务字段之前完成）
  const verdict = verifyProxySignature(req);
  if (!verdict.ok) {
    console.warn('[oauth] 签名校验失败', { reason: verdict.reason, ip: req.ip });
    return res.status(401).json({ ok: false, error: verdict.reason });
  }

  // 3.2 幂等
  const requestId = req.get('X-GH-Proxy-Request-Id') || req.body.request_id;
  if (requestId && !markProcessed(requestId)) {
    return res.json({ ok: true, deduplicated: true });
  }

  const { state, user, token, scope } = req.body;

  // 3.3 校验业务 state 并立即作废
  const expectedState = req.session.oauthState;
  delete req.session.oauthState;
  if (!expectedState || !constantTimeEqual(expectedState, state || '')) {
    console.warn('[oauth] state 不匹配，疑似 CSRF');
    return res.status(400).json({ ok: false, error: 'state_mismatch' });
  }

  // 3.4 以 GitHub 数字 ID 为唯一键建号 / 登录（不要用 login，login 可被改名）
  const account = await upsertGithubUser({
    providerAccountId: String(user.id),
    login: user.login,
    name: user.name,
    email: user.email,
    avatarUrl: user.avatar_url,
    scope,
    accessToken: token.access_token, // 需要长期调 GitHub API 时，请加密后落库
  });

  // 3.5 建立自己的会话
  req.session.userId = account.id;
  req.session.save((err) => {
    if (err) return res.status(500).json({ ok: false, error: 'session_error' });
    // Worker 已把浏览器跳转到 success_redirect，这里只需确认投递成功
    res.json({ ok: true, userId: account.id });
  });
});

/** 示意实现：替换为你的真实用户表逻辑 */
async function upsertGithubUser(profile) {
  // await db.user.upsert({ where: { provider_providerAccountId: ... }, ... })
  return { id: `user_${profile.providerAccountId}` };
}

const PORT = Number(process.env.PORT || 8080);
app.listen(PORT, () => console.log(`business server listening on :${PORT}`));
