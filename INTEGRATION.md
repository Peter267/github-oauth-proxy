# 业务服务器对接说明

本文档面向**使用 GitHub OAuth 中转服务的业务后端**。你只需要做三件事：

1. 把用户重定向到 Worker 的 `/authorize`（或先用 JSON 模式拿到授权 URL）；
2. 实现一个回调端点，接收 Worker 回传的**签名报文**；
3. **验签**后建立自己的登录会话。

> 不需要在业务服务器上配置任何 GitHub 密钥，也不需要在业务服务器上直连 `github.com`。

---

## 0. 名词与角色

| 角色 | 地址示例 | 职责 |
| --- | --- | --- |
| 业务前端 | `https://www.example.com` | 渲染「GitHub 登录」按钮 |
| 业务后端 | `https://api.example.com/auth/github/callback` | 接收授权结果、建会话（**必须公网可达**） |
| OAuth 中转 Worker | `https://gh-oauth.example.workers.dev` | 与 GitHub 通信、签名回传 |
| GitHub | `github.com` | 授权与用户信息 |

两个关键地址（务必不要混淆）：

- **`redirect_uri`（你传给 Worker 的）**：`https://api.example.com/auth/github/callback` —— Worker 把结果发到这里。
- **OAuth App 的 callback URL（你填在 GitHub 后台的）**：`https://gh-oauth.example.workers.dev/callback` —— GitHub 把 code 发到这里。

---

## 1. 第一步：发起登录

### 方式 A：服务端重定向（推荐，最简单）

用户点击登录时，业务后端生成自己的 `state`（防 CSRF，建议 32 字节随机串并写入会话），
然后 302 到 Worker：

```http
GET /login/github HTTP/1.1
Host: api.example.com
```

```js
// Node / Express
app.get('/login/github', async (req, res) => {
  const state = crypto.randomBytes(32).toString('base64url');
  req.session.oauthState = state;           // 存进会话，回调时比对
  req.session.save(() => {
    const url = new URL('https://gh-oauth.example.workers.dev/authorize');
    url.searchParams.set('redirect_uri', 'https://api.example.com/auth/github/callback');
    url.searchParams.set('state', state);
    url.searchParams.set('scope', 'read:user user:email');
    url.searchParams.set('success_redirect', 'https://www.example.com/login/success');
    url.searchParams.set('error_redirect', 'https://www.example.com/login/failed');
    res.redirect(url.toString());
  });
});
```

```python
# Python / Flask
@app.get("/login/github")
def login_github():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "redirect_uri": "https://api.example.com/auth/github/callback",
        "state": state,
        "scope": "read:user user:email",
        "success_redirect": "https://www.example.com/login/success",
        "error_redirect": "https://www.example.com/login/failed",
    }
    return redirect("https://gh-oauth.example.workers.dev/authorize?" + urlencode(params))
```

### 方式 B：前端直接跳转

适用于纯静态前端（无后端会话）。此时建议由前端生成 `state` 并存 `sessionStorage`：

```html
<a href="https://gh-oauth.example.workers.dev/authorize?redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fgithub%2Fcallback&state=<随机串>&success_redirect=https%3A%2F%2Fwww.example.com%2Flogin%2Fsuccess">
  GitHub 登录
</a>
```

> 只要 `redirect_uri` 在 Worker 的白名单里，前端来源也在 `ALLOWED_CALLBACK_ORIGINS` 里即可。

### 方式 C：JSON 模式（SPA / 弹窗）

先取授权 URL，再由前端决定何时跳转（便于先弹自定义 Loading、记录埋点等）：

```js
const res = await fetch(
  'https://gh-oauth.example.workers.dev/authorize?format=json' +
    '&redirect_uri=' + encodeURIComponent('https://api.example.com/auth/github/callback') +
    '&state=' + encodeURIComponent(state),
  { credentials: 'include' }, // 带上 Cookie
);
const { authorize_url, expires_in } = await res.json();
window.location.href = authorize_url;   // 或 window.open(...)
```

**响应示例**：

```json
{
  "ok": true,
  "authorize_url": "https://github.com/login/oauth/authorize?client_id=Ov23li…&redirect_uri=https%3A%2F%2Fgh-oauth.example.workers.dev%2Fcallback&scope=read%3Auser+user%3Aemail&state=Kx7-9pQ…&allow_signup=true",
  "state": "Kx7-9pQ…",
  "scope": "read:user user:email",
  "expires_in": 600,
  "callback_url": "https://gh-oauth.example.workers.dev/callback",
  "request_id": "c1f2a3b4-…"
}
```

> JSON 模式下 Worker 不依赖浏览器 Cookie（跨站 Cookie 不可靠），改由 KV 的一次性 `state` 提供
> CSRF 防护；`state` 由 Worker 签发并只在本次响应里返回，请勿泄露给第三方。

---

## 2. 第二步：实现回调端点

Worker 会用 **`POST` + JSON** 把结果发到你的 `redirect_uri`（`DELIVERY_METHOD=GET` 时为 GET + query）。
你的端点需要：**读原始 body → 验签 → 校验时间窗 → 幂等去重 → 建会话 → 返回 2xx**。

### 2.1 请求头

```http
POST /auth/github/callback HTTP/1.1
Host: api.example.com
Content-Type: application/json; charset=utf-8
User-Agent: github-oauth-proxy/1.0.0 (+https://gh-oauth.example.workers.dev)
Idempotency-Key: 9f2c8e1a-6b7d-4c3e-9a11-2f4b8c0d1e33
X-GH-Proxy-Event: oauth.callback
X-GH-Proxy-Timestamp: 1789000000
X-GH-Proxy-Signature: sha256=1f9c2a7e5b0d4c8a3e6f1b2d9c0a7e4f8b3d6c1a9e2f5b8d0c3a6e9f2b5d8c1a
X-GH-Proxy-Request-Id: 9f2c8e1a-6b7d-4c3e-9a11-2f4b8c0d1e33
X-GH-Proxy-Delivery-Attempt: 1
```

### 2.2 请求体

```json
{
  "event": "oauth.callback",
  "provider": "github",
  "request_id": "9f2c8e1a-6b7d-4c3e-9a11-2f4b8c0d1e33",
  "issued_at": "2026-09-26T15:04:21.318Z",
  "state": "opaque-csrf-token-from-your-server",
  "scope": "read:user user:email",
  "token": {
    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
    "token_type": "bearer",
    "scope": "read:user user:email",
    "obtained_at": "2026-09-26T15:04:21.318Z"
  },
  "user": {
    "id": 583231,
    "login": "octocat",
    "name": "The Octocat",
    "email": "octo@example.com",
    "avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4",
    "html_url": "https://github.com/octocat",
    "company": null,
    "location": "San Francisco",
    "blog": "https://github.blog",
    "bio": null,
    "type": "User",
    "site_admin": false,
    "github_created_at": "2011-01-25T18:44:36Z"
  }
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `state` | 你在 `/authorize` 时传入的串，**原样带回**。务必与本地会话/`sessionStorage` 中的值比对，并作废该值 |
| `user.id` | GitHub 用户数字 ID，**建议作为账号唯一键**（`login` 可改） |
| `user.email` | 优先取 `/user` 的公开邮箱，为空时回落到 `/user/emails` 的主邮箱（需 `user:email` scope） |
| `token.access_token` | GitHub access_token，用于你后续调 GitHub API。**仅在此服务端报文中出现** |
| `token.scope` | 实际授予的 scope，可能少于请求的 |
| `request_id` | 全链路 trace id，同时出现在 Worker 日志和浏览器跳转参数里 |

### 2.3 响应

返回任意 `2xx` 即视为投递成功（响应体建议 `{"ok":true}`）。

| 你的返回 | Worker 行为 |
| --- | --- |
| `2xx` | 成功，跳转 `success_redirect` 或渲染成功页 |
| `4xx`（除 408/429） | 判定为业务拒绝，**不重试**，浏览器看到 `delivery_failed` |
| `5xx` / `408` / `429` / 超时 | 按 `UPSTREAM_RETRIES` 退避重试（同一 `request_id`） |

**幂等要求**：重试会带相同的 `Idempotency-Key`，请按它去重，避免重复建号。

---

## 3. 验签（必做）

签名算法：`HMAC-SHA256(secret = CALLBACK_SIGNING_SECRET, message = timestamp + "." + rawBody)`
输出小写十六进制，比对 `X-GH-Proxy-Signature` 的 `sha256=` 之后部分。

**必须**：

- 用**原始 body 字节**计算，不要用反序列化后再序列化的结果（键序/空格差异会导致验签失败）；
- 校验 `|now - timestamp| <= 300` 秒，防重放；
- 用**常量时间比较**，不要用 `==`；
- 验签通过前不要读 `access_token`。

### 3.1 Node / Express 完整示例

```js
import express from 'express';
import crypto from 'node:crypto';

const app = express();
const SIGNING_SECRET = process.env.CALLBACK_SIGNING_SECRET; // 与 Worker 的 secret 一致
const MAX_SKEW_SECONDS = 300;
const seenRequestIds = new Set(); // 生产环境请用 Redis / 数据库并设置 TTL

// ★ 关键：把原始 body 留一份，用于验签
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  }),
);

function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function verifyProxySignature(req) {
  const timestamp = req.get('X-GH-Proxy-Timestamp');
  const signature = (req.get('X-GH-Proxy-Signature') || '').replace(/^sha256=/, '');
  if (!timestamp || !signature) return false;

  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(skew) || skew > MAX_SKEW_SECONDS) return false;

  const expected = crypto
    .createHmac('sha256', SIGNING_SECRET)
    .update(`${timestamp}.${req.rawBody}`, 'utf8')
    .digest('hex');

  return safeEqual(expected, signature);
}

app.post('/auth/github/callback', async (req, res) => {
  if (!verifyProxySignature(req)) {
    return res.status(401).json({ ok: false, error: 'invalid_signature' });
  }

  const requestId = req.get('X-GH-Proxy-Request-Id');
  if (seenRequestIds.has(requestId)) {
    return res.status(200).json({ ok: true, deduplicated: true }); // 幂等
  }
  seenRequestIds.add(requestId);

  const { state, user, token } = req.body;

  // 1) 校验业务 state（防 CSRF），并立即作废
  const expectedState = req.session?.oauthState;
  if (!expectedState || !safeEqual(String(expectedState), String(state || ''))) {
    return res.status(400).json({ ok: false, error: 'state_mismatch' });
  }
  delete req.session.oauthState;

  // 2) 以 github id 为唯一键建号 / 登录
  const account = await upsertUser({
    provider: 'github',
    providerAccountId: String(user.id),
    login: user.login,
    name: user.name,
    email: user.email,
    avatarUrl: user.avatar_url,
    accessToken: token.access_token, // 如需长期调用 GitHub API，请加密存储
  });

  // 3) 建立你自己的会话
  req.session.userId = account.id;
  await new Promise((resolve) => req.session.save(resolve));

  res.json({ ok: true, userId: account.id });
});
```

### 3.2 Python / Flask 示例

```python
import hmac, hashlib, time
from flask import Flask, request, session, jsonify

app = Flask(__name__)
SIGNING_SECRET = os.environ["CALLBACK_SIGNING_SECRET"].encode()
MAX_SKEW = 300
seen_request_ids = set()

@app.post("/auth/github/callback")
def github_callback():
    raw = request.get_data()                     # 原始字节，验签必须用它
    ts = request.headers.get("X-GH-Proxy-Timestamp", "")
    sig = request.headers.get("X-GH-Proxy-Signature", "").removeprefix("sha256=")

    if not ts or not sig:
        return jsonify(ok=False, error="missing_signature"), 401
    if abs(time.time() - int(ts)) > MAX_SKEW:
        return jsonify(ok=False, error="timestamp_expired"), 401

    expected = hmac.new(SIGNING_SECRET, f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):   # 常量时间比较
        return jsonify(ok=False, error="invalid_signature"), 401

    request_id = request.headers.get("X-GH-Proxy-Request-Id")
    if request_id in seen_request_ids:
        return jsonify(ok=True, deduplicated=True)
    seen_request_ids.add(request_id)

    data = request.get_json()
    if not hmac.compare_digest(session.pop("oauth_state", ""), data.get("state") or ""):
        return jsonify(ok=False, error="state_mismatch"), 400

    user, token = data["user"], data["token"]
    account = upsert_user(
        provider="github",
        provider_account_id=str(user["id"]),
        login=user["login"],
        email=user.get("email"),
        access_token=token["access_token"],
    )
    session["user_id"] = account.id
    return jsonify(ok=True, user_id=account.id)
```

### 3.3 其他语言

只要做到「拿原始 body + HMAC-SHA256 + 常量时间比较 + 时间窗校验」即可，例如 Go：

```go
mac := hmac.New(sha256.New, []byte(signingSecret))
mac.Write([]byte(timestamp + "." + rawBody))
expected := hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(expected), []byte(receivedSig)) { /* 拒绝 */ }
```

---

## 4. `curl` 复现与自测

### 4.1 手动走一遍完整流程

```bash
WORKER=https://gh-oauth.example.workers.dev

# ① 发起授权，观察 302 与 Set-Cookie
curl -si "$WORKER/authorize?redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fgithub%2Fcallback&state=test-123" \
  | sed -n '1,12p'

# ② JSON 模式
curl -s "$WORKER/authorize?format=json&redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fgithub%2Fcallback" | jq

# ③ 白名单拒绝（应返回 400 redirect_uri_not_allowed）
curl -s "$WORKER/authorize?format=json&redirect_uri=https%3A%2F%2Fevil.com%2Fsteal" | jq .error

# ④ 状态绑定异常（应返回 403 state_expired）
curl -s -o /dev/null -w '%{http_code}\n' "$WORKER/callback?code=fake&state=forged"

# ⑤ 健康检查
curl -s "$WORKER/health?deep=1" | jq '{ok, checks}'

# ⑥ 用 curl 模拟 GitHub 回调（手工在浏览器里完成 ① 的授权后，把浏览器地址栏的
#    /callback?code=...&state=... 完整 URL 复制过来，带上 ① 拿到的 Cookie）
curl -si "https://gh-oauth.example.workers.dev/callback?code=<code>&state=<nonce>" \
  -H "Cookie: gh_oauth_state=<贴 ① 的 Cookie 值>" | sed -n '1,15p'
```

### 4.2 本地模拟 Worker 回传，验证你的验签逻辑

不依赖真实 GitHub，直接给你的回调端点打一发签名请求：

```bash
SECRET='与 Worker CALLBACK_SIGNING_SECRET 相同的值'
BODY='{"event":"oauth.callback","provider":"github","request_id":"local-test-1","issued_at":"2026-09-26T15:04:21.318Z","state":"test-123","scope":"read:user","token":{"access_token":"gho_fake","token_type":"bearer","scope":"read:user","obtained_at":"2026-09-26T15:04:21.318Z"},"user":{"id":1,"login":"octocat","name":"The Octocat","email":"octo@example.com","avatar_url":"https://avatars.githubusercontent.com/u/583231?v=4","html_url":"https://github.com/octocat"}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1)

curl -si https://api.example.com/auth/github/callback \
  -X POST \
  -H 'Content-Type: application/json' \
  -H "X-GH-Proxy-Timestamp: $TS" \
  -H "X-GH-Proxy-Signature: sha256=$SIG" \
  -H "X-GH-Proxy-Request-Id: local-test-1" \
  -H "Idempotency-Key: local-test-1" \
  -H 'X-GH-Proxy-Event: oauth.callback' \
  --data-raw "$BODY"
```

> 预期：验签通过、建会话成功、返回 `{"ok":true}`。
> 把 `$TS` 改成 10 分钟前，应被时间窗拒绝；把 `$BODY` 改一个字符，应被签名校验拒绝。

---

## 5. 用户跳转结果参数

配置了 `success_redirect` / `error_redirect` 时，Worker 会把浏览器 302 过去并附加参数：

**成功**

```
https://www.example.com/login/success?status=ok&state=test-123&request_id=9f2c8e1a-…
```

**失败**

```
https://www.example.com/login/failed?status=error&error=state_expired&error_description=state%20%E6%97%A0%E6%95%88%E6%88%96%E5%B7%B2%E8%BF%87%E6%9C%9F&state=test-123&request_id=9f2c8e1a-…
```

前端只需读 `status` 与 `error` 展示提示；**真正的登录态以你后端回调端点的处理结果为准**
（跳转可能先于回传到达，建议前端在成功页做一次 `/api/me` 轮询）。

---

## 6. 上线前检查清单

**Worker 侧**

- [ ] GitHub OAuth App 的 callback URL = `https://<PUBLIC_BASE_URL>/callback`（https、无末尾斜杠）
- [ ] 4 个 Secrets 已通过 `wrangler secret put` 注入，且 `COOKIE_SECRET` / `CALLBACK_SIGNING_SECRET` 各 ≥32 字节随机
- [ ] `ALLOWED_CALLBACK_URIS` 精确列出业务回调地址；`ALLOWED_CALLBACK_ORIGINS` 列出业务前端域名
- [ ] `ALLOWED_REDIRECT_ORIGINS` 列出成功/失败跳转域名
- [ ] `ALLOW_INSECURE_REDIRECTS=false`、`ENVIRONMENT=production`、`LOG_LEVEL=info`
- [ ] 已绑定 `OAUTH_KV`（以及 `RATE_LIMIT_KV`）；`/` 页面自检无红色告警
- [ ] `curl "$WORKER/health?deep=1"` 各项 `ok=true`，`github_api.latency_ms` 合理（通常 < 300ms）
- [ ] 已在 Cloudflare 为 `/authorize`、`/callback` 配置 Rate limiting rules（可选但推荐）

**业务服务器侧**

- [ ] 回调端点公网可达且仅走 HTTPS
- [ ] 用原始 body 验签 + 常量时间比较 + 时间窗校验
- [ ] 按 `X-GH-Proxy-Request-Id` / `Idempotency-Key` 做幂等去重
- [ ] 校验并作废业务自己的 `state`
- [ ] 以 `user.id` 作为账号唯一键（不要用 `login`）
- [ ] `access_token` 加密存储、不写日志、不下发前端
- [ ] `CALLBACK_SIGNING_SECRET` 只存在于环境变量中，且与 Worker 端一致

---

## 7. 常见问题

| 现象 | 处理 |
| --- | --- |
| 回调端点收到请求但验签失败 | 检查是否用了框架解析后的 body 重新序列化（必须留原始字节）；检查密钥两端是否一致；检查是否误读 `sha256=` 前缀 |
| 同一用户建了两次账号 | 幂等去重没做，或唯一键用了 `login` |
| 用户重复刷新回调页导致登录失败 | 正常现象：`code` 与 `state` 都是一次性的；前端应避免回退/刷新回调地址 |
| 前端在成功页拿不到登录态 | 跳转可能先于回传完成，前端应轮询 `/api/me` 或由成功页触发一次会话检查 |
| 想换掉 GitHub 账号体系 | 只需改 `DEFAULT_SCOPE` 与前端展示，业务侧契约不变 |
