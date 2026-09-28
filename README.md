# GitHub OAuth 中转（Proxy）— Cloudflare Workers

解决**国内业务服务器直连 `github.com` 不稳定**导致 GitHub 授权登录失败的问题。

业务服务器不再直接与 GitHub 通信，而是把「换 token、拉用户信息」这两个跨境步骤交给部署在
Cloudflare 边缘网络上的 Worker 完成；Worker 通过**带 HMAC 签名的服务端请求**把结果回传给你的业务服务器。

- 只依赖 Workers 原生能力（WebCrypto / fetch / KV），**零运行时依赖**
- Client ID / Secret 全部走 **Secrets 注入**，代码内无任何硬编码
- 一次性 `state`（KV）+ **AES-256-GCM 加密 Cookie** 双重防 CSRF
- 回调地址白名单 + 来源（Origin/Referer）校验 + 浏览器跳转白名单
- 超时 / 重试 / 限流 / 结构化错误 / 结构化日志 全套

---

## 一键部署（无需命令行）

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Peter267/github-oauth-proxy)

点上面的按钮即可部署。Cloudflare 会自动把本仓库克隆到你的账号、创建两个 KV 命名空间并回填 id、
在部署页引导你填写 4 个 Secret，并配置好 Workers Builds（此后推送到 `main` 自动重新部署）。

**全程只需要浏览器**：不用安装 Node.js、不用装 wrangler、不用打开终端。完整图文步骤见
**[DEPLOY.md](./DEPLOY.md)**。

> 部署完成后打开 Worker 首页：配置尚未就绪时，它会渲染一个**分步配置引导页**
> （列出缺什么、去哪儿填，并给出可直接复制的 GitHub OAuth App 回调地址）；
> 配置补齐后刷新即自动变成绿色运行状态面板 —— 因此纯网页用户不需要靠报错信息猜问题。

---

## 1. 流程总览

```
 浏览器                业务服务器            Cloudflare Worker                GitHub
   │                      │                       │                             │
   │  ① 点击「GitHub 登录」│                       │                             │
   ├─────────────────────>│                       │                             │
   │                      │ ② 生成自己的 state     │                             │
   │  ③ 302 /authorize?redirect_uri=&state=&scope= │                             │
   │<─────────────────────┤                       │                             │
   │  ④ GET /authorize ───────────────────────────>│  校验白名单 / 来源           │
   │                      │                       │  签发一次性 state（KV+Cookie）│
   │  ⑤ 302 github.com/login/oauth/authorize ─────────────────────────────────>│
   │  ⑥ 用户在 GitHub 授权 ───────────────────────────────────────────────────>│
   │  ⑦ 302 /callback?code=&state=<nonce> ─────────────────────────────────────┤
   │  ⑧ GET /callback?code=&state= ───────────────>│  校验 state（读后即删）      │
   │                      │                       │  校验加密 Cookie 绑定        │
   │                      │                       │  ⑨ POST 换 access_token ───>│
   │                      │                       │<── access_token ────────────┤
   │                      │                       │  ⑩ GET /user ──────────────>│
   │                      │                       │<── 用户资料 ────────────────┤
   │                      │ ⑪ POST 签名报文（含 token）│                          │
   │                      │<──────────────────────┤                             │
   │  ⑫ 302 success_redirect?status=ok&state= ────┤                             │
   │<─────────────────────────────────────────────┤                             │
```

关键点：**access_token 只在 ⑨⑪ 两个服务端到服务端的环节流动，永远不会下发给浏览器。**

---

## 2. 目录结构

```
.
├── src/
│   ├── index.ts                  # Worker 入口与路由
│   ├── config.ts                 # 配置装载 + fail-fast 校验（含占位符密钥拒绝）
│   ├── errors.ts                 # 错误码 / AppError / 状态码映射
│   ├── crypto.ts                 # AES-GCM、HMAC、Base64URL、常量时间比较
│   ├── logger.ts                 # 结构化 JSON 日志 + request id
│   ├── state.ts                  # 一次性 state（KV）+ 加密 Cookie
│   ├── validation.ts             # URL / 白名单 / scope / 来源校验
│   ├── github.ts                 # GitHub 上游调用（超时 + 重试 + 限流识别）
│   ├── deliver.ts                # 回传业务服务器（HMAC 签名 + 重试）
│   ├── responses.ts              # 结构化响应与错误渲染
│   ├── pages.ts                  # 状态面板 / 首次部署配置引导页 / 成功页
│   └── handlers/
│       ├── authorize.ts          # GET|POST /authorize
│       ├── callback.ts           # GET /callback
│       └── health.ts             # GET /health
├── test/                         # vitest 用例（含端到端流程测试）
├── examples/                     # 业务服务器对接示例（Express / Flask / 前端）
├── wrangler.toml
├── DEPLOY.md                     # ★ 纯网页一键部署指南（零命令行）
├── INTEGRATION.md                # ★ 业务服务器对接说明（含请求/响应示例）
└── .dev.vars.example
```

---

## 3. 部署

有两条路径，产出的服务完全相同，可以混用（例如先网页部署，之后再克隆到本地开发）：

| 方式 | 适用场景 | 怎么做 |
| --- | --- | --- |
| **A. 网页一键部署**（推荐） | 不熟悉命令行、想 10 分钟内上线、交由非开发同事操作 | 点顶部 **Deploy to Cloudflare** 按钮 → 见 **[DEPLOY.md](./DEPLOY.md)** |
| **B. 命令行部署** | 需要本地调试、接入自动化流水线 | 按下面 3.1 – 3.5 操作 |

### 3.1 创建 GitHub OAuth App

GitHub → Settings → Developer settings → **OAuth Apps** → New OAuth App：

| 字段 | 值 |
| --- | --- |
| Application name | 任意，如 `MyApp Login (Proxy)` |
| Homepage URL | 你的站点首页 |
| **Authorization callback URL** | `https://<你的-worker-域名>/callback` |

> ⚠️ 这里必须填 **Worker 的 `/callback`**，而不是业务服务器的地址。
> 因为「code 换 token」这一步必须由 OAuth App 注册的回调地址来完成。
> 若你已有旧 OAuth App 且不想改动，可另建一个专门给中转用的 OAuth App。

创建后记下 **Client ID** 与 **Client Secret**。

### 3.2 创建 KV 命名空间

```bash
npm install
npx wrangler login

# 存放一次性 state（必需）
npx wrangler kv namespace create OAUTH_KV
# 可选：分布式限流计数器（强烈建议生产环境绑定）
npx wrangler kv namespace create RATE_LIMIT_KV
```

把返回的 `id` 填进 `wrangler.toml`。

> 本模板只声明 `id`、不声明 `preview_id`：`wrangler dev` 默认使用**本地 KV 模拟**，不需要它。
> 若你要用 `wrangler dev --remote`，自行补上 `preview_id` 即可。

### 3.3 注入 Secrets（禁止硬编码）

```bash
# 生成两把随机密钥（各 32 字节）
npm run gen-secret

npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put COOKIE_SECRET           # 加密 state Cookie
npx wrangler secret put CALLBACK_SIGNING_SECRET # 回传报文的 HMAC 签名密钥
```

本地开发时把同样的 4 个值写入 `.dev.vars`（复制 `.dev.vars.example`）。

> ⚠️ `.dev.vars.example` 里的值全部是**模板占位符**。服务会主动拒绝占位符
> （匹配 `replace_with` / `changeme` / `xxxx` 等指纹）并返回 `server_misconfigured`，
> 避免有人把公开仓库里的示例值当成真密钥上线 —— 那等于 state Cookie 与回传签名可被任意伪造。
> 这一约束对网页一键部署尤其重要：部署表单会预填模板值，忘了替换就会被显式拦下。

### 3.4 配置业务侧参数并部署

编辑 `wrangler.toml` 的 `[vars]`（至少改 `PUBLIC_BASE_URL`、`ALLOWED_CALLBACK_URIS`、
`ALLOWED_CALLBACK_ORIGINS`、`ALLOWED_REDIRECT_ORIGINS`），然后：

```bash
npm run deploy

# 首次上线后做一次深检查（会真实探测 GitHub 可达性）
curl -s "https://<你的-worker-域名>/health?deep=1" | jq
```

浏览器打开 Worker 根路径 `/`（等价于 `/setup`）：配置齐全会显示**当前生效配置与自检结果**，
可用来快速确认白名单是否漏配 —— 页面还会直接给出应填到 GitHub OAuth App 的 `/callback` 地址（带复制按钮）；
若配置尚未就绪，则渲染**分步配置引导页**，列出缺哪些项、去哪儿填，全程无需命令行。

### 3.5 本地开发

```bash
cp .dev.vars.example .dev.vars   # 填好 4 个密钥
npm run dev                      # http://127.0.0.1:8787
npm run typecheck
npm test
```

---

## 4. 配置项一览

### 4.1 Secrets（`wrangler secret put`）

| 名称 | 必需 | 说明 |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | ✅ | GitHub OAuth App 的 Client ID |
| `GITHUB_CLIENT_SECRET` | ✅ | GitHub OAuth App 的 Client Secret，**绝不下发、绝不打日志** |
| `COOKIE_SECRET` | ✅ | ≥16 字符。派生 AES-256-GCM 密钥加密 state Cookie（HKDF-SHA256） |
| `CALLBACK_SIGNING_SECRET` | ✅ | ≥32 字符。对回传业务服务器的报文做 HMAC-SHA256 签名 |

> 4 个 Secret 会被逐一校验：**空值**与**模板占位符**（`replace_with…` / `changeme` 等）都会触发
> `server_misconfigured` 并快速失败，避免弱密钥或公开可知的密钥被静默使用。
> 网页一键部署时，这些校验结果会直接呈现在首页引导页上。

### 4.2 Vars（`wrangler.toml` → `[vars]`）

| 名称 | 默认 | 说明 |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | 请求 origin | Worker 对外地址，决定 `redirect_uri=https://<base>/callback` |
| `ALLOWED_CALLBACK_URIS` | 空（拒绝全部） | 业务服务器接收结果的地址白名单，逗号分隔。**必填** |
| `ALLOWED_CALLBACK_ORIGINS` | 空（不校验） | 允许发起 `/authorize` 的前端 Origin 白名单 |
| `ALLOWED_REDIRECT_ORIGINS` | 空 | 允许 `success_redirect` / `error_redirect` 指向的地址 |
| `DEFAULT_SCOPE` | `read:user user:email` | 未传 `scope` 时使用 |
| `ALLOWED_SCOPES` | 空 | 非空时 `?scope=` 只能是它的子集 |
| `SUCCESS_REDIRECT` / `ERROR_REDIRECT` | 空 | 全局默认跳转，可被单次请求覆盖 |
| `STATE_TTL_SECONDS` | `600` | state 有效期（60–3600） |
| `RATE_LIMIT_PER_MINUTE` | `60` | 每 IP 每分钟的 `/authorize` + `/callback` 请求数；`0` = 关闭 |
| `UPSTREAM_TIMEOUT_MS` | `8000` | 调用 GitHub 的超时 |
| `UPSTREAM_RETRIES` | `2` | 幂等请求的额外重试次数（0–5） |
| `DELIVERY_METHOD` | `POST` | 回传方式：`POST`（JSON+签名，推荐）或 `GET`（query） |
| `DELIVERY_TIMEOUT_MS` | `8000` | 回传业务服务器的超时 |
| `ALLOW_INSECURE_REDIRECTS` | `false` | 是否允许 `http://` 跳转地址（仅联调开启） |
| `ENVIRONMENT` | `production` | 非 `production` 时错误页会展示 `detail`，便于调试 |
| `VERSION` / `LOG_LEVEL` | `1.0.0` / `info` | 版本号 / 日志级别（`debug`/`info`/`warn`/`error`） |

### 4.3 白名单匹配规则

`ALLOWED_CALLBACK_URIS`、`ALLOWED_REDIRECT_ORIGINS` 里每一项可以是三种形式：

| 写法 | 含义 | 示例命中 |
| --- | --- | --- |
| `https://api.example.com` | 仅 origin，放行该域名下**任意路径** | `/a`、`/b/c` 全部通过 |
| `https://api.example.com/auth/gh` | origin + 路径**精确匹配**（忽略 query、忽略末尾 `/`） | `…/auth/gh?x=1` ✅ `…/auth/ghx` ❌ |
| `https://api.example.com/auth/*` | 含 `*` 的条目按**通配符**匹配（`*` 匹配任意字符，整串锚定） | `…/auth/a`、`…/auth/b/c` ✅ |
| `https://*.example.com/*` | 通配符可出现在主机名中，便于放行多子域 | `https://a.example.com/x` ✅ `https://a.example.com.evil.com/x` ❌ |

> 未配置 `ALLOWED_CALLBACK_URIS` 时，`/authorize` 会**拒绝所有请求**（fail-closed），
> 避免配置遗漏演变成开放重定向漏洞。

---

## 5. 端点 API

### 5.1 `GET|POST /authorize` — 发起授权

**入参**（GET query / POST form / POST JSON 均可）：

| 参数 | 必需 | 说明 |
| --- | --- | --- |
| `redirect_uri` | ✅ | 业务服务器接收授权结果的地址，必须命中白名单 |
| `state` | 建议 | 业务方自己的防 CSRF 随机串（≤512 字符，`[A-Za-z0-9._~+/=-]`），回调时**原样带回** |
| `scope` | 否 | 空格或逗号分隔，默认取 `DEFAULT_SCOPE` |
| `success_redirect` | 否 | 成功后把浏览器 302 到这里（附 `status=ok&state=&request_id=`） |
| `error_redirect` | 否 | 失败后把浏览器 302 到这里（附 `status=error&error=&error_description=&state=&request_id=`） |
| `format` | 否 | `json` 时返回授权 URL 而不是 302（供 SPA 自己控制跳转） |
| `login` | 否 | 预填 GitHub 用户名 |
| `allow_signup` | 否 | 默认 `true`；`false` 时不允许注册新账号 |

**响应（默认，浏览器导航）**：`302` + `Location: https://github.com/login/oauth/authorize?...`
+ `Set-Cookie: gh_oauth_state=…; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`

**响应（`?format=json`）**：

```json
{
  "ok": true,
  "authorize_url": "https://github.com/login/oauth/authorize?client_id=…&redirect_uri=https%3A%2F%2Fproxy.example.workers.dev%2Fcallback&scope=read%3Auser+user%3Aemail&state=…",
  "state": "Kx7…（Worker 签发的 nonce）",
  "scope": "read:user user:email",
  "expires_in": 600,
  "callback_url": "https://proxy.example.workers.dev/callback",
  "request_id": "c1f2…"
}
```

### 5.2 `GET /callback` — GitHub 回调（由 GitHub 调用）

| 参数 | 说明 |
| --- | --- |
| `code` | GitHub 授权码 |
| `state` | Worker 签发的 nonce（必须与 KV 记录及加密 Cookie 匹配） |
| `error` | 用户拒绝授权等错误（如 `access_denied`） |

处理顺序：限流 → 取用并销毁 state → 校验 Cookie 绑定 → 换 token → 拉用户 → 签名回传 → 跳转。

响应：配置了 `success_redirect` 则 `302`；否则渲染内置成功页（`?format=json` 时返回 JSON）。
两种情况**都不会**把 access_token 返回给浏览器。

### 5.3 `GET /health` — 健康检查

```jsonc
{
  "ok": true,
  "service": "github-oauth-proxy",
  "version": "1.0.0",
  "environment": "production",
  "checks": { "kv_read": { "ok": true, "latency_ms": 3 } },
  "config_summary": { "callback_allowlist": 2, "state_ttl_seconds": 600, "rate_limit_kv_bound": true, "…": "…" }
}
```

`?deep=1` 时额外做 KV 写-读-删往返与 GitHub API 可达性探测（含延迟），用于上线首检。
`kv` 检查失败返回 `503`，可直接给负载均衡做探针。

### 5.4 `GET /`（等价 `GET /setup`）— 状态面板 / 首次部署引导

浏览器访问的落地页，有两种形态：

| 形态 | 状态码 | 内容 |
| --- | --- | --- |
| **状态面板**（配置就绪） | `200` | 端点说明、应填到 GitHub OAuth App 的 `/callback` 地址（带复制按钮）、当前生效配置、配置自检结果 |
| **配置引导页**（配置缺失） | `503` | 分步引导：缺哪些 Secret / 哪个占位符未替换 / KV 是否缺绑定，以及"去 GitHub 建 OAuth App → 去控制台填变量 → 回来验证"的完整操作路径 |

引导页只暴露**配置项名称**，不暴露任何密钥值。带上 `Accept: application/json` 或 `?format=json`
时不会走引导页，而是返回结构化 `server_misconfigured` 错误，便于脚本与探针判断。

---

## 6. 错误码

所有错误响应结构一致：

```json
{
  "ok": false,
  "error": { "code": "state_expired", "message": "state 无效或已过期（可能已使用过，或登录超时）", "detail": {} },
  "request_id": "9f2c…",
  "timestamp": "2026-09-26T15:00:00.000Z"
}
```

| `error.code` | HTTP | 含义与排查方向 |
| --- | --- | --- |
| `invalid_request` | 400 | 参数缺失/非法（缺 `redirect_uri`、`code`、scope 非法等） |
| `redirect_uri_not_allowed` | 400 | 回调地址或跳转地址不在白名单 → 检查 `ALLOWED_CALLBACK_URIS` / `ALLOWED_REDIRECT_ORIGINS` |
| `origin_not_allowed` | 403 | 请求来源不在 `ALLOWED_CALLBACK_ORIGINS` |
| `rate_limited` | 429 | 触发限流，响应带 `Retry-After` |
| `state_missing` | 400 | 回调缺 `state` |
| `state_expired` | 403 | state 不存在/已用过/超时 → 用户重复刷新回调页属正常现象 |
| `state_mismatch` | 403 | state 与加密 Cookie 不匹配，疑似 CSRF 或跨浏览器 |
| `access_denied` | 401 | 用户在 GitHub 页点了拒绝 |
| `invalid_code` | 400 | code 无效/过期/重复使用（常见于回调 URL 被刷新两次） |
| `token_exchange_failed` | 502 | 换 token 失败（含 GitHub 返回的其他 OAuth 错误） |
| `server_misconfigured` | 500 | Client ID/Secret 错误、`redirect_uri_mismatch`、缺 Secrets/KV 绑定 |
| `user_fetch_failed` | 502 | `/user` 拉取失败或 token 权限不足 |
| `upstream_timeout` | 504 | 调 GitHub 超时（已按 `UPSTREAM_RETRIES` 重试） |
| `upstream_unavailable` | 503 | GitHub 5xx |
| `upstream_rate_limited` | 429 | 触发 GitHub 侧限流，`detail` 含 `reset_at` / `retry_after_ms` |
| `delivery_failed` | 502 | 回传业务服务器失败（`detail.status` 为业务侧返回码） |
| `internal_error` | 500 | 未预期异常，凭 `request_id` 查日志 |

---

## 7. 安全设计

| 风险 | 对策 |
| --- | --- |
| CSRF / 授权码注入 | 每次授权签发 256bit 一次性 `state`，存 KV 且**读取即删除**（`expirationTtl` 双重过期）；回调时校验 |
| 跨浏览器重放 | `state` 额外用 **AES-256-GCM 加密绑定到 Cookie**（HttpOnly + Secure + SameSite=Lax），形成双提交校验 |
| 开放重定向 | `redirect_uri` / `success_redirect` / `error_redirect` 全部比对白名单（fail-closed），并剥离 URL hash |
| 凭证泄露 | Client ID/Secret 仅存 Secrets；`code`/`access_token` 永不入日志，日志里只出现 `token_fp`（SHA-256 前 12 位） |
| 报文伪造/重放 | 回传业务服务器的报文做 HMAC-SHA256 签名，签名覆盖 `timestamp + "." + rawBody`；业务侧校验时间窗 + `request_id` 幂等去重 |
| 令牌泄露到浏览器 | `access_token` 仅出现在服务端到服务端的签名报文中；`/callback` 面向浏览器的响应只含用户公开信息 |
| 慢连接拖挂 | 所有上游请求强制超时（`UPSTREAM_TIMEOUT_MS`），失败按幂等性退避重试，尊重 `Retry-After` |
| 刷量/撞库 | KV 固定窗口限流（按 IP 指纹），可与 Cloudflare Rate limiting rules 叠加 |
| 缓存泄露 | 所有响应 `Cache-Control: no-store` + `Referrer-Policy: no-referrer` + `X-Frame-Options: DENY` |

> 关于限流精度：Workers KV 是最终一致的，KV 计数属于**近似限流**，用于兜底；生产环境若要强一致
> 限流，请在 Cloudflare Dashboard 为 `/authorize`、`/callback` 配置 Rate limiting rules。

---

## 8. 可观测性

日志为单行 JSON，字段固定，便于直接接 Workers Logs / Logpush / Grafana：

```jsonc
{"ts":"2026-09-26T15:00:00.000Z","level":"info","event":"callback.success",
 "request_id":"9f2c…","session_request_id":"c1f2…","github_user_id":583231,"github_login":"octocat",
 "scope":"read:user user:email","email_present":true,"token_fp":"a3f9c1b2d4e5",
 "delivery_status":200,"delivery_attempt":1,"delivery_target":"https://api.example.com",
 "duration_ms":842,"ip_fp":"77ab…"}
```

关键事件：`http.request`、`authorize.created`、`authorize.failed`、`authorize.rate_limited`、
`callback.success`、`callback.failed`、`callback.state_invalid`、`callback.state_mismatch`、
`github.token.oauth_error`、`github.token.rate_limited`、`delivery.response`、`delivery.failed`。

实时看日志：

```bash
npm run tail                                # 全部
npx wrangler tail --status error            # 只看错误
npx wrangler tail --search "callback.failed"
```

排障三步：拿响应里的 `request_id` → `wrangler tail --search <request_id>` → 看 `error_code` 与
`detail`。整个会话（authorize 会话 id = `session_request_id`）可跨请求串联。

---

## 9. 测试

```bash
npm run typecheck   # tsc --noEmit
npm test            # vitest
```

`test/flow.test.ts` 用 fetch 桩完整跑通 `/authorize → /callback → 换 token → 拉用户 → 签名回传`，
并覆盖一次性 state 重放、Cookie 缺失（CSRF）、白名单拒绝、来源拒绝、用户取消授权、
GitHub 5xx、业务服务器 4xx、限流等异常分支。

---

## 10. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| GitHub 报 `redirect_uri_mismatch` | OAuth App 的 callback URL 必须精确等于 `https://<PUBLIC_BASE_URL>/callback`（含协议、无末尾斜杠） |
| 回调返回 `state_expired` | 用户在结果页刷新了；或 `STATE_TTL_SECONDS` 太小；或 KV 绑定错误 |
| 回调返回 `state_mismatch` | 用户在别的浏览器/无痕窗口完成授权；或 Worker 换了 `COOKIE_SECRET` |
| 回调返回 `server_misconfigured` | `GITHUB_CLIENT_SECRET` 填错；或漏了 `OAUTH_KV` 绑定；错误详情 `detail.hint` 会指明 |
| `delivery_failed` | 业务服务器拒收：检查签名校验逻辑、`Idempotency-Key` 是否被误判、`ALLOWED_CALLBACK_URIS` 是否指向外网可达地址 |
| 业务服务器收不到回调 | 业务地址必须公网可达；内网地址请改用反向隧道或让前端轮询 |
| 打开 `/` 发现白名单条数为 0 | 忘了配 `ALLOWED_CALLBACK_URIS`，此时 `/authorize` 会全部拒绝 |
| 打开 `/` 是黄色「待配置」页且返回 `503` | 正常：这是首次部署的**配置引导页**，不是故障。按页面 4 步补齐 Secret 与变量即可，补齐后自动变为绿色面板 |
| 报 `检测到未替换的占位符密钥` | 仍在用 `.dev.vars.example` / 部署表单预填的模板值。请换成真实密钥（`COOKIE_SECRET` ≥16、`CALLBACK_SIGNING_SECRET` ≥32 字符） |
| 网页部署后想改配置 | Cloudflare 控制台 → 你的 Worker → Settings → Variables and Secrets，**保存即生效，无需重新部署** |
| 一键部署按钮打不开 | 用 [DEPLOY.md 附录 A](./DEPLOY.md#附录-a不用按钮的纯网页部署) 的手工网页路径（Fork + 连接 Git 仓库）

---

## 11. 与业务服务器的对接

见 **[INTEGRATION.md](./INTEGRATION.md)**：包含发起登录的两种方式、回调端点完整实现
（Node/Express 与 Python/Flask）、验签规范、请求与响应示例、`curl` 复现命令与上线检查清单。

`examples/` 目录可直接拷走参考。

---

## 12. 部署与更新速查

| 需求 | 去哪里做 |
| --- | --- |
| **纯网页部署（零命令行）** | **[DEPLOY.md](./DEPLOY.md)** —— 点一键部署按钮，全程只需浏览器 |
| 命令行部署 | 本文 §3 |
| 改白名单 / 超时 / 限流等参数 | Cloudflare 控制台 → 你的 Worker → Settings → Variables and Secrets（保存即生效） |
| 改密钥 | 同上，类型选 Secret。换 `COOKIE_SECRET` 会作废进行中的登录会话；换 `CALLBACK_SIGNING_SECRET` 需同步业务服务器 |
| 改代码 | 改 Cloudflare 克隆到你账号下的仓库 → 推送到 `main` → Workers Builds 自动构建部署 |
| 回滚到历史版本 | Cloudflare 控制台 → 你的 Worker → Deployments → Rollback |
| 看实时日志 | `npx wrangler tail`，或 Cloudflare 控制台的 Logs 视图 |
