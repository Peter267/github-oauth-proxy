# 纯网页部署指南

> **目标：全程只用浏览器完成部署。** 不需要安装 Node.js，不需要 wrangler CLI，不需要打开终端。
>
> 适合不熟悉命令行的人，也适合把上线操作交给非开发同事执行。全程约 10 分钟。

---

## 目录

- [0. 三分钟速览](#0-三分钟速览)
- [1. 前置条件](#1-前置条件)
- [2. 第 1 步：在 GitHub 创建 OAuth App](#2-第-1-步在-github-创建-oauth-app)
- [3. 第 2 步：点按钮一键部署](#3-第-2-步点按钮一键部署)
- [4. 第 3 步：把真实回调地址回填到 GitHub](#4-第-3-步把真实回调地址回填到-github)
- [5. 第 4 步：配置业务白名单](#5-第-4-步配置业务白名单)
- [6. 第 5 步：验证上线](#6-第-5-步验证上线)
- [7. 部署会创建哪些资源](#7-部署会创建哪些资源)
- [8. 部署之后怎么改东西](#8-部署之后怎么改东西)
- [9. 绑定自定义域名](#9-绑定自定义域名)
- [10. 上线检查清单](#10-上线检查清单)
- [11. 常见问题](#11-常见问题)
- [附录 A：不用按钮的纯网页部署](#附录-a不用按钮的纯网页部署)
- [附录 B：网页部署 vs 命令行部署](#附录-b网页部署-vs-命令行部署)
- [附录 C：费用与容量](#附录-c费用与容量)

---

## 0. 三分钟速览

| # | 在哪里操作 | 做什么 |
| --- | --- | --- |
| 1 | GitHub | 新建 OAuth App，**回调地址先随便填**，稍后再改 |
| 2 | Cloudflare 部署页 | 点 **Deploy to Cloudflare** 按钮，填 4 个 Secret，点部署 |
| 3 | GitHub | 把回调地址改成 `https://<你的 Worker 域名>/callback` |
| 4 | Cloudflare 控制台 | 添加 `ALLOWED_CALLBACK_URIS` 等白名单变量 |
| 5 | 浏览器 | 打开 Worker 首页 + `/health?deep=1` 自检通过 |

> **为什么第 1 步的回调地址要"先随便填"？**
> GitHub 要求 OAuth App 的回调地址必须是 **Worker 的 `/callback`**，而 Worker 地址要部署完成后才会分配。
> 所以先占位、部署后回填，是最省事的顺序。GitHub 允许随时修改回调地址。

---

## 1. 前置条件

| 需要什么 | 说明 |
| --- | --- |
| GitHub 账号 | 用于创建 OAuth App；Cloudflare 还会把本仓库克隆到你的账号下，方便你后续改代码 |
| Cloudflare 账号 | 免费计划即可。[注册](https://dash.cloudflare.com/sign-up)（无需绑卡） |
| 业务后端回调地址 | 例如 `https://api.example.com/auth/github/callback`，**必须公网可达**。它接收 Worker 带签名回传的授权结果 |
| 业务前端域名 | 例如 `https://www.example.com`，发起登录的页面所在站点 |

本仓库必须是**公开仓库**，一键部署按钮才能工作。

---

## 2. 第 1 步：在 GitHub 创建 OAuth App

1. 打开 GitHub → 右上角头像 → **Settings**
2. 左侧最底部 → **Developer settings**
3. 左侧 → **OAuth Apps** → 右上角 **New OAuth App**

填写：

| 字段 | 填什么 |
| --- | --- |
| Application name | 任意，例如 `MyApp Login (Proxy)` |
| Homepage URL | 你的业务站点首页，例如 `https://www.example.com` |
| Application description | 可留空 |
| **Authorization callback URL** | **先随便填**，例如 `https://placeholder.example.com/callback` —— 第 4 步会改成真实值 |

点 **Register application**，然后：

1. 页面顶部会显示 **Client ID**（形如 `Ov23li…`）→ **复制下来，待会要用**
2. 点 **Generate a new client secret** → **Client Secret 只显示一次**，立刻复制

> 这两个值就是稍后要填进 Cloudflare 的 `GITHUB_CLIENT_ID` 与 `GITHUB_CLIENT_SECRET`。
> Client Secret 相当于密码，不要发到聊天群、不要贴进任何前端代码。

---

## 3. 第 2 步：点按钮一键部署

### 3.1 打开部署页

点击仓库 README 顶部的按钮，或直接访问：

```
https://deploy.workers.cloudflare.com/?url=https://github.com/Peter267/github-oauth-proxy
```

### 3.2 按提示完成授权

1. 用 Cloudflare 账号登录（没有就现场注册，免费）
2. 授权 Cloudflare 访问你的 GitHub 账号 —— 授权后 Cloudflare 会把本仓库**克隆到你自己的账号**下
   （原仓库不受影响，你后续改代码改的是自己的副本）

### 3.3 填写部署配置

Cloudflare 会读取仓库里的 `wrangler.toml` 与 `.dev.vars.example`，把需要你确认的东西一次性列出来：

| 配置项 | 说明 | 建议 |
| --- | --- | --- |
| Git 账号 / 仓库名 | 克隆到你账号下的仓库名 | 用默认值即可 |
| Worker 名称 | 部署后的 Worker 名 | 用默认 `github-oauth-proxy`，或改成你喜欢的 |
| KV 命名空间名 | `OAUTH_KV`、`RATE_LIMIT_KV` | **保持默认，让 Cloudflare 自动创建** |
| `GITHUB_CLIENT_ID` | 第 1 步复制的 Client ID | 粘贴（服务端要求 **≥10 字符**，GitHub 实际值远超此下限） |
| `GITHUB_CLIENT_SECRET` | 第 1 步复制的 Client Secret | 粘贴（服务端要求 **≥16 字符、字符种类 ≥8**，GitHub 实际值远超此下限） |
| `COOKIE_SECRET` | 加密防 CSRF 的 state Cookie，**至少 16 字符** | 用下面方法生成随机串；且**必须与 `CALLBACK_SIGNING_SECRET` 不同** |
| `CALLBACK_SIGNING_SECRET` | 回传报文签名密钥，**至少 32 字符** | 用下面方法生成随机串；且**必须与 `COOKIE_SECRET` 不同** |

> ⚠️ **这些字段的默认值是仓库模板里的占位符（`replace_with_…`），必须替换成真实值。**
> 服务端会按下述**五类**校验，逐类快速失败（触发后统一返回 `server_misconfigured`，并由首页
> 降级为"待配置"引导页）：Worker 能部署成功，但访问时会返回该引导页，告诉你还差哪几项
> —— 不会带着有问题的密钥悄悄跑起来：
>
> 1. **缺失 / 空值**：Secret 未注入或为空串（`OAUTH_KV` 绑定缺失也归入这一类）；
> 2. **取值非法**：值不是字符串（如数字、对象），或剔除空白 / 不可见字符后为空（如只填了几个空格）；
> 3. **占位符**：值里含 `replace_with` / `changeme` / `xxxx` 等公开指纹，或整串是纯数字 / `password` 这类公开弱口令；
> 4. **弱密钥**：长度不足（`GITHUB_CLIENT_ID` < 10、`GITHUB_CLIENT_SECRET` < 16、
>    `COOKIE_SECRET` < 16、`CALLBACK_SIGNING_SECRET` < 32 字符），或其中三把随机密钥
>    去重后**字符种类 < 8**（如 `aaaa…`、`1234…` 这类低熵串）；
> 5. **两把密钥相同**：`COOKIE_SECRET` 与 `CALLBACK_SIGNING_SECRET` **取值相同**。
>
> 所以**不能照着占位符直接部署**，本节下面两步就是教你生成两把合格的随机密钥。

**不装任何工具，在浏览器里生成两把随机密钥**：

1. 打开任意网页（比如这个仓库页面）
2. 按 `F12` 打开开发者工具 → 切到 **Console**
3. 粘贴执行：

```js
Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('')
```

4. 复制输出的 64 位十六进制串，分别填给 `COOKIE_SECRET` 和 `CALLBACK_SIGNING_SECRET`
   （**务必再执行一次，拿第二个不同的值**）
   > ⚠️ **服务端会强制拒绝两者相同**：`COOKIE_SECRET` 与 `CALLBACK_SIGNING_SECRET` 一旦相同，
   > 服务会直接以 `server_misconfigured` 快速失败（复用一把密钥会同时削弱 Cookie 加密与回传签名）。
   > 请确保是两个独立生成的随机串。

> `CALLBACK_SIGNING_SECRET` 还要与业务服务器上的同名变量保持一致 —— 记下来，对接时要用。

### 3.4 点 Deploy

Cloudflare 会依次：创建仓库 → 创建两个 KV 命名空间并回填 id → 运行 `wrangler deploy` 构建部署 → 配置 Workers Builds（CI/CD）。
首次构建通常 1–2 分钟。

完成后页面会给出你的 Worker 地址：

```
https://github-oauth-proxy.<你的子域>.workers.dev
```

**把它记下来**，下一步要用。

### 3.5 信任模型与供应链提示（建议先读）

一键部署按钮做的是这件事：**把本仓库的默认分支克隆进你自己的 GitHub 账号，
并在你自己的 Cloudflare 账号内执行该副本里的构建 / 部署脚本**（当前 `deploy` 脚本就是 `wrangler deploy`，本仓库声明零运行时依赖、无 `postinstall`、`package-lock.json` 已跟踪）。

因此「点按钮」等价于「在你的账号内执行本仓库 `main` 的内容」。据此建议：

| 建议 | 说明 |
| --- | --- |
| 先自行审计或先锚定版本 | 按钮 URL 默认指向默认分支（会随上游变动）。若要锁定到你审计过的版本，把 URL 改成 `https://deploy.workers.cloudflare.com/?url=<仓库地址>/tree/<tag 或 commit>`，例如 `https://deploy.workers.cloudflare.com/?url=https://github.com/Peter267/github-oauth-proxy/tree/v1.0.0` |
| 升级靠你自己推送 | 部署后克隆到你账号的副本**不会随上游自动更新**。上游出新版时，需要你自行同步 diff 后再推送，Workers Builds 才会重新部署 |
| 可复现构建 | 依赖锁定在 `package-lock.json`，可用固定 tag 复现同一份代码；改动仓库内容即可审计 diff |

---

## 4. 第 3 步：把真实回调地址回填到 GitHub

1. 回到 GitHub → **Settings → Developer settings → OAuth Apps → 选中刚才那个应用**
2. 点 **Edit**（或直接点页面里的 callback URL 字段）
3. 把 **Authorization callback URL** 改成：

```
https://<你的 Worker 域名>/callback
```

例如 `https://github-oauth-proxy.abc123.workers.dev/callback`

4. 点 **Update application**

> **必须精确一致**：含 `https://`、无末尾斜杠、`/callback` 不能少。
> 不一致时 GitHub 会直接报 `redirect_uri_mismatch`。
>
> 懒得手打？打开 Worker 首页，页面上会显示这个地址并带一个 **复制** 按钮。

---

## 5. 第 4 步：配置业务白名单

这一步决定"谁能唤起登录"和"授权结果发到哪里"。

1. 打开 [Cloudflare 控制台](https://dash.cloudflare.com/) → **Workers & Pages**
2. 点进你的 Worker（`github-oauth-proxy`）
3. 进入 **Settings**（设置）→ **Variables and Secrets**（变量与机密）
4. 点 **Add** / **添加**，类型选 **Text**（普通变量），逐个添加：

| 变量名 | 是否必填 | 值 / 说明 |
| --- | --- | --- |
| `ALLOWED_CALLBACK_URIS` | **必填** | 业务后端接收授权结果的地址。例：`https://api.example.com/auth/github/callback`。**留空 = 拒绝全部授权** |
| `ALLOWED_CALLBACK_ORIGINS` | **强烈建议必填**（服务端仅告警、不强制） | 业务前端域名。例：`https://www.example.com`。**留空 = 不校验来源 = 任意站点都能发起授权**（fail-open，与 `ALLOWED_CALLBACK_URIS` 的 fail-closed 语义相反） |
| `ALLOWED_REDIRECT_ORIGINS` | 按需 | 仅在你要用 `success_redirect` / `error_redirect` 跳转时才需要。例：`https://www.example.com` |
| `PUBLIC_BASE_URL` | 可选（生产建议显式填） | 留空即自动使用「请求的 origin」。绑了自定义域名后填 `https://gh-oauth.example.com`。**生产环境建议显式固定**，原因见下方说明 |
| `SUCCESS_REDIRECT` / `ERROR_REDIRECT` | 可选 | 全局默认跳转地址。留空则成功后渲染内置成功页 |
| `ALLOW_UNBOUND_STATE` | 按需（默认 `false`） | 仅当 JSON 模式（`?format=json`）确实无法使用 Cookie 时才设为 `true`；会削弱 CSRF 防护，详见 [INTEGRATION.md §1 方式 C](./INTEGRATION.md) |

**多个值用英文逗号分隔，不要换行、不要带空格。**

> ⚠️ `ALLOWED_CALLBACK_URIS` **留空是刻意的 fail-closed 设计**：此时 `/authorize` 会拒绝所有请求，
> 避免"忘了配白名单"直接变成开放重定向漏洞。请务必填成你自己的业务地址。
>
> ⚠️ `ALLOWED_CALLBACK_ORIGINS` 与上面**语义相反**：它留空时**不校验来源**（fail-open），
> 任何站点都能发起你的登录流程（login-CSRF 的前置条件）。token 不会因此被窃取
> （`ALLOWED_CALLBACK_URIS` 仍会拦住回传地址），但请务必填上业务前端域名，不要留空。
> 注意：它**不是服务端强制项** —— 留空不会导致启动被拒，只会让首页出现一条告警，
> 服务照常运行且不做任何来源校验；这与 `ALLOWED_CALLBACK_URIS` 留空即拒绝全部请求有本质区别。
>
> 💡 **生产环境建议显式设置 `PUBLIC_BASE_URL`**：留空时，Worker 的「同源」判定与 state Cookie 的
> `Secure` 标志都锚定在**请求自带的 origin** 上；显式填成固定的 `https://` 域名后，回调地址、
> 同源判定、CORS 回显与 `Secure` 标志全部锁定到同一个已知值，属纵深防御。
>
> 界面文案在不同版本可能略有差异（如 "Variables" / "Environment variables"），
> 只要找到带加密开关的变量管理页面即是同一处。

白名单写法（三种形式）：

| 写法 | 含义 |
| --- | --- |
| `https://api.example.com` | 放行该域名下**任意路径** |
| `https://api.example.com/auth/gh` | origin + 路径**精确匹配**（忽略 query 与末尾 `/`） |
| `https://api.example.com/auth/*` | 通配符匹配（`*` 匹配任意字符） |
| `https://*.example.com/*` | 通配符可出现在主机名中，便于放行多子域 |

**改完保存即生效，不需要重新部署。**

---

## 6. 第 5 步：验证上线

### 6.1 打开 Worker 首页

```
https://<你的 Worker 域名>/
```

- **绿色「运行中」面板** → 配置已就绪，页面会列出当前回调白名单条数、scope、KV 绑定等
- **黄色「待配置」引导页** → 还有未完成的项，页面会直接告诉你缺哪些、去哪填

### 6.2 深检查（会真实探测 GitHub 可达性）

```
https://<你的 Worker 域名>/health?deep=1
```

期望结果：

```jsonc
{
  "ok": true,
  "checks": {
    "kv_read":        { "ok": true },
    "kv_round_trip":  { "ok": true },
    "github_api":     { "ok": true, "latency_ms": 120 }   // 说明已能直连 GitHub
  }
}
```

`github_api.latency_ms` 通常在 300 ms 以内。

### 6.3 走一遍真实登录

1. 浏览器打开 `https://<你的 Worker 域名>/authorize?redirect_uri=<你的业务回调地址>&state=test-123`
2. 应跳转到 GitHub 授权页 → 授权 → 最终落到你的业务系统
3. 业务后端应收到一条带 `X-GH-Proxy-Signature` 的 POST 请求（对接细节见 [INTEGRATION.md](./INTEGRATION.md)）

---

## 7. 部署会创建哪些资源

| 资源 | 名称 | 作用 |
| --- | --- | --- |
| Worker | `github-oauth-proxy` | 服务本体 |
| KV 命名空间 | `<worker>-OAUTH_KV` | 一次性 state（防 CSRF），读取即删除 |
| KV 命名空间 | `<worker>-RATE_LIMIT_KV` | 分布式限流计数器（可不绑定；不绑定则退化为不限流） |
| Secrets ×4 | 见上文 | 加密存储，控制台不可回读明文 |
| Workers Builds 项目 | 与仓库关联 | CI/CD：推送到 `main` 自动重新部署 |
| 域名 | `<worker>.<子域>.workers.dev` | 即开即用，无需买域名 |

全部使用免费计划即可运行。

---

## 8. 部署之后怎么改东西

### 8.1 改配置 / 白名单 / 时间参数（最常见）

Cloudflare 控制台 → 你的 Worker → **Settings → Variables and Secrets** → 修改 → 保存。
**即时生效，无需重新部署。**

### 8.2 改密钥

同一页面，类型选 **Secret** 修改。

> ⚠️ 更换 `COOKIE_SECRET` 会让所有**进行中的**登录会话立即失效（用户需重新登录），已完成的登录不受影响。
> 更换 `CALLBACK_SIGNING_SECRET` 时必须**同时**更新业务服务器上的同名变量，否则回传验签会全部失败。

### 8.3 改代码

一键部署时 Cloudflare 已把仓库克隆到你自己的 GitHub 账号下。改代码有两种纯网页方式：

1. **GitHub 网页直接编辑**：打开你账号下的仓库 → 进入文件 → 点铅笔图标 → 编辑 → Commit changes
2. 推送到 `main` 分支后，**Workers Builds 会自动重新构建并部署**，也能在 Cloudflare 控制台的
   Worker → **Deployments** 里看到构建记录与回滚入口

改完建议先在本地跑 `npm test`（有命令行环境时），或直接看部署日志确认构建通过。

### 8.4 回滚

Cloudflare 控制台 → 你的 Worker → **Deployments** → 选择历史版本 → **Rollback**。
纯网页操作，无需重新构建。

### 8.5 下线 / 删除

Cloudflare 控制台 → 你的 Worker → **Settings → Delete**。
如有需要，再到 **Storage & Databases → KV** 删除对应命名空间。
你 GitHub 账号下克隆出来的仓库是独立的，需要的话可另行删除。

---

## 9. 绑定自定义域名

`*.workers.dev` 域名在国内访问质量不稳定，且不利于长期维护。建议绑定自己的域名：

1. 先把域名接入 Cloudflare（域名 → **Add a site**，按提示改 NS）
2. Cloudflare 控制台 → Workers & Pages → 你的 Worker → **Settings → Domains & Routes**
3. 点 **Add → Custom Domain**，填 `gh-oauth.example.com`，SSL 证书由 Cloudflare 自动签发
4. 绑定完成后，**三处要同步修改**：
   - 变量 `PUBLIC_BASE_URL` → `https://gh-oauth.example.com`（无末尾斜杠）
   - GitHub OAuth App 的 callback → `https://gh-oauth.example.com/callback`
   - 业务侧调用 `/authorize` 的地址

> ⚠️ **务必为自定义域名开启 Always Use HTTPS**（Cloudflare → 你的域名 → **SSL/TLS → Edge Certificates →
> Always Use HTTPS = On**）。state Cookie 的 `Secure` 标志由 Worker 的 base URL 协议决定：
> `*.workers.dev` 恒为 https，但自定义域名未开启强制跳转时请求可能是 `http://`，会导致 Cookie 丢失
> `Secure`（更弱）甚至被浏览器拒绝。绑定后请核对 `PUBLIC_BASE_URL` 确为 `https://` 开头。

改完重新访问 `/health?deep=1` 确认 `worker_base_url` 已是新域名（`https://`）。

---

## 10. 上线检查清单

**部署与配置**

- [ ] GitHub OAuth App 的 callback URL **精确等于** `https://<PUBLIC_BASE_URL（已显式设置时）或 Worker 实际域名>/callback`
- [ ] 4 个 Secret 都已替换掉模板占位符（`replace_with_…`），且非弱密钥
- [ ] 4 把 Secret 均满足强度下限：`GITHUB_CLIENT_ID` ≥ 10、`GITHUB_CLIENT_SECRET` ≥ 16、`COOKIE_SECRET` ≥ 16、`CALLBACK_SIGNING_SECRET` ≥ 32 字符，且三把随机密钥去重后**字符种类 ≥ 8**
- [ ] `COOKIE_SECRET` 与 `CALLBACK_SIGNING_SECRET` **不相同**（相同会被服务端强制拒绝）
- [ ] `ALLOWED_CALLBACK_URIS` 已填业务回调地址（**留空会导致全部拒绝**）
- [ ] `ALLOWED_CALLBACK_ORIGINS` 已填业务前端域名（**强烈建议必填**：留空 = 不校验来源，任意站点可发起授权；服务端仅告警、不强制）
- [ ] 生产环境 `PUBLIC_BASE_URL` 已显式填成固定的 `https://` 域名
- [ ] `ALLOW_INSECURE_REDIRECTS` = `false`、`ENVIRONMENT` = `production`
- [ ] 若使用 JSON 模式：前端已带 `credentials: 'include'` 且其 origin 在 `ALLOWED_CALLBACK_ORIGINS` 白名单内（`ALLOW_UNBOUND_STATE` 保持默认 `false`）

**验证**

- [ ] 打开 Worker 首页，自检**无黄色告警**
- [ ] `/health?deep=1` 中 `kv_read` / `kv_round_trip` / `github_api` 全部 `ok=true`
- [ ] 完整走通一次真实登录，业务服务器收到并验签成功
- [ ] （推荐）在 Cloudflare 为 `/authorize`、`/callback` 配置 **Rate limiting rules**

---

## 11. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| 部署表单里 Secrets 是 `replace_with_…` | 这是模板占位符，必须替换成真实值。忘了改不会导致部署失败，但 Worker 会返回"待配置"引导页 |
| 打开 Worker 首页显示黄色"待配置"页（HTTP 503） | 正常。这是首次部署的引导页，按页面 4 步走完即可；不是报错 |
| 提示 `server_misconfigured` / 缺少 Secret | 控制台 **Settings → Variables and Secrets** 里补齐缺失项并保存，开发环境会直接列出缺了哪几个 |
| GitHub 报 `redirect_uri_mismatch` | OAuth App 的 callback URL 与 `<PUBLIC_BASE_URL（若已显式设置）或 Worker 的实际域名>/callback` 不一致（协议、域名、末尾斜杠、路径大小写都要对）。注意：`PUBLIC_BASE_URL` 默认为空，此时以请求的 origin 为准；若已显式设置，则以该值为准 |
| `origin_not_allowed` (403) | 发起 `/authorize` 的前端域名不在 `ALLOWED_CALLBACK_ORIGINS` 里 |
| 任意站点都能拉起登录流程 | `ALLOWED_CALLBACK_ORIGINS` 留空 = 不校验来源。虽然 token 不会被窃取（回传地址受 `ALLOWED_CALLBACK_URIS` 约束），但这是 login-CSRF 的前置条件，请填上业务前端域名 |
| `redirect_uri_not_allowed` (400) | `redirect_uri` 不在 `ALLOWED_CALLBACK_URIS` 里，或该类变量留空了 |
| `/authorize` 一律被拒 | 检查 `ALLOWED_CALLBACK_URIS` 是否为空（空 = 拒绝全部，这是刻意设计） |
| `state_expired` (403) | 用户在结果页刷新了页面；`code` 与 `state` 都是一次性的，属正常现象 |
| `state_mismatch` (403) | 用户在另一个浏览器 / 无痕窗口完成了授权，或 `COOKIE_SECRET` 被更换过；若使用 JSON 模式（`?format=json`），常见原因是前端未带 `credentials: 'include'`（详见 [INTEGRATION.md §1 方式 C](./INTEGRATION.md)） |
| `delivery_failed` (502) | 业务服务器拒收回传：检查验签逻辑、幂等判断，以及回调地址是否公网可达 |
| 业务服务器收不到回调 | 回调地址必须公网可达；内网地址请改用反向隧道，或改为前端轮询方案 |
| 改完变量不生效 | 确认点在 **Variables and Secrets** 而不是某个只读页面；保存后刷新 Worker 首页看自检 |
| 想换 Worker 名 / 换个账号部署 | 用同一个按钮重新部署一遍即可，两份部署互不影响 |
| 担心仓库改乱了 | 你账号下的仓库是 Cloudflare 克隆出来的副本，随时可以从原仓库重新克隆一份 |

---

## 附录 A：不用按钮的纯网页部署

如果按钮因权限或网络原因打不开，可以完全手工地用网页完成同样的事：

1. **Fork 仓库**：GitHub 打开仓库 → 右上角 **Fork** → 创建到你自己的账号
2. **创建 KV 命名空间**：Cloudflare 控制台 → **Storage & Databases → KV** → **Create instance**，
   创建两个，名字任意（例如 `ghproxy-OAUTH_KV`、`ghproxy-RATE_LIMIT_KV`）
3. **把 KV id 写进配置**：
   - 复制两个命名空间的 **ID**（32 位十六进制）
   - 在 GitHub 网页打开 `wrangler.toml` → 铅笔编辑 → 把 `REPLACE_WITH_OAUTH_KV_ID`
     与 `REPLACE_WITH_RATE_LIMIT_KV_ID` 换成真实 id → Commit changes
4. **连接 Git 仓库部署**：Cloudflare 控制台 → **Workers & Pages → Create → Workers →
   Import a repository**（或 "Connect to Git"）→ 选择你 Fork 的仓库
   - **Build command**：留空
   - **Deploy command**：`npx wrangler deploy`
5. **添加 Secrets**：部署完成后，Worker → **Settings → Variables and Secrets**，
   按第 3.3 节的 4 个名字逐个添加，类型选 **Secret**
6. **添加白名单变量**：同页面添加 `ALLOWED_CALLBACK_URIS` 等，然后按第 3–6 步继续

> 差异点：这条路径 **不会自动创建 KV**，必须先手工建好并把 id 写进 `wrangler.toml`，
> 否则部署会因找不到命名空间而失败。按钮路径则把这些全部自动化了。

---

## 附录 B：网页部署 vs 命令行部署

| 对比项 | 网页一键部署 | 命令行部署 |
| --- | --- | --- |
| 需要安装工具 | ❌ 不需要 | Node.js 18+ / wrangler |
| 创建 KV | 自动 | 手动 `npm run kv:create` 后填 id |
| 注入 Secrets | 部署表单里填 | `npx wrangler secret put` |
| 修改配置 | 控制台网页 | 改 `wrangler.toml` 后重新部署 |
| 后续更新 | 推送到 `main` 自动部署 | 本地 `npm run deploy` |
| 适用场景 | 快速上线、不熟悉命令行、交由他人操作 | 需要本地调试与自动化流水线 |

两者产出的服务完全相同，可以混用（例如先网页部署，之后再克隆到本地开发）。

命令行部署步骤见 [README → 部署](./README.md#3-部署)。

---

## 附录 C：费用与容量

Cloudflare 免费计划即可跑起来，但有两个必须了解的限制：

1. **KV 写入次数**（关键约束）。Cloudflare 把 KV 的 **write 与 delete 按同一价格、同一免费额度单独计数**
   （免费额度约 1000 个 write-class 操作/天）。一次成功登录（默认绑定了 `RATE_LIMIT_KV`）实际产生：

   | 操作 | 来源 | 次数 |
   | --- | --- | --- |
   | `OAUTH_KV.put` | 签发一次性 state | 1 |
   | `OAUTH_KV.delete` | 回调读取后删除 state | 1 |
   | `RATE_LIMIT_KV.put` | `/authorize` 限流计数 | 1 |
   | `RATE_LIMIT_KV.put` | `/callback` 限流计数 | 1 |

   合计 **3 次写 + 1 次删除 = 4 个 write-class 操作/次登录**。据此，免费额度约合
   **每天 200–250 次登录**（1000 ÷ 4）。
   若**未绑定 `RATE_LIMIT_KV`**（限流退化为不限流），每次登录仅 **1 次写 + 1 次删除 = 2 个
   write-class 操作**，免费额度约合**每天 500 次登录**。

   > 注意：`GET /health?deep=1` 深检查共消耗 **3 个 write-class 操作**：其中 2 个来自 `OAUTH_KV`
   > 的 写-读-删 往返（1 次 put + 1 次 delete，读取不计入 write-class），另 1 个来自深检查自身的
   > 限流计数写入（`RATE_LIMIT_KV.put`，仅在已绑定 `RATE_LIMIT_KV` 且 `RATE_LIMIT_PER_MINUTE > 0`
   > 时发生）。因此它只适合上线首检，**不要放进高频探针**。

2. **Workers 请求数**：每次登录只消耗 2 次请求（`/authorize` + `/callback`），免费额度相当充裕。

具体数字以 Cloudflare 官方定价页为准（额度与计费口径会调整）：
<https://developers.cloudflare.com/workers/platform/pricing/>

**容量评估建议**：以免费额度为准，**默认配置（绑定 `RATE_LIMIT_KV`）按每天 200–250 次登录规划**；
未绑定限流 KV 时约为每天 500 次。当日登录量接近或超过该量级时，请升级付费计划，
或把限流计数器改为不强依赖 KV（但要接受失去兜底限流）。

---

## 相关文档

| 文档 | 内容 |
| --- | --- |
| [README.md](./README.md) | 架构流程、全部配置项、错误码表、安全设计 |
| [INTEGRATION.md](./INTEGRATION.md) | 业务服务器如何对接：发起登录、实现回调、验签规范、示例代码 |
| `examples/` | Express / Flask / 前端 三份可直接拷走的对接示例 |
