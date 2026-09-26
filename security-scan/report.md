# GitHub OAuth Proxy — Deep Security Scan Report

仿照 Codex Security（`@openai/codex-security`）的扫描工作流执行：
威胁建模 → 发现搜索（deep：多 worker 并行）→ 验证 → 影响与路径分析 → 报告 → 修复 → 复核。

- **Target**: `github_oauth_proxy`（Cloudflare Workers + TypeScript）
- **Mode**: `deep`（repository-wide，delegated workers ×4）
- **Revision**: working tree @ 2026-09-26（仓库尚未初始化 git）
- **Reviewer**: 4 个只读扫描 worker + 主审
- **Coverage**: complete（见 `coverage.json`）
- **结果**: 14 项发现（1 Critical / 3 Medium / 5 Low / 5 Info）；**已修复 6 项**，其余 8 项经评估为设计取舍或需业务侧配合，记录为 defer。

---

## 1. 威胁模型（Threat model）

| 项 | 内容 |
| --- | --- |
| 资产 | GitHub `access_token`、`GITHUB_CLIENT_SECRET`、`COOKIE_SECRET`、`CALLBACK_SIGNING_SECRET`、一次性 `state` |
| 入口点 | `GET /`、`GET /health`、`GET\|POST /authorize`、`GET /callback` |
| 信任边界 | 浏览器 → Worker；Worker → GitHub；Worker → 业务服务器（服务端到服务端，HMAC 签名） |
| 攻击者可控输入 | `redirect_uri`、`success_redirect`、`error_redirect`、`state`、`scope`、`Origin`/`Referer` 头、`code`、`CF-Connecting-IP`/`X-Forwarded-For` |
| 敏感操作 | Worker 用 `client_secret` 换取 token；把含 token 的签名 JSON **POST 到白名单内的 redirect_uri**；302 到 success/error_redirect |
| 安全不变量 | ① 只有白名单内目标能收到 token；② 回调必须绑定一次性 state；③ 日志绝不含 secret/token 原文；④ 错误响应在 production 不回显内部细节 |

**核心攻击路径（source → sink）**：`/authorize?redirect_uri=` → `normalizeUrl` → `isUrlAllowed`（白名单）→ KV state → `/callback` → `deliverToBusinessServer(record.redirect_uri, payload{token.access_token})`。

---

## 2. 发现（Findings）

### F-01 — 白名单通配符跨越 host/path 边界 → OAuth token 外泄 / 开放重定向 ｜ **Critical** ｜ ✅ 已修复

- **根因**：`src/validation.ts` `globToRegExp()` 把 `*` 展开为 `.*`，与 `originPathKey()` 拼接的 `protocol//host/path` 整串匹配。`.*` 可吞掉 `/`，使通配符跨越 host/path 边界。
- **PoC**：白名单 `https://*.example.net/*`（README 官方推荐写法）＋ `redirect_uri=https://attacker.com/a.example.net/x` → 命中 → 受害者完成授权后，含 `access_token` 的签名报文被 POST 到 `attacker.com`。同一根因可经 `success_redirect`/`error_redirect` 形成浏览器开放重定向。
- **验证**：`test/security.test.ts` S-01 修复前失败（实测返回 302 / `isUrlAllowed=true`），修复后通过。
- **修复**：拆分 origin 段与 path 段分别匹配；host 段通配用 `[^/:@]+`（不跨越 `/`），path 段保留 `.*`。既有语义（多子域通配、路径前缀通配）不变。

### F-02 — `CALLBACK_SIGNING_SECRET` 缺少最小长度校验 ｜ **Medium** ｜ ✅ 已修复

- **根因**：`src/config.ts` 只校验了 `GITHUB_CLIENT_SECRET`/`COOKIE_SECRET` 的长度，遗漏签名密钥；与 README/INTEGRATION 承诺不一致。
- **影响**：1 字节密钥被接受 → 离线爆破后伪造回传报文，绕过业务侧验签。
- **修复**：三个密钥统一做最小长度校验（签名密钥 ≥32），并把 README 的 ≥16 更正为 ≥32。

### F-03 — `GET /health?deep=1` 未鉴权、未限流，可资源放大 ｜ **Medium** ｜ ✅ 已修复

- **根因**：`src/handlers/health.ts` 的深检查会 `kv.put` 并外呼 `api.github.com`，但 `/health` 无任何限流。
- **影响**：未鉴权成本型 DoS / 耗尽 GitHub 未鉴权限额。
- **修复**：仅对 `deep=1` 施加限流（浅探针不受影响），超限返回 429 + `Retry-After`。

### F-04 — 回传业务服务器的出站请求跟随重定向 ｜ **Low** ｜ ✅ 已修复

- **根因**：`src/deliver.ts` 两处 `fetch` 未设 `redirect`（默认 `follow`）。
- **影响**：若白名单端点返回 307/308，携带 token/签名的请求会被续发到 `Location`；终点 2xx 还会掩盖该事实。
- **修复**：POST/GET 两处均设 `redirect: 'error'`。

### F-05 — 回调侧未对 `redirect_uri` 二次校验 ｜ **Low** ｜ ✅ 已修复（纵深防御）

- **根因**：`src/handlers/callback.ts` 直接信任 KV 记录中的 `redirect_uri`。
- **修复**：投递前用 `assertCallbackUriAllowed` 再校验一次；格式非法/越白名单即 400，且不发生任何出站请求。

### F-06 — 示例代码内置弱默认会话密钥 `change-me` ｜ **Low** ｜ ✅ 已修复

- **根因**：`examples/express-callback.mjs`、`examples/flask-callback.py` 用 `SESSION_SECRET || 'change-me'`。
- **修复**：改为缺失或 <32 时启动即抛错（fail-fast），避免整合方照抄弱默认值。

### 以下为已评估但 **未修复（defer）** 的发现

| ID | 严重度 | 摘要 | 处置理由 |
| --- | --- | --- | --- |
| F-07 | Medium | `?format=json` 下 `cookie_bound=false`，回调跳过 Cookie 绑定 → 理论 login-CSRF | 属已文档化的设计取舍（JSON 模式 Cookie 跨站不可靠）；修复需业务侧配合引入非 Cookie 绑定，超出本次有界补丁范围。已在报告中标注，建议业务侧自行校验浏览器会话。 |
| F-08 | Low | `clientIp` 兜底信任 `X-Real-IP`/`X-Forwarded-For`，可伪造限流键 | 标准 Cloudflare 边缘必注入不可伪造的 `CF-Connecting-IP`，生产不可达；且代码已声明为「近似限流」。 |
| F-09 | Low | KV `get`-then-`delete` 非原子 + 最终一致，「一次性 state」存在重放窗口 | `code` 本身一次性，重放无现实收益；已在 `state.ts` 注释说明。 |
| F-10 | Low | production 下 JSON 错误分支仍返回 `detail`（含缺失的 secret **名称**，非值） | 与 HTML 分支不对称，但泄露仅为环境变量名，且现有测试固化了该行为（可调试性），改动会变更对外契约。 |
| F-11 | Low | `POST /authorize` 在限流前解析完整 body 且无大小上限 | 受平台请求体上限约束；建议加 `Content-Length` 门限与限流前置。 |
| F-12 | Low | `DELIVERY_METHOD=GET` 把 token + 签名放进 URL query | 非默认（默认 POST）；建议移除该分支或仅在联调启用。 |
| F-13 | Info | `/authorize` 失败路径把未校验的原始 `state` 反射进 `error_redirect`（已 URL 编码） | 由整合方渲染方式决定风险，Proxy 侧已编码。 |
| F-14 | Info | HTML 响应缺少 CSP（已有 XFO/nosniff/Referrer-Policy） | 纵深防御建议，当前无可用注入点。 |

---

## 3. 复核（Fix verification）

| 校验手段 | 结果 |
| --- | --- |
| 回归测试「修复前失败 / 修复后通过」 | ✅ `test/security.test.ts` 9 用例，修复前 7 失败 → 修复后全通过 |
| 原始 PoC 载荷对当前 checkout 直接复核 | ✅ `https://attacker.com/a.example.net/x` 等载荷均已不命中白名单 |
| `tsc --noEmit` | ✅ 通过 |
| 全量测试 | ✅ 5 文件 / 64 用例全通过（原 55 + 新增 9） |

---

## 4. 覆盖范围（Coverage）

已评审：`src/`（16 文件全量）、`test/`、`wrangler.toml`、`.dev.vars.example`、`.gitignore`、`README.md`、`INTEGRATION.md`、`examples/`。
已确认无真实问题的区域：HTML 转义/XSS、提交的真实密钥、CORS 凭证泄露、AES-GCM IV/HKDF、常量时间比较（未使用的可利用性）、token 不回落浏览器、POST 验签规范一致性。详见 `coverage.json`。
