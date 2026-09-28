# 安全审计报告 —— 一键部署适配 + 配置引导页 + 安全修复

**审计对象**：`github-oauth-proxy`（Cloudflare Workers 上的 GitHub OAuth 中转服务）
**基线**：`7ab6192`（一键部署适配完成时的状态）
**方法**：多 Agent 隔离流水线 —— 独立检查 → 独立验证 → 独立修复 → 独立复验，各环节由不同执行体完成，互不采信结论

> 本报告与 `report.md`（对应 commit `440e51a`）相互独立，请勿混用结论。

---

## 1. 范围

本轮改动让服务可以「纯网页一键部署」，因此审计重点放在**新增攻击面**与**部署默认值的安全语义**上：

| 改动 | 提交 |
| --- | --- |
| `wrangler.toml` / `.dev.vars.example` / `package.json` 适配 Deploy to Cloudflare 按钮 | `101cfdd` |
| 首页在配置未就绪时渲染浏览器内配置引导页；新增占位符密钥拒绝 | `6a9b20f` |
| 新增 `DEPLOY.md` 纯网页部署指南 | `7ab6192` |
| 本轮安全修复（详见 §3） | 本提交 |

---

## 2. 流程

```
阶段一  独立检查（3 个互不通气的视角，并行）
        ├─ 输出编码 / XSS / 信息泄露
        ├─ 认证 / CSRF / state / 回传签名 / 新增配置校验
        └─ 部署链路 / 基础设施 / 供应链
              ↓ 提交 11 项待验证发现
阶段二  独立验证（2 个对抗性复核，试图推翻全部结论）
        ├─ 认证与配置类（V-1 ~ V-5）
        └─ 部署与校验类（W-1 ~ W-6）
              ↓ 收敛为「确认为真实缺陷 / 降级为加固 / 证伪」
阶段三  独立修复（按文件分区并行，避免写冲突）
        ├─ 代码 + 测试
        └─ 文档 + 配置描述
阶段四  独立复验（2 个对抗性复核 + 主控独立采样）
        ├─ 尝试继续攻破修复点、寻找修复引入的新问题
        ├─ 回归与文档一致性核验
        └─ 主控用自有实现独立复测关键验收指标
              ↓ 暴露 1 项由修复自身引入的可用性回归 → 二次修复 → 复测
```

**关键机制**：检查者、验证者、修复者、复验者均不重叠；每条结论必须附可执行的复现证据，无法复现的一律降级或撤回。

---

## 3. 确认的缺陷与处置

### 3.1 已修复（代码）

| 编号 | 级别 | 位置 | 问题 | 处置 |
| --- | --- | --- | --- | --- |
| SEC-1 | **P2** | `src/handlers/callback.ts` | 失败跳转回落到**未经校验**的 `config.errorRedirect`，`ALLOWED_REDIRECT_ORIGINS` 契约在失败路径失效 → 开放重定向 + 业务 `state` 外泄给第三方域 | 删除该兜底，跳转地址一律取自「`/authorize` 阶段已校验后写入 KV」的记录 |
| SEC-2 | **P2** | `src/handlers/authorize.ts` | JSON 模式（`?format=json` **或** `Accept: application/json`）整体跳过 state Cookie 绑定，仅靠 KV 一次性 state → **login-CSRF / 账号绑定混淆**（已端到端复现：受害者无 Cookie 回调仍 200 且投递含 `access_token` 的签名报文） | 默认强制绑定；新增 `ALLOW_UNBOUND_STATE`（默认 `false`）作为显式降级通道，开启时首页给出 login-CSRF 告警 |
| SEC-3 | **P2** | `src/handlers/callback.ts` | `record.error_redirect` / `record.success_redirect` **使用前不做二次白名单校验**（与 `redirect_uri` 的处理不对称）→ KV 投毒或 TOCTOU 可造成开放重定向 | 两个地址在使用前统一走 `assertBrowserRedirectAllowed`，不通过则忽略并记 `callback.redirect_ignored` |
| SEC-4 | Low | `src/handlers/callback.ts` | `/callback` 成功页手写响应头，缺失 `X-Content-Type-Options` / `X-Frame-Options` / `Pragma` | 统一接入 `applySecurityHeaders`，并把剩余手写分支（首页、引导页、`/authorize` JSON）一并接入，消除「某分支漏设」整类问题 |
| SEC-5 | Low | `src/handlers/callback.ts` | 成功分支只认 `?format=json`、失败分支同时认 `Accept` → 同一端点口径不一致 | 统一复用 `wantsJson` |
| SEC-6 | Low | `src/index.ts`、`src/responses.ts` | bootstrap 失败分支未传环境上下文，`production` 判定失效 → `/health` 等路由在**生产环境也泄露** `detail`（缺失/弱/占位密钥名与内部 hint） | 改为显式传入最小上下文，HTML 与 JSON 分支均按环境裁掉 `detail`；`/` 与 `/setup` 的引导页保留点名（已文档化的刻意行为） |
| SEC-7 | Low | `src/config.ts` | 占位符/弱密钥检测：marker 召回不足、零宽与全角字符可绕过、非字符串与纯空白值绕过全部校验、`GITHUB_CLIENT_ID` 无长度校验、文档承诺的两密钥互异未强制 | 归一化（剥离不可见码位 + NFKC）后再匹配；补 marker；新增「取值非法」校验层；补长度与字符种类下限；强制两密钥互异 |
| SEC-8 | Low | `src/config.ts` | `toBool` / `toInt` 假定输入为字符串，绑定类型不符时抛 `TypeError` → 全局 500 | 改为对非字符串安全降级 |

### 3.2 由修复自身引入、并在复验中拦截的回归

| 编号 | 级别 | 问题 | 处置 |
| --- | --- | --- | --- |
| REG-1 | **中-高** | 为提升召回而加入的 3 字符 marker（`xxx` / `tbd`）在**真实随机密钥**中碰撞率过高：实测单个 base64url 密钥误拒 **0.2425%**，一次部署填 4 个值即 **≈0.81%（约 1/123）服务直接起不来** —— 比修复前基线（0.030%）放大约 31 倍 | 移除过短 marker；子串清单只保留长度 ≥7 或含 `_`/`-`（不可能出现在 hex/base64url 中）的指纹；短词改为**整词匹配**或**整串相等** |

> 这条是本轮最重要的教训：**「更严格的校验」本身可能成为可用性事故**。因此把「随机密钥零误拒」提升为显式验收指标并固化为回归测试。

### 3.3 验收指标（关键项）

「随机密钥零误拒」—— 由**主控用独立于仓库测试的自有实现**重新采样复核：

| 形态 | 误拒数 |
| --- | --- |
| `COOKIE_SECRET` ← hex(64) | `0 / 200000` |
| `COOKIE_SECRET` ← base64url(43) | `0 / 200000` |
| `CALLBACK_SIGNING_SECRET` ← base64url(43) | `0 / 200000` |
| `GITHUB_CLIENT_SECRET` ← hex(40) | `0 / 200000` |
| `GITHUB_CLIENT_ID` ← `Ov23li…` | `0 / 200000` |
| `GITHUB_CLIENT_ID` ← `Iv1.…` | `0 / 200000` |
| **部署维度**（4 个值同时随机生成） | `0 / 200000` |

---

## 4. 核实后**不成立**的结论（避免后续重复劳动）

| 结论 | 复核裁决 | 依据 |
| --- | --- | --- |
| `PUBLIC_BASE_URL` 置空引发 Host 头注入 → `redirect_uri` 劫持 / token 外泄 | **证伪** | 全量检索 `src/` 未读取 `Host` / `X-Forwarded-Host`；token 去向由 KV 记录中的 `redirect_uri` 决定且经两次 fail-closed 白名单校验；Workers 路由不可伪造 Host |
| 缓存投毒 | 证伪 | 所有安全响应带 `Cache-Control: no-store`，未使用 Cache API |
| 新增的内联复制脚本构成 DOM XSS | 证伪 | `data-copy` / `id` 均为硬编码常量，无 HTML sink，且只 `writeText` 不 `readText` |
| `avatarUrl` / `error_description` / `state` 反射型 XSS | 证伪 | 全部经 `escapeHtml`，「属性上下文」亦已实测无法闭合 |
| `ALLOWED_CALLBACK_ORIGINS` 留空可导致 token 外泄 | 部分证伪 | 真实危害限于 **login-CSRF**；`ALLOWED_CALLBACK_URIS` 是有效补偿控制，token 不外泄 |
| `?format=json` 可绕过配置引导页降级 | 证伪 | 条件限定路径 + `!wantsJson`，JSON 请求始终返回结构化错误 |
| `looksLikePlaceholder` 的 Unicode 归一化缺失构成漏洞 | 降级 | 部署者无法被外部控制 Secret 注入，属检测器健壮性问题 |
| 非字符串 env 值绕过校验 | 降级 | Cloudflare 绑定恒为字符串，生产不可达；仍按健壮性修复 |

---

## 5. 残余风险与范围外事项

1. **`ALLOWED_CALLBACK_ORIGINS` 留空的语义未改为 fail-closed。** 当前仍为「留空 = 不校验来源」，仅在首页给出告警并在文档中标注为强烈建议必填。原因：改为 fail-closed 会破坏「业务后端 302 跳转（浏览器导航可能携带业务的 `Referer`）」这一既有合法流程，属破坏性变更。**残余危害为 login-CSRF，前提是业务侧未校验自身的 `state`** —— 业务侧校验 `state` 本就是既有强制要求（见 `INTEGRATION.md`）。
2. **KV 被投毒的威胁模型**：写 KV 需要 Cloudflare 账号权限。SEC-3 的修复把「即使 KV 被投毒也不放行白名单外跳转」补齐到与 `redirect_uri` 同等强度。
3. **`CALLBACK_SIGNING_SECRET` 与业务侧一致性**：签名校验在业务服务器完成，Worker 侧无法兜底；轮换时须两端同步。
4. **同一作用域下的配置面**：控制台账号被攻陷后可直接修改 `ALLOWED_*` / `ALLOW_UNBOUND_STATE`，代码层无法兜底。
5. **限流为近似限流**：基于 KV，最终一致；生产建议叠加 Cloudflare Rate limiting rules。
6. **`/favicon.ico` 的 204 空响应不含安全头**（无内容，无实际影响），已在 `README.md` §7 显式标注为例外。
7. **未在真实 Workers 运行时（`workerd`）做端到端验证**：本仓库的全部验证基于 Node + vitest 与内存 KV/ fetch 桩。

---

## 6. 验证记录

```bash
# 类型检查
node node_modules/typescript/bin/tsc --noEmit
# → exit 0，零错误

# 全量测试（必须串行：并行模式下本机沙箱写 vitest 临时缓存会报 EPERM 并随机掉文件）
node node_modules/vitest/vitest.mjs run --no-file-parallelism
# → Test Files  8 passed (8)
#   Tests      121 passed (121)

# 配置语法
python -c "import tomllib,json; tomllib.load(open('wrangler.toml','rb')); json.load(open('package.json',encoding='utf-8'))"
# → OK
```

`test/` 覆盖情况：原 6 文件 / 77 用例 → 现 8 文件 / 121 用例。新增 `test/fixes.test.ts`（本轮缺陷的定向回归）、`test/config-hardening.test.ts`（密钥校验的零误拒采样与重复模式检测），并扩充 `test/deploy.test.ts`、`test/security.test.ts`（新增 S-06 跳转地址二次校验）、`test/router.test.ts`（production 不泄露 detail、安全头统一）。

**回归有效性**：每个修复项均在「临时回退该修复」后确认对应用例失败，再恢复，确保测试真的能拦住回归，而非恒真断言。
