/**
 * HTML 页面：根路由说明页、成功落地页、错误页样式由 responses.ts 复用 escapeHtml。
 * 保持零依赖 + 无外部资源，避免引入额外攻击面。
 */

export function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const BASE_STYLE = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; background:#f6f7f9; color:#1f2328; padding:40px 20px;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
         -webkit-font-smoothing:antialiased; }
  .wrap { width:min(880px,100%); margin:0 auto; }
  .card { background:#fff; border:1px solid #d8dee4; border-radius:12px; padding:28px 30px;
          box-shadow:0 6px 22px rgba(27,31,36,.06); }
  h1 { font-size:22px; margin:0 0 6px; letter-spacing:-.01em; }
  h2 { font-size:15px; margin:26px 0 10px; color:#1f2328; }
  p { color:#57606a; line-height:1.65; font-size:14px; margin:0 0 10px; }
  .sub { color:#8b949e; font-size:13px; margin:0 0 4px; }
  code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  code { background:#f6f8fa; border:1px solid #d8dee4; border-radius:6px; padding:2px 6px; font-size:12.5px; }
  pre { background:#f6f8fa; border:1px solid #d8dee4; border-radius:8px; padding:14px;
        overflow:auto; font-size:12.5px; line-height:1.6; margin:0 0 12px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid #eaeef2; vertical-align:top; }
  th { color:#57606a; font-weight:600; background:#f6f8fa; }
  .pill { display:inline-block; font-size:12px; font-weight:600; border-radius:999px;
          padding:3px 10px; border:1px solid #cbd5e1; background:#f1f5f9; color:#334155; }
  .pill.ok { border-color:#abefc6; background:#ecfdf3; color:#067647; }
  .muted { color:#8b949e; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; }
  .tile { border:1px solid #d8dee4; border-radius:10px; padding:14px 16px; background:#fcfcfd; }
  .tile b { display:block; font-size:13px; margin-bottom:6px; }
`;

export interface LandingInfo {
  version: string;
  environment: string;
  baseUrl: string;
  callbackUrl: string;
  successRedirect: string | null;
  errorRedirect: string | null;
  scope: string;
  stateTtlSeconds: number;
  rateLimitPerMinute: number;
  upstreamTimeoutMs: number;
  callbackAllowlistCount: number;
  rateLimitKvBound: boolean;
  kvBound: boolean;
  issues: string[];
}

export function renderLandingPage(info: LandingInfo): string {
  const issueBlock =
    info.issues.length > 0
      ? `<pre>${escapeHtml(info.issues.join('\n'))}</pre>`
      : '<p class="muted">配置自检通过。</p>';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>GitHub OAuth 中转服务</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <span class="pill ok">运行中</span>
    <h1 style="margin-top:12px">GitHub OAuth 中转（Proxy）服务</h1>
    <p class="sub">版本 ${escapeHtml(info.version)} · 环境 ${escapeHtml(info.environment)} · ${escapeHtml(info.baseUrl)}</p>
    <p>本服务部署在 Cloudflare Workers 上，代替国内业务服务器完成与 GitHub 的授权码交换流程，
       屏蔽跨境链路的不稳定性。业务服务器只需把用户重定向到 <code>/authorize</code>，
       并在自己的回调地址上接收带 HMAC 签名的授权结果。</p>

    <h2>端点</h2>
    <table>
      <tr><th style="width:210px">端点</th><th>说明</th></tr>
      <tr><td><code>GET /authorize</code></td><td>发起登录：校验白名单后重定向到 GitHub 授权页；加 <code>?format=json</code> 则返回授权 URL</td></tr>
      <tr><td><code>GET /callback</code></td><td>GitHub 回调：校验一次性 state → 换取 access_token → 拉取用户信息 → 回传业务服务器</td></tr>
      <tr><td><code>GET /health</code></td><td>健康检查，<code>?deep=1</code> 时额外探测 GitHub 可达性</td></tr>
    </table>

    <h2>当前生效配置</h2>
    <div class="grid">
      <div class="tile"><b>回调白名单条数</b>${info.callbackAllowlistCount} 条</div>
      <div class="tile"><b>默认 scope</b><code>${escapeHtml(info.scope)}</code></div>
      <div class="tile"><b>state 有效期</b>${info.stateTtlSeconds} 秒</div>
      <div class="tile"><b>限流阈值</b>${info.rateLimitPerMinute} 次 / IP / 分钟</div>
      <div class="tile"><b>上游超时</b>${info.upstreamTimeoutMs} ms</div>
      <div class="tile"><b>KV 绑定</b>state ${info.kvBound ? '✓' : '✗'} · ratelimit ${info.rateLimitKvBound ? '✓' : '✗'}</div>
    </div>

    <h2>配置自检</h2>
    ${issueBlock}

    <h2>调用示例</h2>
    <pre>GET /authorize?redirect_uri=https://api.example.com/auth/github/callback
              &amp;state=opaque-csrf-token
              &amp;scope=read:user%20user:email
              &amp;success_redirect=https://www.example.com/login/success</pre>
    <p class="muted">完整对接说明见仓库 INTEGRATION.md。所有错误响应均含 <code>error.code</code> 与 <code>request_id</code>，便于对齐日志。</p>
  </div>
</div>
</body>
</html>`;
}

export interface SuccessPageInfo {
  login: string;
  name: string | null;
  avatarUrl: string | null;
  requestId: string;
  state: string | null;
}

export function renderSuccessPage(info: SuccessPageInfo): string {
  const displayName = info.name || info.login;
  const avatar = info.avatarUrl
    ? `<img src="${escapeHtml(info.avatarUrl)}" alt="" width="56" height="56"
         style="border-radius:50%;border:1px solid #d8dee4">`
    : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>授权成功</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <span class="pill ok">授权成功</span>
    <h1 style="margin-top:12px">已获取 GitHub 授权</h1>
    <p>授权结果已通过带签名的服务端请求回传给你的业务服务器。此页面不包含 access_token，
       请等待业务服务器完成会话建立（或已跳转到 <code>success_redirect</code>）。</p>
    <div style="display:flex;gap:14px;align-items:center;margin:18px 0 6px">
      ${avatar}
      <div>
        <div style="font-size:16px;font-weight:600">${escapeHtml(displayName)}</div>
        <div class="muted">@${escapeHtml(info.login)}</div>
      </div>
    </div>
    <div class="muted">request_id: <code>${escapeHtml(info.requestId)}</code>${info.state ? ` · state: <code>${escapeHtml(info.state)}</code>` : ''}</div>
  </div>
</div>
</body>
</html>`;
}
