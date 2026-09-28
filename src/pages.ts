/**
 * HTML 页面：根路由说明页 / 首次部署配置引导页、成功落地页。
 * 样式由 responses.ts 复用 escapeHtml。
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
  .pill.warn { border-color:#fedf89; background:#fffaeb; color:#b54708; }
  .muted { color:#8b949e; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; }
  .tile { border:1px solid #d8dee4; border-radius:10px; padding:14px 16px; background:#fcfcfd; }
  .tile b { display:block; font-size:13px; margin-bottom:6px; }
  .steps { margin:8px 0 0; padding:0; list-style:none; }
  .steps > li { position:relative; padding:0 0 20px 38px; margin-left:12px; border-left:1px solid #eaeef2; }
  .steps > li:last-child { border-left-color:transparent; padding-bottom:0; }
  .steps > li::before { content:attr(data-step); position:absolute; left:-13px; top:-1px;
          width:25px; height:25px; border-radius:50%; background:#1f2328; color:#fff;
          font-size:12px; font-weight:600; display:flex; align-items:center; justify-content:center; }
  .steps > li > b { display:block; font-size:14px; margin-bottom:4px; color:#1f2328; }
  .urlbox { display:flex; gap:8px; align-items:stretch; margin:8px 0 6px; }
  .urlbox code { flex:1; padding:10px 12px; font-size:12.5px; background:#f6f8fa;
                 border:1px solid #d8dee4; border-radius:8px; word-break:break-all;
                 display:flex; align-items:center; }
  .btn { border:1px solid #d0d7de; background:#f6f8fa; color:#1f2328; border-radius:8px;
         padding:0 14px; font-size:13px; font-weight:500; cursor:pointer; white-space:nowrap;
         font-family:inherit; }
  .btn:hover { background:#eef1f4; }
  .warnbox { border:1px solid #fedf89; background:#fffaeb; border-radius:10px;
             padding:14px 16px; margin:0 0 18px; }
  .warnbox > p { margin:0 0 6px; color:#b54708; font-weight:600; }
  .tight { margin:0; padding-left:20px; }
  .tight li { color:#57606a; font-size:13.5px; line-height:1.85; }
  .tight li code { font-size:12px; }
`;

export interface SetupState {
  /** 值仍为空、尚未注入的 Secret 名称 */
  missing: string[];
  /** 值仍是仓库模板占位符的 Secret 名称 */
  placeholders: string[];
  /** 取值非法（类型不是字符串，或仅含空白/不可见字符）的 Secret */
  invalid: Array<{ name: string; type: string; reason: 'not_string' | 'blank' }>;
  /** 是否缺少 OAUTH_KV 绑定 */
  kvMissing: boolean;
  /** 排查建议 */
  hint: string;
}

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
  /** 非 null 表示「刚部署完、尚未配好」，首页渲染为分步引导而非状态面板 */
  setup?: SetupState | null;
}

const COPY_SCRIPT = `<script>
(function () {
  document.addEventListener('click', function (event) {
    var button = event.target && event.target.closest ? event.target.closest('[data-copy]') : null;
    if (!button) return;
    var source = document.getElementById(button.getAttribute('data-copy'));
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent.trim()).then(function () {
      var original = button.textContent;
      button.textContent = '已复制';
      setTimeout(function () { button.textContent = original; }, 1500);
    }).catch(function () { /* 剪贴板不可用时静默忽略，用户可手动选中复制 */ });
  });
})();
</script>`;

function renderCallbackBox(callbackUrl: string): string {
  return `<div class="urlbox">
        <code id="callback-url">${escapeHtml(callbackUrl)}</code>
        <button class="btn" type="button" data-copy="callback-url">复制</button>
      </div>`;
}

/** 首次部署引导：把「还缺什么、去哪填」直接渲染在浏览器里，全程无需命令行 */
function renderSetupSection(info: LandingInfo, setup: SetupState): string {
  const reasons: string[] = [];
  if (setup.missing.length > 0) {
    reasons.push(
      `<li>尚未注入的 Secret：${setup.missing.map((name) => `<code>${escapeHtml(name)}</code>`).join(' ')}</li>`,
    );
  }
  if (setup.placeholders.length > 0) {
    reasons.push(
      `<li>仍在使用模板占位符的 Secret：${setup.placeholders
        .map((name) => `<code>${escapeHtml(name)}</code>`)
        .join(' ')}</li>`,
    );
  }
  // 必须点名：类型非法/纯空白既不算「缺失」也不算「占位符」，
  // 若这里不列出来，用户会看到一个不说明任何问题的「待配置」页而无从下手。
  if (setup.invalid.length > 0) {
    reasons.push(
      `<li>取值非法、会被服务端直接拒绝的 Secret：${setup.invalid
        .map(
          (item) =>
            `<code>${escapeHtml(item.name)}</code>（${
              item.reason === 'blank'
                ? '仅含空白或不可见字符'
                : `类型为 ${escapeHtml(item.type)}，应为字符串`
            }）`,
        )
        .join('、')}</li>`,
    );
  }
  if (setup.kvMissing) reasons.push('<li>缺少 <code>OAUTH_KV</code> 绑定</li>');

  const reasonList =
    reasons.length > 0
      ? reasons.join('')
      : '<li>配置校验未通过，请检查 Cloudflare 控制台里的变量与机密。</li>';

  const secretFields = [
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'COOKIE_SECRET',
    'CALLBACK_SIGNING_SECRET',
  ];

  return `
    <span class="pill warn">待配置</span>
    <h1 style="margin-top:12px">Worker 已部署，还差几步的配置</h1>
    <p class="sub">版本 ${escapeHtml(info.version)} · 环境 ${escapeHtml(info.environment)} · ${escapeHtml(info.baseUrl)}</p>
    <p>下面的步骤<b>全部在浏览器里完成，不需要安装任何命令行工具</b>。配置补齐后刷新本页，
       它会自动变成绿色的运行状态面板。完整图文说明见仓库的 <code>DEPLOY.md</code>。</p>

    <div class="warnbox">
      <p>当前未就绪的原因</p>
      <ul class="tight">${reasonList}</ul>
    </div>

    <ol class="steps">
      <li data-step="1">
        <b>在 GitHub 创建一个 OAuth App</b>
        <p>打开 GitHub → <b>Settings → Developer settings → OAuth Apps → New OAuth App</b>。
           其中 <b>Authorization callback URL</b> 必须精确填成下面这个地址（https、无末尾斜杠）：</p>
        ${renderCallbackBox(info.callbackUrl)}
        <p class="muted">Homepage URL 填你的业务站点首页即可。创建后记下 Client ID，
           并点「Generate a new client secret」生成 Client Secret（只显示一次，请立刻复制）。</p>
      </li>
      <li data-step="2">
        <b>把这 4 个 Secret 写进 Cloudflare</b>
        <p>Cloudflare 控制台 → <b>Workers &amp; Pages</b> → 选中本 Worker →
           <b>Settings → Variables and Secrets</b> → 添加，类型选 <b>Secret</b>（加密存储）：</p>
        <ul class="tight">
          ${secretFields.map((name) => `<li><code>${name}</code></li>`).join('')}
        </ul>
        <p><code>COOKIE_SECRET</code> 与 <code>CALLBACK_SIGNING_SECRET</code> 需要随机串，
           可在任意网页按 F12 打开控制台生成：</p>
        <pre>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=&gt;b.toString(16).padStart(2,'0')).join('')</pre>
        <p class="muted">两者分别至少 16 / 32 字符；<code>CALLBACK_SIGNING_SECRET</code> 还需与业务服务器上的同名变量保持一致。</p>
      </li>
      <li data-step="3">
        <b>配置业务白名单变量</b>
        <p>同一页面继续添加普通变量（类型选 Text）：</p>
        <ul class="tight">
          <li><code>ALLOWED_CALLBACK_URIS</code> —— <b>必填</b>，你的业务后端接收授权结果的地址，
              例如 <code>https://api.example.com/auth/github/callback</code>。留空会拒绝所有 <code>/authorize</code> 请求（fail-closed）。</li>
          <li><code>ALLOWED_CALLBACK_ORIGINS</code> —— <b>必填</b>，你的业务前端域名，例如
              <code>https://www.example.com</code>。<b>留空等于完全不做来源校验</b>：
              任意站点都能把用户送进授权流程（login-CSRF 的前置条件）。</li>
          <li><code>ALLOWED_REDIRECT_ORIGINS</code> —— 仅当你要用 <code>success_redirect</code> / <code>error_redirect</code> 跳转时才需要。</li>
        </ul>
        <p class="muted">多个值用英文逗号分隔。删掉默认值比保留错误值更安全。</p>
        <p class="muted">另需注意：JSON 模式（<code>?format=json</code>）默认同样要求完成 state Cookie 绑定，
           前端调用须带 <code>credentials: 'include'</code>；确需关闭请设 <code>ALLOW_UNBOUND_STATE=true</code>（会削弱 CSRF 防护）。</p>
      </li>
      <li data-step="4">
        <b>回到本页验证</b>
        <p>刷新本页，自检应全部通过；再访问 <code>/health?deep=1</code>，
           确认 <code>kv_round_trip</code> 与 <code>github_api</code> 均为 <code>true</code>，即表示可直连 GitHub。</p>
        <p class="muted">${escapeHtml(setup.hint)}</p>
      </li>
    </ol>
`;
}

export function renderLandingPage(info: LandingInfo): string {
  const setup = info.setup ?? null;

  const body = setup
    ? renderSetupSection(info, setup)
    : `
    <span class="pill ok">运行中</span>
    <h1 style="margin-top:12px">GitHub OAuth 中转（Proxy）服务</h1>
    <p class="sub">版本 ${escapeHtml(info.version)} · 环境 ${escapeHtml(info.environment)} · ${escapeHtml(info.baseUrl)}</p>
    <p>本服务部署在 Cloudflare Workers 上，代替国内业务服务器完成与 GitHub 的授权码交换流程，
       屏蔽跨境链路的不稳定性。业务服务器只需把用户重定向到 <code>/authorize</code>，
       并在自己的回调地址上接收带 HMAC 签名的授权结果。</p>

    <h2>GitHub OAuth App 回调地址</h2>
    ${renderCallbackBox(info.callbackUrl)}
    <p class="muted">把上面这个地址填到 GitHub OAuth App 的 <b>Authorization callback URL</b>：
       必须与它完全一致（含协议、无末尾斜杠），否则 GitHub 会返回 <code>redirect_uri_mismatch</code>。</p>

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
    ${info.issues.length > 0 ? `<pre>${escapeHtml(info.issues.join('\n'))}</pre>` : '<p class="muted">配置自检通过。</p>'}

    <h2>调用示例</h2>
    <pre>GET /authorize?redirect_uri=https://api.example.com/auth/github/callback
              &amp;state=opaque-csrf-token
              &amp;scope=read:user%20user:email
              &amp;success_redirect=https://www.example.com/login/success</pre>
    <p class="muted">所有变量（含白名单与跳转）都可以在 Cloudflare 控制台的
       Settings → Variables and Secrets 里随时修改，改完即时生效、无需重新部署。
       完整的对接说明见仓库 INTEGRATION.md，部署与更新流程见 DEPLOY.md。
       所有错误响应均含 <code>error.code</code> 与 <code>request_id</code>，便于对齐日志。</p>
`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${setup ? '待配置 · GitHub OAuth 中转服务' : 'GitHub OAuth 中转服务'}</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="wrap">
  <div class="card">${body}
  </div>
</div>
${COPY_SCRIPT}
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
