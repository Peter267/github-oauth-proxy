"""
业务服务器对接示例：Python + Flask

    pip install flask
    export CALLBACK_SIGNING_SECRET=与 Worker 端一致的密钥
    export SESSION_SECRET=你自己的会话密钥
    python flask-callback.py

接口：
    GET  /login/github            -> 重定向到 OAuth 中转 Worker
    POST /auth/github/callback    -> 接收 Worker 签名回传并建立会话
"""

import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, request, session

PROXY_BASE_URL = os.environ.get("PROXY_BASE_URL", "https://gh-oauth.example.workers.dev")
SIGNING_SECRET = os.environ["CALLBACK_SIGNING_SECRET"].encode("utf-8")
MY_CALLBACK_URI = "https://api.example.com/auth/github/callback"
MAX_SKEW_SECONDS = 300

app = Flask(__name__)

# 不要为会话密钥设置默认值：弱/可预测的 session secret 会导致会话伪造与账号接管。
_session_secret = os.environ.get("SESSION_SECRET", "")
if len(_session_secret) < 32:
    raise RuntimeError("请设置长度 >= 32 的环境变量 SESSION_SECRET（真实随机串）")
app.secret_key = _session_secret

# 幂等表：生产环境请换成 Redis SET NX EX 或数据库唯一索引
_processed_request_ids: set[str] = set()
_seen_at: dict[str, float] = {}


def _mark_processed(request_id: str) -> bool:
    now = time.time()
    for key, ts in list(_seen_at.items()):
        if now - ts > 600:
            _seen_at.pop(key, None)
            _processed_request_ids.discard(key)
    if request_id in _processed_request_ids:
        return False
    _processed_request_ids.add(request_id)
    _seen_at[request_id] = now
    return True


@app.get("/login/github")
def login_github():
    """① 发起登录：生成业务自己的 state，重定向到中转 Worker。"""
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "redirect_uri": MY_CALLBACK_URI,
        "state": state,
        "scope": "read:user user:email",
        "success_redirect": "https://www.example.com/login/success",
        "error_redirect": "https://www.example.com/login/failed",
    }
    return redirect(f"{PROXY_BASE_URL}/authorize?{urlencode(params)}")


@app.post("/auth/github/callback")
def github_callback():
    """② 接收挂载了 HMAC 签名的回传报文。"""
    raw_body: bytes = request.get_data()  # ★ 原始字节，验签必须用它
    timestamp = request.headers.get("X-GH-Proxy-Timestamp", "")
    signature = request.headers.get("X-GH-Proxy-Signature", "")
    if signature.startswith("sha256="):
        signature = signature[len("sha256="):]

    # 2.1 基础校验
    if not timestamp or not signature:
        return jsonify(ok=False, error="missing_signature"), 401
    try:
        skew = abs(time.time() - int(timestamp))
    except ValueError:
        return jsonify(ok=False, error="bad_timestamp"), 401
    if skew > MAX_SKEW_SECONDS:
        return jsonify(ok=False, error="timestamp_expired"), 401

    # 2.2 验签（常量时间比较）
    expected = hmac.new(
        SIGNING_SECRET, timestamp.encode("utf-8") + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify(ok=False, error="invalid_signature"), 401

    # 2.3 幂等
    request_id = request.headers.get("X-GH-Proxy-Request-Id", "")
    if request_id and not _mark_processed(request_id):
        return jsonify(ok=True, deduplicated=True)

    data = request.get_json(silent=True) or {}

    # 2.4 校验业务 state 并作废
    expected_state = session.pop("oauth_state", "")
    if not expected_state or not hmac.compare_digest(expected_state, str(data.get("state") or "")):
        return jsonify(ok=False, error="state_mismatch"), 400

    user = data.get("user") or {}
    token = data.get("token") or {}

    # 2.5 建号 / 登录：以 GitHub 数字 id 为唯一键
    account = upsert_github_user(
        provider_account_id=str(user.get("id")),
        login=user.get("login"),
        name=user.get("name"),
        email=user.get("email"),
        avatar_url=user.get("avatar_url"),
        access_token=token.get("access_token"),  # 长期使用时请加密落库
    )

    session["user_id"] = account["id"]
    return jsonify(ok=True, user_id=account["id"])


def upsert_github_user(**profile) -> dict:
    """示意实现：替换为真实数据库逻辑。"""
    return {"id": f"user_{profile['provider_account_id']}"}


if __name__ == "__main__":
    app.run(port=8080)
