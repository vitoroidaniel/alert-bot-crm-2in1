"""
api.py — CRM API with Telegram Login Widget authentication.

How auth works:
  1. Browser shows Telegram Login Widget (official Telegram button)
  2. User taps it, Telegram redirects back with signed user data
  3. POST /auth  — API verifies the Telegram signature using BOT_TOKEN
                   checks user_id is in ADMINS, issues a session token
  4. All other endpoints require  Authorization: Bearer <token>

Endpoints:
  GET  /health          — no auth
  POST /auth            — Telegram login data → session token
  GET  /cases           — all cases (Bearer token required)
  GET  /cases?status=.. — filtered
  POST /logout          — invalidate token

Security:
  - Telegram signature verified with HMAC-SHA256 using bot token hash
  - auth_date checked — rejects logins older than 5 minutes
  - user_id checked against ADMINS whitelist
  - tokens are random 32-byte hex, stored in memory with expiry
  - CORS locked to ALLOWED_ORIGIN env var
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ── Add parent dir so we can import shifts.py ────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from shifts import ADMINS, SUPER_ADMINS

logger   = logging.getLogger(__name__)
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
API_PORT = int(os.getenv("API_PORT", "8080"))

BOT_TOKEN      = os.getenv("BOT_TOKEN", "")
ALLOWED_ORIGIN = os.getenv("CRM_ORIGIN", "*")   # set to your CRM URL in production

# Session store: token → {user_id, name, expires_at}
_sessions: dict[str, dict] = {}
SESSION_TTL = 8 * 3600  # 8 hours
AUTH_MAX_AGE = 300       # reject Telegram data older than 5 min


# ── Telegram signature verification ──────────────────────────────────────────

def _verify_telegram_auth(data: dict) -> bool:
    """
    Verify data from Telegram Login Widget.
    https://core.telegram.org/widgets/login#checking-authorization
    """
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not set — cannot verify Telegram auth")
        return False

    received_hash = data.pop("hash", None)
    if not received_hash:
        return False

    # Reject stale auth
    auth_date = int(data.get("auth_date", 0))
    if time.time() - auth_date > AUTH_MAX_AGE:
        logger.warning(f"Telegram auth too old: {int(time.time()) - auth_date}s")
        return False

    # Build check string
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))

    # Secret key = SHA256 of bot token (not the token itself)
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    expected = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, received_hash)


def _is_allowed(user_id: int) -> bool:
    return user_id in ADMINS


def _is_super(user_id: int) -> bool:
    return user_id in SUPER_ADMINS


# ── Session helpers ───────────────────────────────────────────────────────────

def _create_session(user_id: int, name: str) -> str:
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user_id":    user_id,
        "name":       name,
        "is_super":   _is_super(user_id),
        "expires_at": time.time() + SESSION_TTL,
    }
    return token


def _get_session(token: str) -> dict | None:
    s = _sessions.get(token)
    if not s:
        return None
    if time.time() > s["expires_at"]:
        del _sessions[token]
        return None
    return s


def _purge_expired():
    now = time.time()
    expired = [t for t, s in _sessions.items() if now > s["expires_at"]]
    for t in expired:
        del _sessions[t]


# ── Data helpers ──────────────────────────────────────────────────────────────

def _load_cases() -> list[dict]:
    f = DATA_DIR / "cases.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return []


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(self, code: int, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(data))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def _auth(self) -> dict | None:
        """Extract and validate Bearer token. Returns session or None."""
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return _get_session(header[7:])

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        if path == "/health":
            self._send(200, {"ok": True})
            return

        if path == "/cases":
            session = self._auth()
            if not session:
                self._send(401, {"error": "unauthorized"})
                return

            _purge_expired()
            cases = _load_cases()

            status_filter = qs.get("status", [None])[0]
            if status_filter:
                cases = [c for c in cases if c.get("status") == status_filter]

            self._send(200, cases)
            return

        self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if path == "/auth":
            data = self._body()
            if not data:
                self._send(400, {"error": "no data"})
                return

            # Make a copy because _verify_telegram_auth pops 'hash'
            data_copy = dict(data)
            if not _verify_telegram_auth(data_copy):
                self._send(401, {"error": "invalid telegram auth"})
                return

            user_id = int(data.get("id", 0))
            if not _is_allowed(user_id):
                self._send(403, {"error": "access denied"})
                return

            name  = data.get("first_name", "") + " " + data.get("last_name", "")
            name  = name.strip() or data.get("username", str(user_id))
            token = _create_session(user_id, name)

            self._send(200, {
                "token":    token,
                "name":     name,
                "is_super": _is_super(user_id),
                "expires":  int(time.time()) + SESSION_TTL,
            })
            return

        if path == "/logout":
            header = self.headers.get("Authorization", "")
            if header.startswith("Bearer "):
                _sessions.pop(header[7:], None)
            self._send(200, {"ok": True})
            return

        self._send(404, {"error": "not found"})


def run():
    logging.basicConfig(level=logging.INFO)
    if not BOT_TOKEN:
        logger.warning("BOT_TOKEN not set — Telegram auth will fail")
    server = HTTPServer(("0.0.0.0", API_PORT), Handler)
    logger.info(f"CRM API on :{API_PORT}  CORS origin: {ALLOWED_ORIGIN}")
    server.serve_forever()


if __name__ == "__main__":
    run()