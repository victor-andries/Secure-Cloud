import os
import uuid
import logging

import redis as _redis_pkg
from eth_account import Account
from eth_account.messages import encode_defunct
from flask import Blueprint, request, jsonify

logger = logging.getLogger("gateway.routes_auth")
auth_bp = Blueprint("auth", __name__)

_REDIS_URL  = f"redis://{os.getenv('REDIS_HOST', '')}:{os.getenv('REDIS_PORT', '')}"
_NONCE_TTL  = 300   # 5 minutes
_SESSION_TTL = 3600  # 1 hour
_RATE_LIMIT  = 5    # max nonce requests per minute per address

try:
    _rc = _redis_pkg.from_url(_REDIS_URL, decode_responses=True)
    _rc.ping()
except Exception:
    _rc = None
    logger.warning("Redis unavailable — nonce store disabled, all auth will fail")


def _is_rate_limited(address: str) -> bool:
    if _rc is None:
        return False
    key = f"ratelimit:nonce:{address}"
    count = _rc.incr(key)
    if count == 1:
        _rc.expire(key, 60)
    return count > _RATE_LIMIT


def _verify(address: str, signature: str, nonce: str) -> bool:
    try:
        msg = encode_defunct(text=nonce)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == address.lower()
    except Exception as exc:
        logger.warning(f"Signature verification error: {exc}")
        return False


@auth_bp.route("/auth/nonce", methods=["GET"])
def get_nonce() -> tuple:
    """Issue a one-time nonce for wallet signing."""
    address = (request.args.get("address") or "").lower().strip()
    if not address:
        return jsonify({"error": "address required"}), 400
    if _is_rate_limited(address):
        return jsonify({"error": "Too many requests — try again shortly"}), 429
    nonce = f"Sign to authenticate with SecureCloud: {uuid.uuid4()}"
    if _rc:
        _rc.setex(f"nonce:{address}", _NONCE_TTL, nonce)
    return jsonify({"nonce": nonce}), 200


@auth_bp.route("/auth/session", methods=["POST"])
def create_session() -> tuple:
    """Exchange a signed nonce for a 1-hour session token."""
    if _rc is None:
        return jsonify({"error": "Auth service unavailable"}), 503
    body      = request.get_json() or {}
    address   = body.get("user_address", "").lower().strip()
    signature = body.get("signature", "")
    if not address or not signature:
        return jsonify({"error": "user_address and signature required"}), 400
    nonce = _rc.get(f"nonce:{address}")
    if not nonce:
        return jsonify({"error": "Nonce not found or expired — call /auth/nonce first"}), 401
    if not _verify(address, signature, nonce):
        return jsonify({"error": "Invalid signature"}), 401
    _rc.delete(f"nonce:{address}")
    token = str(uuid.uuid4())
    _rc.setex(f"session:{token}", _SESSION_TTL, address)
    return jsonify({"session_token": token, "expires_in": _SESSION_TTL}), 200
