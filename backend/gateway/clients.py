import os
import time
import logging
import requests
import redis as _redis_pkg
from concurrent.futures import ThreadPoolExecutor
from flask import request as flask_request
from eth_account import Account
from eth_account.messages import encode_defunct

_log_pool = ThreadPoolExecutor(max_workers=5)

from .config import AI_URL, BLOCKCHAIN_URL, SANDBOX_URL, REQUEST_TIMEOUT

_REDIS_HOST     = os.getenv("REDIS_HOST", "")
_REDIS_PORT     = int(os.getenv("REDIS_PORT", ""))
_REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
try:
    _nonce_rc = _redis_pkg.Redis(host=_REDIS_HOST, port=_REDIS_PORT, password=_REDIS_PASSWORD, decode_responses=True)
    _nonce_rc.ping()
except Exception:
    _nonce_rc = None

logger = logging.getLogger("gateway.clients")

_TRUSTED_PROXIES: set[str] = {
    ip.strip() for ip in os.getenv("TRUSTED_PROXIES", "").split(",") if ip.strip()
}


def get_client_ip() -> str:
    remote = flask_request.remote_addr or "0.0.0.0"
    if remote in _TRUSTED_PROXIES:
        forwarded = flask_request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
        real_ip = flask_request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip
    return remote


def verify_wallet_signature(address: str, signature: str, nonce: str) -> bool:
    try:
        message   = encode_defunct(text=nonce)
        recovered = Account.recover_message(message, signature=signature)
        return recovered.lower() == address.lower()
    except Exception as exc:
        logger.warning(f"Signature verification failed: {exc}")
        return False


def require_session(token: str) -> tuple[bool, str, str]:
    if not token:
        return False, "Authentication required — connect your wallet and sign in", ""
    if _nonce_rc is None:
        return False, "Auth service unavailable", ""
    key = f"session:{token}"
    address = _nonce_rc.get(key)
    if not address:
        return False, "Session expired — please reconnect your wallet", ""
    _nonce_rc.expire(key, 3600)
    return True, "", address


def require_signature(address: str, signature: str) -> tuple[bool, str]:
    if not address or not signature:
        return False, "user_address and signature are required"
    key = f"nonce:{address.lower()}"
    if _nonce_rc is None:
        return False, "Auth service unavailable"
    nonce = _nonce_rc.get(key)
    if not nonce:
        return False, "Nonce expired or not found — call GET /auth/nonce first"
    if not verify_wallet_signature(address, signature, nonce):
        return False, "Invalid signature"
    _nonce_rc.delete(key)
    return True, ""


def ai_detect(user_id: str, action: str, file_size: int = 0) -> dict:
    try:
        payload = {
            "user_id": user_id,
            "action": action,
            "timestamp": time.time(),
            "ip_address": get_client_ip(),
            "file_size": file_size
        }
        resp = requests.post(f"{AI_URL}/detect", json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"AI detection failed (non-blocking): {exc}")
        return {"level": "NORMAL", "ensemble_score": 0.0, "is_anomalous": False}


def ai_scan(user_id: str, action: str, file_size: int,
            file_bytes: bytes, filename: str) -> dict:
    try:
        resp = requests.post(
            f"{AI_URL}/scan",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            data={
                "user_id":    user_id,
                "action":     action,
                "timestamp":  str(time.time()),
                "ip_address": get_client_ip(),
                "file_size":  str(file_size),
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"AI scan failed (non-blocking): {exc}")
        return {"level": "NORMAL", "ensemble_score": 0.0, "is_anomalous": False}


def sandbox_scan(file_bytes: bytes, filename: str) -> dict:
    if not SANDBOX_URL:
        return {"verdict": "SKIPPED", "sandbox_score": 0.0, "behaviors": []}
    try:
        resp = requests.post(
            f"{SANDBOX_URL}/analyze",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"Sandbox scan failed (non-blocking): {exc}")
        return {"verdict": "ERROR", "sandbox_score": 0.0, "behaviors": []}


def blockchain_log(
    file_id: str,
    action: str,
    success: bool,
    anomaly_flag: bool,
    anomaly_level: str = "NORMAL",
    reasons: list[str] | None = None,
    user_address: str = "",
) -> None:
    ip = get_client_ip()
    chain_id = flask_request.headers.get("X-Chain-ID", "11155111")
    payload = {
        "file_id": file_id,
        "action": action,
        "ip_address": ip,
        "success": success,
        "anomaly_flag": anomaly_flag,
        "anomaly_level": anomaly_level,
        "reasons": reasons or [],
        "user_address": user_address,
    }
    def _send():
        try:
            requests.post(
                f"{BLOCKCHAIN_URL}/audit/log",
                json=payload,
                headers={"X-Chain-ID": chain_id},
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as exc:
            logger.warning(f"Blockchain audit log failed: {exc}")
    _log_pool.submit(_send)
