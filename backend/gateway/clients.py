import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from flask import request as flask_request

_log_pool = ThreadPoolExecutor(max_workers=5)

from .config import AI_URL, BLOCKCHAIN_URL, SANDBOX_URL, REQUEST_TIMEOUT

logger = logging.getLogger("gateway.clients")


def get_client_ip() -> str:
    """Extract client IP from request headers."""
    return (
        flask_request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        flask_request.headers.get("X-Real-IP", "") or
        flask_request.remote_addr or
        "0.0.0.0"
    )


def ai_detect(user_id: str, action: str, file_size: int = 0) -> dict:
    """Behavioural-only detection via /detect — used for downloads."""
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
    """Layer 1 + Layer 2 scan via /scan — used for uploads (sends file bytes)."""
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
    """Dynamic sandbox execution via /analyze — used for executable uploads."""
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


def blockchain_log(file_id: str, action: str, success: bool,
                   anomaly_flag: bool, anomaly_level: str = "NORMAL") -> None:
    """Fire-and-forget audit log — does not block the HTTP response."""
    ip = get_client_ip()
    payload = {
        "file_id": file_id,
        "action": action,
        "ip_address": ip,
        "success": success,
        "anomaly_flag": anomaly_flag,
        "anomaly_level": anomaly_level,
    }
    def _send():
        try:
            requests.post(f"{BLOCKCHAIN_URL}/audit/log", json=payload, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            logger.warning(f"Blockchain audit log failed: {exc}")
    _log_pool.submit(_send)
