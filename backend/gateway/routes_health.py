import logging
import requests

from flask import Blueprint, jsonify
from .config import STORAGE_URL, BLOCKCHAIN_URL, AI_URL, SANDBOX_URL, REQUEST_TIMEOUT

logger = logging.getLogger("gateway.routes_health")
health_bp = Blueprint("health_gateway", __name__)


@health_bp.route("/health", methods=["GET"])
def health() -> tuple:
    services = {
        "storage":      f"{STORAGE_URL}/health",
        "blockchain":   f"{BLOCKCHAIN_URL}/health",
        "ai_detection": f"{AI_URL}/health",
        "sandbox":      f"{SANDBOX_URL}/health",
    }
    statuses = {}
    overall_ok = True

    for name, url in services.items():
        try:
            resp = requests.get(url, timeout=5)
            data = resp.json()
            statuses[name] = {"status": data.get("status", "ok"), "detail": data}
        except Exception as exc:
            statuses[name] = {"status": "error", "error": str(exc)}
            overall_ok = False

    return jsonify({
        "status": "ok" if overall_ok else "degraded",
        "service": "gateway",
        "services": statuses
    }), 200


@health_bp.route("/storage/stats", methods=["GET"])
def storage_stats() -> tuple:
    try:
        resp = requests.get(f"{STORAGE_URL}/stats", timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Storage stats error: {exc}")
        return jsonify({"error": str(exc)}), 500
