import logging
import requests

from flask import Blueprint, request, jsonify
from .config import BLOCKCHAIN_URL, REQUEST_TIMEOUT
from .clients import require_session

logger = logging.getLogger("gateway.routes_audit")
audit_bp = Blueprint("audit", __name__)


def _validated_pagination() -> tuple:
    page      = max(0, int(request.args.get("page", 0)))
    page_size = min(100, max(1, int(request.args.get("page_size", 20))))
    return page, page_size


@audit_bp.route("/audit/<file_id>", methods=["GET"])
def get_audit_logs(file_id: str) -> tuple:
    try:
        ok, err, _ = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        try:
            page, page_size = _validated_pagination()
        except (ValueError, TypeError):
            return jsonify({"error": "page and page_size must be integers"}), 400
        chain_id = request.headers.get("X-Chain-ID", "")
        resp = requests.get(
            f"{BLOCKCHAIN_URL}/audit/logs/{file_id}",
            params={"page": page, "page_size": page_size},
            headers={"X-Chain-ID": chain_id},
            timeout=REQUEST_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Audit logs error: {exc}", exc_info=True)
        return jsonify({"error": "Failed to fetch audit logs"}), 500


@audit_bp.route("/audit/all", methods=["GET"])
def get_all_logs() -> tuple:
    try:
        ok, err, _ = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        try:
            page, page_size = _validated_pagination()
        except (ValueError, TypeError):
            return jsonify({"error": "page and page_size must be integers"}), 400
        chain_id = request.headers.get("X-Chain-ID", "")
        resp = requests.get(
            f"{BLOCKCHAIN_URL}/audit/all",
            params={"page": page, "page_size": page_size},
            headers={"X-Chain-ID": chain_id},
            timeout=REQUEST_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"All logs error: {exc}", exc_info=True)
        return jsonify({"error": "Failed to fetch logs"}), 500


@audit_bp.route("/audit/anomalies", methods=["GET"])
def get_anomalies() -> tuple:
    try:
        ok, err, _ = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        try:
            page, page_size = _validated_pagination()
        except (ValueError, TypeError):
            return jsonify({"error": "page and page_size must be integers"}), 400
        chain_id = request.headers.get("X-Chain-ID", "")
        resp = requests.get(
            f"{BLOCKCHAIN_URL}/audit/anomalies",
            params={"page": page, "page_size": page_size},
            headers={"X-Chain-ID": chain_id},
            timeout=REQUEST_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Anomalies error: {exc}", exc_info=True)
        return jsonify({"error": "Failed to fetch anomalies"}), 500
