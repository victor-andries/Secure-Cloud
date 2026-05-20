import logging
import requests

from flask import Blueprint, request, jsonify
from .config import BLOCKCHAIN_URL, REQUEST_TIMEOUT
from .clients import require_session

logger = logging.getLogger("gateway.routes_access")
access_bp = Blueprint("access", __name__)


@access_bp.route("/files/<file_id>/access/grant", methods=["POST"])
def grant_access(file_id: str) -> tuple:
    """Proxy grant access request to blockchain service."""
    try:
        ok, err, _ = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        body = request.get_json() or {}
        body["file_id"] = file_id
        chain_id = request.headers.get("X-Chain-ID", "11155111")
        resp = requests.post(
            f"{BLOCKCHAIN_URL}/access/grant",
            json=body,
            headers={"X-Chain-ID": chain_id},
            timeout=REQUEST_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Grant access error: {exc}", exc_info=True)
        return jsonify({"error": "Operation failed"}), 500


@access_bp.route("/files/<file_id>/access/revoke", methods=["POST"])
def revoke_access(file_id: str) -> tuple:
    """Proxy revoke access request to blockchain service."""
    try:
        ok, err, _ = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        body = request.get_json() or {}
        body["file_id"] = file_id
        chain_id = request.headers.get("X-Chain-ID", "11155111")
        resp = requests.post(
            f"{BLOCKCHAIN_URL}/access/revoke",
            json=body,
            headers={"X-Chain-ID": chain_id},
            timeout=REQUEST_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Revoke access error: {exc}", exc_info=True)
        return jsonify({"error": "Operation failed"}), 500
