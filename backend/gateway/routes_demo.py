import os
import logging

import requests
from flask import Blueprint, request, jsonify

from .config import AI_URL, REQUEST_TIMEOUT

logger = logging.getLogger("gateway.routes_demo")
demo_bp = Blueprint("demo", __name__)

DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes")
_PROFILES = ("normal", "night")


@demo_bp.route("/admin/reseed", methods=["POST"])
def reseed() -> tuple:
    if not DEMO_MODE:
        return jsonify({"error": "Not found"}), 404

    body = request.get_json(silent=True) or {}
    profile = body.get("profile", "")
    if profile not in _PROFILES:
        return jsonify({"error": f"profile must be one of {list(_PROFILES)}"}), 400

    payload = {"profile": profile}
    if body.get("user_address"):
        payload["user_address"] = body["user_address"]

    try:
        resp = requests.post(f"{AI_URL}/admin/reseed", json=payload, timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Reseed proxy failed: {exc}")
        return jsonify({"error": "AI service unavailable"}), 503
