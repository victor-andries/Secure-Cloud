from dotenv import load_dotenv
load_dotenv()

import os
import time
import hashlib
import logging
import uuid
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("api_gateway")

app = Flask(__name__)
CORS(app)

STORAGE_URL    = os.getenv("STORAGE_URL",    "")
BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_URL", "")
AI_URL         = os.getenv("AI_URL",         "")
SANDBOX_URL    = os.getenv("SANDBOX_URL",    "")
# Public-facing base URL used in blockchain references for large files.
# Falls back to localhost if not set (fine for local dev/demo).
GATEWAY_PUBLIC_URL = os.getenv("GATEWAY_PUBLIC_URL", "http://localhost:5000")
REQUEST_TIMEOUT = 60

# File extensions that warrant dynamic sandbox execution
_SANDBOX_EXTENSIONS = {"sh", "bash", "zsh", "py", "pl", "jar"}


def get_client_ip() -> str:
    """Extract client IP from request headers."""
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
        request.headers.get("X-Real-IP", "") or
        request.remote_addr or
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
            timeout=90,  # container execution takes time
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"Sandbox scan failed (non-blocking): {exc}")
        return {"verdict": "ERROR", "sandbox_score": 0.0, "behaviors": []}


def blockchain_log(file_id: str, action: str, success: bool, anomaly_flag: bool) -> None:
    """Log access event to blockchain (best-effort)."""
    try:
        payload = {
            "file_id": file_id,
            "action": action,
            "ip_address": get_client_ip(),
            "success": success,
            "anomaly_flag": anomaly_flag
        }
        requests.post(f"{BLOCKCHAIN_URL}/audit/log", json=payload, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        logger.warning(f"Blockchain audit log failed (non-blocking): {exc}")


@app.route("/files/upload", methods=["POST"])
def upload_file() -> tuple:
    """
    Full upload pipeline:
    1. AI pre-check
    2. MinIO encrypted upload
    3. Blockchain registration
    4. Audit log
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        if "password" not in request.form:
            return jsonify({"error": "No password provided"}), 400

        uploaded_file = request.files["file"]
        password = request.form["password"]
        user_address = request.form.get("user_address", "anonymous")
        file_id = request.form.get("file_id", str(uuid.uuid4()))

        file_data = uploaded_file.read()
        uploaded_file.stream.seek(0)
        file_size = len(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()

        logger.info(f"Upload request: file={uploaded_file.filename}, size={file_size}, user={user_address}")

        # Step 1: AI pre-check (Layer 1 content scan + Layer 2 behavioural)
        ai_result = ai_scan(user_address, "upload", file_size,
                            file_data, uploaded_file.filename or "unknown")
        ai_level = ai_result.get("level", "NORMAL")
        ai_score = ai_result.get("ensemble_score", 0.0)

        if ai_level in ("CRITICAL", "HIGH"):
            logger.warning(f"Upload BLOCKED by AI: user={user_address}, level={ai_level}, score={ai_score}")
            blockchain_log(file_id, "upload_blocked", False, True)
            return jsonify({
                "error": "Upload blocked due to anomaly detection",
                "ai_level": ai_level,
                "ai_score": ai_score
            }), 403

        # Step 1b: Sandbox dynamic analysis (executables only)
        fname = uploaded_file.filename or "unknown"
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        is_elf = file_data[:4] == b"\x7fELF"
        needs_sandbox = ext in _SANDBOX_EXTENSIONS or is_elf

        sb_result  = sandbox_scan(file_data, fname) if needs_sandbox else {"verdict": "SKIPPED"}
        sb_verdict = sb_result.get("verdict", "SKIPPED")
        sb_score   = sb_result.get("sandbox_score", 0.0)

        if sb_verdict == "MALICIOUS":
            logger.warning(
                f"Upload BLOCKED by sandbox: user={user_address}, "
                f"behaviors={sb_result.get('behaviors', [])}"
            )
            blockchain_log(file_id, "upload_blocked_sandbox", False, True)
            return jsonify({
                "error": "Upload blocked by sandbox analysis",
                "sandbox_verdict": sb_verdict,
                "sandbox_behaviors": sb_result.get("behaviors", []),
            }), 403

        # Sandbox SUSPICIOUS + AI MEDIUM → escalate to block
        if sb_verdict == "SUSPICIOUS" and ai_level == "MEDIUM":
            logger.warning(
                f"Upload BLOCKED (sandbox SUSPICIOUS + AI MEDIUM): user={user_address}"
            )
            blockchain_log(file_id, "upload_blocked_sandbox", False, True)
            return jsonify({
                "error": "Upload blocked — suspicious executable behaviour combined with anomalous activity",
                "sandbox_verdict": sb_verdict,
                "sandbox_behaviors": sb_result.get("behaviors", []),
                "ai_level": ai_level,
            }), 403

        # Step 2: Upload to MinIO
        form_data = {
            "password": password,
            "file_id": file_id
        }
        uploaded_file.stream.seek(0)
        storage_resp = requests.post(
            f"{STORAGE_URL}/upload",
            files={"file": (uploaded_file.filename, uploaded_file.stream, uploaded_file.content_type)},
            data=form_data,
            timeout=REQUEST_TIMEOUT * 5
        )
        if not storage_resp.ok:
            logger.error(f"Storage upload failed: {storage_resp.text}")
            blockchain_log(file_id, "upload", False, ai_level != "NORMAL")
            return jsonify({"error": "Storage upload failed", "detail": storage_resp.json()}), 500

        storage_data = storage_resp.json()
        logger.info(f"Storage upload complete: {file_id}, chunks: {storage_data.get('num_chunks')}")

        # Step 3: Blockchain registration
        LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
        tx_hash = None
        try:
            if file_size > LARGE_FILE_THRESHOLD:
                # Large file: store a single reference chunk on-chain to save gas.
                # chunkId encodes the real chunk count so downloads can reassemble.
                num_chunks = storage_data.get("num_chunks", 1)
                bc_payload = {
                    "file_id": file_id,
                    "file_hash": file_hash,
                    "file_name": uploaded_file.filename or "unknown",
                    "file_size": file_size,
                    "chunk_ids":       [f"ref:{num_chunks}"],
                    "chunk_hashes":    [file_hash],
                    "chunk_sizes":     [file_size],
                    "chunk_locations": [f"{GATEWAY_PUBLIC_URL}/files/download/{file_id}"],
                }
                logger.info(f"Large file ({file_size} bytes): storing storage reference on-chain ({num_chunks} chunks)")
            else:
                bc_payload = {
                    "file_id": file_id,
                    "file_hash": file_hash,
                    "file_name": uploaded_file.filename or "unknown",
                    "file_size": file_size,
                    "chunk_ids": storage_data.get("chunk_ids", []),
                    "chunk_hashes": storage_data.get("chunk_hashes", []),
                    "chunk_sizes": storage_data.get("chunk_sizes", []),
                    "chunk_locations": storage_data.get("chunk_locations", [])
                }
            bc_resp = requests.post(f"{BLOCKCHAIN_URL}/register", json=bc_payload, timeout=REQUEST_TIMEOUT)
            if bc_resp.ok:
                tx_hash = bc_resp.json().get("tx_hash")
                logger.info(f"Blockchain registered: {file_id}, tx: {tx_hash}")
            else:
                logger.warning(f"Blockchain registration failed: {bc_resp.text}")
        except Exception as exc:
            logger.warning(f"Blockchain registration error (non-blocking): {exc}")

        # Step 4: Audit log
        blockchain_log(file_id, "upload", True, ai_level not in ("NORMAL", "MEDIUM"))

        return jsonify({
            "success": True,
            "file_id": file_id,
            "file_name": uploaded_file.filename,
            "file_size": file_size,
            "file_hash": file_hash,
            "num_chunks": storage_data.get("num_chunks"),
            "tx_hash": tx_hash,
            "ai_score": ai_score,
            "ai_level": ai_level,
            "sandbox_verdict": sb_verdict,
            "sandbox_score": sb_score,
        }), 200

    except Exception as exc:
        logger.error(f"Upload error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/files/download/<file_id>", methods=["POST"])
def download_file(file_id: str) -> tuple:
    """
    Full download pipeline:
    1. Blockchain permission check
    2. AI detection
    3. MinIO download
    4. Audit log
    """
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        password = body.get("password")
        user_address = body.get("user_address", "anonymous")
        if not password:
            return jsonify({"error": "password required"}), 400

        logger.info(f"Download request: file_id={file_id}, user={user_address}")

        # Step 1: Blockchain permission check
        num_chunks = 1
        try:
            check_resp = requests.post(
                f"{BLOCKCHAIN_URL}/access/check",
                json={"file_id": file_id, "user_address": user_address, "required_permission": "READ"},
                timeout=REQUEST_TIMEOUT
            )
            if check_resp.ok:
                access_data = check_resp.json()
                if not access_data.get("has_access", True):
                    blockchain_log(file_id, "download_denied", False, False)
                    return jsonify({"error": "Access denied — insufficient permissions"}), 403

            meta_resp = requests.get(f"{BLOCKCHAIN_URL}/file/{file_id}", timeout=REQUEST_TIMEOUT)
            if meta_resp.ok:
                meta = meta_resp.json()
                chunks = meta.get("chunks", [])
                # Large files store a single reference chunk: chunkId = "ref:{n}"
                if len(chunks) == 1 and chunks[0].get("chunk_id", "").startswith("ref:"):
                    num_chunks = int(chunks[0]["chunk_id"].split(":", 1)[1])
                else:
                    num_chunks = len(chunks) or 1
        except Exception as exc:
            logger.warning(f"Blockchain permission check failed (non-blocking): {exc}")

        # Step 2: AI detection
        ai_result = ai_detect(user_address, "download")
        ai_level = ai_result.get("level", "NORMAL")
        ai_score = ai_result.get("ensemble_score", 0.0)

        if ai_level in ("CRITICAL", "HIGH"):
            blockchain_log(file_id, "download_blocked", False, True)
            return jsonify({
                "error": "Download blocked due to anomaly detection",
                "ai_level": ai_level,
                "ai_score": ai_score
            }), 403

        # Step 3: Download from MinIO
        dl_resp = requests.post(
            f"{STORAGE_URL}/download/{file_id}",
            json={"password": password, "num_chunks": num_chunks},
            timeout=REQUEST_TIMEOUT * 5
        )
        if not dl_resp.ok:
            blockchain_log(file_id, "download", False, ai_level != "NORMAL")
            return jsonify({"error": "Download failed", "detail": dl_resp.json()}), 500

        dl_data = dl_resp.json()

        # Step 4: Audit log
        blockchain_log(file_id, "download", True, ai_level not in ("NORMAL", "MEDIUM"))

        return jsonify({
            "success": True,
            "file_id": file_id,
            "data": dl_data.get("data"),
            "size": dl_data.get("size"),
            "ai_score": ai_score,
            "ai_level": ai_level
        }), 200

    except Exception as exc:
        logger.error(f"Download error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/files/<file_id>", methods=["DELETE"])
def delete_file(file_id: str) -> tuple:
    """Delete all chunks from MinIO and log on blockchain."""
    try:
        user_address = (request.get_json() or {}).get("user_address", "anonymous")
        logger.info(f"Delete request: file_id={file_id}, user={user_address}")

        resp = requests.delete(f"{STORAGE_URL}/delete/{file_id}", timeout=REQUEST_TIMEOUT)
        if not resp.ok:
            return jsonify({"error": "Storage deletion failed"}), resp.status_code

        blockchain_log(file_id, "delete", True, False)
        return jsonify({"success": True, "file_id": file_id}), 200
    except Exception as exc:
        logger.error(f"Delete error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/files/<file_id>/access/grant", methods=["POST"])
def grant_access(file_id: str) -> tuple:
    """Proxy grant access request to blockchain service."""
    try:
        body = request.get_json() or {}
        body["file_id"] = file_id
        resp = requests.post(f"{BLOCKCHAIN_URL}/access/grant", json=body, timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Grant access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/files/<file_id>/access/revoke", methods=["POST"])
def revoke_access(file_id: str) -> tuple:
    """Proxy revoke access request to blockchain service."""
    try:
        body = request.get_json() or {}
        body["file_id"] = file_id
        resp = requests.post(f"{BLOCKCHAIN_URL}/access/revoke", json=body, timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Revoke access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/<file_id>", methods=["GET"])
def get_audit_logs(file_id: str) -> tuple:
    """Proxy audit log request to blockchain service."""
    try:
        params = request.args.to_dict()
        resp = requests.get(f"{BLOCKCHAIN_URL}/audit/logs/{file_id}", params=params, timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Audit logs error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/anomalies", methods=["GET"])
def get_anomalies() -> tuple:
    """Proxy anomaly request to blockchain service."""
    try:
        params = request.args.to_dict()
        resp = requests.get(f"{BLOCKCHAIN_URL}/audit/anomalies", params=params, timeout=REQUEST_TIMEOUT)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        logger.error(f"Anomalies error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    """Ping all 3 services and return their statuses."""
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


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting API gateway on port 5000 (debug={debug})")
    app.run(host="0.0.0.0", port=5000, debug=debug, use_reloader=debug)
