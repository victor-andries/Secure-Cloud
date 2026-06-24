import hashlib
import logging
import os
import time
import uuid
import requests

from flask import Blueprint, request, jsonify
from .config import (
    STORAGE_URL, BLOCKCHAIN_URL, AI_URL, SANDBOX_URL,
    GATEWAY_PUBLIC_URL, REQUEST_TIMEOUT, _SANDBOX_EXTENSIONS,
)
from .clients import ai_detect, ai_scan, sandbox_scan, blockchain_log, require_session

logger = logging.getLogger("gateway.routes_files")
files_bp = Blueprint("files", __name__)

_THREAT_LABELS = {
    "EICAR_TEST":                    "EICAR antivirus test file",
    "MALWARE":                       "malware signatures in file content",
    "MALICIOUS_CODE":                "malicious code patterns",
    "SUSPICIOUS_SCRIPT":             "suspicious script patterns",
    "ELF_INFECTOR":                  "ELF infector indicators",
    "PACKED_PE":                     "packed/obfuscated PE executable",
    "MALICIOUS_PE_IMPORTS":          "dangerous Windows API imports",
    "MACHO_EXECUTABLE":              "Mach-O executable",
    "MACHO_DYLIB_HIJACKING":         "Mach-O dylib hijacking",
    "MACHO_SUSPICIOUS":              "suspicious Mach-O binary",
    "ARCHIVE_CONTAINS_EXECUTABLES":  "executables hidden inside archive",
    "MALWARE_IN_ARCHIVE":            "malware patterns inside archive",
    "MALICIOUS_CODE_IN_ARCHIVE":     "malicious code inside archive",
    "SUSPICIOUS_SCRIPT_IN_ARCHIVE":  "suspicious script inside archive",
}


def _ai_block_reasons(ai_result: dict, ai_level: str) -> list:
    rs = ai_result.get("reasons") or []
    if rs:
        return rs
    tt = (ai_result.get("layer1") or {}).get("threat_type")
    if tt:
        return [f"Static analysis: {_THREAT_LABELS.get(tt, tt)}"]
    return [f"AI threat detection ({ai_level})"]


def _is_behavioural_block(ai_result: dict) -> bool:
    if (ai_result.get("layer1") or {}).get("threat_type"):
        return False
    reasons = ai_result.get("reasons") or []
    return bool(reasons) and all(
        r.startswith(("ECOD", "Behavioural", "Behavioral")) for r in reasons
    )


def _ai_block_message(ai_result: dict, verb: str, behavioural: bool | None = None) -> str:
    if behavioural is None:
        behavioural = _is_behavioural_block(ai_result)
    if behavioural:
        return f"{verb} blocked — anomalous account activity detected"
    return f"{verb} blocked — security threat detected in file"


@files_bp.route("/files/upload", methods=["POST"])
def upload_file() -> tuple:
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        if "password" not in request.form:
            return jsonify({"error": "No password provided"}), 400

        uploaded_file = request.files["file"]
        password = request.form["password"]
        ok, err, user_address = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        file_id = request.form.get("file_id", str(uuid.uuid4()))

        _MAX_UPLOAD = int(os.environ["MAX_UPLOAD_FILE_BYTES"])
        file_data = uploaded_file.read()
        if len(file_data) > _MAX_UPLOAD:
            return jsonify({"error": f"File exceeds maximum upload size of {_MAX_UPLOAD // (1024*1024)} MB"}), 413
        uploaded_file.stream.seek(0)
        file_size = len(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()

        logger.info(f"Upload request: file={uploaded_file.filename}, size={file_size}, user={user_address}")

        _t_pipeline = time.time()
        _t_ai = time.time()
        ai_result = ai_scan(user_address, "upload", file_size,
                            file_data, uploaded_file.filename or "unknown")
        ai_ms = (time.time() - _t_ai) * 1000
        ai_level = ai_result.get("level", "NORMAL")
        ai_score = ai_result.get("ensemble_score", 0.0)

        if ai_level == "CRITICAL":
            reasons = _ai_block_reasons(ai_result, ai_level)
            logger.warning(f"Upload BLOCKED by AI (CRITICAL): user={user_address}, score={ai_score}")
            blockchain_log(file_id, "upload_blocked", False, True, ai_level, reasons=reasons, user_address=user_address)
            return jsonify({
                "error": _ai_block_message(ai_result, "Upload"),
                "ai_level": ai_level,
                "ai_score": ai_score,
                "reasons": reasons,
            }), 403

        fname = uploaded_file.filename or "unknown"
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        is_elf = file_data[:4] == b"\x7fELF"
        needs_sandbox = ext in _SANDBOX_EXTENSIONS or is_elf or ext == "com"

        sb_result  = sandbox_scan(file_data, fname) if needs_sandbox else {"verdict": "SKIPPED"}
        sb_verdict = sb_result.get("verdict", "SKIPPED")
        sb_score   = sb_result.get("sandbox_score", 0.0)

        if sb_verdict == "MALICIOUS":
            logger.warning(
                f"Upload BLOCKED by sandbox: user={user_address}, "
                f"behaviors={sb_result.get('behaviors', [])}"
            )
            blockchain_log(file_id, "upload_blocked_sandbox", False, True, ai_level, reasons=[f"Sandbox: {b}" for b in sb_result.get("behaviors", [])] or [f"Sandbox: {sb_result.get('verdict', 'flagged')} executable behaviour"], user_address=user_address)
            return jsonify({
                "error": "Upload blocked by sandbox analysis",
                "sandbox_verdict": sb_verdict,
                "sandbox_behaviors": sb_result.get("behaviors", []),
            }), 403

        if sb_verdict == "SUSPICIOUS":
            logger.warning(
                f"Upload BLOCKED by sandbox (SUSPICIOUS): user={user_address}, "
                f"behaviors={sb_result.get('behaviors', [])}"
            )
            blockchain_log(file_id, "upload_blocked_sandbox", False, True, ai_level, reasons=[f"Sandbox: {b}" for b in sb_result.get("behaviors", [])] or [f"Sandbox: {sb_result.get('verdict', 'flagged')} executable behaviour"], user_address=user_address)
            return jsonify({
                "error": "Upload blocked — suspicious executable behaviour detected at runtime",
                "sandbox_verdict": sb_verdict,
                "sandbox_behaviors": sb_result.get("behaviors", []),
            }), 403

        if ai_level == "HIGH":
            reasons = _ai_block_reasons(ai_result, ai_level)
            logger.warning(f"Upload BLOCKED by AI (HIGH): user={user_address}, score={ai_score}")
            blockchain_log(file_id, "upload_blocked", False, True, ai_level, reasons=reasons, user_address=user_address)
            return jsonify({
                "error": _ai_block_message(ai_result, "Upload"),
                "ai_level": ai_level,
                "ai_score": ai_score,
                "reasons": reasons,
            }), 403

        form_data = {"password": password, "file_id": file_id}
        uploaded_file.stream.seek(0)
        _t_storage = time.time()
        storage_resp = requests.post(
            f"{STORAGE_URL}/upload",
            files={"file": (uploaded_file.filename, uploaded_file.stream, uploaded_file.content_type)},
            data=form_data,
            timeout=REQUEST_TIMEOUT * 5
        )
        storage_ms = (time.time() - _t_storage) * 1000
        if not storage_resp.ok:
            logger.error(f"Storage upload failed: {storage_resp.text}")
            blockchain_log(file_id, "upload", False, ai_level != "NORMAL", ai_level, user_address=user_address)
            return jsonify({"error": "Storage upload failed"}), 500

        storage_data = storage_resp.json()
        logger.info(f"Storage upload complete: {file_id}, chunks: {storage_data.get('num_chunks')}")

        chain_id = request.headers.get("X-Chain-ID", "")
        bc_headers = {"X-Chain-ID": chain_id}
        LARGE_FILE_THRESHOLD = 10 * 1024 * 1024
        tx_hash = None
        blockchain_ms = 0.0
        try:
            if file_size > LARGE_FILE_THRESHOLD:
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
            _t_bc = time.time()
            bc_resp = requests.post(f"{BLOCKCHAIN_URL}/register", json=bc_payload, headers=bc_headers, timeout=REQUEST_TIMEOUT)
            blockchain_ms = (time.time() - _t_bc) * 1000
            if bc_resp.ok:
                tx_hash = bc_resp.json().get("tx_hash")
                logger.info(f"Blockchain registered: {file_id}, tx: {tx_hash}")
            else:
                logger.warning(f"Blockchain registration failed: {bc_resp.text}")
        except Exception as exc:
            logger.warning(f"Blockchain registration error (non-blocking): {exc}")

        blockchain_log(file_id, "upload", True, ai_level not in ("NORMAL", "MEDIUM"), ai_level, reasons=ai_result.get("reasons", []), user_address=user_address)

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
            "timings": {
                "ai_scan_ms":    round(ai_ms, 1),
                "storage_ms":    round(storage_ms, 1),
                "blockchain_ms": round(blockchain_ms, 1),
                "total_ms":      round((time.time() - _t_pipeline) * 1000, 1),
            },
        }), 200

    except Exception as exc:
        logger.error(f"Upload error: {exc}", exc_info=True)
        return jsonify({"error": "Upload failed"}), 500


@files_bp.route("/files/download/<file_id>", methods=["POST"])
def download_file(file_id: str) -> tuple:
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        password = body.get("password")
        ok, err, user_address = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        if not password:
            return jsonify({"error": "password required"}), 400

        logger.info(f"Download request: file_id={file_id}, user={user_address}")

        chain_id = request.headers.get("X-Chain-ID", "")
        bc_headers = {"X-Chain-ID": chain_id}
        num_chunks = 1
        _t_pipeline = time.time()
        blockchain_read_ms = 0.0
        _t_bc = time.time()
        try:
            check_resp = requests.post(
                f"{BLOCKCHAIN_URL}/access/check",
                json={"file_id": file_id, "user_address": user_address, "required_permission": "READ"},
                headers=bc_headers,
                timeout=REQUEST_TIMEOUT
            )
            if not check_resp.ok:
                logger.error(f"Blockchain permission check returned {check_resp.status_code}")
                return jsonify({"error": "Service unavailable — cannot verify access"}), 503
            access_data = check_resp.json()
            if not access_data.get("has_access", False):
                blockchain_log(file_id, "download_denied", False, False, user_address=user_address)
                return jsonify({"error": "Access denied — insufficient permissions"}), 403

            meta_resp = requests.get(f"{BLOCKCHAIN_URL}/file/{file_id}", headers=bc_headers, timeout=REQUEST_TIMEOUT)
            if meta_resp.ok:
                meta = meta_resp.json()
                chunks = meta.get("chunks", [])
                if len(chunks) == 1 and chunks[0].get("chunk_id", "").startswith("ref:"):
                    num_chunks = int(chunks[0]["chunk_id"].split(":", 1)[1])
                else:
                    num_chunks = len(chunks) or 1
            blockchain_read_ms = (time.time() - _t_bc) * 1000
        except Exception as exc:
            logger.error(f"Blockchain permission check failed: {exc}", exc_info=True)
            return jsonify({"error": "Service unavailable — cannot verify access"}), 503

        _t_ecod = time.time()
        ai_result = ai_detect(user_address, "download")
        ecod_ms = (time.time() - _t_ecod) * 1000
        ai_level = ai_result.get("level", "NORMAL")
        ai_score = ai_result.get("ensemble_score", 0.0)

        if ai_level in ("CRITICAL", "HIGH"):
            reasons = ai_result.get("reasons") or [f"Behavioural anomaly ({ai_level})"]
            blockchain_log(file_id, "download_blocked", False, True, ai_level, reasons=reasons, user_address=user_address)
            return jsonify({
                # downloads only run behavioural (ECOD) detection — no file content
                "error": _ai_block_message(ai_result, "Download", behavioural=True),
                "ai_level": ai_level,
                "ai_score": ai_score,
                "reasons": reasons,
            }), 403

        _t_storage = time.time()
        dl_resp = requests.post(
            f"{STORAGE_URL}/download/{file_id}",
            json={"password": password, "num_chunks": num_chunks},
            timeout=REQUEST_TIMEOUT * 5
        )
        storage_decrypt_ms = (time.time() - _t_storage) * 1000
        if not dl_resp.ok:
            blockchain_log(file_id, "download", False, ai_level != "NORMAL", ai_level, user_address=user_address)
            logger.error(f"Download failed: {dl_resp.text}")
            return jsonify({"error": "Download failed"}), 500

        dl_data = dl_resp.json()

        blockchain_log(file_id, "download", True, ai_level not in ("NORMAL", "MEDIUM"), ai_level, reasons=ai_result.get("reasons", []), user_address=user_address)

        return jsonify({
            "success": True,
            "file_id": file_id,
            "data": dl_data.get("data"),
            "size": dl_data.get("size"),
            "ai_score": ai_score,
            "ai_level": ai_level,
            "timings": {
                "blockchain_read_ms": round(blockchain_read_ms, 1),
                "ecod_ms":            round(ecod_ms, 1),
                "storage_decrypt_ms": round(storage_decrypt_ms, 1),
                "total_ms":           round((time.time() - _t_pipeline) * 1000, 1),
            },
        }), 200

    except Exception as exc:
        logger.error(f"Download error: {exc}", exc_info=True)
        return jsonify({"error": "Download failed"}), 500


@files_bp.route("/files/<file_id>", methods=["DELETE"])
def delete_file(file_id: str) -> tuple:
    try:
        ok, err, user_address = require_session(request.headers.get("X-Session-Token", ""))
        if not ok:
            return jsonify({"error": f"Unauthorized: {err}"}), 401
        logger.info(f"Delete request: file_id={file_id}, user={user_address}")

        chain_id = request.headers.get("X-Chain-ID", "")
        bc_headers = {"X-Chain-ID": chain_id}
        try:
            check_resp = requests.post(
                f"{BLOCKCHAIN_URL}/access/check",
                json={"file_id": file_id, "user_address": user_address, "required_permission": "FULL"},
                headers=bc_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if not check_resp.ok:
                return jsonify({"error": "Service unavailable — cannot verify ownership"}), 503
            if not check_resp.json().get("has_access", False):
                return jsonify({"error": "Access denied — you do not own this file"}), 403
        except Exception as exc:
            logger.error(f"Blockchain ownership check failed: {exc}", exc_info=True)
            return jsonify({"error": "Service unavailable — cannot verify ownership"}), 503

        resp = requests.delete(f"{STORAGE_URL}/delete/{file_id}", timeout=REQUEST_TIMEOUT)
        if not resp.ok:
            return jsonify({"error": "Storage deletion failed"}), resp.status_code

        blockchain_log(file_id, "delete", True, False, user_address=user_address)
        return jsonify({"success": True, "file_id": file_id}), 200
    except Exception as exc:
        logger.error(f"Delete error: {exc}", exc_info=True)
        return jsonify({"error": "Delete failed"}), 500
