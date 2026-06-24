import time
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3

from . import web3_client
from .web3_client import audit_append, audit_entries, _build_level_log_map, get_chain, send_transaction, send_transaction_nowait

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("blockchain.routes")

app = Flask(__name__)
CORS(app, origins=[])


def _get_chain():
    chain_id = request.headers.get("X-Chain-ID", "11155111")
    chain = get_chain(chain_id)
    return chain, chain_id


def _validated_pagination() -> tuple[int, int]:
    try:
        page      = max(0, int(request.args.get("page", 0)))
        page_size = min(100, max(1, int(request.args.get("page_size", 20))))
    except (ValueError, TypeError):
        page, page_size = 0, 20
    return page, page_size



@app.route("/register", methods=["POST"])
def register_file() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400

        required = ["file_id", "file_hash", "file_name", "file_size",
                    "chunk_ids", "chunk_hashes", "chunk_sizes", "chunk_locations"]
        for f in required:
            if f not in body:
                return jsonify({"error": f"Missing field: {f}"}), 400

        fn_call = chain.contract.functions.registerFile(
            body["file_id"],
            body["file_hash"],
            body["file_name"],
            int(body["file_size"]),
            body["chunk_ids"],
            body["chunk_hashes"],
            [int(s) for s in body["chunk_sizes"]],
            body["chunk_locations"]
        )
        tx_hash = send_transaction(fn_call, chain)
        logger.info(f"File registered: {body['file_id']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash, "file_id": body["file_id"]}), 200

    except Exception as exc:
        logger.error(f"Register error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/file/<file_id>", methods=["GET"])
def get_file(file_id: str) -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        metadata = chain.contract.functions.getFileMetadata(file_id).call()
        chunks = chain.contract.functions.getFileChunks(file_id).call()

        result = {
            "file_id":    metadata[0],
            "file_hash":  metadata[1],
            "file_name":  metadata[2],
            "file_size":  metadata[3],
            "owner":      metadata[4],
            "timestamp":  metadata[5],
            "is_active":  metadata[6],
            "chunks": [
                {
                    "chunk_id":       c[0],
                    "chunk_hash":     c[1],
                    "chunk_size":     c[2],
                    "chunk_location": c[3]
                }
                for c in chunks
            ]
        }
        return jsonify(result), 200

    except Exception as exc:
        logger.error(f"Get file error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/access/grant", methods=["POST"])
def grant_access() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for f in ["file_id", "user_address", "permission"]:
            if f not in body:
                return jsonify({"error": f"Missing field: {f}"}), 400

        permission_map = {"NONE": 0, "READ": 1, "WRITE": 2, "FULL": 3}
        perm_value = permission_map.get(str(body["permission"]).upper(), 1)

        fn_call = chain.contract.functions.grantAccess(
            body["file_id"],
            Web3.to_checksum_address(body["user_address"]),
            perm_value
        )
        tx_hash = send_transaction(fn_call, chain)
        logger.info(f"Access granted: {body['file_id']} -> {body['user_address']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Grant access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/access/revoke", methods=["POST"])
def revoke_access() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for f in ["file_id", "user_address"]:
            if f not in body:
                return jsonify({"error": f"Missing field: {f}"}), 400

        fn_call = chain.contract.functions.revokeAccess(
            body["file_id"],
            Web3.to_checksum_address(body["user_address"])
        )
        tx_hash = send_transaction(fn_call, chain)
        logger.info(f"Access revoked: {body['file_id']} -> {body['user_address']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Revoke access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/access/check", methods=["POST"])
def check_access() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for f in ["file_id", "user_address", "required_permission"]:
            if f not in body:
                return jsonify({"error": f"Missing field: {f}"}), 400

        permission_map = {"NONE": 0, "READ": 1, "WRITE": 2, "FULL": 3}
        perm_value = permission_map.get(str(body["required_permission"]).upper(), 1)

        has_access = chain.contract.functions.checkPermission(
            body["file_id"],
            Web3.to_checksum_address(body["user_address"]),
            perm_value
        ).call()

        return jsonify({"has_access": has_access, "file_id": body["file_id"],
                        "user_address": body["user_address"]}), 200

    except Exception as exc:
        logger.error(f"Check access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/log", methods=["POST"])
def log_access() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for field in ["file_id", "action", "ip_address", "success", "anomaly_flag"]:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        anomaly_level = body.get("anomaly_level", "HIGH" if body["anomaly_flag"] else "NORMAL")
        audit_append({
            "file_id":       body["file_id"],
            "action":        body["action"],
            "ip_address":    body["ip_address"],
            "user":          body.get("user_address", ""),
            "success":       bool(body["success"]),
            "anomaly_flag":  bool(body["anomaly_flag"]),
            "anomaly_level": anomaly_level,
            "reasons":       body.get("reasons", []),
            "logged_at":     int(time.time()),
        })

        fn_call = chain.contract.functions.logAccess(
            body["file_id"],
            body["action"],
            body["ip_address"],
            bool(body["success"]),
            bool(body["anomaly_flag"])
        )
        tx_hash = send_transaction_nowait(fn_call, chain)
        logger.info(
            f"Access logged: {body['file_id']}, action: {body['action']}, "
            f"level: {anomaly_level}, tx: {tx_hash}"
        )
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Log access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/logs/<file_id>", methods=["GET"])
def get_audit_logs(file_id: str) -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        page, page_size = _validated_pagination()

        logs_raw = chain.contract.functions.getAccessLogs(file_id, page, page_size).call()
        logs = [
            {
                "user":         log[0],
                "file_id":      log[1],
                "action":       log[2],
                "ip_address":   log[3],
                "timestamp":    log[4],
                "success":      log[5],
                "anomaly_flag": log[6]
            }
            for log in logs_raw
        ]
        return jsonify({"file_id": file_id, "page": page, "page_size": page_size, "logs": logs}), 200

    except Exception as exc:
        logger.error(f"Get audit logs error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/all", methods=["GET"])
def get_all_logs() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        page, page_size = _validated_pagination()

        PAGE_LIMIT = 200
        MAX_PAGES  = 50
        all_raw    = []
        page_num   = 0
        for _ in range(MAX_PAGES):
            chunk = chain.contract.functions.getAllAccessLogs(page_num, PAGE_LIMIT).call()
            logger.info(f"[audit/all] page={page_num} fetched={len(chunk)}")
            all_raw.extend(chunk)
            if len(chunk) < PAGE_LIMIT:
                break
            page_num += 1
        _audit = audit_entries()
        logger.info(f"[audit/all] total_onchain={len(all_raw)} level_log_size={len(_audit)}")
        all_raw = list(reversed(all_raw))
        pending_logs = []
        if page == 0:
            now = int(time.time())
            onchain_keys = {(log[1], log[2], log[3]) for log in all_raw}
            for entry in _audit:
                age = now - entry.get("logged_at", 0)
                key = (entry["file_id"], entry["action"], entry["ip_address"])
                logger.info(f"[audit/all] _level_log entry: file={entry['file_id'][:8]} action={entry['action']} age={age}s in_onchain={key in onchain_keys}")
                if age > 300:
                    continue
                if key in onchain_keys:
                    continue
                pending_logs.append({
                    "user":          entry.get("user", ""),
                    "file_id":       entry["file_id"],
                    "action":        entry["action"],
                    "ip_address":    entry["ip_address"],
                    "timestamp":     entry["logged_at"],
                    "success":       entry.get("success", True),
                    "anomaly_flag":  entry.get("anomaly_flag", False),
                    "anomaly_level": entry["anomaly_level"],
                    "reasons":       entry.get("reasons", []),
                    "pending":       True,
                })

        start    = page * page_size
        page_raw = all_raw[start : start + page_size]

        ll_map = _build_level_log_map()

        confirmed_logs = []
        for log in page_raw:
            file_id, action, ip_address = log[1], log[2], log[3]
            entry  = ll_map.get((file_id, action, ip_address), {})
            level  = entry.get("anomaly_level") or ("HIGH" if log[6] else "NORMAL")
            confirmed_logs.append({
                "user":          log[0],
                "file_id":       file_id,
                "action":        action,
                "ip_address":    ip_address,
                "timestamp":     log[4],
                "success":       log[5],
                "anomaly_flag":  log[6],
                "anomaly_level": level,
                "reasons":       entry.get("reasons", []),
            })

        logs = pending_logs + confirmed_logs
        has_more = len(page_raw) >= page_size

        uploads   = sum(1 for l in all_raw if l[2].startswith("upload")   and l[5])
        downloads = sum(1 for l in all_raw if l[2].startswith("download") and l[5])
        deletes   = sum(1 for l in all_raw if l[2].startswith("delete"))
        blocked   = sum(1 for l in all_raw if not l[5])
        uploads   += sum(1 for e in pending_logs if e["action"].startswith("upload")   and e["success"])
        downloads += sum(1 for e in pending_logs if e["action"].startswith("download") and e["success"])
        deletes   += sum(1 for e in pending_logs if e["action"].startswith("delete"))
        blocked   += sum(1 for e in pending_logs if not e["success"])

        level_counts = {"NORMAL": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for log in all_raw:
            lvl = ll_map.get((log[1], log[2], log[3]), {}).get("anomaly_level") or ("HIGH" if log[6] else "NORMAL")
            level_counts[lvl] = level_counts.get(lvl, 0) + 1
        for entry in pending_logs:
            lvl = entry.get("anomaly_level", "NORMAL")
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        action_counts: dict = {}
        for log in all_raw:
            action_counts[log[2]] = action_counts.get(log[2], 0) + 1
        for entry in pending_logs:
            action_counts[entry["action"]] = action_counts.get(entry["action"], 0) + 1

        return jsonify({
            "page":        page,
            "page_size":   page_size,
            "total_count": len(all_raw) + len(pending_logs),
            "stats": {
                "uploads":   uploads,
                "downloads": downloads,
                "deletes":   deletes,
                "blocked":   blocked,
            },
            "level_counts":  level_counts,
            "action_counts": action_counts,
            "logs":          logs,
            "has_more":      has_more,
        }), 200

    except Exception as exc:
        logger.error(f"Get all logs error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/anomalies", methods=["GET"])
def get_anomalies() -> tuple:
    try:
        chain, chain_id = _get_chain()
        if not chain:
            return jsonify({"error": f"Chain {chain_id} not configured"}), 503
        page, page_size = _validated_pagination()

        logs_raw = chain.contract.functions.getAnomalyLogs(page, page_size).call()
        ll_map = _build_level_log_map()
        logs = []
        for log in logs_raw:
            file_id, action, ip_address = log[1], log[2], log[3]
            entry = ll_map.get((file_id, action, ip_address), {})
            level = entry.get("anomaly_level") or ("HIGH" if log[6] else "NORMAL")
            logs.append({
                "user":          log[0],
                "file_id":       file_id,
                "action":        action,
                "ip_address":    ip_address,
                "timestamp":     log[4],
                "success":       log[5],
                "anomaly_flag":  log[6],
                "anomaly_level": level,
                "reasons":       entry.get("reasons", []),
            })
        return jsonify({"page": page, "page_size": page_size, "anomalies": logs}), 200

    except Exception as exc:
        logger.error(f"Get anomalies error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    from .web3_client import _chains
    chain_statuses = {}
    overall_ok = False
    for cid, ch in _chains.items():
        try:
            connected    = ch.w3.is_connected()
            block_number = ch.w3.eth.block_number if connected else None
            chain_statuses[cid] = {
                "connected":    connected,
                "block_number": block_number,
            }
            if connected:
                overall_ok = True
        except Exception as exc:
            chain_statuses[cid] = {"connected": False, "error": str(exc)}

    return jsonify({
        "status":  "ok" if overall_ok else "error",
        "service": "blockchain",
        "chains":  chain_statuses,
    }), 200 if overall_ok else 503