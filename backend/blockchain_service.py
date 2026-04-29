from dotenv import load_dotenv
load_dotenv()

import os
import json
import logging
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("blockchain_service")

app = Flask(__name__)
CORS(app)

SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL", "")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
ABI_PATH = os.path.join(os.path.dirname(__file__), "abi", "SecureDataManagement.json")

w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))

contract = None
account  = None

_nonce_lock:  threading.Lock = threading.Lock()
_local_nonce: int | None     = None


def load_contract() -> None:
    """Load contract ABI and instantiate contract object."""
    global contract, account
    try:
        if not os.path.exists(ABI_PATH):
            logger.warning(f"ABI file not found at {ABI_PATH}. Contract calls will fail.")
            return
        with open(ABI_PATH, "r") as f:
            abi_data = json.load(f)
        abi = abi_data.get("abi", abi_data)
        if CONTRACT_ADDRESS:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=abi
            )
            logger.info(f"Contract loaded at {CONTRACT_ADDRESS}")
        else:
            logger.warning("CONTRACT_ADDRESS not set — contract calls disabled")
        if PRIVATE_KEY:
            account = w3.eth.account.from_key(PRIVATE_KEY)
            logger.info(f"Account loaded: {account.address}")
        else:
            logger.warning("PRIVATE_KEY not set — write transactions disabled")
    except Exception as exc:
        logger.error(f"Failed to load contract: {exc}", exc_info=True)


def send_transaction(fn_call) -> str:
    """
    Build, sign, and send a transaction. Returns tx hash.
    Uses a threading lock + local nonce counter so concurrent requests
    never read the same nonce from the network, preventing 'nonce too low' errors.
    """
    global _local_nonce

    if not account:
        raise RuntimeError("No account configured")

    with _nonce_lock:
        # Refresh from network if first call or local nonce has fallen behind
        network_nonce = w3.eth.get_transaction_count(account.address, "pending")
        if _local_nonce is None or network_nonce > _local_nonce:
            _local_nonce = network_nonce

        nonce        = _local_nonce
        _local_nonce += 1   # reserve this nonce before releasing the lock

        try:
            gas_estimate = fn_call.estimate_gas({"from": account.address})
            tx = fn_call.build_transaction({
                "from":     account.address,
                "nonce":    nonce,
                "gas":      int(gas_estimate * 1.2),
                "gasPrice": w3.eth.gas_price,
            })
            signed  = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        except Exception:
            _local_nonce = None   # force re-fetch on next call after any error
            raise

    # Wait for receipt outside the lock — mining takes ~12 s and must not
    # block other transactions from being submitted in the meantime.
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1:
        raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
    return tx_hash.hex()


@app.route("/register", methods=["POST"])
def register_file() -> tuple:
    """Register a file on the blockchain."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400

        required = ["file_id", "file_hash", "file_name", "file_size",
                    "chunk_ids", "chunk_hashes", "chunk_sizes", "chunk_locations"]
        for field in required:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        fn_call = contract.functions.registerFile(
            body["file_id"],
            body["file_hash"],
            body["file_name"],
            int(body["file_size"]),
            body["chunk_ids"],
            body["chunk_hashes"],
            [int(s) for s in body["chunk_sizes"]],
            body["chunk_locations"]
        )
        tx_hash = send_transaction(fn_call)
        logger.info(f"File registered: {body['file_id']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash, "file_id": body["file_id"]}), 200

    except Exception as exc:
        logger.error(f"Register error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/file/<file_id>", methods=["GET"])
def get_file(file_id: str) -> tuple:
    """Get file metadata from the blockchain."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        metadata = contract.functions.getFileMetadata(file_id).call()
        chunks = contract.functions.getFileChunks(file_id).call()

        result = {
            "file_id": metadata[0],
            "file_hash": metadata[1],
            "file_name": metadata[2],
            "file_size": metadata[3],
            "owner": metadata[4],
            "timestamp": metadata[5],
            "is_active": metadata[6],
            "chunks": [
                {
                    "chunk_id": c[0],
                    "chunk_hash": c[1],
                    "chunk_size": c[2],
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
    """Grant access permission to a user for a file."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for field in ["file_id", "user_address", "permission"]:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        permission_map = {"NONE": 0, "READ": 1, "WRITE": 2, "FULL": 3}
        perm_value = permission_map.get(str(body["permission"]).upper(), 1)

        fn_call = contract.functions.grantAccess(
            body["file_id"],
            Web3.to_checksum_address(body["user_address"]),
            perm_value
        )
        tx_hash = send_transaction(fn_call)
        logger.info(f"Access granted: {body['file_id']} -> {body['user_address']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Grant access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/access/revoke", methods=["POST"])
def revoke_access() -> tuple:
    """Revoke access permission from a user for a file."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for field in ["file_id", "user_address"]:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        fn_call = contract.functions.revokeAccess(
            body["file_id"],
            Web3.to_checksum_address(body["user_address"])
        )
        tx_hash = send_transaction(fn_call)
        logger.info(f"Access revoked: {body['file_id']} -> {body['user_address']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Revoke access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/access/check", methods=["POST"])
def check_access() -> tuple:
    """Check if a user has the required permission for a file."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for field in ["file_id", "user_address", "required_permission"]:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        permission_map = {"NONE": 0, "READ": 1, "WRITE": 2, "FULL": 3}
        perm_value = permission_map.get(str(body["required_permission"]).upper(), 1)

        has_access = contract.functions.checkPermission(
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
    """Log an access event to the blockchain."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        for field in ["file_id", "action", "ip_address", "success", "anomaly_flag"]:
            if field not in body:
                return jsonify({"error": f"Missing field: {field}"}), 400

        fn_call = contract.functions.logAccess(
            body["file_id"],
            body["action"],
            body["ip_address"],
            bool(body["success"]),
            bool(body["anomaly_flag"])
        )
        tx_hash = send_transaction(fn_call)
        logger.info(f"Access logged: {body['file_id']}, action: {body['action']}, tx: {tx_hash}")
        return jsonify({"success": True, "tx_hash": tx_hash}), 200

    except Exception as exc:
        logger.error(f"Log access error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/logs/<file_id>", methods=["GET"])
def get_audit_logs(file_id: str) -> tuple:
    """Get paginated access logs for a file."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        page = int(request.args.get("page", 0))
        page_size = int(request.args.get("page_size", 20))

        logs_raw = contract.functions.getAccessLogs(file_id, page, page_size).call()
        logs = [
            {
                "user": log[0],
                "file_id": log[1],
                "action": log[2],
                "ip_address": log[3],
                "timestamp": log[4],
                "success": log[5],
                "anomaly_flag": log[6]
            }
            for log in logs_raw
        ]
        return jsonify({"file_id": file_id, "page": page, "page_size": page_size, "logs": logs}), 200

    except Exception as exc:
        logger.error(f"Get audit logs error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/audit/anomalies", methods=["GET"])
def get_anomalies() -> tuple:
    """Get paginated anomaly-flagged access logs."""
    try:
        if not contract:
            return jsonify({"error": "Contract not loaded"}), 503
        page = int(request.args.get("page", 0))
        page_size = int(request.args.get("page_size", 20))

        logs_raw = contract.functions.getAnomalyLogs(page, page_size).call()
        logs = [
            {
                "user": log[0],
                "file_id": log[1],
                "action": log[2],
                "ip_address": log[3],
                "timestamp": log[4],
                "success": log[5],
                "anomaly_flag": log[6]
            }
            for log in logs_raw
        ]
        return jsonify({"page": page, "page_size": page_size, "anomalies": logs}), 200

    except Exception as exc:
        logger.error(f"Get anomalies error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    """Health check — verify blockchain connection."""
    try:
        connected = w3.is_connected()
        block_number = w3.eth.block_number if connected else None
        return jsonify({
            "status": "ok" if connected else "error",
            "service": "blockchain",
            "connected": connected,
            "block_number": block_number,
            "contract_loaded": contract is not None
        }), 200 if connected else 503
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


load_contract()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting blockchain service on port 5002 (debug={debug})")
    app.run(host="0.0.0.0", port=5002, debug=debug, use_reloader=debug)
