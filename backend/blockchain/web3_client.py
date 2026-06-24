import os
import json
import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import redis as _redis_pkg
from web3 import Web3

logger = logging.getLogger("blockchain.web3_client")

PRIVATE_KEY  = os.getenv("PRIVATE_KEY", "")

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ABI_DIR     = os.path.join(_BACKEND_DIR, "abi")

_CHAIN_CONFIG = {
    "11155111": {
        "name":     "sepolia",
        "rpc":      os.getenv("SEPOLIA_RPC_URL",          ""),
        "address":  os.getenv("SEPOLIA_CONTRACT_ADDRESS",  ""),
    },
    "421614": {
        "name":     "arbitrum-sepolia",
        "rpc":      os.getenv("ARBITRUM_SEPOLIA_RPC_URL",           ""),
        "address":  os.getenv("ARBITRUM_SEPOLIA_CONTRACT_ADDRESS",   ""),
    },
}

_receipt_semaphore = threading.Semaphore(5)
_receipt_pool      = ThreadPoolExecutor(max_workers=10)

_level_log: deque = deque(maxlen=2000)   # in-memory fallback if Redis is down

_AUDIT_KEY    = "audit:level_log"
_AUDIT_MAXLEN = 2000
try:
    _audit_rc = _redis_pkg.Redis(
        host=os.getenv("REDIS_HOST", ""),
        port=int(os.getenv("REDIS_PORT", "6379") or 6379),
        password=os.getenv("REDIS_PASSWORD") or None,
        decode_responses=True,
    )
    _audit_rc.ping()
    logger.info("Audit log: Redis-backed (persistent across restarts)")
except Exception as exc:
    _audit_rc = None
    logger.warning(f"Audit log: Redis unavailable ({exc}) — using in-memory deque (lost on restart)")


def audit_append(entry: dict) -> None:
    if _audit_rc is not None:
        try:
            _audit_rc.lpush(_AUDIT_KEY, json.dumps(entry))
            _audit_rc.ltrim(_AUDIT_KEY, 0, _AUDIT_MAXLEN - 1)
            return
        except Exception as exc:
            logger.warning(f"Audit Redis append failed, using deque: {exc}")
    _level_log.appendleft(entry)


def audit_entries() -> list:
    if _audit_rc is not None:
        try:
            return [json.loads(x) for x in _audit_rc.lrange(_AUDIT_KEY, 0, -1)]
        except Exception as exc:
            logger.warning(f"Audit Redis read failed, using deque: {exc}")
    return list(_level_log)


@dataclass
class _Chain:
    w3:          Web3
    contract:    object
    account:     object
    nonce_lock:  threading.Lock = field(default_factory=threading.Lock)
    local_nonce: int | None     = None


_chains: dict[str, _Chain] = {}


def get_chain(chain_id: str) -> _Chain | None:
    return _chains.get(str(chain_id))


def _load_abi(network_name: str) -> list | None:
    specific = os.path.join(_ABI_DIR, f"SecureDataManagement-{network_name}.json")
    default  = os.path.join(_ABI_DIR, "SecureDataManagement.json")
    path = specific if os.path.exists(specific) else default
    if not os.path.exists(path):
        logger.warning(f"ABI not found for {network_name} at {path}")
        return None
    with open(path, "r") as f:
        data = json.load(f)
    return data.get("abi", data)


def load_contracts() -> None:
    for chain_id, cfg in _CHAIN_CONFIG.items():
        rpc     = cfg["rpc"]
        address = cfg["address"]
        name    = cfg["name"]
        if not rpc or not address:
            logger.info(f"Chain {chain_id} ({name}) skipped — RPC or address not configured")
            continue
        abi = _load_abi(name)
        if not abi:
            continue
        try:
            w3      = Web3(Web3.HTTPProvider(rpc))
            contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
            account  = w3.eth.account.from_key(PRIVATE_KEY) if PRIVATE_KEY else None
            _chains[chain_id] = _Chain(w3=w3, contract=contract, account=account)
            logger.info(f"Chain {chain_id} ({name}) loaded — contract: {address}")
        except Exception as exc:
            logger.error(f"Failed to load chain {chain_id} ({name}): {exc}", exc_info=True)

    if not _chains:
        logger.warning("No chains loaded — all blockchain calls will fail")


def _build_level_log_map() -> dict:
    return {(e["file_id"], e["action"], e["ip_address"]): e for e in audit_entries()}


def _build_and_submit(fn_call, chain: _Chain) -> str:
    if not chain.account:
        raise RuntimeError("No account configured")

    with chain.nonce_lock:
        network_nonce = chain.w3.eth.get_transaction_count(chain.account.address, "pending")
        if chain.local_nonce is None or network_nonce > chain.local_nonce:
            chain.local_nonce = network_nonce

        nonce             = chain.local_nonce
        chain.local_nonce += 1

        try:
            latest   = chain.w3.eth.get_block("latest")
            base_fee = latest.get("baseFeePerGas") or chain.w3.eth.gas_price
            priority = chain.w3.to_wei(2, "gwei")
            max_fee  = base_fee * 2 + priority

            gas_est = fn_call.estimate_gas({"from": chain.account.address})
            tx = fn_call.build_transaction({
                "from":                 chain.account.address,
                "nonce":                nonce,
                "gas":                  int(gas_est * 1.2),
                "maxFeePerGas":         max_fee,
                "maxPriorityFeePerGas": priority,
            })
            signed  = chain.account.sign_transaction(tx)
            raw_tx  = getattr(signed, "raw_transaction", None) or signed.rawTransaction
            tx_hash = chain.w3.eth.send_raw_transaction(raw_tx)
        except Exception:
            chain.local_nonce = None
            raise

    return tx_hash.hex()


def _await_receipt(tx_hash_hex: str, chain: _Chain) -> None:
    with _receipt_semaphore:
        for attempt in range(6):
            try:
                receipt = chain.w3.eth.wait_for_transaction_receipt(tx_hash_hex, timeout=180)
                if receipt.status != 1:
                    logger.error(f"Transaction reverted: {tx_hash_hex}")
                return
            except Exception as exc:
                if "429" in str(exc) and attempt < 5:
                    time.sleep(2 ** attempt)
                    continue
                with chain.nonce_lock:
                    chain.local_nonce = None
                logger.warning(f"Receipt wait failed for {tx_hash_hex}: {exc}")
                return


def send_transaction(fn_call, chain: _Chain) -> str:
    tx_hash_hex = _build_and_submit(fn_call, chain)
    _await_receipt(tx_hash_hex, chain)
    return tx_hash_hex


def send_transaction_nowait(fn_call, chain: _Chain) -> str:
    tx_hash_hex = _build_and_submit(fn_call, chain)
    _receipt_pool.submit(_await_receipt, tx_hash_hex, chain)
    return tx_hash_hex
