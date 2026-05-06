import os
import json
import logging
import threading
import time
from collections import deque
from web3 import Web3

_receipt_semaphore = threading.Semaphore(5)  # max 5 concurrent Infura receipt polls

logger = logging.getLogger("blockchain.web3_client")

SEPOLIA_RPC_URL  = os.getenv("SEPOLIA_RPC_URL",  "")
PRIVATE_KEY      = os.getenv("PRIVATE_KEY",      "")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ABI_PATH = os.path.join(_BACKEND_DIR, "abi", "SecureDataManagement.json")

w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))

contract = None
account  = None

_nonce_lock:  threading.Lock = threading.Lock()
_local_nonce: int | None     = None

# Off-chain level cache: stores anomaly_level string alongside on-chain boolean flag
_level_log: deque = deque(maxlen=2000)


def _lookup_level(file_id: str, action: str, ip_address: str) -> str | None:
    for entry in _level_log:
        if (entry["file_id"] == file_id
                and entry["action"] == action
                and entry["ip_address"] == ip_address):
            return entry["anomaly_level"]
    return None


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
        network_nonce = w3.eth.get_transaction_count(account.address, "pending")
        if _local_nonce is None or network_nonce > _local_nonce:
            _local_nonce = network_nonce

        nonce        = _local_nonce
        _local_nonce += 1

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
            _local_nonce = None
            raise

    # Wait for receipt outside the lock — mining takes ~12 s and must not
    # block other transactions from being submitted in the meantime.
    # Semaphore caps concurrent Infura polling to avoid 429 rate limits.
    with _receipt_semaphore:
        receipt = None
        for attempt in range(6):
            try:
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                break
            except Exception as exc:
                if "429" in str(exc) and attempt < 5:
                    time.sleep(2 ** attempt)
                    continue
                raise
    if receipt is None or receipt.status != 1:
        raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
    return tx_hash.hex()
