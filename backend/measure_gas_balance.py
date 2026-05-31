import os
import time
import uuid
import requests
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

from web3 import Web3
from eth_account import Account

BLOCKCHAIN_URL  = os.getenv("BLOCKCHAIN_URL", "")
_private_key    = os.getenv("PRIVATE_KEY", "")
OWNER_ADDRESS   = Account.from_key(_private_key).address if _private_key else ""

SEPOLIA_RPC     = os.getenv("SEPOLIA_RPC_URL")
ARBITRUM_RPC    = os.getenv("ARBITRUM_SEPOLIA_RPC_URL")

w3_sep = Web3(Web3.HTTPProvider(SEPOLIA_RPC))
w3_arb = Web3(Web3.HTTPProvider(ARBITRUM_RPC))

N = 5  # uploads + downloads each

CHAINS = {
    "Sepolia": {
        "chain_id": "11155111",
        "w3":       w3_sep,
    },
    "Arbitrum Sepolia": {
        "chain_id": "421614",
        "w3":       w3_arb,
    },
}

def _h(chain_id: str) -> dict:
    return {"X-Chain-ID": chain_id}

def _balance_eth(w3: Web3) -> float:
    return w3.eth.get_balance(OWNER_ADDRESS) / 1e18

def _receipt_fee(w3: Web3, tx_hash: str) -> dict:
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if "effectiveGasPrice" in receipt and receipt["effectiveGasPrice"]:
            gas_price_wei = receipt["effectiveGasPrice"]
        else:
            tx = w3.eth.get_transaction(tx_hash)
            gas_price_wei = tx["gasPrice"]
        gas_used = receipt["gasUsed"]
        fee_eth  = (gas_used * gas_price_wei) / 1e18
        return {
            "gas_used":  gas_used,
            "gwei":      gas_price_wei / 1e9,
            "fee_eth":   fee_eth,
            "status":    receipt["status"],
        }
    except Exception as e:
        return {"error": str(e), "gas_used": 0, "gwei": 0, "fee_eth": 0.0}
    
def do_register(chain_id: str, label: str) -> dict:
    fid      = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    size     = 1024 * 512
    payload  = {
        "file_id":         fid,
        "file_hash":       uuid.uuid4().hex,
        "file_name":       f"test-{fid[:8]}.bin",
        "file_size":       size,
        "chunk_ids":       [chunk_id],
        "chunk_hashes":    [uuid.uuid4().hex],
        "chunk_sizes":     [size],
        "chunk_locations": [f"scp-test/{fid}/chunk_0000"],
    }
    t0   = time.time()
    resp = requests.post(f"{BLOCKCHAIN_URL}/register",
                         headers=_h(chain_id), json=payload, timeout=120)
    lat  = (time.time() - t0) * 1000
    ok   = resp.status_code in (200, 201)
    tx   = resp.json().get("tx_hash", "") if ok else ""
    print(f"    upload {label}: {lat:8.1f} ms  {'✓ ' + tx[:20] + '...' if ok else '✗ ' + resp.text[:60]}")
    return {"ok": ok, "lat_ms": lat, "tx_hash": tx, "file_id": fid}


def do_log(chain_id: str, file_id: str, action: str, label: str) -> dict:
    payload = {
        "file_id":       file_id,
        "action":        action,
        "ip_address":    "127.0.0.1",
        "success":       True,
        "anomaly_flag":  False,
        "anomaly_level": "NORMAL",
        "user_address":  OWNER_ADDRESS,
    }
    t0   = time.time()
    resp = requests.post(f"{BLOCKCHAIN_URL}/audit/log",
                         headers=_h(chain_id), json=payload, timeout=120)
    lat  = (time.time() - t0) * 1000
    ok   = resp.status_code in (200, 201)
    tx   = resp.json().get("tx_hash", "") if ok else ""
    print(f"    {action:<8} {label}: {lat:8.1f} ms  {'✓ ' + tx[:20] + '...' if ok else '✗ ' + resp.text[:60]}")
    return {"ok": ok, "lat_ms": lat, "tx_hash": tx}

def run_chain(chain_name: str, info: dict) -> dict:
    chain_id = info["chain_id"]
    w3       = info["w3"]

    print(f"\n{'='*68}")
    print(f"  {chain_name}  (chain_id={chain_id})")
    print(f"{'='*68}")

    if not w3.is_connected():
        print("  ✗ RPC not reachable — skipping")
        return {}

    bal_before = _balance_eth(w3)
    print(f"\n  Balance BEFORE: {bal_before:.8f} ETH")

    tx_hashes = []
    file_ids  = []
    print(f"\n  --- UPLOADS ({N} files) ---")
    for i in range(N):
        r = do_register(chain_id, f"file-{i+1}")
        if r["ok"]:
            file_ids.append(r["file_id"])
            if r["tx_hash"]:
                tx_hashes.append(("registerFile", f"upload-{i+1}", r["tx_hash"]))
        if r["ok"]:
            l = do_log(chain_id, r["file_id"], "upload", f"file-{i+1}")
            if l["ok"] and l["tx_hash"]:
                tx_hashes.append(("logAccess-upload", f"upload-{i+1}", l["tx_hash"]))
    print(f"\n  --- DOWNLOADS ({N} access logs) ---")
    for i, fid in enumerate(file_ids[:N]):
        l = do_log(chain_id, fid, "download", f"file-{i+1}")
        if l["ok"] and l["tx_hash"]:
            tx_hashes.append(("logAccess-download", f"download-{i+1}", l["tx_hash"]))
    print(f"\n  Waiting 20s for transactions to mine ...")
    time.sleep(20)
    print(f"\n  --- RECEIPT BREAKDOWN ---")
    calc_total_eth = 0.0
    receipt_rows   = []
    for op, label, txhash in tx_hashes:
        g = _receipt_fee(w3, txhash)
        if "error" not in g:
            calc_total_eth += g["fee_eth"]
            status = "✓" if g["status"] == 1 else "✗ REVERTED"
            print(
                f"    {status} {op:<22} {label:<14}"
                f"  gas={g['gas_used']:>7,}"
                f"  {g['gwei']:>7.4f} Gwei"
                f"  {g['fee_eth']:.8f} ETH"
            )
            receipt_rows.append(g)
        else:
            print(f"    ✗ {op:<22} {label:<14}  receipt error: {g['error']}")

    bal_after    = _balance_eth(w3)
    actual_spent = bal_before - bal_after

    print(f"\n  Balance AFTER :  {bal_after:.8f} ETH")
    print(f"  ─────────────────────────────────────────────────")
    print(f"  Actual spent  :  {actual_spent:.8f} ETH  (balance diff)")
    print(f"  Calculated    :  {calc_total_eth:.8f} ETH  (sum of gasUsed × effectiveGasPrice)")
    if calc_total_eth > 0:
        ratio = actual_spent / calc_total_eth
        print(f"  Ratio         :  {ratio:.4f}  (actual / calculated)")

    return {
        "bal_before":    bal_before,
        "bal_after":     bal_after,
        "actual_spent":  actual_spent,
        "calc_total":    calc_total_eth,
        "tx_count":      len(tx_hashes),
        "receipts":      receipt_rows,
    }

def print_summary(results: dict) -> None:
    print(f"\n\n{'='*80}")
    print(f"  FINAL SUMMARY  —  {N} uploads + {N} downloads per chain")
    print(f"{'='*80}")
    print(f"  {'Chain':<22} {'Before (ETH)':>14} {'After (ETH)':>14} {'Actual spent':>14} {'Calculated':>14} {'Ratio':>8}")
    print(f"  {'-'*22} {'-'*14} {'-'*14} {'-'*14} {'-'*14} {'-'*8}")
    for chain_name, r in results.items():
        if not r:
            print(f"  {chain_name:<22}  {'N/A':>14}")
            continue
        ratio = r["actual_spent"] / r["calc_total"] if r["calc_total"] > 0 else 0
        print(
            f"  {chain_name:<22}"
            f"  {r['bal_before']:>14.8f}"
            f"  {r['bal_after']:>14.8f}"
            f"  {r['actual_spent']:>14.8f}"
            f"  {r['calc_total']:>14.8f}"
            f"  {ratio:>8.4f}"
        )

    print(f"\n  Average per transaction:")
    for chain_name, r in results.items():
        if r and r["tx_count"] > 0:
            avg_calc = r["calc_total"] / r["tx_count"]
            avg_act  = r["actual_spent"] / r["tx_count"]
            print(f"    {chain_name:<22}  calc={avg_calc:.8f} ETH/tx   actual={avg_act:.8f} ETH/tx")

    print(f"\n{'='*80}\n")

if __name__ == "__main__":
    print(f"Blockchain URL : {BLOCKCHAIN_URL}")
    print(f"Owner address  : {OWNER_ADDRESS or '(not set)'}")
    print(f"Operations     : {N} uploads + {N} downloads per chain  ({N*3*2} total transactions)")

    results = {}
    for chain_name, info in CHAINS.items():
        results[chain_name] = run_chain(chain_name, info)

    print_summary(results)
