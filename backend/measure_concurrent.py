import os
import time
import uuid
import statistics
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

from eth_account import Account

BLOCKCHAIN_URL = os.getenv("BLOCKCHAIN_URL", "")
_private_key   = os.getenv("PRIVATE_KEY", "")
OWNER_ADDRESS  = Account.from_key(_private_key).address if _private_key else ""

CHAINS = {
    "Sepolia":          "11155111",
    "Arbitrum Sepolia": "421614",
}

CONCURRENCY = 10

def _h(chain_id: str) -> dict:
    return {"X-Chain-ID": chain_id}

def _ms(t0: float) -> float:
    return (time.time() - t0) * 1000

def _register(chain_id: str, worker_id: int) -> tuple:
    fid = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    size = 1024 * (worker_id + 1)
    payload = {
        "file_id":         fid,
        "file_hash":       uuid.uuid4().hex,
        "file_name":       f"concurrent-{worker_id}-{fid[:8]}.bin",
        "file_size":       size,
        "chunk_ids":       [chunk_id],
        "chunk_hashes":    [uuid.uuid4().hex],
        "chunk_sizes":     [size],
        "chunk_locations": [f"scp-concurrent/{fid}/chunk_0000"],
    }
    t0 = time.time()
    try:
        resp = requests.post(
            f"{BLOCKCHAIN_URL}/register",
            headers=_h(chain_id),
            json=payload,
            timeout=120,
        )
        lat = _ms(t0)
        ok  = resp.status_code in (200, 201)
        return worker_id, lat, ok, fid if ok else ""
    except Exception as e:
        return worker_id, _ms(t0), False, ""


def _log_access(chain_id: str, file_id: str, worker_id: int) -> tuple:
    if not file_id:
        return worker_id, 0.0, False
    payload = {
        "file_id":      file_id,
        "action":       "upload",
        "ip_address":   "127.0.0.1",
        "success":      True,
        "anomaly_flag": False,
        "anomaly_level": "NORMAL",
        "user_address": OWNER_ADDRESS,
    }
    t0 = time.time()
    try:
        resp = requests.post(
            f"{BLOCKCHAIN_URL}/audit/log",
            headers=_h(chain_id),
            json=payload,
            timeout=120,
        )
        return worker_id, _ms(t0), resp.status_code in (200, 201)
    except Exception as e:
        return worker_id, _ms(t0), False

def run_concurrent(chain_name: str, chain_id: str) -> dict:
    print(f"\n{'='*62}")
    print(f"  {chain_name}  (chain_id={chain_id})  — {CONCURRENCY} concurrent workers")
    print(f"{'='*62}")
    print(f"\n  [registerFile] — firing {CONCURRENCY} requests simultaneously ...")
    file_ids     = {}
    reg_lats     = []
    reg_ok_count = 0

    t_wall_start = time.time()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {pool.submit(_register, chain_id, i): i for i in range(CONCURRENCY)}
        for fut in as_completed(futures):
            wid, lat, ok, fid = fut.result()
            reg_lats.append(lat)
            if ok:
                reg_ok_count += 1
                file_ids[wid] = fid
            status = "✓" if ok else "✗"
            print(f"    worker {wid:>2}: {lat:8.1f} ms  {status}")
    t_wall_reg = _ms(t_wall_start)
    print(f"    → wall time (all {CONCURRENCY} finished): {t_wall_reg:.1f} ms")
    print(f"\n  [logAccess] — firing {CONCURRENCY} requests simultaneously ...")
    log_lats     = []
    log_ok_count = 0

    t_wall_start = time.time()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {
            pool.submit(_log_access, chain_id, file_ids.get(i, ""), i): i
            for i in range(CONCURRENCY)
        }
        for fut in as_completed(futures):
            wid, lat, ok = fut.result()
            if lat > 0:
                log_lats.append(lat)
            if ok:
                log_ok_count += 1
            status = "✓" if ok else "✗"
            if lat > 0:
                print(f"    worker {wid:>2}: {lat:8.1f} ms  {status}")
    t_wall_log = _ms(t_wall_start)
    print(f"    → wall time (all {CONCURRENCY} finished): {t_wall_log:.1f} ms")
    
    def stats(lats: list) -> dict:
        if not lats:
            return dict(mean=None, median=None, stdev=0.0,
                        min=None, max=None, p95=None)
        s = sorted(lats)
        p95_idx = max(0, int(len(s) * 0.95) - 1)
        return {
            "mean":   statistics.mean(lats),
            "median": statistics.median(lats),
            "stdev":  statistics.stdev(lats) if len(lats) > 1 else 0.0,
            "min":    min(lats),
            "max":    max(lats),
            "p95":    s[p95_idx],
        }

    return {
        "registerFile": {**stats(reg_lats), "ok": reg_ok_count, "wall_ms": t_wall_reg},
        "logAccess":    {**stats(log_lats),  "ok": log_ok_count, "wall_ms": t_wall_log},
    }

def print_summary(results: dict) -> None:
    ops     = ["registerFile", "logAccess"]
    metrics = [
        ("mean",    "mean"),
        ("median",  "median"),
        ("stdev",   "stdev"),
        ("min",     "min"),
        ("max",     "max"),
        ("p95",     "p95 (95th %)"),
        ("wall_ms", "wall time"),
    ]
    col_w = 26

    print(f"\n\n{'='*80}")
    print(f"  CONCURRENT LATENCY SUMMARY  ({CONCURRENCY} workers, milliseconds)")
    print(f"{'='*80}")

    header = f"  {'Operation':<20}"
    for cn in results:
        header += f"  {cn:>{col_w}}"
    print(header)
    print(f"  {'-'*20}" + f"  {'-'*col_w}" * len(results))

    for op in ops:
        print(f"\n  {op}")
        for key, label in metrics:
            row = f"    {label:<20}"
            for cn, chain_res in results.items():
                val = chain_res.get(op, {}).get(key)
                if val is None:
                    row += f"  {'N/A':>{col_w}}"
                else:
                    row += f"  {val:>16.1f} ms    "
            print(row)

        row = f"    {'success rate':<20}"
        for cn, chain_res in results.items():
            ok = chain_res.get(op, {}).get("ok", 0)
            row += f"  {f'{ok}/{CONCURRENCY}':>{col_w}}"
        print(row)

    print(f"\n{'='*80}\n")

if __name__ == "__main__":
    print(f"Blockchain URL : {BLOCKCHAIN_URL}")
    print(f"Owner address  : {OWNER_ADDRESS or '(not set)'}")
    print(f"Concurrency    : {CONCURRENCY} simultaneous workers per chain")

    results = {}
    for chain_name, chain_id in CHAINS.items():
        results[chain_name] = run_concurrent(chain_name, chain_id)

    print_summary(results)
