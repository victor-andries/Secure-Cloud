"""
Blockchain latency measurement script for thesis Section 4.3.3.

Run with: python measure_blockchain.py
Requires the full Docker Compose stack to be running.

Write operations (registerFile, grantAccess, logAccess) cost gas on testnet.
The script runs writes only 3 times to keep costs low.
Reads (checkAccess, getAllAccessLogs) are free and run 10 times.
"""

import time
import uuid
import statistics
import requests

BLOCKCHAIN_URL = ""

READ_RUNS  = 10
WRITE_RUNS = 3

# A file registered during this run, used for read tests afterwards
_registered_file_id = None


def measure(label, fn, runs):
    results = []
    errors  = 0
    print(f"\n  Running {label} x{runs}...")
    for i in range(runs):
        t0 = time.perf_counter()
        try:
            resp = fn()
            elapsed = (time.perf_counter() - t0) * 1000
            if resp.status_code < 500:
                results.append(elapsed)
                print(f"    [{i+1}/{runs}] {elapsed:.0f} ms  (HTTP {resp.status_code})")
            else:
                errors += 1
                print(f"    [{i+1}/{runs}] ERROR  HTTP {resp.status_code}: {resp.text[:80]}")
        except Exception as exc:
            errors += 1
            print(f"    [{i+1}/{runs}] EXCEPTION: {exc}")
        time.sleep(1)

    if not results:
        print(f"  No successful runs for {label}.")
        return

    mean   = statistics.mean(results)
    stdev  = statistics.stdev(results) if len(results) > 1 else 0
    lo, hi = min(results), max(results)
    print(f"  Result: mean={mean:.0f} ms  stdev={stdev:.0f} ms  range=[{lo:.0f}, {hi:.0f}]  errors={errors}")
    return mean, stdev, lo, hi


def register_file():
    global _registered_file_id
    file_id = f"timing-test-{uuid.uuid4().hex[:8]}"
    _registered_file_id = file_id
    return requests.post(
        f"{BLOCKCHAIN_URL}/register",
        json={
            "file_id":          file_id,
            "file_hash":        uuid.uuid4().hex,
            "file_name":        "timing_test.bin",
            "file_size":        1024,
            "chunk_ids":        [f"{file_id}/chunk_0000"],
            "chunk_hashes":     [uuid.uuid4().hex],
            "chunk_sizes":      [1024],
            "chunk_locations":  [f"minio://secure-storage/{file_id}/chunk_0000"],
        },
        timeout=60,
    )


def log_access():
    fid = _registered_file_id or "timing-test-placeholder"
    return requests.post(
        f"{BLOCKCHAIN_URL}/audit/log",
        json={
            "file_id":      fid,
            "action":       "download",
            "ip_address":   "127.0.0.1",
            "success":      True,
            "anomaly_flag": False,
            "user_address": "0x0000000000000000000000000000000000000001",
        },
        timeout=10,
    )


def check_access():
    fid = _registered_file_id or "timing-test-placeholder"
    return requests.post(
        f"{BLOCKCHAIN_URL}/access/check",
        json={"file_id": fid, "user_address": "0x0000000000000000000000000000000000000001"},
        timeout=10,
    )


def get_all_logs():
    return requests.get(
        f"{BLOCKCHAIN_URL}/audit/all",
        params={"page": 0, "page_size": 20},
        timeout=30,
    )


def main():
    print("=" * 60)
    print("Blockchain Latency Measurement")
    print("=" * 60)

    # Quick health check
    try:
        r = requests.get(f"{BLOCKCHAIN_URL}/health", timeout=5)
        print(f"\nBlockchain service: {r.status_code}")
    except Exception as exc:
        print(f"\nCannot reach blockchain service at {BLOCKCHAIN_URL}: {exc}")
        print("Make sure Docker Compose is running.")
        return

    results = {}

    print("\n--- WRITE OPERATIONS (costs gas, runs x3) ---")
    r = measure("registerFile (write, blocking)", register_file, WRITE_RUNS)
    if r:
        results["registerFile"] = r

    r = measure("logAccess (write, fire-and-forget)", log_access, WRITE_RUNS)
    if r:
        results["logAccess"] = r

    print("\n--- READ OPERATIONS (free, runs x10) ---")
    r = measure("checkAccess (read, RPC call)", check_access, READ_RUNS)
    if r:
        results["checkAccess"] = r

    r = measure("getAllAccessLogs (read)", get_all_logs, READ_RUNS)
    if r:
        results["getAllAccessLogs"] = r

    print("\n")
    print("=" * 60)
    print("SUMMARY TABLE (paste into thesis)")
    print("=" * 60)
    print(f"{'Operation':<40} {'Mean (ms)':>10} {'Stdev (ms)':>12} {'Range (ms)':>20}")
    print("-" * 84)
    for op, (mean, stdev, lo, hi) in results.items():
        print(f"{op:<40} {mean:>10.0f} {stdev:>12.0f} {lo:>8.0f} to {hi:<8.0f}")


if __name__ == "__main__":
    main()
