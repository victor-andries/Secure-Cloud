import json
import logging

import numpy as np

from . import redis_buffer
from .config import REDIS_FEAT_KEY, N_FEATURES

logger = logging.getLogger("ai_detection.demo_seed")

PROFILES = ("normal", "night")
_BASE_SEED = 1337
DEFAULT_N = 300


def _shared_nontime(rng) -> list:
    is_upload = 1.0 if rng.random() < 0.5 else 0.0
    if is_upload:                                 # uploads span all file sizes
        file_size_mb = float(min(10 ** rng.uniform(np.log10(0.05), np.log10(1000.0)), 1000.0))
    else:                                         # downloads carry size 0
        file_size_mb = 0.0

    if rng.random() < 0.45:                                    # idle
        events_1h = 0.0
        events_24h = 0.0
        rapid_succession = 0.0
    else:                                                      # active / bursty
        events_1h = float(rng.integers(1, 21))                 # 1-20 (covers 10-15 bursts)
        events_24h = float(events_1h + min(int(rng.exponential(1.0)), 5))
        rapid_succession = 1.0 if rng.random() < 0.55 else 0.0
    prev_anomaly_count = float(rng.integers(0, 3))             # 0-2, clean-ish
    ip_is_private      = 1.0                                   # localhost / Docker
    events_per_hour    = events_24h / 24.0
    high_volume        = 1.0 if events_1h > 10 else 0.0
    return [file_size_mb, is_upload, events_1h, events_24h,
            rapid_succession, prev_anomaly_count, ip_is_private,
            events_per_hour, high_volume]


def _time_features(profile: str, rng) -> list:
    if profile == "normal":
        hour = int(np.clip(round(rng.normal(9.0, 2.0)), 6, 18))
        dow  = int(rng.integers(0, 5))
    else:
        hour = int(rng.integers(0, 6))
        dow  = int(rng.choice([5, 6]))
    is_night = 1.0 if hour < 6 else 0.0
    return [float(hour), float(dow), is_night]


def generate_profile(profile: str, n: int = DEFAULT_N) -> np.ndarray:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {PROFILES}")
    rng = np.random.default_rng(_BASE_SEED + PROFILES.index(profile))
    rows = []
    for _ in range(n):
        t = _time_features(profile, rng)
        nt = _shared_nontime(rng)
        rows.append([t[0], t[1], t[2], nt[0], nt[1], nt[2], nt[3],
                     nt[4], nt[5], nt[6], nt[7], nt[8]])
    X = np.asarray(rows, dtype=np.float32)
    assert X.shape == (n, N_FEATURES), X.shape
    return X


def load_into_buffer(profile: str, n: int = DEFAULT_N, redis_client=None) -> int:
    rc = redis_client or redis_buffer.redis_client
    if rc is None:
        raise RuntimeError("Redis not connected — cannot seed buffer")
    X = generate_profile(profile, n)
    pipe = rc.pipeline()
    pipe.delete(REDIS_FEAT_KEY)
    for row in X.tolist():
        pipe.rpush(REDIS_FEAT_KEY, json.dumps(row))
    pipe.execute()
    size = rc.llen(REDIS_FEAT_KEY)
    logger.info(f"[DEMO] seeded ECOD buffer with profile={profile} ({size} samples)")
    return size


def reset_user(user_address: str, redis_client=None) -> None:
    """Clear a user's accumulated anomaly counter and event history."""
    rc = redis_client or redis_buffer.redis_client
    if rc is None or not user_address:
        return
    rc.delete(f"user_anomalies:{user_address}", f"user_events:{user_address}")
    logger.info(f"[DEMO] reset behavioural history for {user_address}")

def _demo_request(is_upload: float, events_1h: float, file_size_mb: float = 0.0) -> np.ndarray:
    events_24h = events_1h
    return np.asarray([
        8.0,
        4.0,
        0.0,
        file_size_mb, is_upload,
        events_1h, events_24h,
        1.0,
        0.0,
        1.0,
        events_24h / 24.0,
        1.0 if events_1h > 10 else 0.0,
    ], dtype=np.float32)


def _norm_score(clf, vec: np.ndarray) -> float:
    raw = float(clf.decision_function(vec.reshape(1, -1))[0])
    s = clf.decision_scores_
    lo, hi = float(np.percentile(s, 2)), float(np.percentile(s, 98))
    return float(max(0.0, min(1.0, (raw - lo) / (hi - lo + 1e-9))))


def _level(score: float, thresholds) -> str:
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"
    if score >= thresholds["HIGH"]:
        return "HIGH"
    if score >= thresholds["MEDIUM"]:
        return "MEDIUM"
    return "NORMAL"


def self_test(n: int = DEFAULT_N) -> bool:
    from pyod.models.ecod import ECOD
    from .config import THRESHOLDS

    requests = {
        "first download":  _demo_request(0.0, 0.0),
        "quiet download":  _demo_request(0.0, 1.0),
        "few downloads":   _demo_request(0.0, 6.0),
        "small upload":    _demo_request(1.0, 3.0, 20.0),
        "busier session":  _demo_request(0.0, 12.0),
    }
    BLOCK = THRESHOLDS["HIGH"]
    ok = True
    for profile in PROFILES:
        X = generate_profile(profile, n)
        clf = ECOD(contamination=0.05)
        clf.fit(X)
        print(f"\n=== profile '{profile}' (fitted on {n} samples) ===")
        for name, vec in requests.items():
            score = _norm_score(clf, vec)
            lvl = _level(score, THRESHOLDS)
            blocked = score >= BLOCK
            if profile == "normal":
                passed = not blocked
            else:
                passed = blocked
            ok = ok and passed
            verdict = "BLOCKED" if blocked else "allowed"
            flag = "" if passed else "   <-- UNEXPECTED"
            print(f"   {name:16s} score={score:.4f}  {lvl:8s} {verdict}{flag}")
    print(f"\nself-test {'PASS' if ok else 'FAIL'}")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
