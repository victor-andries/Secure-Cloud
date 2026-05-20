import threading
import logging
import numpy as np

from .config import THRESHOLDS, MIN_FIT_SAMPLES, REFIT_EVERY, BEHAVIORAL_FEATURES
from . import redis_buffer

logger = logging.getLogger("ai_detection.detector")

pyod_detector       = None
models_loaded       = False
_detector_lock      = threading.Lock()
_events_since_refit = 0
_synthetic_only     = False  # True when fitted on synthetic padding, not real data


def _fit_detector(X: np.ndarray, synthetic: bool = False) -> None:
    """Fit ECOD on X and atomically swap the global detector."""
    global pyod_detector, models_loaded, _synthetic_only
    try:
        from pyod.models.ecod import ECOD
        clf = ECOD(contamination=0.05)
        clf.fit(X)
        with _detector_lock:
            pyod_detector = clf
            models_loaded = True
            _synthetic_only = synthetic
        label = "synthetic" if synthetic else "real"
        logger.info(f"ECOD fitted on {len(X)} {label} samples (threshold={clf.threshold_:.4f})")
    except Exception as exc:
        logger.error(f"ECOD fit failed: {exc}", exc_info=True)


def _generate_normal_vectors(n: int) -> np.ndarray:
    """Generate synthetic normal behavior vectors for pre-seeding ECOD."""
    rng = np.random.default_rng(seed=42)
    n_day   = int(n * 0.9)
    n_night = n - n_day

    # Day rows: business hours, weekdays
    hour_day   = rng.integers(9, 18, size=n_day).astype(np.float32)
    dow_day    = rng.integers(0, 7,  size=n_day).astype(np.float32)
    night_day  = np.zeros(n_day, dtype=np.float32)

    # Night rows: off hours, any day
    hour_night  = rng.choice(np.r_[0:7, 22:24], size=n_night).astype(np.float32)
    dow_night   = rng.integers(0, 7, size=n_night).astype(np.float32)
    night_night = np.ones(n_night, dtype=np.float32)

    hour     = np.concatenate([hour_day, hour_night])
    dow      = np.concatenate([dow_day, dow_night])
    is_night = np.concatenate([night_day, night_night])

    file_size   = rng.uniform(0.1, 50.0, size=n).astype(np.float32)
    is_upload   = rng.integers(0, 2, size=n).astype(np.float32)
    events_1h   = rng.integers(0, 6, size=n).astype(np.float32)
    events_24h  = rng.integers(1, 16, size=n).astype(np.float32)
    rapid       = np.zeros(n, dtype=np.float32)
    prev_anom   = np.zeros(n, dtype=np.float32)
    ip_private  = np.ones(n, dtype=np.float32)
    evts_per_hr = rng.uniform(0.0, 5.0, size=n).astype(np.float32)
    high_vol    = np.zeros(n, dtype=np.float32)
    return np.column_stack([
        hour, dow, is_night, file_size, is_upload,
        events_1h, events_24h, rapid, prev_anom,
        ip_private, evts_per_hr, high_vol,
    ])


def load_models() -> None:
    """Fit detector on buffered feature vectors. Pre-seeds with synthetic normal data if buffer is empty."""
    X = redis_buffer._load_buffer()
    if X is not None:
        _fit_detector(X)
        return

    buf_size = 0
    if redis_buffer.redis_client:
        try:
            buf_size = int(redis_buffer.redis_client.llen(redis_buffer.REDIS_FEAT_KEY))
        except Exception:
            pass

    logger.info(
        f"Buffer has {buf_size} samples (< {MIN_FIT_SAMPLES}). "
        "Pre-seeding ECOD with synthetic normal vectors — scores suppressed until real data accumulates."
    )
    synthetic = _generate_normal_vectors(MIN_FIT_SAMPLES)
    _fit_detector(synthetic, synthetic=True)


def run_pyod_detector(features: np.ndarray) -> float:
    """Score one event; also handles buffer growth and async refitting."""
    global _events_since_refit

    buf_size = redis_buffer._store_feature(features)

    _events_since_refit += 1
    if _events_since_refit >= REFIT_EVERY and buf_size >= MIN_FIT_SAMPLES:
        _events_since_refit = 0
        X = redis_buffer._load_buffer()
        if X is not None:
            threading.Thread(target=_fit_detector, args=(X,), daemon=True).start()

    with _detector_lock:
        clf = pyod_detector
        using_synthetic = _synthetic_only

    if using_synthetic:
        return 0.0  # suppress ECOD until fitted on real data

    if clf is None:
        if buf_size >= MIN_FIT_SAMPLES:
            X = redis_buffer._load_buffer()
            if X is not None:
                _fit_detector(X)
                with _detector_lock:
                    clf = pyod_detector
        if clf is None:
            return 0.0

    try:
        score  = float(clf.decision_function(features.reshape(1, -1))[0])
        scores = clf.decision_scores_
        p_lo   = float(np.percentile(scores, 2))
        p_hi   = float(np.percentile(scores, 98))
        return float(max(0.0, min(1.0, (score - p_lo) / (p_hi - p_lo + 1e-9))))
    except Exception as exc:
        logger.warning(f"ECOD inference failed: {exc}")
        return 0.0


def classify_score(score: float) -> str:
    if score >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "NORMAL"


_FEATURE_LABELS = {
    "hour_of_day":        "hour of day",
    "day_of_week":        "day of week",
    "is_night":           "night-time access",
    "file_size_mb":       "file size (MB)",
    "is_upload":          "upload activity",
    "events_1h":          "events in past hour",
    "events_24h":         "events in past 24h",
    "rapid_succession":   "rapid successive requests",
    "prev_anomaly_count": "prior anomaly flags",
    "ip_is_private":      "IP address type",
    "events_per_hour":    "average events/hour",
    "high_volume":        "high-volume activity",
}


def get_ecod_reasons(features: np.ndarray) -> list[str]:
    """
    Return up to 3 human-readable reasons explaining why ECOD scored this event.
    Uses z-score against the training buffer to identify the most anomalous features.
    Returns [] if buffer is too small or Redis is unavailable.
    """
    try:
        X = redis_buffer._load_buffer()
        if X is None or len(X) < 10:
            return []
        means = X.mean(axis=0)
        stds  = X.std(axis=0) + 1e-6
        z     = np.abs((features - means) / stds)
        top   = np.argsort(z)[::-1][:3]
        reasons = []
        for idx in top:
            if z[idx] < 2.0:
                break  # not anomalous enough to mention
            name  = BEHAVIORAL_FEATURES[idx]
            label = _FEATURE_LABELS.get(name, name)
            val   = float(features[idx])
            typ   = float(means[idx])
            reasons.append(
                f"ECOD: unusual {label} (observed={val:.2f}, typical={typ:.2f})"
            )
        return reasons
    except Exception as exc:
        logger.warning(f"ECOD reasons failed: {exc}")
        return []
