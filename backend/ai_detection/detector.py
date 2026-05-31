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


def _fit_detector(X: np.ndarray) -> None:
    global pyod_detector, models_loaded
    try:
        from pyod.models.ecod import ECOD
        clf = ECOD(contamination=0.05)
        clf.fit(X)
        with _detector_lock:
            pyod_detector = clf
            models_loaded = True
        logger.info(f"ECOD fitted on {len(X)} real samples (threshold={clf.threshold_:.4f})")
    except Exception as exc:
        logger.error(f"ECOD fit failed: {exc}", exc_info=True)


def load_models() -> None:
    X = redis_buffer._load_buffer()
    if X is not None:
        _fit_detector(X)
    else:
        logger.info(
            f"Buffer below {MIN_FIT_SAMPLES} samples — ECOD detector not fitted yet; "
            "scores will return 0.0 until enough real data accumulates."
        )


def run_pyod_detector(features: np.ndarray) -> float:
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
