import threading
import logging
import numpy as np

from .config import THRESHOLDS, MIN_FIT_SAMPLES, REFIT_EVERY
from . import redis_buffer

logger = logging.getLogger("ai_detection.detector")

pyod_detector       = None
models_loaded       = False
_detector_lock      = threading.Lock()
_events_since_refit = 0


def _fit_detector(X: np.ndarray) -> None:
    """Fit ECOD on X and atomically swap the global detector."""
    global pyod_detector, models_loaded
    try:
        from pyod.models.ecod import ECOD
        clf = ECOD(contamination=0.05)
        clf.fit(X)
        with _detector_lock:
            pyod_detector = clf
            models_loaded = True
        logger.info(f"ECOD fitted on {len(X)} samples (threshold={clf.threshold_:.4f})")
    except Exception as exc:
        logger.error(f"ECOD fit failed: {exc}", exc_info=True)


def load_models() -> None:
    """Fit detector on any feature vectors already in Redis (warm restart)."""
    X = redis_buffer._load_buffer()
    if X is not None:
        _fit_detector(X)
    else:
        logger.info(
            f"Feature buffer has fewer than {MIN_FIT_SAMPLES} samples — "
            "detector will fit automatically once enough events arrive."
        )


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
