import json
import logging
import numpy as np
import redis as _redis

from .config import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_FEAT_KEY, BUFFER_MAXLEN, MIN_FIT_SAMPLES

logger = logging.getLogger("ai_detection.redis_buffer")

redis_client = None


def connect_redis() -> None:
    global redis_client
    try:
        redis_client = _redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
        redis_client.ping()
        logger.info(f"Redis connected at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as exc:
        logger.warning(f"Redis connection failed: {exc}. Event history disabled.")
        redis_client = None


def _store_feature(features: np.ndarray) -> int:
    if not redis_client:
        return 0
    try:
        redis_client.rpush(REDIS_FEAT_KEY, json.dumps(features.tolist()))
        redis_client.ltrim(REDIS_FEAT_KEY, -BUFFER_MAXLEN, -1)
        return redis_client.llen(REDIS_FEAT_KEY)
    except Exception:
        return 0


def _load_buffer() -> np.ndarray | None:
    if not redis_client:
        return None
    try:
        raw = redis_client.lrange(REDIS_FEAT_KEY, 0, -1)
        if len(raw) < MIN_FIT_SAMPLES:
            return None
        return np.array([json.loads(r) for r in raw], dtype=np.float32)
    except Exception:
        return None
