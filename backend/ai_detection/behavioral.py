import json
import time
import logging
import datetime
import numpy as np

from .config import BEHAVIORAL_FEATURES
from . import redis_buffer

logger = logging.getLogger("ai_detection.behavioral")


def extract_features(event_data: dict) -> np.ndarray:
    user_id    = event_data.get("user_id",    "unknown")
    timestamp  = float(event_data.get("timestamp", time.time()))
    file_size  = float(event_data.get("file_size",  0))
    ip_address = event_data.get("ip_address", "0.0.0.0")
    action     = event_data.get("action",     "download")

    dt  = datetime.datetime.fromtimestamp(timestamp)
    hour       = float(dt.hour)
    dow        = float(dt.weekday())
    is_night   = 1.0 if dt.hour < 6 else 0.0
    file_size_mb = min(file_size / 1_000_000.0, 1000.0)
    is_upload  = 1.0 if action == "upload" else 0.0

    events_1h          = 0.0
    events_24h         = 0.0
    rapid_succession   = 0.0
    prev_anomaly_count = 0.0

    if redis_buffer.redis_client:
        try:
            history_key  = f"user_events:{user_id}"
            one_hour_ago = timestamp - 3600
            one_day_ago  = timestamp - 86400

            events_raw = redis_buffer.redis_client.lrange(history_key, 0, 500)
            events = []
            for e in events_raw:
                try:
                    events.append(json.loads(e))
                except Exception:
                    pass

            events_1h  = float(sum(1 for e in events if float(e.get("ts", 0)) > one_hour_ago))
            events_24h = float(sum(1 for e in events if float(e.get("ts", 0)) > one_day_ago))

            if events:
                last_ts = float(events[0].get("ts", timestamp))
                rapid_succession = 1.0 if (timestamp - last_ts) < 5 else 0.0

            anomaly_key        = f"user_anomalies:{user_id}"
            prev_anomaly_count = float(redis_buffer.redis_client.get(anomaly_key) or 0)
        except Exception as exc:
            logger.warning(f"Redis feature extraction failed: {exc}")

    try:
        octets = [int(x) for x in ip_address.split(".")]
        ip_is_private = float(
            octets[0] == 10 or
            (octets[0] == 172 and 16 <= octets[1] <= 31) or
            (octets[0] == 192 and octets[1] == 168) or
            octets[0] == 127
        )
    except Exception:
        ip_is_private = 1.0

    events_per_hour = events_24h / 24.0
    high_volume     = 1.0 if events_1h > 10 else 0.0

    return np.array([
        hour, dow, is_night, file_size_mb, is_upload,
        events_1h, events_24h, rapid_succession, prev_anomaly_count,
        ip_is_private, events_per_hour, high_volume,
    ], dtype=np.float32)

def _persist_event(user_id: str, timestamp: float, ensemble_score: float,
                   level: str, action: str, threat_type: str | None = None) -> None:
    if not redis_buffer.redis_client:
        return
    try:
        history_key  = f"user_events:{user_id}"
        event_record = json.dumps({
            "ts": float(timestamp), "score": ensemble_score,
            "level": level, "action": action,
        })
        redis_buffer.redis_client.lpush(history_key, event_record)
        redis_buffer.redis_client.ltrim(history_key, 0, 999)
        redis_buffer.redis_client.expire(history_key, 86400 * 7)

        if level != "NORMAL":
            alert = json.dumps({
                "user_id": user_id, "level": level,
                "score": ensemble_score, "timestamp": timestamp,
                "action": action, "threat_type": threat_type,
            })
            redis_buffer.redis_client.publish("anomaly_alerts", alert)
            if threat_type:
                logger.warning(f"Threat blocked: user={user_id} level={level} "
                               f"type={threat_type} score={ensemble_score:.4f}")
            else:
                logger.warning(f"Behavioral anomaly: user={user_id} level={level} "
                               f"score={ensemble_score:.4f}")
    except Exception as exc:
        logger.warning(f"Redis persist failed: {exc}")
