import time
import json
import logging

import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

from .binary_analysis import analyze_file_content
from .behavioral import extract_features, _persist_event
from .detector import run_pyod_detector, classify_score
from .config import BEHAVIORAL_FEATURES, MIN_FIT_SAMPLES, REDIS_FEAT_KEY, N_FEATURES
from . import detector, redis_buffer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("ai_detection.routes")

app = Flask(__name__)
CORS(app)


@app.route("/scan", methods=["POST"])
def scan_file() -> tuple:
    """
    Layer 1 + Layer 2 combined scan for file uploads.
    Expects multipart/form-data with optional 'file' field and metadata
    fields: user_id, action, timestamp, ip_address, file_size.
    """
    try:
        file_bytes = b""
        filename   = ""
        if "file" in request.files:
            f          = request.files["file"]
            filename   = f.filename or ""
            file_bytes = f.read()

        body = {
            "user_id":    request.form.get("user_id",    "unknown"),
            "action":     request.form.get("action",     "upload"),
            "timestamp":  float(request.form.get("timestamp", time.time())),
            "ip_address": request.form.get("ip_address", "0.0.0.0"),
            "file_size":  float(request.form.get("file_size", len(file_bytes))),
        }
        user_id   = body["user_id"]
        timestamp = body["timestamp"]

        layer1        = analyze_file_content(file_bytes, filename)
        content_score = layer1["content_risk_score"]

        features    = extract_features(body)
        pyod_score  = run_pyod_detector(features)
        behavioral  = pyod_score

        _CONTENT_DOMINANT_TYPES = {
            "ARCHIVE_CONTAINS_EXECUTABLES", "MALICIOUS_CODE_IN_ARCHIVE",
            "MALWARE_IN_ARCHIVE", "SUSPICIOUS_SCRIPT_IN_ARCHIVE",
            "ELF_INFECTOR",
            "DOS_COM_INFECTOR",
            "MALICIOUS_PE_IMPORTS",
            "PACKED_PE",
            "MACHO_DYLIB_HIJACKING",
            "MACHO_SUSPICIOUS",
        }
        is_specific_threat = layer1.get("threat_type") in _CONTENT_DOMINANT_TYPES
        if content_score >= 0.80 or is_specific_threat:
            ensemble_score = 0.85 * content_score + 0.15 * behavioral
        else:
            ensemble_score = 0.30 * content_score + 0.70 * behavioral

        logger.info(
            f"Scan '{filename}' — L1:{content_score:.4f} | "
            f"L2(ECOD:{pyod_score:.4f}) behav:{behavioral:.4f} | Final:{ensemble_score:.4f}"
        )

        level = classify_score(ensemble_score)
        _persist_event(user_id, timestamp, ensemble_score, level,
                       body["action"], layer1.get("threat_type"))

        action_map = {"CRITICAL": "BLOCK", "HIGH": "ALERT", "MEDIUM": "LOG", "NORMAL": "PASS"}
        return jsonify({
            "user_id":            user_id,
            "ensemble_score":     round(ensemble_score, 4),
            "level":              level,
            "recommended_action": action_map[level],
            "is_anomalous":       level != "NORMAL",
            "layer1":             layer1,
            "layer2": {
                "behavioral_score": round(behavioral, 4),
                "model_scores": {
                    "ecod": round(pyod_score, 4),
                },
            },
            "model_scores": {
                "ecod": round(pyod_score, 4),
            },
        }), 200

    except Exception as exc:
        logger.error(f"Scan error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/detect", methods=["POST"])
def detect_anomaly() -> tuple:
    """
    Behavioural-only detection (Layer 2) — used for downloads and other
    actions where no file bytes are available.
    """
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400

        user_id   = body.get("user_id",   "unknown")
        timestamp = body.get("timestamp", time.time())

        features       = extract_features(body)
        pyod_score     = run_pyod_detector(features)
        ensemble_score = pyod_score
        logger.info(
            f"Detect — ECOD:{pyod_score:.4f} | Ensemble:{ensemble_score:.4f}"
        )

        level = classify_score(ensemble_score)
        _persist_event(user_id, float(timestamp), ensemble_score, level,
                       body.get("action", "unknown"))

        action_map = {"CRITICAL": "BLOCK", "HIGH": "ALERT", "MEDIUM": "LOG", "NORMAL": "PASS"}
        feat_dict  = dict(zip(BEHAVIORAL_FEATURES, features.tolist()))
        return jsonify({
            "user_id":            user_id,
            "ensemble_score":     round(ensemble_score, 4),
            "level":              level,
            "recommended_action": action_map[level],
            "is_anomalous":       level != "NORMAL",
            "model_scores": {
                "ecod": round(pyod_score, 4),
            },
            "features": {k: round(v, 4) for k, v in feat_dict.items()},
        }), 200

    except Exception as exc:
        logger.error(f"Detection error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/stats/<user_id>", methods=["GET"])
def get_stats(user_id: str) -> tuple:
    """Get anomaly statistics for a user from Redis."""
    try:
        if not redis_buffer.redis_client:
            return jsonify({"error": "Redis not available"}), 503

        history_key = f"user_events:{user_id}"
        anomaly_key = f"user_anomalies:{user_id}"

        events_raw = redis_buffer.redis_client.lrange(history_key, 0, 999)
        events = []
        for e in events_raw:
            try:
                events.append(json.loads(e))
            except Exception:
                pass

        total_events    = len(events)
        total_anomalies = int(redis_buffer.redis_client.get(anomaly_key) or 0)
        level_counts    = {"NORMAL": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        scores          = []
        for e in events:
            lv = e.get("level", "NORMAL")
            level_counts[lv] = level_counts.get(lv, 0) + 1
            scores.append(e.get("score", 0.0))

        avg_score = float(np.mean(scores)) if scores else 0.0
        max_score = float(np.max(scores))  if scores else 0.0

        return jsonify({
            "user_id":            user_id,
            "total_events":       total_events,
            "total_anomalies":    total_anomalies,
            "level_distribution": level_counts,
            "average_score":      round(avg_score, 4),
            "max_score":          round(max_score, 4),
        }), 200

    except Exception as exc:
        logger.error(f"Stats error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    """Health check — return model load status."""
    redis_ok = False
    if redis_buffer.redis_client:
        try:
            redis_buffer.redis_client.ping()
            redis_ok = True
        except Exception:
            pass

    buf_size = 0
    if redis_buffer.redis_client:
        try:
            buf_size = redis_buffer.redis_client.llen(REDIS_FEAT_KEY)
        except Exception:
            pass

    return jsonify({
        "status":        "ok",
        "service":       "ai_detection",
        "models_loaded": detector.models_loaded,
        "model_status": {
            "ecod": detector.pyod_detector is not None,
        },
        "buffer_size":     buf_size,
        "min_fit_samples": MIN_FIT_SAMPLES,
        "redis_connected": redis_ok,
        "n_features":      N_FEATURES,
    }), 200
