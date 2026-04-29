from dotenv import load_dotenv
load_dotenv()

import os
import re
import json
import time
import logging
import numpy as np
import redis
from flask import Flask, request, jsonify
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("ai_detection_service")

app = Flask(__name__)
CORS(app)

MODEL_DIR  = os.getenv("MODEL_DIR",  "models")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

isolation_forest = None
random_forest    = None
scaler           = None
models_loaded    = False
feature_names: list = []
N_FEATURES: int = 12

redis_client = None

THRESHOLDS = {
    "CRITICAL": 0.85,
    "HIGH":     0.65,
    "MEDIUM":   0.45,
    "NORMAL":   0.0,
}

# IF is unsupervised (catches unknown patterns), RF is supervised (high accuracy).
WEIGHTS = {
    "isolation_forest": 0.40,
    "random_forest":    0.60,
}

# These 12 features must stay in sync with train_behavioral_models.py.
BEHAVIORAL_FEATURES = [
    "hour_of_day",
    "day_of_week",
    "is_night",
    "file_size_mb",
    "is_upload",
    "events_1h",
    "events_24h",
    "rapid_succession",
    "prev_anomaly_count",
    "ip_is_private",
    "events_per_hour",
    "high_volume",
]


def load_models() -> None:
    """Load all ML models from MODEL_DIR."""
    global isolation_forest, random_forest, scaler
    global models_loaded, feature_names, N_FEATURES
    try:
        import joblib

        if_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
        rf_path = os.path.join(MODEL_DIR, "random_forest.pkl")
        sc_path = os.path.join(MODEL_DIR, "scaler.pkl")

        if os.path.exists(if_path):
            isolation_forest = joblib.load(if_path)
            logger.info("Isolation Forest loaded")
        if os.path.exists(rf_path):
            random_forest = joblib.load(rf_path)
            logger.info("Random Forest loaded")
        if os.path.exists(sc_path):
            scaler = joblib.load(sc_path)
            logger.info("Scaler loaded")

        fn_path = os.path.join(MODEL_DIR, "feature_names.json")
        if os.path.exists(fn_path):
            with open(fn_path) as f:
                feature_names = json.load(f)
            N_FEATURES = len(feature_names)
            logger.info(f"Feature names loaded: {N_FEATURES} features")

        models_loaded = all([isolation_forest, random_forest, scaler])
        logger.info(f"Model loading complete. All models loaded: {models_loaded}")
    except Exception as exc:
        logger.error(f"Failed to load models: {exc}", exc_info=True)


def connect_redis() -> None:
    """Establish Redis connection."""
    global redis_client
    try:
        redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        redis_client.ping()
        logger.info(f"Redis connected at {REDIS_HOST}:{REDIS_PORT}")
    except Exception as exc:
        logger.warning(f"Redis connection failed: {exc}. Event history disabled.")
        redis_client = None


# ---------------------------------------------------------------------------
# Layer 1 — File content analysis
# ---------------------------------------------------------------------------

# EICAR standard test file prefix (safe to store — not a real virus)
_EICAR_PREFIX = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"

# High-risk patterns — each match adds 0.30 to content score (cap 0.60)
_HIGH_RISK_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        # VBA/Office macro auto-execution
        r"sub\s+auto(open|exec|close|new)\s*\(",
        r"sub\s+(document|workbook)_(open|close|new|activate)\s*\(",
        r"options\.virusprotection\s*=\s*false",
        r"application\.organizercopy",
        # PowerShell encoded/download-and-execute
        r"powershell[^\n]{0,30}-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
        r"iex\s*\(\s*\(?\s*new-object\s+net\.webclient\s*\)\.downloadstring",
        r"invoke-expression\s*\(\s*\(?\s*new-object",
        # Shell command execution from scripting contexts
        r"shell\s+[\"']?\s*cmd[\s/]",
        r"wscript\.shell.*\.run\s*\(",
        r"createobject\s*\(\s*[\"']wscript\.shell",
        # Download + execute chains
        r"curl\s+.+\|\s*(bash|sh|python|perl)",
        r"wget\s+.+\|\s*(bash|sh|python|perl)",
        r"wget\s+.+-O\s*-\s*\|\s*(bash|sh)",
        # Windows API for code injection
        r"virtualalloc(ex)?\s*\(",
        r"createremotethread\s*\(",
        r"writeprocessmemory\s*\(",
        # Registry persistence
        r"reg\s+add\s+.*(\\run\\|\\runonce\\)",
        r"hk(lm|cu)\\software\\microsoft\\windows\\currentversion\\run",
        # Scheduled task persistence
        r"schtasks\s+/create\s+.+/sc\s+(minute|hourly|daily|onlogon|onstart)",
    ]
]

# Medium-risk patterns — each match adds 0.15 to content score (cap 0.45)
_MEDIUM_RISK_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        # Code obfuscation
        r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}",       # hex shellcode runs
        r"chr\([0-9]+\)\s*(&\s*chr\([0-9]+\)){3,}",   # VBScript chr() chains
        r"string\.fromcharcode\s*\(\s*[0-9]+",         # JS fromCharCode
        r"base64[_\-\.]?(decode|encode)\s*\(",
        r"[A-Za-z0-9+/]{60,}={0,2}",                  # long base64 blob
        # Generic dangerous calls (all languages)
        r"eval\s*\(",
        r"exec\s*\(",
        r"shell_exec\s*\(",
        r"passthru\s*\(",
        r"system\s*\(\s*['\"]",
        r"os\.system\s*\(",
        r"subprocess\.(call|popen|run)\s*\(\s*['\"]",
        # PowerShell suspicious
        r"invoke-expression\b",
        r"invoke-command\b",
        r"\biex\b\s*[\(\$]",
        r"new-object\s+net\.webclient",
        r"invoke-webrequest\b",
        # PHP webshell patterns
        r"<\?php.{0,50}(eval|exec|system|passthru|shell_exec)\s*\(",
        # Privilege escalation
        r"runas\s+/user\s*:",
        r"\bsudo\s+-[si]\b",
        # Network backdoor indicators
        r"socket\.(connect|bind)\s*\(\s*[\(\"']",
        r"/dev/tcp/[0-9]{1,3}\.[0-9]{1,3}",           # bash reverse shell
        r"nc\s+-[a-z]*e\s+",                           # netcat -e (bind shell)
        # Anti-forensics
        r"(clear-eventlog|wevtutil\s+cl)\b",
        r"vssadmin\s+delete\s+shadows",
        r"bcdedit\s+.+recoveryenabled\s+no",
        # On error resume next + shell (VBA evasion combo)
        r"on\s+error\s+resume\s+next",
    ]
]

_PE_EXTENSIONS = {"exe", "dll", "sys", "scr", "com"}


def _analyze_com_file(data: bytes, filename: str) -> float:
    """Heuristic scoring for DOS COM file infectors."""
    if not filename.lower().endswith('.com'):
        return 0.0
    if len(data) < 1:
        return 0.0
    if data[:2] == b'MZ':  # 32-bit PE disguised with .com extension — handled by PE path
        return 0.0
    if data[0] not in (0xEB, 0xE9):  # must start with a jump to be a valid DOS COM
        return 0.0

    score = 0.20  # baseline: valid DOS COM executable

    infector_score = 0.0
    specific_indicators = 0  # count of infector-specific indicators (excludes generic INT 21h)

    if b'\xCD\x21' in data:
        infector_score += 0.25  # INT 21h — the only way a COM file does I/O

    idx = data.find(b'\xCD\x21')
    if idx != -1:
        window = data[max(0, idx - 10): idx + 10]
        if b'\x4E' in window or b'\x4F' in window:  # FindFirst / FindNext
            infector_score += 0.25
            specific_indicators += 1

    if b'*.com' in data or b'*.COM' in data or b'*.exe' in data or b'*.EXE' in data:
        infector_score += 0.25
        specific_indicators += 1

    if b'\xB4\x3C' in data or b'\xB4\x3D' in data:  # create / open file via INT 21h
        infector_score += 0.25
        specific_indicators += 1

    if len(data) < 2048 and specific_indicators > 0:
        infector_score += 0.25  # COM infectors are characteristically tiny (only when infector-specific indicators present)

    score += min(infector_score, 0.70)
    return min(score, 0.90)


# Document/media formats that are inherently compressed — high entropy is normal,
# so entropy scoring is suppressed. Pattern scanning still runs on their bytes.
_DOCUMENT_FORMATS = {
    "pdf",
    "jpg", "jpeg", "png", "gif", "webp",
    "mp4", "mp3", "avi", "mov", "mkv",
    "docx", "xlsx", "pptx", "odt",
}

# Archive formats — contents must be inspected, not scanned as raw bytes.
_ARCHIVE_EXTENSIONS = {"zip", "tar", "gz", "bz2", "xz", "7z", "rar"}

# Extensions considered dangerous when found *inside* an archive.
_DANGEROUS_IN_ARCHIVE = {
    "exe", "dll", "sys", "scr", "com",
    "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "jar",
}

# Text-based extensions worth scanning for malicious patterns when inside an archive.
_SCANNABLE_IN_ARCHIVE = {
    "txt", "js", "jse", "ps1", "vbs", "bat", "cmd", "py", "sh",
    "html", "htm", "php", "asp", "aspx", "hta", "xml",
}


def _inspect_archive(file_bytes: bytes, filename: str) -> dict:
    """
    Inspect archive contents for dangerous executables and malicious scripts.
    Protects against zip bombs by capping total extraction at 50 MB.
    Returns: {"score": float 0-1, "threat_type": str|None, "details": list}
    """
    import io
    import zipfile
    import tarfile

    _MAX_EXTRACT = 50 * 1024 * 1024  # 50 MB total uncompressed limit

    score = 0.0
    threat_type = None
    details: list = []

    def _scan_text(text: str, source: str) -> float:
        """Scan text from an archive entry. Returns score contribution (1.0 = force CRITICAL)."""
        nonlocal threat_type
        high_hits   = sum(1 for p in _HIGH_RISK_RE   if p.search(text))
        medium_hits = sum(1 for p in _MEDIUM_RISK_RE if p.search(text))
        if high_hits >= 3:
            threat_type = "MALWARE_IN_ARCHIVE"
            details.append(f"Malware patterns in {source}")
            return 1.0  # signal caller to force CRITICAL immediately
        added = min(high_hits * 0.30, 0.60) + min(medium_hits * 0.15, 0.45)
        if added:
            threat_type = threat_type or (
                "MALICIOUS_CODE_IN_ARCHIVE" if high_hits else "SUSPICIOUS_SCRIPT_IN_ARCHIVE"
            )
            details.append(f"Suspicious patterns in {source} (H:{high_hits} M:{medium_hits})")
        return added * 0.85  # slight discount for nested content

    # --- ZIP ---
    try:
        bio = io.BytesIO(file_bytes)
        if zipfile.is_zipfile(bio):
            bio.seek(0)
            with zipfile.ZipFile(bio) as zf:
                members = zf.infolist()
                total_uncompressed = sum(m.file_size for m in members)
                dangerous = [
                    m.filename for m in members
                    if m.filename.rsplit(".", 1)[-1].lower() in _DANGEROUS_IN_ARCHIVE
                ]
                if dangerous:
                    # 1 exe = 0.60 (MEDIUM signal), 2+ = 0.80 (HIGH signal before blending)
                    score = max(score, 0.80 if len(dangerous) >= 2 else 0.60)
                    threat_type = "ARCHIVE_CONTAINS_EXECUTABLES"
                    details.append(f"Executables inside archive: {dangerous[:5]}")
                if total_uncompressed <= _MAX_EXTRACT:
                    for m in members[:30]:
                        m_ext = m.filename.rsplit(".", 1)[-1].lower() if "." in m.filename else ""
                        if m_ext not in _SCANNABLE_IN_ARCHIVE or m.file_size > 2 * 1024 * 1024:
                            continue
                        try:
                            text = zf.read(m.filename)[:65536].decode("utf-8", errors="ignore")
                            added = _scan_text(text, m.filename)
                            if added >= 1.0:
                                return {"score": 1.0, "threat_type": threat_type, "details": details}
                            score += added
                        except Exception:
                            pass
            return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}
    except Exception:
        pass

    # --- TAR (handles .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz) ---
    try:
        bio = io.BytesIO(file_bytes)
        if tarfile.is_tarfile(bio):
            bio.seek(0)
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                members = tf.getmembers()
                total_uncompressed = sum(m.size for m in members if m.isfile())
                dangerous = [
                    m.name for m in members
                    if m.isfile() and m.name.rsplit(".", 1)[-1].lower() in _DANGEROUS_IN_ARCHIVE
                ]
                if dangerous:
                    # 1 exe = 0.60 (MEDIUM signal), 2+ = 0.80 (HIGH signal before blending)
                    score = max(score, 0.80 if len(dangerous) >= 2 else 0.60)
                    threat_type = "ARCHIVE_CONTAINS_EXECUTABLES"
                    details.append(f"Executables inside archive: {dangerous[:5]}")
                if total_uncompressed <= _MAX_EXTRACT:
                    for m in members[:30]:
                        m_ext = m.name.rsplit(".", 1)[-1].lower() if "." in m.name else ""
                        if not m.isfile() or m_ext not in _SCANNABLE_IN_ARCHIVE or m.size > 2 * 1024 * 1024:
                            continue
                        try:
                            fobj = tf.extractfile(m)
                            if fobj:
                                text = fobj.read(65536).decode("utf-8", errors="ignore")
                                added = _scan_text(text, m.name)
                                if added >= 1.0:
                                    return {"score": 1.0, "threat_type": threat_type, "details": details}
                                score += added
                        except Exception:
                            pass
            return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}
    except Exception:
        pass

    # --- Plain gzip / bz2 / xz (single compressed file, not a tar) ---
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ("gz", "bz2", "xz"):
        try:
            import gzip
            import bz2 as _bz2
            import lzma
            decompress = {"gz": gzip.decompress, "bz2": _bz2.decompress, "xz": lzma.decompress}[ext]
            inner = decompress(file_bytes[:5 * 1024 * 1024])
            if _EICAR_PREFIX in inner[:1000]:
                return {"score": 1.0, "threat_type": "EICAR_TEST", "details": ["EICAR in compressed content"]}
            text = inner[:65536].decode("utf-8", errors="ignore")
            added = _scan_text(text, f"{filename}[inner]")
            if added >= 1.0:
                return {"score": 1.0, "threat_type": threat_type, "details": details}
            score += added
        except Exception:
            pass

    return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}


def analyze_file_content(file_bytes: bytes, filename: str) -> dict:
    """
    Layer 1 — rule-based content analysis.
    Returns a dict with content_risk_score (0–1) and metadata.
    No external dependencies — stdlib only (re, numpy already imported).
    """
    result: dict = {
        "content_risk_score": 0.0,
        "entropy": 0.0,
        "is_high_entropy": False,
        "is_pe_file": False,
        "threat_type": None,
    }

    if not file_bytes:
        return result

    # --- Shannon entropy ---
    freq = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
    prob = freq[freq > 0] / len(file_bytes)
    entropy = float(-np.sum(prob * np.log2(prob)))
    result["entropy"] = round(entropy, 4)

    score = 0.0

    # --- EICAR test string detection ---
    if _EICAR_PREFIX in file_bytes[:1000]:
        result["threat_type"] = "EICAR_TEST"
        result["content_risk_score"] = 1.0
        logger.warning(f"EICAR test string detected in '{filename}'")
        return result

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # --- Archive inspection (zip, tar, gz, rar, etc.) ---
    # Compressed binary is not scannable as text — inspect the contained files instead.
    if ext in _ARCHIVE_EXTENSIONS:
        arch = _inspect_archive(file_bytes, filename)
        if arch["score"] >= 1.0:
            result["threat_type"] = arch["threat_type"]
            result["content_risk_score"] = 1.0
            logger.warning(f"Malware in archive '{filename}': {arch['details']}")
            return result
        score += arch["score"]
        if arch["threat_type"]:
            result["threat_type"] = arch["threat_type"]
        if arch["details"]:
            logger.info(f"Archive scan '{filename}': score={arch['score']:.4f} {arch['details']}")
    else:
        # --- Entropy scoring (skip for inherently-compressed document formats) ---
        if ext not in _DOCUMENT_FORMATS:
            if entropy > 7.8:
                score += 0.35   # Likely packed / encrypted payload
                result["is_high_entropy"] = True
            elif entropy > 7.2:
                score += 0.15   # Compressed or encrypted content
                result["is_high_entropy"] = True

        # --- DOS COM file analysis ---
        com_score = _analyze_com_file(file_bytes, filename)
        if com_score > 0.0:
            score += com_score
            if com_score >= 0.50:
                result["threat_type"] = result["threat_type"] or "DOS_COM_INFECTOR"
                logger.warning(
                    f"DOS COM infector indicators in '{filename}': score={com_score:.2f}"
                )

        # --- PE file analysis ---
        if ext in _PE_EXTENSIONS:
            result["is_pe_file"] = True
            if file_bytes[:2] == b"MZ":
                if entropy > 6.5:
                    score += 0.40
                    result["threat_type"] = "PACKED_PE"
                    logger.info(f"Packed PE detected: '{filename}' (entropy={entropy:.2f})")
                else:
                    score += 0.10   # Plain PE — low baseline risk

        # --- Malicious pattern scan (all non-archive, text-decodable files) ---
        # Runs regardless of extension — macro viruses appear in .txt, .html, .rtf, etc.
        try:
            text = file_bytes[:131072].decode("utf-8", errors="ignore")

            high_hits   = sum(1 for p in _HIGH_RISK_RE   if p.search(text))
            medium_hits = sum(1 for p in _MEDIUM_RISK_RE if p.search(text))

            if high_hits >= 3:
                # 3+ high-risk patterns = unambiguous malware — force CRITICAL
                result["threat_type"] = "MALWARE"
                result["content_risk_score"] = 1.0
                logger.warning(f"MALWARE detected in '{filename}': {high_hits} high-risk patterns")
                return result

            if high_hits or medium_hits:
                pattern_score = min(high_hits * 0.30, 0.60) + min(medium_hits * 0.15, 0.45)
                score += pattern_score

                if high_hits:
                    result["threat_type"] = result["threat_type"] or "MALICIOUS_CODE"
                    logger.warning(
                        f"High-risk patterns ({high_hits}) in '{filename}': score +{min(high_hits*0.30,0.60):.2f}"
                    )
                elif medium_hits:
                    result["threat_type"] = result["threat_type"] or "SUSPICIOUS_SCRIPT"
                    logger.info(
                        f"Medium-risk patterns ({medium_hits}) in '{filename}': score +{min(medium_hits*0.15,0.45):.2f}"
                    )
        except Exception:
            pass

    result["content_risk_score"] = round(min(score, 1.0), 4)
    return result


# ---------------------------------------------------------------------------
# Layer 2 — Behavioural feature extraction
# ---------------------------------------------------------------------------

def extract_features(event_data: dict) -> np.ndarray:
    """
    Extract 12 behavioural features from a runtime access event.
    Feature order matches BEHAVIORAL_FEATURES in train_behavioral_models.py.
    """
    import datetime

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

    if redis_client:
        try:
            history_key  = f"user_events:{user_id}"
            one_hour_ago = timestamp - 3600
            one_day_ago  = timestamp - 86400

            events_raw = redis_client.lrange(history_key, 0, 500)
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
            prev_anomaly_count = float(redis_client.get(anomaly_key) or 0)
        except Exception as exc:
            logger.warning(f"Redis feature extraction failed: {exc}")

    # IP risk
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


# ---------------------------------------------------------------------------
# Model inference helpers
# ---------------------------------------------------------------------------

def _scale(features: np.ndarray) -> np.ndarray:
    """Scale features and clip to ±3σ."""
    scaled = scaler.transform(features.reshape(1, -1))
    return np.clip(scaled, -3.0, 3.0).astype(np.float32)


def run_isolation_forest(features: np.ndarray) -> float:
    if not isolation_forest or not scaler:
        return 0.0
    try:
        scaled = _scale(features)
        score  = isolation_forest.score_samples(scaled)[0]
        return float(max(0.0, min(1.0, (-score - 0.1) / 0.9)))
    except Exception as exc:
        logger.warning(f"Isolation Forest inference failed: {exc}")
        return 0.0


def run_random_forest(features: np.ndarray) -> float:
    if not random_forest or not scaler:
        return 0.0
    try:
        scaled = _scale(features)
        proba  = random_forest.predict_proba(scaled)[0]
        return float(proba[1]) if len(proba) > 1 else 0.0
    except Exception as exc:
        logger.warning(f"Random Forest inference failed: {exc}")
        return 0.0


def classify_score(score: float) -> str:
    if score >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "NORMAL"


def _compute_ensemble(iso: float, rf: float) -> float:
    return (
        WEIGHTS["isolation_forest"] * iso +
        WEIGHTS["random_forest"]    * rf
    )


def _persist_event(user_id: str, timestamp: float, ensemble_score: float,
                   level: str, action: str, threat_type: str | None = None) -> None:
    """Write event to Redis and publish alert if anomalous."""
    if not redis_client:
        return
    try:
        history_key  = f"user_events:{user_id}"
        event_record = json.dumps({
            "ts": float(timestamp), "score": ensemble_score,
            "level": level, "action": action,
        })
        redis_client.lpush(history_key, event_record)
        redis_client.ltrim(history_key, 0, 999)
        redis_client.expire(history_key, 86400 * 7)

        if level != "NORMAL":
            anomaly_key = f"user_anomalies:{user_id}"
            redis_client.incr(anomaly_key)
            redis_client.expire(anomaly_key, 86400 * 30)
            alert = json.dumps({
                "user_id": user_id, "level": level,
                "score": ensemble_score, "timestamp": timestamp,
                "action": action, "threat_type": threat_type,
            })
            redis_client.publish("anomaly_alerts", alert)
            logger.warning(f"Anomaly: user={user_id} level={level} score={ensemble_score:.4f}")
    except Exception as exc:
        logger.warning(f"Redis persist failed: {exc}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

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

        # Layer 1: content risk
        layer1        = analyze_file_content(file_bytes, filename)
        content_score = layer1["content_risk_score"]

        # Layer 2: behavioural risk
        features   = extract_features(body)
        if_score   = run_isolation_forest(features)
        rf_score   = run_random_forest(features)
        behavioral = _compute_ensemble(if_score, rf_score)

        # Combined scoring — content dominates when clearly malicious OR archive contains executables.
        # Without this, the 0.30× multiplier would dilute archive threats below detection thresholds.
        _ARCHIVE_THREAT_TYPES = {
            "ARCHIVE_CONTAINS_EXECUTABLES", "MALICIOUS_CODE_IN_ARCHIVE",
            "MALWARE_IN_ARCHIVE", "SUSPICIOUS_SCRIPT_IN_ARCHIVE",
        }
        is_archive_threat = layer1.get("threat_type") in _ARCHIVE_THREAT_TYPES
        if content_score >= 0.8 or is_archive_threat:
            ensemble_score = 0.85 * content_score + 0.15 * behavioral
        else:
            ensemble_score = 0.30 * content_score + 0.70 * behavioral

        logger.info(
            f"Scan '{filename}' — L1:{content_score:.4f} | "
            f"L2(IF:{if_score:.4f} RF:{rf_score:.4f}) "
            f"behav:{behavioral:.4f} | Final:{ensemble_score:.4f}"
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
                    "isolation_forest": round(if_score, 4),
                    "random_forest":    round(rf_score, 4),
                },
            },
            "model_scores": {
                "isolation_forest": round(if_score, 4),
                "random_forest":    round(rf_score, 4),
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

        features   = extract_features(body)
        if_score   = run_isolation_forest(features)
        rf_score   = run_random_forest(features)

        ensemble_score = _compute_ensemble(if_score, rf_score)
        logger.info(
            f"Detect — IF:{if_score:.4f} RF:{rf_score:.4f} | Ensemble:{ensemble_score:.4f}"
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
                "isolation_forest": round(if_score, 4),
                "random_forest":    round(rf_score, 4),
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
        if not redis_client:
            return jsonify({"error": "Redis not available"}), 503

        history_key = f"user_events:{user_id}"
        anomaly_key = f"user_anomalies:{user_id}"

        events_raw = redis_client.lrange(history_key, 0, 999)
        events = []
        for e in events_raw:
            try:
                events.append(json.loads(e))
            except Exception:
                pass

        total_events    = len(events)
        total_anomalies = int(redis_client.get(anomaly_key) or 0)
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
    if redis_client:
        try:
            redis_client.ping()
            redis_ok = True
        except Exception:
            pass

    return jsonify({
        "status":        "ok",
        "service":       "ai_detection",
        "models_loaded": models_loaded,
        "model_status": {
            "isolation_forest": isolation_forest is not None,
            "random_forest":    random_forest    is not None,
            "scaler":           scaler           is not None,
        },
        "redis_connected": redis_ok,
        "n_features":      N_FEATURES,
    }), 200


load_models()
connect_redis()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting AI detection service on port 5003 (debug={debug})")
    app.run(host="0.0.0.0", port=5003, debug=debug, use_reloader=debug)
