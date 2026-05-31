import logging

from flask import Flask, request, jsonify
from flask_cors import CORS

from .config import _MAX_SANDBOX_FILE, SANDBOX_BASE_IMAGE, SANDBOX_DOS_IMAGE, SANDBOX_WINE_IMAGE, _RUNNERS
from .platform import _detect_platform
from .runners import _run_in_elf_sandbox, _run_in_dos_sandbox, _run_in_wine_sandbox

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("sandbox.routes")

app = Flask(__name__)
CORS(app)


@app.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        f          = request.files["file"]
        filename   = f.filename or "unknown"
        file_bytes = f.read()

        if not file_bytes:
            return jsonify({"verdict": "SKIPPED", "sandbox_score": 0.0,
                            "behaviors": [], "reason": "Empty file"}), 200

        if len(file_bytes) > _MAX_SANDBOX_FILE:
            return jsonify({"verdict": "SKIPPED", "sandbox_score": 0.0,
                            "behaviors": [], "reason": "File too large for sandbox"}), 200

        platform = _detect_platform(file_bytes, filename)
        logger.info(f"Sandboxing '{filename}' (platform={platform}, size={len(file_bytes)} bytes)")

        if platform == "unknown":
            return jsonify({"verdict": "SKIPPED", "sandbox_score": 0.0,
                            "behaviors": [], "reason": "File type not executable"}), 200

        if platform == "macos":
            return jsonify({
                "verdict":          "SKIPPED",
                "sandbox_score":    0.0,
                "behaviors":        [],
                "reason":           "macOS dynamic analysis not available in this environment",
                "platform":         "macos",
                "dynamic_analysis": "not_available",
            }), 200

        if platform in ("elf", "script"):
            ext    = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
            runner = _RUNNERS.get(ext, [])
            result = _run_in_elf_sandbox(file_bytes, filename, runner)
        elif platform == "dos":
            result = _run_in_dos_sandbox(file_bytes, filename)
        elif platform == "windows":
            result = _run_in_wine_sandbox(file_bytes, filename)
        else:
            logger.warning(f"analyze: unhandled platform '{platform}' for '{filename}'")
            return jsonify({"verdict": "SKIPPED", "sandbox_score": 0.0,
                            "behaviors": [], "reason": f"Unhandled platform: {platform}"}), 200

        result["filename"] = filename
        result["platform"] = platform

        logger.info(
            f"Sandbox result for '{filename}': verdict={result['verdict']} "
            f"score={result.get('sandbox_score', 0)} "
            f"behaviors={result.get('behaviors', [])}"
        )
        return jsonify(result), 200

    except Exception as exc:
        logger.error(f"Analyze error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    docker_ok = False
    images: dict = {}
    extra: dict  = {}

    try:
        import docker
        client = docker.from_env()
        client.ping()
        docker_ok = True
        for name, tag in [
            ("base",  SANDBOX_BASE_IMAGE),
            ("dos",   SANDBOX_DOS_IMAGE),
            ("wine",  SANDBOX_WINE_IMAGE),
        ]:
            try:
                client.images.get(tag)
                images[name] = "ready"
            except docker.errors.ImageNotFound:
                images[name] = "missing"
    except Exception as exc:
        extra["error"] = str(exc)

    all_ready = docker_ok and all(v == "ready" for v in images.values())
    return jsonify({
        "status":    "ok" if all_ready else "degraded",
        "service":  "sandbox",
        "docker_ok": docker_ok,
        "images":   images,
        **extra,
    }), 200 if docker_ok else 503
