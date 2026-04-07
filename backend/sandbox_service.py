from dotenv import load_dotenv
load_dotenv()

import os
import re
import time
import uuid
import logging
import tempfile
import shutil

from flask import Flask, request, jsonify
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("sandbox_service")

app = Flask(__name__)
CORS(app)

SANDBOX_BASE_IMAGE = os.getenv("SANDBOX_BASE_IMAGE", "scp-sandbox-base")

# Max file size eligible for sandboxing (50 MB)
_MAX_SANDBOX_FILE = 50 * 1024 * 1024

# Extensions that can be executed and are worth sandboxing
_RUNNERS = {
    "sh":   ["bash"],
    "bash": ["bash"],
    "zsh":  ["bash"],
    "py":   ["python3"],
    "pl":   ["perl"],
}

# ---------------------------------------------------------------------------
# Syscall analysis patterns
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, human-readable label)
_MALICIOUS_PATTERNS = [
    (re.compile(r'connect\('),                      "Network connection attempt"),
    (re.compile(r'socket\(AF_INET'),                "IPv4 socket creation"),
    (re.compile(r'socket\(AF_INET6'),               "IPv6 socket creation"),
    (re.compile(r'openat?\(.*"/etc/shadow"'),       "Shadow password file access"),
    (re.compile(r'ptrace\(PTRACE_ATTACH'),          "Process injection attempt"),
    (re.compile(r'mount\('),                        "Filesystem mount attempt"),
    (re.compile(r'init_module\(|finit_module\('),   "Kernel module load attempt"),
]

_SUSPICIOUS_PATTERNS = [
    (re.compile(r'openat?\(.*"/etc/passwd"'),       "Credential file read"),
    (re.compile(r'openat?\(.*"/proc/self/mem"'),    "Self-memory manipulation"),
    (re.compile(r'chmod\(.*0[0-9]*[67][0-9]*\)'),  "Making file executable"),
    (re.compile(r'unlink\(|unlinkat\('),            "File deletion"),
    (re.compile(r'bind\('),                         "Socket bind (listener)"),
]

# Thresholds for counting-based heuristics
_FORK_BOMB_THRESHOLD = 30   # >30 fork/clone = fork bomb
_EXEC_CHAIN_THRESHOLD = 8   # >8 execve calls = dropper chain


def _get_runner(filename: str, file_bytes: bytes):
    """Return the command prefix to run the file, or None if not executable."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in _RUNNERS:
        return _RUNNERS[ext]
    # ELF binary — run directly
    if file_bytes[:4] == b"\x7fELF":
        return []
    return None


def _analyze_trace(trace_text: str) -> dict:
    """
    Parse strace output and return verdict, score, behaviors, and syscall counts.
    """
    behaviors = []
    syscall_counts = {}
    malicious_hits = []
    suspicious_hits = []

    for line in trace_text.splitlines():
        # Count key syscalls
        for syscall in ("fork", "clone", "execve", "connect", "socket"):
            if f"{syscall}(" in line:
                syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1

        # Check malicious patterns
        for pattern, label in _MALICIOUS_PATTERNS:
            if pattern.search(line) and label not in malicious_hits:
                malicious_hits.append(label)

        # Check suspicious patterns
        for pattern, label in _SUSPICIOUS_PATTERNS:
            if pattern.search(line) and label not in suspicious_hits:
                suspicious_hits.append(label)

    fork_count = syscall_counts.get("fork", 0) + syscall_counts.get("clone", 0)
    exec_count = syscall_counts.get("execve", 0)

    # Determine verdict
    if malicious_hits or fork_count > _FORK_BOMB_THRESHOLD:
        verdict = "MALICIOUS"
        score = 0.95
        behaviors = malicious_hits[:]
        if fork_count > _FORK_BOMB_THRESHOLD:
            behaviors.append(f"Fork bomb detected ({fork_count} fork/clone calls)")
    elif exec_count > _EXEC_CHAIN_THRESHOLD or suspicious_hits:
        verdict = "SUSPICIOUS"
        score = 0.70 if exec_count > _EXEC_CHAIN_THRESHOLD else 0.55
        behaviors = suspicious_hits[:]
        if exec_count > _EXEC_CHAIN_THRESHOLD:
            behaviors.append(f"Dropper chain detected ({exec_count} execve calls)")
    else:
        verdict = "CLEAN"
        score = 0.0

    return {
        "verdict": verdict,
        "sandbox_score": score,
        "behaviors": behaviors,
        "syscall_counts": syscall_counts,
    }


def _run_in_sandbox(file_bytes: bytes, filename: str, runner: list) -> dict:
    """
    Write file to a temp dir, spin up a Docker container under strace,
    and return the raw analysis dict. Cleans up temp files on exit.
    """
    import docker
    import docker.errors

    tmp_dir = tempfile.mkdtemp(prefix="scp_sandbox_")
    target_path = os.path.join(tmp_dir, "target")
    output_dir  = os.path.join(tmp_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Write file with no execute permission on the host
        with open(target_path, "wb") as fh:
            fh.write(file_bytes)

        command = (
            ["strace", "-f",
             "-e", "trace=network,file,process,signal",
             "-o", "/output/trace.log",
             "timeout", "20"]
            + runner
            + ["/malware/target"]
        )

        start_ms = time.time()
        client = docker.from_env()

        try:
            client.containers.run(
                image=SANDBOX_BASE_IMAGE,
                command=command,
                volumes={
                    target_path: {"bind": "/malware/target", "mode": "ro"},
                    output_dir:  {"bind": "/output",          "mode": "rw"},
                },
                network_mode="none",
                read_only=True,
                mem_limit="256m",
                nano_cpus=500_000_000,   # 0.5 CPU
                pids_limit=50,
                cap_drop=["ALL"],
                cap_add=["SYS_PTRACE"],
                security_opt=["no-new-privileges"],
                tmpfs={"/tmp": "size=50m,noexec,nosuid"},
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )
        except docker.errors.ContainerError:
            # Non-zero exit is expected for malware — still analyze the trace
            pass

        runtime_ms = int((time.time() - start_ms) * 1000)

        # Read strace output
        trace_path = os.path.join(output_dir, "trace.log")
        trace_text = ""
        if os.path.exists(trace_path):
            with open(trace_path, "r", errors="replace") as fh:
                trace_text = fh.read(5 * 1024 * 1024)  # cap at 5 MB

        result = _analyze_trace(trace_text)
        result["runtime_ms"] = runtime_ms
        return result

    except Exception as exc:
        logger.error(f"Sandbox execution error: {exc}", exc_info=True)
        return {
            "verdict": "ERROR",
            "sandbox_score": 0.0,
            "behaviors": [],
            "syscall_counts": {},
            "runtime_ms": 0,
            "error": str(exc),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    """
    Sandbox a file by executing it in an isolated Docker container under strace.
    Accepts multipart/form-data with a 'file' field.
    Returns: verdict (CLEAN/SUSPICIOUS/MALICIOUS/SKIPPED/ERROR), sandbox_score, behaviors.
    """
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

        runner = _get_runner(filename, file_bytes)
        if runner is None:
            return jsonify({"verdict": "SKIPPED", "sandbox_score": 0.0,
                            "behaviors": [], "reason": "File type not executable"}), 200

        logger.info(f"Sandboxing '{filename}' (runner={runner or 'direct ELF'}, "
                    f"size={len(file_bytes)} bytes)")

        result = _run_in_sandbox(file_bytes, filename, runner)
        result["filename"] = filename

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
    """Health check — verify Docker daemon is reachable and base image exists."""
    docker_ok   = False
    image_ok    = False
    docker_info = {}

    try:
        import docker
        client = docker.from_env()
        client.ping()
        docker_ok = True
        try:
            client.images.get(SANDBOX_BASE_IMAGE)
            image_ok = True
        except docker.errors.ImageNotFound:
            image_ok = False
    except Exception as exc:
        docker_info["error"] = str(exc)

    return jsonify({
        "status":       "ok" if docker_ok else "degraded",
        "service":      "sandbox",
        "docker_ok":    docker_ok,
        "base_image":   SANDBOX_BASE_IMAGE,
        "image_ready":  image_ok,
        **docker_info,
    }), 200 if docker_ok else 503


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting sandbox service on port 5004 (debug={debug})")
    app.run(host="0.0.0.0", port=5004, debug=debug, use_reloader=debug)
