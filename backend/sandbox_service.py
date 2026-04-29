from dotenv import load_dotenv
load_dotenv()

import os
import re
import io
import time
import struct
import tarfile
import logging

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

_MACHO_MAGICS = {
    0xFEEDFACE, 0xCEFAEDFE,   # Mach-O 32-bit (big and little endian)
    0xFEEDFACF, 0xCFFAEDFE,   # Mach-O 64-bit
    0xCAFEBABE,                # Fat/universal binary
}


def _detect_platform(data: bytes, filename: str) -> str:
    """
    Detect execution platform from magic bytes and filename.
    MZ header is checked before .com extension so 32-bit PE .com files
    are correctly routed to the Windows sandbox, not DOSBox.
    """
    if data[:4] == b'\x7fELF':
        return "elf"
    if data[:2] == b'MZ':
        return "windows"
    if len(data) >= 4:
        try:
            magic = struct.unpack('>I', data[:4])[0]
            if magic in _MACHO_MAGICS:
                return "macos"
        except struct.error:
            pass
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if ext == 'com' and len(data) >= 1 and data[0] in (0xEB, 0xE9):
        return "dos"
    if ext in _RUNNERS:
        return "script"
    return "unknown"


# ---------------------------------------------------------------------------
# Syscall analysis patterns
# ---------------------------------------------------------------------------

_MALICIOUS_PATTERNS = [
    (re.compile(r'connect\('),                         "Network connection attempt"),
    (re.compile(r'socket\(AF_INET'),                   "IPv4 socket creation"),
    (re.compile(r'socket\(AF_INET6'),                  "IPv6 socket creation"),
    (re.compile(r'openat?\(.*"/etc/shadow"'),          "Shadow password file access"),
    (re.compile(r'ptrace\(PTRACE_ATTACH'),             "Process injection attempt"),
    (re.compile(r'mount\('),                           "Filesystem mount attempt"),
    (re.compile(r'init_module\(|finit_module\('),      "Kernel module load attempt"),
    # Unix virus infection: writing ELF magic bytes into another file
    (re.compile(r'write\(.*"\\177ELF'),                "Writing ELF header — binary infection"),
]

_SUSPICIOUS_PATTERNS = [
    (re.compile(r'openat?\(.*"/etc/passwd"'),          "Credential file read"),
    (re.compile(r'openat?\(.*"/proc/self/mem"'),       "Self-memory manipulation"),
    (re.compile(r'chmod\(.*0[0-9]*[67][0-9]*\)'),     "Making file executable"),
    (re.compile(r'unlink\(|unlinkat\('),               "File deletion"),
    (re.compile(r'bind\('),                            "Socket bind (listener)"),
]

_FORK_BOMB_THRESHOLD  = 30
_EXEC_CHAIN_THRESHOLD = 8
# A Unix virus opens many files for writing (to infect them); 3+ is suspicious
_WRITE_ATTEMPT_THRESHOLD = 3


def _get_runner(filename: str, file_bytes: bytes):
    """Return the command prefix to run the file, or None if not executable."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in _RUNNERS:
        return _RUNNERS[ext]
    if file_bytes[:4] == b"\x7fELF":
        return []
    return None


def _analyze_trace(trace_text: str) -> dict:
    """Parse strace output and return verdict, score, behaviors, syscall counts."""
    behaviors      = []
    syscall_counts = {}
    malicious_hits = []
    suspicious_hits = []

    lines = trace_text.splitlines()

    for line in lines:
        for syscall in ("fork", "clone", "execve", "connect", "socket"):
            if f"{syscall}(" in line:
                syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1

        for pattern, label in _MALICIOUS_PATTERNS:
            if pattern.search(line) and label not in malicious_hits:
                malicious_hits.append(label)

        for pattern, label in _SUSPICIOUS_PATTERNS:
            if pattern.search(line) and label not in suspicious_hits:
                suspicious_hits.append(label)

    fork_count  = syscall_counts.get("fork", 0) + syscall_counts.get("clone", 0)
    exec_count  = syscall_counts.get("execve", 0)

    # Count file write attempts — classic Unix virus infection pattern
    write_attempts = sum(
        1 for line in lines
        if re.search(r'openat?\(.*O_(?:WRONLY|RDWR)', line)
    )
    if write_attempts >= _WRITE_ATTEMPT_THRESHOLD:
        suspicious_hits.append(
            f"Mass file write attempts ({write_attempts} files) — possible virus infection"
        )

    if malicious_hits or fork_count > _FORK_BOMB_THRESHOLD:
        verdict  = "MALICIOUS"
        score    = 0.95
        behaviors = malicious_hits[:]
        if fork_count > _FORK_BOMB_THRESHOLD:
            behaviors.append(f"Fork bomb detected ({fork_count} fork/clone calls)")
    elif exec_count > _EXEC_CHAIN_THRESHOLD or suspicious_hits:
        verdict   = "SUSPICIOUS"
        score     = 0.70 if exec_count > _EXEC_CHAIN_THRESHOLD else 0.55
        behaviors = suspicious_hits[:]
        if exec_count > _EXEC_CHAIN_THRESHOLD:
            behaviors.append(f"Dropper chain detected ({exec_count} execve calls)")
    else:
        verdict  = "CLEAN"
        score    = 0.0

    return {
        "verdict":        verdict,
        "sandbox_score":  score,
        "behaviors":      behaviors,
        "syscall_counts": syscall_counts,
    }


def _run_in_sandbox(file_bytes: bytes, filename: str, runner: list) -> dict:
    """
    Inject file into an ephemeral Docker container via put_archive (no bind mount),
    run it under strace, and return the analysis result.

    Using put_archive instead of bind mounts avoids the Docker-in-Docker path
    resolution problem where the sandbox service runs inside a container and
    the host Docker daemon cannot resolve paths inside that container.
    """
    import docker
    import docker.errors

    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        # strace writes to stdout via /proc/self/fd/1 — no output file needed,
        # so we avoid any filesystem write issues inside the container.
        command = (
            ["strace", "-f",
             "-e", "trace=network,file,process,signal",
             "-o", "/proc/self/fd/1",
             "timeout", "20"]
            + runner
            + ["/malware/target"]
        )

        # Create container but do NOT start it yet
        container = client.containers.create(
            image=SANDBOX_BASE_IMAGE,
            command=command,
            network_mode="none",
            read_only=True,
            mem_limit="256m",
            nano_cpus=500_000_000,   # 0.5 CPU
            pids_limit=50,
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],
            security_opt=["no-new-privileges"],
            tmpfs={"/tmp": "size=50m,noexec,nosuid"},
        )

        # Inject the file via Docker API (works regardless of where this service runs)
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info      = tarfile.TarInfo(name="target")
            info.size = len(file_bytes)
            info.mode = 0o755   # must be executable
            tar.addfile(info, io.BytesIO(file_bytes))
        tar_buf.seek(0)
        container.put_archive("/malware", tar_buf)

        # Start and wait (up to 25 s wall-clock)
        container.start()
        try:
            container.wait(timeout=25)
        except Exception:
            logger.warning(f"Container timeout for '{filename}' — collecting partial trace")

        runtime_ms = int((time.time() - start_ms) * 1000)

        # Collect strace output written to container stdout
        trace_text = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")

        if not trace_text.strip():
            logger.warning(f"Empty strace output for '{filename}' — binary may have crashed immediately")

        logger.debug(f"Trace sample for '{filename}': {trace_text[:500]}")

        result = _analyze_trace(trace_text)
        result["runtime_ms"] = runtime_ms
        return result

    except Exception as exc:
        logger.error(f"Sandbox execution error for '{filename}': {exc}", exc_info=True)
        return {
            "verdict":        "ERROR",
            "sandbox_score":  0.0,
            "behaviors":      [],
            "syscall_counts": {},
            "runtime_ms":     int((time.time() - start_ms) * 1000),
            "error":          str(exc),
        }
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    """
    Sandbox a file by executing it in an isolated Docker container under strace.
    Accepts multipart/form-data with a 'file' field.
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

        runner_label = runner[0] if runner else "direct ELF"
        logger.info(f"Sandboxing '{filename}' (runner={runner_label}, size={len(file_bytes)} bytes)")

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
    docker_ok  = False
    image_ok   = False
    extra: dict = {}

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
        extra["error"] = str(exc)

    return jsonify({
        "status":      "ok" if docker_ok else "degraded",
        "service":     "sandbox",
        "docker_ok":   docker_ok,
        "base_image":  SANDBOX_BASE_IMAGE,
        "image_ready": image_ok,
        **extra,
    }), 200 if docker_ok else 503


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting sandbox service on port 5004 (debug={debug})")
    app.run(host="0.0.0.0", port=5004, debug=debug, use_reloader=debug)
