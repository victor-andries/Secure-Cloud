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
SANDBOX_DOS_IMAGE  = os.getenv("SANDBOX_DOS_IMAGE",  "scp-sandbox-dos")
SANDBOX_WINE_IMAGE = os.getenv("SANDBOX_WINE_IMAGE", "scp-sandbox-wine")

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
    (re.compile(r'openat?\(.*"/targets/[^"]+",.*O_(?:WRONLY|RDWR)'),
     "Writing to decoy target file"),
]

_SUSPICIOUS_PATTERNS = [
    (re.compile(r'openat?\(.*"/etc/passwd"'),          "Credential file read"),
    (re.compile(r'openat?\(.*"/proc/self/mem"'),       "Self-memory manipulation"),
    (re.compile(r'chmod\(.*0[0-9]*[67][0-9]*\)'),     "Making file executable"),
    (re.compile(r'unlink\(|unlinkat\('),               "File deletion"),
    (re.compile(r'bind\('),                            "Socket bind (listener)"),
    (re.compile(r'openat?\(.*O_(?:WRONLY|RDWR|CREAT).*=\s*-1\s*E(?:PERM|ACCES|ROFS)'),
     "Blocked file write attempt — possible file infector"),
    (re.compile(r'write\(.*=\s*-1\s*E(?:PERM|ROFS)'),
     "Write syscall blocked by read-only filesystem"),
]

_FORK_BOMB_THRESHOLD  = 30
_EXEC_CHAIN_THRESHOLD = 8
# A Unix virus opens many files for writing (to infect them); 3+ is suspicious
_WRITE_ATTEMPT_THRESHOLD = 3


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


def _run_in_elf_sandbox(file_bytes: bytes, filename: str, runner: list) -> dict:
    """
    Run ELF binary or script in isolated sandbox.
    Uses decoy ELF files in /targets/ (writable tmpfs) to detect file infectors:
    hashes are captured before and after execution; any change = MALICIOUS.
    """
    import docker
    import docker.errors

    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        container = client.containers.create(
            image=SANDBOX_BASE_IMAGE,
            command=["sleep", "30"],
            network_mode="none",
            read_only=True,
            mem_limit="256m",
            nano_cpus=500_000_000,
            pids_limit=50,
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],
            security_opt=["no-new-privileges"],
            tmpfs={
                "/tmp":     "size=50m,noexec,nosuid",
                "/targets": "size=10m",   # writable + exec for decoy ELFs
            },
        )
        container.start()

        # Copy decoys from image's /decoys/ (read-only) into /targets/ (writable tmpfs)
        container.exec_run(["sh", "-c", "cp /decoys/* /targets/"], demux=False)

        # Capture baseline hashes of all decoy files
        _, baseline_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/*"], demux=False
        )
        baseline_hashes = baseline_raw.decode("utf-8", errors="replace") if baseline_raw else ""

        # Inject malware via Docker API (bypasses read_only for the overlay write)
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info      = tarfile.TarInfo(name="target")
            info.size = len(file_bytes)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(file_bytes))
        tar_buf.seek(0)
        container.put_archive("/malware", tar_buf)

        # Build strace command string (runner is [] for ELF, ["python3"] for .py, etc.)
        runner_str = " ".join(runner) + " " if runner else ""
        strace_cmd = (
            f"strace -f -e trace=network,file,process,signal "
            f"-o /proc/self/fd/1 timeout 20 {runner_str}/malware/target 2>/dev/null"
        )
        _, strace_raw = container.exec_run(["sh", "-c", strace_cmd], demux=False)
        trace_text = strace_raw.decode("utf-8", errors="replace") if strace_raw else ""

        if not trace_text.strip():
            logger.warning(f"Empty strace output for '{filename}'")

        logger.debug(f"Trace sample for '{filename}': {trace_text[:500]}")

        # Re-hash decoys; any change means the malware modified them (file infector)
        _, current_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/*"], demux=False
        )
        current_hashes = current_raw.decode("utf-8", errors="replace") if current_raw else ""
        decoy_modified = bool(
            baseline_hashes and current_hashes and baseline_hashes != current_hashes
        )

        result = _analyze_trace(trace_text)
        result["runtime_ms"] = int((time.time() - start_ms) * 1000)

        if decoy_modified:
            result["verdict"]       = "MALICIOUS"
            result["sandbox_score"] = 0.95
            result["behaviors"].insert(0, "File infector: decoy ELF files were modified after execution")
            logger.warning(f"File infector confirmed for '{filename}': decoy hashes changed")

        return result

    except Exception as exc:
        logger.error(f"ELF sandbox error for '{filename}': {exc}", exc_info=True)
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


def _run_in_dos_sandbox(file_bytes: bytes, filename: str) -> dict:
    """
    Run DOS COM file in DOSBox sandbox.
    Decoy COM files (2 bytes each) are placed alongside the target.
    Any size increase in a decoy = file infector confirmed.
    Any new .com files = dropper behavior.
    """
    import docker
    import docker.errors

    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        container = client.containers.create(
            image=SANDBOX_DOS_IMAGE,
            command=["sleep", "30"],
            network_mode="none",
            read_only=False,   # DOSBox writes its own state files
            mem_limit="256m",
            nano_cpus=500_000_000,
            pids_limit=50,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            tmpfs={"/tmp": "size=50m,noexec,nosuid"},
        )
        container.start()

        # Copy decoys from /dosbox/c/decoys/ into target_dir so infector finds them
        container.exec_run(
            ["sh", "-c", "cp /dosbox/c/decoys/*.com /dosbox/c/target_dir/"],
            demux=False
        )

        # Inject the COM target file
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info      = tarfile.TarInfo(name="target.com")
            info.size = len(file_bytes)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(file_bytes))
        tar_buf.seek(0)
        container.put_archive("/dosbox/c/target_dir", tar_buf)

        # Run DOSBox headlessly (SDL_VIDEODRIVER=dummy suppresses the window)
        container.exec_run(
            ["sh", "-c",
             "SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy "
             "timeout 15 dosbox -conf /dosbox/dosbox.conf -exit 2>/dev/null || true"],
            demux=False
        )

        behaviors = []
        verdict   = "CLEAN"
        score     = 0.0

        # Check for new .com files (dropper/replication): initial count = 5 decoys + 1 target
        _, ls_raw = container.exec_run(
            ["sh", "-c", "ls /dosbox/c/target_dir/*.com 2>/dev/null | wc -l"],
            demux=False
        )
        try:
            file_count = int((ls_raw or b'0').decode().strip())
        except ValueError:
            file_count = 0

        if file_count > 6:  # 5 decoys + 1 target.com = 6
            new_files = file_count - 6
            behaviors.append(f"COM dropper: {new_files} new file(s) created in target directory")
            verdict = "SUSPICIOUS"
            score   = 0.75

        # Check decoy file sizes: each decoy is exactly 2 bytes (0xCD 0x20)
        # Any size > 2 means the COM infector appended/prepended its code
        _, sizes_raw = container.exec_run(
            ["sh", "-c",
             "wc -c /dosbox/c/target_dir/decoy_*.com 2>/dev/null"],
            demux=False
        )
        sizes_text = (sizes_raw or b'').decode()
        for line in sizes_text.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                try:
                    size = int(parts[0])
                    path = parts[1]
                    if size > 2:
                        behaviors.append(
                            f"File infector: {os.path.basename(path)} modified "
                            f"({size} bytes, was 2)"
                        )
                        verdict = "MALICIOUS"
                        score   = 0.95
                except ValueError:
                    pass

        runtime_ms = int((time.time() - start_ms) * 1000)
        logger.info(
            f"DOS sandbox result for '{filename}': verdict={verdict} "
            f"score={score} behaviors={behaviors}"
        )
        return {
            "verdict":        verdict,
            "sandbox_score":  score,
            "behaviors":      behaviors,
            "syscall_counts": {},
            "runtime_ms":     runtime_ms,
        }

    except Exception as exc:
        logger.error(f"DOS sandbox error for '{filename}': {exc}", exc_info=True)
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


def _run_in_wine_sandbox(file_bytes: bytes, filename: str) -> dict:
    """
    Run Windows PE file under Wine with strace monitoring.
    strace captures Linux syscalls Wine makes on behalf of the Windows process.
    Decoy PE files in /targets/ are integrity-checked after execution.
    """
    import docker
    import docker.errors

    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        container = client.containers.create(
            image=SANDBOX_WINE_IMAGE,
            command=["sleep", "60"],   # Wine needs more startup time
            network_mode="none",
            read_only=True,
            mem_limit="256m",
            nano_cpus=500_000_000,
            pids_limit=100,            # Wine spawns several helper processes
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],
            security_opt=["no-new-privileges"],
            tmpfs={
                "/tmp":     "size=50m,noexec,nosuid",
                "/targets": "size=20m",
                "/wine":    "size=100m",   # Wine prefix must be writable
            },
        )
        container.start()

        # Copy decoys into /targets/ (writable tmpfs)
        container.exec_run(["sh", "-c", "cp /decoys/*.exe /targets/"], demux=False)

        # Baseline decoy hashes
        _, baseline_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/*.exe"], demux=False
        )
        baseline_hashes = (baseline_raw or b'').decode("utf-8", errors="replace")

        # Inject PE target
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info      = tarfile.TarInfo(name="target.exe")
            info.size = len(file_bytes)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(file_bytes))
        tar_buf.seek(0)
        container.put_archive("/malware", tar_buf)

        # Run wine under strace — captures Linux syscalls Wine makes for the PE
        strace_cmd = (
            "WINEPREFIX=/wine WINEDEBUG=-all "
            "strace -f -e trace=network,file,process,signal "
            "-o /proc/self/fd/1 timeout 30 wine /malware/target.exe 2>/dev/null"
        )
        _, strace_raw = container.exec_run(["sh", "-c", strace_cmd], demux=False)
        trace_text = (strace_raw or b'').decode("utf-8", errors="replace")

        logger.debug(f"Wine strace sample for '{filename}': {trace_text[:500]}")

        # Post-execution decoy integrity check
        _, current_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/*.exe"], demux=False
        )
        current_hashes = (current_raw or b'').decode("utf-8", errors="replace")
        decoy_modified = bool(
            baseline_hashes and current_hashes and baseline_hashes != current_hashes
        )

        result = _analyze_trace(trace_text)
        result["runtime_ms"] = int((time.time() - start_ms) * 1000)

        if decoy_modified:
            result["verdict"]       = "MALICIOUS"
            result["sandbox_score"] = 0.95
            result["behaviors"].insert(0, "PE file infector: decoy EXE files were modified")
            logger.warning(f"PE file infector confirmed for '{filename}'")

        return result

    except Exception as exc:
        logger.error(f"Wine sandbox error for '{filename}': {exc}", exc_info=True)
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
    """Health check — verify Docker daemon is reachable and all sandbox images exist."""
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


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting sandbox service on port 5004 (debug={debug})")
    app.run(host="0.0.0.0", port=5004, debug=debug, use_reloader=debug)
