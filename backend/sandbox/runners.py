import io
import os
import time
import tarfile
import logging
import base64 as _b64
import docker

from .config import SANDBOX_BASE_IMAGE, SANDBOX_DOS_IMAGE, SANDBOX_WINE_IMAGE
from .platform import _qemu_for_elf
from .trace import _analyze_trace

logger = logging.getLogger("sandbox.runners")


def _run_in_elf_sandbox(file_bytes: bytes, filename: str, runner: list) -> dict:
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
                "/targets": "size=10m,exec",
            },
        )
        container.start()

        container.exec_run(["sh", "-c", "cp /decoys/* /targets/"], demux=False)

        _, baseline_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/decoy*"], demux=False
        )
        baseline_hashes = baseline_raw.decode("utf-8", errors="replace") if baseline_raw else ""

        encoded = _b64.b64encode(file_bytes).decode("ascii")
        container.exec_run(
            ["sh", "-c", f"printf '%s' '{encoded}' | base64 -d > /targets/malware"],
            demux=False
        )
        container.exec_run(["chmod", "755", "/targets/malware"], demux=False)

        qemu = _qemu_for_elf(file_bytes)
        qemu_prefix = f"{qemu} " if qemu else ""
        if qemu:
            logger.info(f"'{filename}' is non-native ELF — using {qemu} for execution")

        runner_str = " ".join(runner) + " " if runner else ""
        strace_cmd = (
            f"strace -f -e trace=network,file,process,signal "
            f"-o /tmp/trace.log timeout 20 {qemu_prefix}{runner_str}/targets/malware 2>/dev/null; "
            f"cat /tmp/trace.log"
        )
        _, strace_raw = container.exec_run(
            ["sh", "-c", strace_cmd], demux=False, workdir="/targets"
        )
        trace_text = strace_raw.decode("utf-8", errors="replace") if strace_raw else ""

        if not trace_text.strip():
            logger.warning(f"Empty strace output for '{filename}'")

        trace_lines = trace_text.splitlines()
        if len(trace_lines) <= 150:
            logger.info(f"Full trace for '{filename}' ({len(trace_lines)} lines):\n{trace_text}")
        else:
            keywords = ("malware", "decoy", "sendfile", "O_WRONLY", "O_RDWR", "O_CREAT",
                        "ENOEXEC", "EPERM", "EROFS", "EACCES", "creat(", "getdents", r"\.elf")
            relevant = [l for l in trace_lines if any(k in l for k in keywords)]
            logger.info(
                f"Trace diagnostics for '{filename}' "
                f"(total_lines={len(trace_lines)}, relevant={len(relevant)}): "
                f"{relevant[:60]}"
            )

        _, current_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/decoy*"], demux=False
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
    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        container = client.containers.create(
            image=SANDBOX_DOS_IMAGE,
            command=["sleep", "30"],
            network_mode="none",
            read_only=False,
            mem_limit="256m",
            nano_cpus=500_000_000,
            pids_limit=50,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            tmpfs={"/tmp": "size=50m,noexec,nosuid"},
        )
        container.start()

        container.exec_run(
            ["sh", "-c", "cp /dosbox/c/decoys/*.com /dosbox/c/target_dir/"],
            demux=False
        )

        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info      = tarfile.TarInfo(name="target.com")
            info.size = len(file_bytes)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(file_bytes))
        tar_buf.seek(0)
        container.put_archive("/dosbox/c/target_dir", tar_buf)

        def _decoy_sizes() -> dict:
            _, raw = container.exec_run(
                ["sh", "-c", "wc -c /dosbox/c/target_dir/decoy_*.com 2>/dev/null"],
                demux=False
            )
            sizes: dict = {}
            for line in (raw or b'').decode().splitlines():
                parts = line.strip().split()
                if len(parts) == 2 and parts[1].startswith('/'):
                    try:
                        sizes[os.path.basename(parts[1])] = int(parts[0])
                    except ValueError:
                        pass
            return sizes

        baseline_sizes = _decoy_sizes()

        container.exec_run(
            ["sh", "-c",
             "SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy "
             "timeout 15 dosbox -conf /dosbox/dosbox.conf -exit 2>/dev/null || true"],
            demux=False
        )

        behaviors = []
        verdict   = "CLEAN"
        score     = 0.0

        _, ls_raw = container.exec_run(
            ["sh", "-c", "ls /dosbox/c/target_dir/*.com 2>/dev/null | wc -l"],
            demux=False
        )
        try:
            file_count = int((ls_raw or b'0').decode().strip())
        except ValueError:
            file_count = 0

        if file_count > 6:
            new_files = file_count - 6
            behaviors.append(f"COM dropper: {new_files} new file(s) created in target directory")
            verdict = "SUSPICIOUS"
            score   = 0.75

        final_sizes = _decoy_sizes()
        for name, size in final_sizes.items():
            base = baseline_sizes.get(name)
            if base is not None and size != base:
                behaviors.append(
                    f"File infector: {name} modified "
                    f"({size} bytes, was {base})"
                )
                verdict = "MALICIOUS"
                score   = 0.95

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
    start_ms  = time.time()
    container = None

    try:
        client = docker.from_env()

        container = client.containers.create(
            image=SANDBOX_WINE_IMAGE,
            command=["sleep", "60"],
            network_mode="none",
            read_only=True,
            mem_limit="256m",
            nano_cpus=500_000_000,
            pids_limit=100,
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],
            security_opt=["no-new-privileges"],
            tmpfs={
                "/tmp":     "size=50m,noexec,nosuid",
                "/targets": "size=20m",
                "/wine":    "size=100m",
            },
        )
        container.start()

        container.exec_run(
            ["sh", "-c", "WINEPREFIX=/wine WINEDEBUG=-all wineboot --init 2>/dev/null"],
            demux=False
        )

        container.exec_run(["sh", "-c", "cp /decoys/*.exe /targets/"], demux=False)

        _, baseline_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/decoy*"], demux=False
        )
        baseline_hashes = (baseline_raw or b'').decode("utf-8", errors="replace")

        encoded = _b64.b64encode(file_bytes).decode("ascii")
        container.exec_run(
            ["sh", "-c", f"printf '%s' '{encoded}' | base64 -d > /targets/malware.exe"],
            demux=False
        )
        container.exec_run(["chmod", "755", "/targets/malware.exe"], demux=False)

        strace_cmd = (
            "WINEPREFIX=/wine WINEDEBUG=-all "
            "strace -f -e trace=network,file,process,signal "
            "-o /tmp/trace.log timeout 30 wine /targets/malware.exe 2>/dev/null; "
            "cat /tmp/trace.log"
        )
        _, strace_raw = container.exec_run(["sh", "-c", strace_cmd], demux=False)
        trace_text = (strace_raw or b'').decode("utf-8", errors="replace")

        logger.debug(f"Wine strace sample for '{filename}': {trace_text[:500]}")

        _, current_raw = container.exec_run(
            ["sh", "-c", "sha256sum /targets/decoy*"], demux=False
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
