# Virus Detection & Sandbox Improvements Design

**Date:** 2026-04-29
**Branch:** master
**Approach:** B — Targeted heuristics + multi-platform sandbox

---

## Problem Statement

Two malware samples uploaded as CLEAN (undetected):

1. **x21 COM file infector** — DOS/COM format not recognized by sandbox; no static heuristics for COM executables
2. **ELF32 file infector** — Sandbox runs ELF but `readonlyrootfs=True` blocks all writes with `EPERM`; infection attempts fail silently; strace never sees the `\177ELF` write pattern the detector expects

---

## Root Causes

| Sample | Layer 1 (Static) | Layer 2 (Sandbox) |
|--------|-----------------|-------------------|
| COM file infector | No COM heuristics | Not routed to sandbox at all |
| ELF32 file infector | Low entropy, no pattern strings | `EPERM` on infection attempts; no decoy targets; CLEAN reported |

---

## Architecture Changes

### 1. Sandbox Dispatcher (sandbox_service.py)

New `_detect_platform()` function replaces the current single-path ELF check:

```
File received
    ↓
_detect_platform():
    ├─ Magic \x7fELF          → Linux ELF sandbox (fixed with decoys)
    ├─ MZ header (0x4D5A)     → Windows sandbox (Wine, port 5006)  ← checked before .com
    ├─ .com + jump byte       → DOS sandbox (DOSBox, port 5005)
    ├─ Mach-O magic bytes     → Static-only Mach-O analysis
    ├─ .sh / .py / .pl        → Linux script sandbox (existing)
    └─ Unknown                → Static content scan only
```

Note: MZ header is checked before `.com` extension so that 32-bit PE files with a `.com` extension are correctly routed to the Wine sandbox, not DOSBox.

The sandbox service acts as a dispatcher, forwarding files to the correct backend container service based on detected format.

---

## Section 1: ELF File Infector Detection Fix

### Sandbox Changes (sandbox_service.py + scp-sandbox-base image)

- Keep `readonlyrootfs=True` — do NOT remove it
- Add explicit `tmpfs` mounts for `/targets/` and `/tmp/` in the container config; Docker allows writable tmpfs mounts even on a read-only rootfs
- `/targets/` tmpfs is pre-populated at container startup by copying decoy binaries from the image into the tmpfs (via an entrypoint script)
- 5 pre-built minimal ELF32 and ELF64 decoy binaries baked into the image at `/decoys/`; entrypoint copies them to `/targets/` before malware execution
- Before execution: SHA-256 hash all decoy files, store in memory
- After execution: re-hash all decoy files — any change → **file infector confirmed**, score forced to 0.95, verdict MALICIOUS

### New strace Patterns

| Pattern | Verdict | Score |
|---------|---------|-------|
| `openat`/`open` on `/targets/*` with `O_WRONLY`/`O_RDWR`/`O_CREAT` | SUSPICIOUS | +0.30 |
| `EPERM` on write syscall targeting non-target executable | SUSPICIOUS | +0.20 |
| `lseek` to offset 0 on open file + subsequent `write` (header injection) | SUSPICIOUS | +0.25 |
| Decoy file hash mismatch after execution | MALICIOUS | 0.95 forced |

---

## Section 2: COM File Detection

### Static Analysis (ai_detection_service.py)

New `_analyze_com_file()` method:

**Format identification** (baseline +0.20):
- `.com` extension AND first byte is `0xEB` (short jump) or `0xE9` (near jump)

**File infector signatures** (each +0.25, cap 0.70):
- `\xCD\x21` — INT 21h DOS interrupt (required for any COM file I/O)
- `\x4E` or `\x4F` near INT 21h — FindFirst / FindNext file search
- Wildcard strings `*.com` or `*.exe` in binary — target search pattern
- File size < 2 KB — COM infectors are characteristically tiny
- `\xB4\x3C` or `\xB4\x3D` — AH=3Ch (create file) or AH=3Dh (open file) via INT 21h

### Dynamic Analysis (new scp-sandbox-dos service)

**Image:** `debian:bookworm-slim` + `dosbox`

**Execution flow:**
1. DOSBox mounts working directory as `C:` drive
2. Directory contains: target COM file + 5 pre-hashed decoy `.com` files (tiny valid DOS programs baked into image)
3. Autoexec script runs target COM file with 10-second timeout
4. After execution: re-hash all decoy COM files
5. New `.com` files appearing in directory = dropper behavior
6. DOSBox stdout/stderr captured and scanned for crash vs clean exit patterns

**Scoring:**
- Decoy COM file modified → score 0.95, verdict MALICIOUS
- New files created → score 0.75, verdict SUSPICIOUS
- Clean exit, no changes → score from static analysis only

---

## Section 3: Windows PE Analysis via Wine

### Static Analysis Improvements (ai_detection_service.py)

New `_analyze_pe_imports()` method extending the existing PE entropy check:

**Import table heuristics** (each match adds to score):

| Pattern | Score |
|---------|-------|
| `CreateRemoteThread` + `VirtualAllocEx` + `WriteProcessMemory` | +0.35 |
| `RegSetValueEx` + run key path pattern | +0.25 |
| `CryptEncrypt` + `CryptGenRandom` + file enumeration APIs | +0.30 |
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | +0.15 |
| `W`+`X` section flags (write + execute) | +0.25 |

**File types routed through PE analysis:** `.exe`, `.dll`, `.scr`, `.com` (32-bit PE variant, distinguished from DOS COM by MZ header)

### Dynamic Analysis (new scp-sandbox-wine service)

**Image:** `debian:bookworm-slim` + `wine` + `wine32`

**Execution flow:**
1. Wine's `C:\targets\` mapped to writable tmpfs containing pre-hashed decoy PE files
2. `strace` wraps the `wine` host process — captures Linux syscalls made by Wine on behalf of the Windows program
3. 30-second timeout (Wine needs extra startup time vs native ELF)
4. Same decoy hash comparison as ELF and DOS sandboxes

**Detected behaviors via Wine strace:**

| Linux syscall pattern | Windows behavior | Score |
|----------------------|-----------------|-------|
| `connect()` / `socket()` | Network C2 callback | MALICIOUS |
| `openat` on `*.exe`/`*.dll` with write flags | PE file infector | MALICIOUS |
| Mass `unlink()` calls | Ransomware deletion | MALICIOUS |
| `fork()` + `execve()` chains (>8) | Dropper chain | SUSPICIOUS |

**Isolation:** `network_mode="none"`, 256MB RAM, 0.5 CPU — same as existing ELF sandbox.

---

## Section 4: macOS Static Analysis (Mach-O)

Dynamic macOS analysis is not feasible in Docker without macOS hardware. This layer is static-only.

### Magic Byte Detection (ai_detection_service.py)

| Magic bytes | Format | Baseline score |
|-------------|--------|---------------|
| `0xFEEDFACE` / `0xCEFAEDFE` | Mach-O 32-bit | +0.15 |
| `0xFEEDFACF` / `0xCFFAEDFE` | Mach-O 64-bit | +0.15 |
| `0xCAFEBABE` | Fat/universal binary | +0.15 |

### Load Command Analysis (+0.20–0.30 each)

- `LC_RPATH` with relative path → dylib hijacking setup, +0.25
- `__TEXT`+`__DATA` segment with write+execute permissions → shellcode staging, +0.30
- `LC_LOAD_DYLIB` referencing injection frameworks → +0.20

### String Heuristics (+0.20 each, cap 0.60)

- `/Library/LaunchAgents/` or `/Library/LaunchDaemons/` → launchd persistence
- `osascript` / `applescript` → scripted system access
- `kext` / `IOKit` → kernel extension (rootkit potential)
- `task_for_pid` → process injection API
- `/var/db/dslocal/nodes/Default/users/` → credential theft target

### Archive Support

`.dmg` and `.pkg` files: scan internal file listings for Mach-O files and apply the above heuristics to each.

### API Response

When Mach-O is detected, response includes:
```json
{
  "platform": "macos",
  "dynamic_analysis": "not_available",
  "reason": "macOS dynamic analysis requires macOS hardware"
}
```

---

## Section 5: Integration

### Docker Compose Additions

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `scp-sandbox-dos` | `scp-sandbox-dos` | 5005 | DOSBox COM analysis |
| `scp-sandbox-wine` | `scp-sandbox-wine` | 5006 | Wine PE analysis |

Both services use identical isolation to existing `scp-sandbox`: `network_mode="none"`, memory limit 256MB, CPU 0.5, `SYS_PTRACE` capability only.

### Sandbox Base Image Updates

| Image | Changes |
|-------|---------|
| `scp-sandbox-base` (existing) | Add decoy ELF32+ELF64 binaries; remove `readonlyrootfs`; add `/targets/` tmpfs |
| `scp-sandbox-dos` (new) | `debian:bookworm-slim` + `dosbox` + decoy COM files |
| `scp-sandbox-wine` (new) | `debian:bookworm-slim` + `wine` + `wine32` + decoy PE files |

### Scoring Pipeline (no changes to existing thresholds)

- Decoy file modification → forces score to 0.95, bypasses normal blending
- Blocked infection attempt (`EPERM` on write) → SUSPICIOUS 0.65
- All results feed into existing `ensemble_score` blending in `main.py` unchanged

### Files Modified

| File | Changes |
|------|---------|
| `backend/ai_detection_service.py` | Add `_analyze_com_file()`, `_analyze_pe_imports()`, `_analyze_macho()`, Mach-O archive inspection |
| `backend/sandbox_service.py` | Add `_detect_platform()` dispatcher, decoy hash comparison, new strace patterns, Wine/DOS routing |
| `backend/sandbox_base/Dockerfile` | Add decoy ELF binaries, remove readonlyrootfs dependency |
| `backend/sandbox_dos/Dockerfile` | New: DOSBox image with decoy COM files |
| `backend/sandbox_wine/Dockerfile` | New: Wine image with decoy PE files |
| `docker-compose.yml` | Add `scp-sandbox-dos` and `scp-sandbox-wine` services |

---

## Out of Scope

- ClamAV / external AV engine integration
- YARA rules
- macOS dynamic analysis
- Android / iOS / WASM formats
- Network-level traffic capture (sandbox has no network)
