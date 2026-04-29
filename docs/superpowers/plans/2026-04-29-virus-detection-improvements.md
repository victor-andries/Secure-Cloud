# Virus Detection & Sandbox Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the ELF file infector going undetected, add COM/DOS detection, add Windows PE import analysis, add macOS Mach-O static analysis, and wire all into the sandbox dispatcher.

**Architecture:** Three new static analysis functions added to `ai_detection_service.py`; `sandbox_service.py` gains a platform dispatcher and per-format sandbox runners (ELF fixed with decoy integrity, DOS via DOSBox, Windows via Wine); two new Docker images (`scp-sandbox-dos`, `scp-sandbox-wine`) added alongside the existing `scp-sandbox-base`.

**Tech Stack:** Python 3.10, Flask, Docker SDK (docker-py), DOSBox, Wine + wine32, mingw-w64 (compile-time only), pytest, struct (stdlib)

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `backend/ai_detection_service.py` | Add `_analyze_com_file()`, `_analyze_pe_imports()`, `_analyze_macho()` + call sites in `analyze_file_content()` |
| Modify | `backend/sandbox_service.py` | Add `_detect_platform()`, refactor `_run_in_sandbox()` → `_run_in_elf_sandbox()`, add `_run_in_dos_sandbox()`, `_run_in_wine_sandbox()`, update `analyze()` endpoint |
| Modify | `backend/sandbox_base/Dockerfile` | Multi-stage: compile ELF32/ELF64 decoy binaries, bake into `/decoys/` |
| Create | `backend/sandbox_dos/Dockerfile` | DOSBox + 1-byte COM decoys baked into `/dosbox/c/decoys/` |
| Create | `backend/sandbox_dos/dosbox.conf` | Headless DOSBox config with autoexec that runs `target.com` |
| Create | `backend/sandbox_wine/Dockerfile` | Multi-stage: mingw-w64 builds decoy EXEs, Wine + strace in runtime image |
| Modify | `docker-compose.yml` | Add build sections for `scp-sandbox-dos` and `scp-sandbox-wine` |
| Create | `backend/tests/test_static_analysis.py` | Unit tests for all three new static analysis functions |
| Create | `backend/tests/test_sandbox_routing.py` | Unit tests for `_detect_platform()` |

---

## Task 1: COM Static Analysis

**Files:**
- Modify: `backend/ai_detection_service.py` (after line 191, and inside `analyze_file_content()` at line 403)
- Create: `backend/tests/test_static_analysis.py`

- [ ] **Step 1: Create the test file with failing COM tests**

Create `backend/tests/__init__.py` (empty) and `backend/tests/test_static_analysis.py`:

```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Patch redis before importing the module (avoids connection errors in tests)
import unittest.mock as mock
with mock.patch('redis.Redis'):
    from ai_detection_service import _analyze_com_file, analyze_file_content


def test_com_infector_detected():
    # Classic COM infector: jump, INT 21h FindNext, wildcard, create-file call
    data = (
        b'\xEB\x00'       # short jump (COM identifier)
        b'\xCD\x21'       # INT 21h
        b'\x4E'           # FindFirst
        b'*.com\x00'      # wildcard target
        b'\xB4\x3C'       # MOV AH, 3Ch (create file)
    )
    score = _analyze_com_file(data, "virus.com")
    assert score >= 0.50, f"Expected >= 0.50, got {score}"


def test_com_pe_not_analyzed():
    # A .com file that is actually a PE (MZ header) must be skipped
    data = b'MZ' + b'\x00' * 100
    score = _analyze_com_file(data, "app.com")
    assert score == 0.0, f"PE .com must return 0.0, got {score}"


def test_com_not_com_extension():
    data = b'\xEB\x00' + b'\xCD\x21' + b'*.com\x00'
    score = _analyze_com_file(data, "script.py")
    assert score == 0.0, f"Non-.com extension must return 0.0, got {score}"


def test_com_no_jump_byte():
    # COM file without initial jump byte is not recognized
    data = b'\x90\x90' + b'\xCD\x21' + b'*.com\x00'
    score = _analyze_com_file(data, "test.com")
    assert score == 0.0, f"No jump byte must return 0.0, got {score}"


def test_com_clean_baseline():
    # Minimal valid COM (just a NOP + exit via INT 21h AH=4Ch)
    data = b'\xEB\x00' + b'\xB4\x4C' + b'\xCD\x21'
    score = _analyze_com_file(data, "clean.com")
    # Gets baseline 0.20 for being a valid COM + 0.25 for INT 21h = 0.45
    assert score <= 0.50, f"Clean COM should score low, got {score}"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -v 2>&1 | head -30
```

Expected: `ImportError` or `AttributeError: module has no attribute '_analyze_com_file'`

- [ ] **Step 3: Add `_analyze_com_file()` to `ai_detection_service.py`**

Add after line 191 (after the `_PE_EXTENSIONS` definition):

```python
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
    if b'\xCD\x21' in data:
        infector_score += 0.25  # INT 21h — the only way a COM file does I/O

    idx = data.find(b'\xCD\x21')
    if idx != -1:
        window = data[max(0, idx - 10): idx + 10]
        if b'\x4E' in window or b'\x4F' in window:  # FindFirst / FindNext
            infector_score += 0.25

    if b'*.com' in data or b'*.COM' in data or b'*.exe' in data or b'*.EXE' in data:
        infector_score += 0.25

    if len(data) < 2048:
        infector_score += 0.25  # COM infectors are characteristically tiny

    if b'\xB4\x3C' in data or b'\xB4\x3D' in data:  # create / open file via INT 21h
        infector_score += 0.25

    score += min(infector_score, 0.70)
    return min(score, 0.90)
```

- [ ] **Step 4: Call `_analyze_com_file()` inside `analyze_file_content()`**

In `analyze_file_content()`, add the following block inside the `else:` branch (non-archive files), immediately before the PE analysis block (around line 403, before `if ext in _PE_EXTENSIONS:`):

```python
        # --- DOS COM file analysis ---
        com_score = _analyze_com_file(file_bytes, filename)
        if com_score > 0.0:
            score += com_score
            if com_score >= 0.50:
                result["threat_type"] = result["threat_type"] or "DOS_COM_INFECTOR"
                logger.warning(
                    f"DOS COM infector indicators in '{filename}': score={com_score:.2f}"
                )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_static_analysis.py::test_com_infector_detected tests/test_static_analysis.py::test_com_pe_not_analyzed tests/test_static_analysis.py::test_com_not_com_extension tests/test_static_analysis.py::test_com_no_jump_byte tests/test_static_analysis.py::test_com_clean_baseline -v
```

Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add backend/ai_detection_service.py backend/tests/__init__.py backend/tests/test_static_analysis.py
git commit -m "feat: add DOS COM file infector static analysis"
```

---

## Task 2: PE Import Analysis

**Files:**
- Modify: `backend/ai_detection_service.py` (new function + updated PE block)
- Modify: `backend/tests/test_static_analysis.py` (append tests)

- [ ] **Step 1: Append failing PE import tests to test file**

Append to `backend/tests/test_static_analysis.py`:

```python
with mock.patch('redis.Redis'):
    from ai_detection_service import _analyze_pe_imports


def test_pe_injection_triad():
    data = b'CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00'
    score = _analyze_pe_imports(data)
    assert score >= 0.35, f"Injection triad must score >= 0.35, got {score}"


def test_pe_persistence():
    data = b'RegSetValueEx\x00CurrentVersion\\Run\x00'
    score = _analyze_pe_imports(data)
    assert score >= 0.25, f"Run key persistence must score >= 0.25, got {score}"


def test_pe_ransomware():
    data = b'CryptEncrypt\x00FindFirstFileW\x00FindNextFileW\x00'
    score = _analyze_pe_imports(data)
    assert score >= 0.30, f"Ransomware pattern must score >= 0.30, got {score}"


def test_pe_antidebug():
    data = b'IsDebuggerPresent\x00'
    score = _analyze_pe_imports(data)
    assert score >= 0.15, f"Anti-debug must score >= 0.15, got {score}"


def test_pe_benign():
    data = b'CreateWindowEx\x00MessageBox\x00GetLastError\x00'
    score = _analyze_pe_imports(data)
    assert score == 0.0, f"Benign imports must score 0.0, got {score}"
```

- [ ] **Step 2: Run to verify failure**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -k "pe_" -v 2>&1 | head -20
```

Expected: `AttributeError` — `_analyze_pe_imports` not defined

- [ ] **Step 3: Add `_analyze_pe_imports()` to `ai_detection_service.py`**

Add immediately after `_analyze_com_file()`:

```python
def _analyze_pe_imports(data: bytes) -> float:
    """Score PE binary based on dangerous import name patterns found in its bytes."""
    score = 0.0

    if (b'CreateRemoteThread' in data
            and b'VirtualAllocEx' in data
            and b'WriteProcessMemory' in data):
        score += 0.35

    if b'RegSetValueEx' in data and b'CurrentVersion\\Run' in data:
        score += 0.25

    has_crypto = b'CryptEncrypt' in data or b'CryptGenRandom' in data
    has_enum = b'FindFirstFileW' in data or b'FindFirstFileA' in data
    if has_crypto and has_enum:
        score += 0.30

    if b'IsDebuggerPresent' in data or b'CheckRemoteDebuggerPresent' in data:
        score += 0.15

    return min(score, 0.90)
```

- [ ] **Step 4: Update the PE analysis block in `analyze_file_content()`**

Find the PE analysis block (around line 403):

```python
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
```

Replace with:

```python
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
                import_score = _analyze_pe_imports(file_bytes)
                if import_score > 0.0:
                    score += import_score
                    result["threat_type"] = result["threat_type"] or "MALICIOUS_PE_IMPORTS"
                    logger.warning(
                        f"Dangerous PE imports in '{filename}': score +{import_score:.2f}"
                    )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -k "pe_" -v
```

Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add backend/ai_detection_service.py backend/tests/test_static_analysis.py
git commit -m "feat: add PE import table heuristic analysis"
```

---

## Task 3: Mach-O Static Analysis

**Files:**
- Modify: `backend/ai_detection_service.py`
- Modify: `backend/tests/test_static_analysis.py`

- [ ] **Step 1: Append failing Mach-O tests**

Append to `backend/tests/test_static_analysis.py`:

```python
import struct as _struct

with mock.patch('redis.Redis'):
    from ai_detection_service import _analyze_macho


def _make_macho(magic_int: int) -> bytes:
    return _struct.pack('>I', magic_int) + b'\x00' * 200


def test_macho_64bit_detected():
    data = _make_macho(0xFEEDFACF)
    result = _analyze_macho(data)
    assert result["score"] >= 0.15
    assert result["platform"] == "macho64"


def test_macho_32bit_detected():
    data = _make_macho(0xFEEDFACE)
    result = _analyze_macho(data)
    assert result["score"] >= 0.15
    assert result["platform"] == "macho32"


def test_macho_fat_detected():
    data = _make_macho(0xCAFEBABE)
    result = _analyze_macho(data)
    assert result["score"] >= 0.15
    assert result["platform"] == "fat"


def test_macho_little_endian_detected():
    # 0xCFFAEDFE is little-endian 0xFEEDFACF
    data = _struct.pack('<I', 0xFEEDFACF) + b'\x00' * 200
    result = _analyze_macho(data)
    assert result["score"] >= 0.15


def test_macho_launchagent_persistence():
    data = _make_macho(0xFEEDFACF) + b'/Library/LaunchAgents/evil.plist\x00'
    result = _analyze_macho(data)
    assert result["score"] >= 0.35


def test_macho_task_for_pid():
    data = _make_macho(0xFEEDFACF) + b'task_for_pid\x00'
    result = _analyze_macho(data)
    assert result["score"] >= 0.35


def test_macho_dylib_hijacking():
    data = _make_macho(0xFEEDFACF) + b'@rpath/evil.dylib\x00'
    result = _analyze_macho(data)
    assert result["score"] >= 0.40


def test_not_macho():
    data = b'\x7fELF' + b'\x00' * 200
    result = _analyze_macho(data)
    assert result["score"] == 0.0
    assert result["platform"] == ""
```

- [ ] **Step 2: Run to verify failure**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -k "macho" -v 2>&1 | head -20
```

Expected: `AttributeError` — `_analyze_macho` not defined

- [ ] **Step 3: Add imports and constants to `ai_detection_service.py`**

At the top of the file, `import struct` is not yet imported. Add it to the existing imports block (after line 10, alongside `import re`):

```python
import struct
```

Then add these constants after `_analyze_pe_imports()`:

```python
_MACHO_MAGICS = {
    0xFEEDFACE: "macho32",
    0xCEFAEDFE: "macho32",
    0xFEEDFACF: "macho64",
    0xCFFAEDFE: "macho64",
    0xCAFEBABE: "fat",
}

_MACHO_DANGEROUS_STRINGS = [
    (b'/Library/LaunchAgents/',                0.20),
    (b'/Library/LaunchDaemons/',               0.20),
    (b'osascript',                              0.20),
    (b'applescript',                            0.20),
    (b'.kext',                                  0.20),
    (b'IOKit',                                  0.20),
    (b'task_for_pid',                           0.20),
    (b'/var/db/dslocal/nodes/Default/users/',   0.20),
]
```

- [ ] **Step 4: Add `_analyze_macho()` after the constants**

```python
def _analyze_macho(data: bytes) -> dict:
    """
    Static analysis of Mach-O binaries.
    Returns {"score": float, "platform": str, "threat_type": str|None}
    """
    if len(data) < 4:
        return {"score": 0.0, "platform": "", "threat_type": None}

    try:
        magic = struct.unpack('>I', data[:4])[0]
    except struct.error:
        return {"score": 0.0, "platform": "", "threat_type": None}

    if magic not in _MACHO_MAGICS:
        return {"score": 0.0, "platform": "", "threat_type": None}

    platform = _MACHO_MAGICS[magic]
    score = 0.15
    threat_type = "MACHO_EXECUTABLE"

    if b'@rpath' in data or b'@executable_path' in data or b'@loader_path' in data:
        score += 0.25
        threat_type = "MACHO_DYLIB_HIJACKING"

    string_score = sum(w for pat, w in _MACHO_DANGEROUS_STRINGS if pat in data)
    score += min(string_score, 0.60)
    if string_score > 0:
        threat_type = "MACHO_SUSPICIOUS"

    return {
        "score": round(min(score, 0.90), 4),
        "platform": platform,
        "threat_type": threat_type,
    }
```

- [ ] **Step 5: Call `_analyze_macho()` in `analyze_file_content()`**

Add a new `_MACHO_EXTENSIONS` set after `_PE_EXTENSIONS`:

```python
_MACHO_EXTENSIONS = {"dylib", "bundle", "framework", "app"}
```

Then inside `analyze_file_content()`, in the `else:` branch, add a Mach-O block after the PE block:

```python
        # --- Mach-O file analysis ---
        macho_result = _analyze_macho(file_bytes)
        if macho_result["score"] > 0.0:
            score += macho_result["score"]
            result["threat_type"] = result["threat_type"] or macho_result["threat_type"]
            result["platform"] = macho_result["platform"]
            logger.warning(
                f"Mach-O binary '{filename}': platform={macho_result['platform']} "
                f"score={macho_result['score']:.2f} type={macho_result['threat_type']}"
            )
```

Also handle `.dmg` and `.pkg` inside `_inspect_archive()`: add `"dmg"` and `"pkg"` to `_ARCHIVE_EXTENSIONS`:

```python
_ARCHIVE_EXTENSIONS = {"zip", "tar", "gz", "bz2", "xz", "7z", "rar", "dmg", "pkg"}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -k "macho" -v
```

Expected: 8 passed

- [ ] **Step 7: Run full test suite to check for regressions**

```bash
cd backend && python -m pytest tests/test_static_analysis.py -v
```

Expected: all tests pass

- [ ] **Step 8: Commit**

```bash
git add backend/ai_detection_service.py backend/tests/test_static_analysis.py
git commit -m "feat: add Mach-O static analysis and DMG/PKG archive inspection"
```

---

## Task 4: Platform Dispatcher in sandbox_service.py

**Files:**
- Create: `backend/tests/test_sandbox_routing.py`
- Modify: `backend/sandbox_service.py`

- [ ] **Step 1: Create failing platform dispatcher tests**

Create `backend/tests/test_sandbox_routing.py`:

```python
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sandbox_service import _detect_platform


def test_elf64():
    data = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
    assert _detect_platform(data, "binary") == "elf"


def test_elf32():
    data = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 100
    assert _detect_platform(data, "binary") == "elf"


def test_windows_exe():
    data = b'MZ' + b'\x00' * 100
    assert _detect_platform(data, "malware.exe") == "windows"


def test_windows_dll():
    data = b'MZ' + b'\x00' * 100
    assert _detect_platform(data, "inject.dll") == "windows"


def test_pe_com_not_dos():
    # .com extension but MZ header → must route to Windows, not DOS
    data = b'MZ' + b'\x00' * 100
    assert _detect_platform(data, "app.com") == "windows"


def test_dos_com():
    data = b'\xEB\x00' + b'\xCD\x21' + b'*.com\x00'
    assert _detect_platform(data, "virus.com") == "dos"


def test_dos_com_e9_jump():
    data = b'\xE9\x00\x00' + b'\xCD\x21'
    assert _detect_platform(data, "virus.com") == "dos"


def test_macho64():
    data = struct.pack('>I', 0xFEEDFACF) + b'\x00' * 100
    assert _detect_platform(data, "binary") == "macos"


def test_macho32():
    data = struct.pack('>I', 0xFEEDFACE) + b'\x00' * 100
    assert _detect_platform(data, "binary") == "macos"


def test_macho_le():
    data = struct.pack('<I', 0xFEEDFACF) + b'\x00' * 100
    assert _detect_platform(data, "binary") == "macos"


def test_fat_macho():
    data = struct.pack('>I', 0xCAFEBABE) + b'\x00' * 100
    assert _detect_platform(data, "binary") == "macos"


def test_script_py():
    data = b'#!/usr/bin/env python3\nprint("hello")'
    assert _detect_platform(data, "exploit.py") == "script"


def test_script_sh():
    data = b'#!/bin/bash\nrm -rf /'
    assert _detect_platform(data, "bomb.sh") == "script"


def test_unknown():
    data = b'Hello, world!'
    assert _detect_platform(data, "readme.txt") == "unknown"
```

- [ ] **Step 2: Run to verify failure**

```bash
cd backend && python -m pytest tests/test_sandbox_routing.py -v 2>&1 | head -20
```

Expected: `ImportError` — `_detect_platform` not defined

- [ ] **Step 3: Add `_detect_platform()` to `sandbox_service.py`**

Add `import struct` to the imports at the top of `sandbox_service.py` (after line 9, alongside `import re`).

Then add `_MACHO_MAGICS` constant and `_detect_platform()` after the `_RUNNERS` dict (after line 35):

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_sandbox_routing.py -v
```

Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
git add backend/sandbox_service.py backend/tests/test_sandbox_routing.py
git commit -m "feat: add platform dispatcher for multi-format sandbox routing"
```

---

## Task 5: Fix ELF Sandbox with Decoy Integrity Checking

**Files:**
- Modify: `backend/sandbox_base/Dockerfile`
- Modify: `backend/sandbox_service.py`

- [ ] **Step 1: Update `sandbox_base/Dockerfile` with multi-stage decoy build**

Replace the entire content of `backend/sandbox_base/Dockerfile` with:

```dockerfile
# Stage 1: compile minimal ELF32 and ELF64 decoy binaries
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc gcc-multilib libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
# ELF64 decoys (x86-64)
RUN gcc -o /decoys/decoy64_a /tmp/decoy.c
RUN gcc -o /decoys/decoy64_b /tmp/decoy.c
RUN gcc -o /decoys/decoy64_c /tmp/decoy.c
# ELF32 decoys (i386) — targets for 32-bit file infectors
RUN gcc -m32 -o /decoys/decoy32_a /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy32_b /tmp/decoy.c

# Stage 2: runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace bash python3 perl coreutils file libc6-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys /malware /targets
COPY --from=builder /decoys/ /decoys/
WORKDIR /malware
```

- [ ] **Step 2: Build the updated sandbox base image**

```bash
cd backend && docker build -f sandbox_base/Dockerfile -t scp-sandbox-base .
```

Expected: build succeeds, image tagged `scp-sandbox-base`

- [ ] **Step 3: Refactor `_run_in_sandbox()` into `_run_in_elf_sandbox()` in `sandbox_service.py`**

Add the following environment variable constant below `SANDBOX_BASE_IMAGE`:

```python
SANDBOX_DOS_IMAGE  = os.getenv("SANDBOX_DOS_IMAGE",  "scp-sandbox-dos")
SANDBOX_WINE_IMAGE = os.getenv("SANDBOX_WINE_IMAGE", "scp-sandbox-wine")
```

Then replace the entire `_run_in_sandbox()` function (lines 136–226) with:

```python
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
```

- [ ] **Step 4: Add new strace patterns for decoy access and blocked writes**

In `_MALICIOUS_PATTERNS` (around line 41), add one new entry:

```python
    (re.compile(r'openat?\(.*"/targets/[^"]+",.*O_(?:WRONLY|RDWR)'),
     "Writing to decoy target file"),
```

In `_SUSPICIOUS_PATTERNS` (around line 53), add two new entries:

```python
    (re.compile(r'openat?\(.*O_(?:WRONLY|RDWR|CREAT).*=\s*-1\s*E(?:PERM|ACCES|ROFS)'),
     "Blocked file write attempt — possible file infector"),
    (re.compile(r'write\(.*=\s*-1\s*E(?:PERM|ROFS)'),
     "Write syscall blocked by read-only filesystem"),
```

- [ ] **Step 5: Verify sandbox_service imports run cleanly**

```bash
cd backend && python -c "import sandbox_service; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add backend/sandbox_base/Dockerfile backend/sandbox_service.py
git commit -m "fix: ELF sandbox decoy integrity check detects file infectors"
```

---

## Task 6: DOS Sandbox (DOSBox)

**Files:**
- Create: `backend/sandbox_dos/Dockerfile`
- Create: `backend/sandbox_dos/dosbox.conf`
- Modify: `backend/sandbox_service.py`

- [ ] **Step 1: Create `backend/sandbox_dos/` directory and `dosbox.conf`**

Create `backend/sandbox_dos/dosbox.conf`:

```ini
[sdl]
output=dummy

[dosbox]
memsize=16

[render]
frameskip=0

[mixer]
nosound=true

[midi]
mididevice=none

[sblaster]
sbtype=none

[speaker]
pcspeaker=false

[joystick]
joysticktype=none

[serial]
serial1=dummy
serial2=dummy
serial3=disabled
serial4=disabled

[autoexec]
mount c /dosbox/c
c:
cd target_dir
target.com
exit
```

- [ ] **Step 2: Create `backend/sandbox_dos/Dockerfile`**

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dosbox coreutils \
    && rm -rf /var/lib/apt/lists/*

# Minimal COM decoys: single byte INT 20h (exit) = 0xCD 0x20
RUN mkdir -p /dosbox/c/decoys /dosbox/c/target_dir
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_a.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_b.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_c.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_d.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_e.com

COPY dosbox.conf /dosbox/dosbox.conf
WORKDIR /dosbox
```

- [ ] **Step 3: Build the DOS sandbox image**

```bash
cd backend && docker build -f sandbox_dos/Dockerfile -t scp-sandbox-dos sandbox_dos/
```

Expected: build succeeds, image tagged `scp-sandbox-dos`

- [ ] **Step 4: Add `_run_in_dos_sandbox()` to `sandbox_service.py`**

Add after `_run_in_elf_sandbox()`:

```python
def _run_in_dos_sandbox(file_bytes: bytes, filename: str) -> dict:
    """
    Run DOS COM file in DOSBox sandbox.
    Decoy COM files (1-byte each) are placed alongside the target.
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
```

- [ ] **Step 5: Verify import**

```bash
cd backend && python -c "import sandbox_service; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add backend/sandbox_dos/ backend/sandbox_service.py
git commit -m "feat: add DOSBox sandbox for COM file infector detection"
```

---

## Task 7: Wine Sandbox (Windows PE)

**Files:**
- Create: `backend/sandbox_wine/Dockerfile`
- Modify: `backend/sandbox_service.py`

- [ ] **Step 1: Create `backend/sandbox_wine/Dockerfile`**

```dockerfile
# Stage 1: compile minimal PE decoys using mingw-w64
FROM debian:bookworm-slim AS pe-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc mingw-w64 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_a.exe /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_b.exe /tmp/decoy.c
RUN i686-w64-mingw32-gcc   -o /decoys/decoy_x86_a.exe /tmp/decoy.c
RUN i686-w64-mingw32-gcc   -o /decoys/decoy_x86_b.exe /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_c.exe /tmp/decoy.c

# Stage 2: runtime image with Wine and strace
FROM debian:bookworm-slim
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       strace wine wine32 coreutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=pe-builder /decoys/ /decoys/
RUN mkdir -p /targets /malware /wine
ENV WINEPREFIX=/wine
ENV WINEDEBUG=-all
WORKDIR /malware
```

- [ ] **Step 2: Build the Wine sandbox image**

```bash
cd backend && docker build -f sandbox_wine/Dockerfile -t scp-sandbox-wine sandbox_wine/
```

Expected: build succeeds (may take several minutes — mingw-w64 is large), image tagged `scp-sandbox-wine`

- [ ] **Step 3: Add `_run_in_wine_sandbox()` to `sandbox_service.py`**

Add after `_run_in_dos_sandbox()`:

```python
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
```

- [ ] **Step 4: Verify import**

```bash
cd backend && python -c "import sandbox_service; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add backend/sandbox_wine/ backend/sandbox_service.py
git commit -m "feat: add Wine sandbox for Windows PE analysis with strace monitoring"
```

---

## Task 8: Wire Dispatcher into the `analyze()` Endpoint

**Files:**
- Modify: `backend/sandbox_service.py` (the `analyze()` endpoint and `health()` endpoint)
- Modify: `docker-compose.yml`

- [ ] **Step 1: Replace `_get_runner()` usage in `analyze()` endpoint**

Find the `analyze()` function (around line 233). Replace the entire body of the `try:` block:

```python
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
```

Also delete the now-unused `_get_runner()` function (lines 67–74).

- [ ] **Step 2: Update `health()` to check all three images**

Replace the `health()` function body with:

```python
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
        "status":   "ok" if all_ready else "degraded",
        "service":  "sandbox",
        "docker_ok": docker_ok,
        "images":   images,
        **extra,
    }), 200 if docker_ok else 503
```

- [ ] **Step 3: Add build entries to `docker-compose.yml`**

Add the following two services to `docker-compose.yml`, inside the `services:` block, before the closing of the Backend Services section:

```yaml
  sandbox-dos-builder:
    build:
      context: ./backend/sandbox_dos
      dockerfile: Dockerfile
    image: scp-sandbox-dos
    entrypoint: ["echo", "scp-sandbox-dos image built"]
    profiles:
      - build

  sandbox-wine-builder:
    build:
      context: ./backend/sandbox_wine
      dockerfile: Dockerfile
    image: scp-sandbox-wine
    entrypoint: ["echo", "scp-sandbox-wine image built"]
    profiles:
      - build
```

Also update the `sandbox` service environment block to include the new image names:

```yaml
  sandbox:
    ...
    environment:
      SANDBOX_BASE_IMAGE: scp-sandbox-base
      SANDBOX_DOS_IMAGE: scp-sandbox-dos
      SANDBOX_WINE_IMAGE: scp-sandbox-wine
```

- [ ] **Step 4: Run sandbox routing tests to verify nothing broke**

```bash
cd backend && python -m pytest tests/test_sandbox_routing.py tests/test_static_analysis.py -v
```

Expected: all tests pass

- [ ] **Step 5: Build all three sandbox images**

```bash
cd backend
docker build -f sandbox_base/Dockerfile -t scp-sandbox-base .
docker build -f sandbox_dos/Dockerfile  -t scp-sandbox-dos  sandbox_dos/
docker build -f sandbox_wine/Dockerfile -t scp-sandbox-wine sandbox_wine/
```

Expected: all three builds succeed

- [ ] **Step 6: Smoke test the sandbox service locally**

```bash
cd backend && python sandbox_service.py &
sleep 2

# Test ELF routing (should return SKIPPED or CLEAN, not error)
echo -e '\x7fELF\x02\x01\x01\x00' > /tmp/test_elf
curl -s -F "file=@/tmp/test_elf;filename=test_elf" http://localhost:5004/analyze | python -m json.tool

# Test COM routing
printf '\xEB\x00\xCD\x21' > /tmp/test.com
curl -s -F "file=@/tmp/test.com;filename=test.com" http://localhost:5004/analyze | python -m json.tool

# Test health endpoint
curl -s http://localhost:5004/health | python -m json.tool

kill %1
```

Expected: each curl returns JSON with a `verdict` field (not a 500 error)

- [ ] **Step 7: Commit**

```bash
git add backend/sandbox_service.py docker-compose.yml
git commit -m "feat: wire platform dispatcher into analyze endpoint, add multi-image health check"
```

---

## Self-Review Notes

- **Spec §1 (ELF decoy):** Covered in Tasks 5 + 8 — `readonlyrootfs` kept, `/targets/` tmpfs added, hash comparison before/after execution, new strace patterns for blocked writes.
- **Spec §2 (COM):** Covered in Tasks 1 + 6 — static `_analyze_com_file()` + DOSBox runtime with decoy COM size checking.
- **Spec §3 (Windows PE):** Covered in Tasks 2 + 7 — `_analyze_pe_imports()` static + Wine+strace runtime with decoy EXE integrity.
- **Spec §4 (Mach-O):** Covered in Task 3 — static-only, `_analyze_macho()` + DMG/PKG added to archive extensions.
- **Spec §5 (Integration):** Covered in Task 8 — dispatcher in `analyze()` endpoint, all three images in `docker-compose.yml`, updated `health()`.
- **No orphaned types:** `_MACHO_MAGICS` defined in both `ai_detection_service.py` (Task 3) and `sandbox_service.py` (Task 4) — intentional duplication to keep services independent.
- **`_get_runner()` deleted** in Task 8 — no longer needed after dispatcher introduced.
- **DOS decoy size check uses 2 bytes** (matching the `\xcd\x20` decoys in the Dockerfile) — consistent throughout Task 6.
