import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest.mock as mock
with mock.patch('redis.Redis'):
    from ai_detection_service import _analyze_com_file, _analyze_elf_file, analyze_file_content


def test_com_infector_detected():
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
    data = b'\x90\x90' + b'\xCD\x21' + b'*.com\x00'
    score = _analyze_com_file(data, "test.com")
    assert score == 0.0, f"No jump byte must return 0.0, got {score}"


def test_com_clean_baseline():
    data = b'\xEB\x00' + b'\xB4\x4C' + b'\xCD\x21'
    score = _analyze_com_file(data, "clean.com")
    assert score <= 0.50, f"Clean COM should score low, got {score}"


def test_elf_file_infector_detected():
    data = b'\x7fELF' + b'\x00' * 4 + b'opendir\x00readdir\x00rename\x00fwrite\x00chmod\x00execve\x00'
    score = _analyze_elf_file(data)
    assert score >= 0.75, f"ELF file infector triad must score >= 0.75, got {score}"


def test_elf_not_elf():
    data = b'MZ' + b'\x00' * 100
    score = _analyze_elf_file(data)
    assert score == 0.0, f"Non-ELF must score 0.0, got {score}"


def test_elf_partial_indicators():
    data = b'\x7fELF' + b'\x00' * 4 + b'opendir\x00readdir\x00fwrite\x00'
    score = _analyze_elf_file(data)
    assert 0.0 < score < 0.60, f"Partial indicators must score between 0 and 0.60, got {score}"


def test_elf_sendfile_fork_execv_detected():
    data = b'\x7fELF' + b'\x00' * 4 + b'opendir\x00readdir\x00sendfile\x00fork\x00execv\x00'
    score = _analyze_elf_file(data)
    assert score >= 0.75, f"sendfile+fork+execv infector triad must score >= 0.75, got {score}"


def test_elf_creat_fork_execv_detected():
    data = b'\x7fELF' + b'\x00' * 4 + b'opendir\x00readdir\x00creat\x00fork\x00execv\x00'
    score = _analyze_elf_file(data)
    assert score >= 0.75, f"creat+fork+execv infector triad must score >= 0.75, got {score}"


def test_elf_clean():
    data = b'\x7fELF' + b'\x00' * 4 + b'printf\x00malloc\x00free\x00'
    score = _analyze_elf_file(data)
    assert score == 0.0, f"Clean ELF must score 0.0, got {score}"


def test_analyze_file_content_com_infector_sets_threat_type():
    data = (
        b'\xEB\x00'
        b'\xCD\x21'
        b'\x4E'
        b'*.com\x00'
        b'\xB4\x3C'
    )
    with mock.patch('redis.Redis'):
        result = analyze_file_content(data, "virus.com")
    assert result["threat_type"] == "DOS_COM_INFECTOR"
    assert result["content_risk_score"] >= 0.50


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
    data = b'CryptEncrypt\x00FindFirstFileW\x00'
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


def test_analyze_file_content_pe_imports_sets_threat_type():
    data = (
        b'MZ' + b'\x00' * 60
        + b'CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00'
    )
    with mock.patch('redis.Redis'):
        result = analyze_file_content(data, "malware.exe")
    assert result["threat_type"] in ("MALICIOUS_PE_IMPORTS", "PACKED_PE")
    assert result["content_risk_score"] > 0.0


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
