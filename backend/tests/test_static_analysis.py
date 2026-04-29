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
    # Gets baseline 0.20 + 0.25 for INT 21h = 0.45
    # Size bonus (+0.25) is suppressed because specific_indicators == 0 (no infector-specific pattern)
    assert score <= 0.50, f"Clean COM should score low, got {score}"


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
    # Minimal MZ-headed PE data with injection triad import names
    data = (
        b'MZ' + b'\x00' * 60
        + b'CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00'
    )
    with mock.patch('redis.Redis'):
        result = analyze_file_content(data, "malware.exe")
    assert result["threat_type"] in ("MALICIOUS_PE_IMPORTS", "PACKED_PE")
    assert result["content_risk_score"] > 0.0
