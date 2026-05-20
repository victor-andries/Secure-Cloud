import sys
import os
import struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

import unittest.mock as mock
with mock.patch('redis.Redis'):
    from ai_detection.binary_analysis import analyze_file_content


def _make_pe_with_section(section_name: bytes, data: bytes) -> bytes:
    """Minimal PE with one section — enough for pefile to parse."""
    # MZ header
    mz = b'MZ' + b'\x00' * 58 + struct.pack('<I', 64)
    # PE header offset at 64
    pe_sig = b'PE\x00\x00'
    machine = struct.pack('<H', 0x014c)   # i386
    num_sections = struct.pack('<H', 1)
    timestamp = struct.pack('<I', 0)
    sym_table = struct.pack('<I', 0)
    num_syms = struct.pack('<I', 0)
    opt_hdr_size = struct.pack('<H', 0)
    characteristics = struct.pack('<H', 0x0102)
    coff = pe_sig + machine + num_sections + timestamp + sym_table + num_syms + opt_hdr_size + characteristics
    # Section header (40 bytes)
    name_padded = section_name[:8].ljust(8, b'\x00')
    vsize = struct.pack('<I', len(data))
    vaddr = struct.pack('<I', 0x1000)
    raw_size = struct.pack('<I', len(data))
    raw_ptr = struct.pack('<I', 64 + len(coff) + 40)
    rest = b'\x00' * 16
    section_hdr = name_padded + vsize + vaddr + raw_size + raw_ptr + rest
    return mz + coff + section_hdr + data


def test_high_entropy_text_section_flagged():
    high_entropy_data = os.urandom(4096)
    pe_bytes = _make_pe_with_section(b'.text', high_entropy_data)
    result = analyze_file_content(pe_bytes, 'test.exe')
    reasons = result.get('reasons', [])
    assert any('.text' in r and 'entropy' in r.lower() for r in reasons), (
        f"Expected .text entropy reason, got: {reasons}"
    )


def test_normal_entropy_text_section_not_flagged():
    low_entropy_data = b'\x00' * 4096
    pe_bytes = _make_pe_with_section(b'.text', low_entropy_data)
    result = analyze_file_content(pe_bytes, 'test.exe')
    reasons = result.get('reasons', [])
    entropy_reasons = [r for r in reasons if 'entropy' in r.lower() and '.text' in r]
    assert len(entropy_reasons) == 0, f"Unexpected entropy reason: {entropy_reasons}"


def test_non_pe_file_returns_no_entropy_reasons():
    result = analyze_file_content(b"hello world plain text", "readme.txt")
    reasons = result.get('reasons', [])
    entropy_reasons = [r for r in reasons if 'entropy' in r.lower()]
    assert len(entropy_reasons) == 0


def test_malformed_pe_does_not_crash():
    # Truncated PE — valid MZ header but no PE signature
    malformed = b'MZ' + b'\x00' * 30
    result = analyze_file_content(malformed, 'bad.exe')
    # Must not raise — returns a result dict
    assert isinstance(result, dict)


def test_high_entropy_data_section_flagged():
    import os
    high_entropy_data = os.urandom(4096)
    pe_bytes = _make_pe_with_section(b'.data', high_entropy_data)
    result = analyze_file_content(pe_bytes, 'test.exe')
    reasons = result.get('reasons', [])
    assert any('.data' in r and 'entropy' in r.lower() for r in reasons), (
        f"Expected .data entropy reason, got: {reasons}"
    )


def test_high_entropy_code_section_flagged():
    import os
    high_entropy_data = os.urandom(4096)
    pe_bytes = _make_pe_with_section(b'.code', high_entropy_data)
    result = analyze_file_content(pe_bytes, 'test.exe')
    reasons = result.get('reasons', [])
    assert any('.code' in r and 'entropy' in r.lower() for r in reasons), (
        f"Expected .code entropy reason, got: {reasons}"
    )
