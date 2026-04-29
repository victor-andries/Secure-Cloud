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
