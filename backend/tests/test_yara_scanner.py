import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

import unittest.mock as mock
with mock.patch('redis.Redis'):
    from ai_detection import yara_scanner


def test_scan_returns_dict_structure():
    result = yara_scanner.scan(b"hello world", "test.txt")
    assert "is_god_mode_match" in result
    assert "yara_score" in result
    assert "matches" in result
    assert "reasons" in result

def test_clean_file_returns_zero_score():
    result = yara_scanner.scan(b"hello world safe content", "readme.txt")
    assert result["yara_score"] == 0.0
    assert result["is_god_mode_match"] is False

def test_god_mode_match_forces_score_to_one():
    mock_match = MagicMock()
    mock_match.rule = "TestGodModeRule"
    mock_rules = MagicMock()
    mock_rules.match.return_value = [mock_match]

    with patch.object(yara_scanner, '_god_mode_rules', mock_rules):
        result = yara_scanner.scan(b"malicious bytes", "bad.exe")

    assert result["is_god_mode_match"] is True
    assert result["yara_score"] == 1.0
    assert "TestGodModeRule" in result["matches"]
    assert any("god-mode" in r for r in result["reasons"])

def test_signature_base_match_sets_score_090():
    mock_match = MagicMock()
    mock_match.rule = "Ransomware_Generic"
    mock_rules = MagicMock()
    mock_rules.match.return_value = [mock_match]

    with patch.object(yara_scanner, '_god_mode_rules', None):
        with patch.object(yara_scanner, '_signature_rules', mock_rules):
            result = yara_scanner.scan(b"suspect bytes", "suspect.exe")

    assert result["is_god_mode_match"] is False
    assert result["yara_score"] == 0.90
    assert "Ransomware_Generic" in result["matches"]
    assert any("signature-base" in r for r in result["reasons"])

def test_scan_error_returns_zero_not_exception():
    mock_rules = MagicMock()
    mock_rules.match.side_effect = Exception("YARA internal error")
    with patch.object(yara_scanner, '_god_mode_rules', None):
        with patch.object(yara_scanner, '_signature_rules', mock_rules):
            result = yara_scanner.scan(b"bytes", "file.exe")
    assert result["yara_score"] == 0.0  # must not raise
