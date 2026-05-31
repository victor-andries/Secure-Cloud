import struct
import logging
import numpy as np
import pefile

from .config import (
    _EICAR_PREFIX, _HIGH_RISK_RE, _MEDIUM_RISK_RE, _PE_EXTENSIONS,
    _MACHO_MAGICS, _MACHO_DANGEROUS_STRINGS,
    _DOCUMENT_FORMATS, _ARCHIVE_EXTENSIONS, _DANGEROUS_IN_ARCHIVE, _SCANNABLE_IN_ARCHIVE,
)

logger = logging.getLogger("ai_detection.binary_analysis")


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    prob = freq[freq > 0] / len(data)
    return float(-np.sum(prob * np.log2(prob)))


def _pe_section_entropy(file_bytes: bytes) -> list[str]:
    reasons = []
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            data = section.get_data()
            if not data:
                continue
            entropy = _shannon_entropy(data)
            if name in ('.text', '.data', '.code') and entropy > 7.2:
                reasons.append(
                    f"PE section {name} entropy {entropy:.2f} (packed/encrypted, threshold 7.2)"
                )
    except pefile.PEFormatError:
        pass  # not a valid PE — silently skip
    except Exception as exc:
        logger.debug(f"PE section entropy analysis failed: {exc}")
    return reasons


def _analyze_elf_file(data: bytes) -> float:
    """Heuristic scoring for ELF executables based on imported symbol strings."""
    if data[:4] != b'\x7fELF':
        return 0.0

    score = 0.0

    has_dir_walk   = b'opendir' in data and b'readdir' in data
    has_file_write = (b'rename' in data or b'fwrite' in data or
                      b'sendfile' in data or b'creat' in data)
    has_replicate  = (
        (b'chmod' in data or b'fchmod' in data or b'fork' in data)
        and (b'execve' in data or b'execv\x00' in data)
    )

    if has_dir_walk and has_file_write and has_replicate:
        score += 0.75
    elif has_dir_walk and has_file_write:
        score += 0.35

    if b'ptrace' in data:
        score += 0.20

    if b'/proc/self/mem' in data:
        score += 0.25

    return min(score, 0.90)


def _analyze_com_file(data: bytes, filename: str) -> float:
    """Heuristic scoring for DOS COM file infectors."""
    if not filename.lower().endswith('.com'):
        return 0.0
    if len(data) < 1:
        return 0.0
    if data[:2] == b'MZ':
        return 0.0
    if data[0] not in (0xEB, 0xE9):
        return 0.0

    score = 0.20

    infector_score = 0.0
    specific_indicators = 0

    if b'\xCD\x21' in data:
        infector_score += 0.25

    idx = data.find(b'\xCD\x21')
    if idx != -1:
        window = data[max(0, idx - 10): idx + 10]
        if b'\x4E' in window or b'\x4F' in window:
            infector_score += 0.25
            specific_indicators += 1

    if b'*.com' in data or b'*.COM' in data or b'*.exe' in data or b'*.EXE' in data:
        infector_score += 0.25
        specific_indicators += 1

    if b'\xB4\x3C' in data or b'\xB4\x3D' in data:
        infector_score += 0.25
        specific_indicators += 1

    if len(data) < 2048 and specific_indicators > 0:
        infector_score += 0.25

    score += min(infector_score, 0.70)
    return min(score, 0.90)


def _analyze_pe_imports(data: bytes) -> float:
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


def _analyze_macho(data: bytes) -> dict:
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


def _inspect_archive(file_bytes: bytes, filename: str) -> dict:
    import io
    import zipfile
    import tarfile

    _MAX_EXTRACT = 50 * 1024 * 1024

    score = 0.0
    threat_type = None
    details: list = []

    def _scan_text(text: str, source: str) -> float:
        nonlocal threat_type
        high_hits   = sum(1 for p in _HIGH_RISK_RE   if p.search(text))
        medium_hits = sum(1 for p in _MEDIUM_RISK_RE if p.search(text))
        if high_hits >= 3:
            threat_type = "MALWARE_IN_ARCHIVE"
            details.append(f"Malware patterns in {source}")
            return 1.0
        added = min(high_hits * 0.30, 0.60) + min(medium_hits * 0.15, 0.45)
        if added:
            threat_type = threat_type or (
                "MALICIOUS_CODE_IN_ARCHIVE" if high_hits else "SUSPICIOUS_SCRIPT_IN_ARCHIVE"
            )
            details.append(f"Suspicious patterns in {source} (H:{high_hits} M:{medium_hits})")
        return added * 0.85

    # --- ZIP ---
    try:
        bio = io.BytesIO(file_bytes)
        if zipfile.is_zipfile(bio):
            bio.seek(0)
            with zipfile.ZipFile(bio) as zf:
                members = zf.infolist()
                total_uncompressed = sum(m.file_size for m in members)
                dangerous = [
                    m.filename for m in members
                    if m.filename.rsplit(".", 1)[-1].lower() in _DANGEROUS_IN_ARCHIVE
                ]
                if dangerous:
                    score = max(score, 0.80 if len(dangerous) >= 2 else 0.70)
                    threat_type = "ARCHIVE_CONTAINS_EXECUTABLES"
                    details.append(f"Executables inside archive: {dangerous[:5]}")
                if total_uncompressed <= _MAX_EXTRACT:
                    for m in members[:30]:
                        m_ext = m.filename.rsplit(".", 1)[-1].lower() if "." in m.filename else ""
                        if m_ext not in _SCANNABLE_IN_ARCHIVE or m.file_size > 2 * 1024 * 1024:
                            continue
                        try:
                            text = zf.read(m.filename)[:65536].decode("utf-8", errors="ignore")
                            added = _scan_text(text, m.filename)
                            if added >= 1.0:
                                return {"score": 1.0, "threat_type": threat_type, "details": details}
                            score += added
                        except Exception:
                            pass
            return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}
    except Exception:
        pass

    # --- TAR ---
    try:
        bio = io.BytesIO(file_bytes)
        if tarfile.is_tarfile(bio):
            bio.seek(0)
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                members = tf.getmembers()
                total_uncompressed = sum(m.size for m in members if m.isfile())
                dangerous = [
                    m.name for m in members
                    if m.isfile() and m.name.rsplit(".", 1)[-1].lower() in _DANGEROUS_IN_ARCHIVE
                ]
                if dangerous:
                    score = max(score, 0.80 if len(dangerous) >= 2 else 0.70)
                    threat_type = "ARCHIVE_CONTAINS_EXECUTABLES"
                    details.append(f"Executables inside archive: {dangerous[:5]}")
                if total_uncompressed <= _MAX_EXTRACT:
                    for m in members[:30]:
                        m_ext = m.name.rsplit(".", 1)[-1].lower() if "." in m.name else ""
                        if not m.isfile() or m_ext not in _SCANNABLE_IN_ARCHIVE or m.size > 2 * 1024 * 1024:
                            continue
                        try:
                            fobj = tf.extractfile(m)
                            if fobj:
                                text = fobj.read(65536).decode("utf-8", errors="ignore")
                                added = _scan_text(text, m.name)
                                if added >= 1.0:
                                    return {"score": 1.0, "threat_type": threat_type, "details": details}
                                score += added
                        except Exception:
                            pass
            return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}
    except Exception:
        pass

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ("gz", "bz2", "xz"):
        try:
            import gzip
            import bz2 as _bz2
            import lzma
            decompress = {"gz": gzip.decompress, "bz2": _bz2.decompress, "xz": lzma.decompress}[ext]
            inner = decompress(file_bytes[:5 * 1024 * 1024])
            if _EICAR_PREFIX in inner[:1000]:
                return {"score": 1.0, "threat_type": "EICAR_TEST", "details": ["EICAR in compressed content"]}
            text = inner[:65536].decode("utf-8", errors="ignore")
            added = _scan_text(text, f"{filename}[inner]")
            if added >= 1.0:
                return {"score": 1.0, "threat_type": threat_type, "details": details}
            score += added
        except Exception:
            pass

    return {"score": min(score, 1.0), "threat_type": threat_type, "details": details}


def analyze_file_content(file_bytes: bytes, filename: str) -> dict:
    result: dict = {
        "content_risk_score": 0.0,
        "entropy": 0.0,
        "is_high_entropy": False,
        "is_pe_file": False,
        "threat_type": None,
        "reasons": [],
    }

    if not file_bytes:
        return result

    freq = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
    prob = freq[freq > 0] / len(file_bytes)
    entropy = float(-np.sum(prob * np.log2(prob)))
    result["entropy"] = round(entropy, 4)

    score = 0.0

    if _EICAR_PREFIX in file_bytes[:1000]:
        result["threat_type"] = "EICAR_TEST"
        result["content_risk_score"] = 1.0
        logger.warning(f"EICAR test string detected in '{filename}'")
        return result

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext in _ARCHIVE_EXTENSIONS:
        arch = _inspect_archive(file_bytes, filename)
        if arch["score"] >= 1.0:
            result["threat_type"] = arch["threat_type"]
            result["content_risk_score"] = 1.0
            logger.warning(f"Malware in archive '{filename}': {arch['details']}")
            return result
        score += arch["score"]
        if arch["threat_type"]:
            result["threat_type"] = arch["threat_type"]
        if arch["details"]:
            logger.info(f"Archive scan '{filename}': score={arch['score']:.4f} {arch['details']}")
    else:
        if ext not in _DOCUMENT_FORMATS:
            if entropy > 7.8:
                score += 0.35
                result["is_high_entropy"] = True
            elif entropy > 7.2:
                score += 0.15
                result["is_high_entropy"] = True

        elf_score = _analyze_elf_file(file_bytes)
        if elf_score > 0.0:
            score += elf_score
            result["threat_type"] = result["threat_type"] or "ELF_INFECTOR"
            logger.warning(f"ELF infector indicators in '{filename}': score={elf_score:.2f}")

        com_score = _analyze_com_file(file_bytes, filename)
        if com_score > 0.0:
            score += com_score
            if com_score >= 0.50:
                result["threat_type"] = result["threat_type"] or "DOS_COM_INFECTOR"
                logger.warning(f"DOS COM infector indicators in '{filename}': score={com_score:.2f}")

        if ext in _PE_EXTENSIONS:
            if file_bytes[:2] == b"MZ":
                result["is_pe_file"] = True
                if entropy > 6.5:
                    score += 0.40
                    result["threat_type"] = "PACKED_PE"
                    logger.info(f"Packed PE detected: '{filename}' (entropy={entropy:.2f})")
                else:
                    score += 0.10
                import_score = _analyze_pe_imports(file_bytes)
                if import_score > 0.0:
                    score += import_score
                    result["threat_type"] = result["threat_type"] or "MALICIOUS_PE_IMPORTS"
                    logger.warning(f"Dangerous PE imports in '{filename}': score +{import_score:.2f}")
                section_reasons = _pe_section_entropy(file_bytes)
                if section_reasons:
                    result["reasons"].extend(section_reasons)
                    logger.info(f"PE section entropy flags in '{filename}': {section_reasons}")

        macho_result = _analyze_macho(file_bytes)
        if macho_result["score"] > 0.0:
            score += macho_result["score"]
            result["threat_type"] = result["threat_type"] or macho_result["threat_type"]
            result["platform"] = macho_result["platform"]
            logger.warning(
                f"Mach-O binary '{filename}': platform={macho_result['platform']} "
                f"score={macho_result['score']:.2f} type={macho_result['threat_type']}"
            )

        try:
            text = file_bytes[:131072].decode("utf-8", errors="ignore")

            high_hits   = sum(1 for p in _HIGH_RISK_RE   if p.search(text))
            medium_hits = sum(1 for p in _MEDIUM_RISK_RE if p.search(text))

            if high_hits >= 3:
                result["threat_type"] = "MALWARE"
                result["content_risk_score"] = 1.0
                logger.warning(f"MALWARE detected in '{filename}': {high_hits} high-risk patterns")
                return result

            if high_hits or medium_hits:
                pattern_score = min(high_hits * 0.30, 0.60) + min(medium_hits * 0.15, 0.45)
                score += pattern_score

                if high_hits:
                    result["threat_type"] = result["threat_type"] or "MALICIOUS_CODE"
                    logger.warning(f"High-risk patterns ({high_hits}) in '{filename}': score +{min(high_hits*0.30,0.60):.2f}")
                elif medium_hits:
                    result["threat_type"] = result["threat_type"] or "SUSPICIOUS_SCRIPT"
                    logger.info(f"Medium-risk patterns ({medium_hits}) in '{filename}': score +{min(medium_hits*0.15,0.45):.2f}")
        except Exception:
            pass

    result["content_risk_score"] = round(min(score, 1.0), 4)
    return result
