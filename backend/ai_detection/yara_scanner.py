import os
import glob
import logging
import yara

logger = logging.getLogger("ai_detection.yara_scanner")

_god_mode_rules: yara.Rules | None = None
_signature_rules: yara.Rules | None = None

_RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))


def load_rules() -> None:
    global _god_mode_rules, _signature_rules

    gm_path = os.path.join(_RULES_DIR, "god-mode-rules")
    sb_path  = os.path.join(_RULES_DIR, "signature-base", "yara")

    _god_mode_rules = _compile_dir(gm_path, "god-mode-rules")
    _signature_rules = _compile_dir(sb_path, "signature-base")


_EXTERNALS = {"filepath": "", "filename": "", "extension": "", "filetype": ""}


def _compile_dir(path: str, label: str) -> yara.Rules | None:
    yar_files = (
        glob.glob(os.path.join(path, "**", "*.yar"),  recursive=True) +
        glob.glob(os.path.join(path, "**", "*.yara"), recursive=True)
    )
    if not yar_files:
        logger.critical(f"YARA {label}: no rule files found in {path}. Scanning disabled for this ruleset.")
        return None
    try:
        filepaths = {f"ns_{i}": p for i, p in enumerate(yar_files)}
        rules = yara.compile(filepaths=filepaths, externals=_EXTERNALS)
        logger.info(f"YARA {label}: compiled {len(yar_files)} rule files")
        return rules
    except Exception as exc:
        logger.critical(f"YARA {label}: compile failed — {exc}. Scanning disabled for this ruleset.")
        return None


def scan(file_bytes: bytes, filename: str) -> dict:
    result: dict = {
        "is_god_mode_match": False,
        "yara_score": 0.0,
        "matches": [],
        "reasons": [],
    }

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    scan_externals = {"filepath": filename, "filename": filename, "extension": ext, "filetype": ext}

    if _god_mode_rules is not None:
        try:
            matches = _god_mode_rules.match(data=file_bytes, externals=scan_externals)
            if matches:
                names = [m.rule for m in matches]
                result["is_god_mode_match"] = True
                result["yara_score"] = 1.0
                result["matches"].extend(names)
                result["reasons"].extend([f"YARA god-mode: {n}" for n in names])
                return result  # early return — no need to check signature-base
        except Exception as exc:
            logger.warning(f"YARA god-mode scan error for {filename}: {exc}")

    if _signature_rules is not None:
        try:
            matches = _signature_rules.match(data=file_bytes, externals=scan_externals)
            if matches:
                names = [m.rule for m in matches[:10]]  # cap at 10
                result["yara_score"] = 0.90
                result["matches"].extend(names)
                result["reasons"].extend([f"YARA signature-base: {n}" for n in names])
        except Exception as exc:
            logger.warning(f"YARA signature-base scan error for {filename}: {exc}")

    return result
