from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from ai_detection import app, load_models, connect_redis
from ai_detection import (
    analyze_file_content,
    _analyze_elf_file,
    _analyze_com_file,
    _analyze_pe_imports,
    _analyze_macho,
    _inspect_archive,
)
import os

connect_redis()
load_models()

from ai_detection import yara_scanner
yara_scanner.load_rules()

if __name__ == "__main__":
    import logging
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logging.getLogger("ai_detection_service").info(
        f"Starting AI detection service on port 5003 (debug={debug})"
    )
    app.run(host="0.0.0.0", port=5003, debug=debug, use_reloader=debug)
