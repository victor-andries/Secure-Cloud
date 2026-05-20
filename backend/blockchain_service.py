from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from blockchain import app, load_contracts
import os

load_contracts()

if __name__ == "__main__":
    import logging
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logging.getLogger("blockchain_service").info(
        f"Starting blockchain service on port 5002 (debug={debug})"
    )
    app.run(host="0.0.0.0", port=5002, debug=debug, use_reloader=debug)
