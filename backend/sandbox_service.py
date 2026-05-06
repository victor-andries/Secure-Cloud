from dotenv import load_dotenv
load_dotenv()

from sandbox import app
import os

if __name__ == "__main__":
    import logging
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logging.getLogger("sandbox_service").info(
        f"Starting sandbox service on port 5004 (debug={debug})"
    )
    app.run(host="0.0.0.0", port=5004, debug=debug, use_reloader=debug)
