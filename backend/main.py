from dotenv import load_dotenv
load_dotenv()

from gateway import app
import os

if __name__ == "__main__":
    import logging
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logging.getLogger("api_gateway").info(
        f"Starting API gateway on port 5000 (debug={debug})"
    )
    app.run(host="0.0.0.0", port=5000, debug=debug, use_reloader=debug)
