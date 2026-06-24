import logging
import os

from flask import Flask
from flask_cors import CORS

from .routes_files  import files_bp
from .routes_access import access_bp
from .routes_audit  import audit_bp
from .routes_health import health_bp
from .routes_auth   import auth_bp
from .routes_demo   import demo_bp
from .config        import ALLOWED_ORIGINS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ["MAX_UPLOAD_FILE_BYTES"])
CORS(app, origins=ALLOWED_ORIGINS, allow_headers=["Content-Type", "X-Session-Token", "X-Chain-ID"])

app.register_blueprint(files_bp)
app.register_blueprint(access_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(health_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(demo_bp)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
