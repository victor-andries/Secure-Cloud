from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

import os
import io
import hashlib
import base64
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from minio import Minio
from minio.error import S3Error
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("storage_service")

app = Flask(__name__)
CORS(app, origins=[])

MINIO_ENDPOINT   = os.environ["MINIO_ENDPOINT"]
MINIO_ACCESS_KEY = os.environ["MINIO_ACCESS_KEY"]
MINIO_SECRET_KEY = os.environ["MINIO_SECRET_KEY"]
MINIO_BUCKET     = os.getenv("MINIO_BUCKET", " ")
CHUNK_SIZE = 10 * 1024 * 1024  # 10MB

_MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=_MINIO_SECURE
)
logger.info(f"MinIO connection: {'HTTPS' if _MINIO_SECURE else 'HTTP'} ({MINIO_ENDPOINT})")


def ensure_bucket() -> None:
    """Ensure the MinIO bucket exists, creating it if necessary."""
    try:
        if not minio_client.bucket_exists(MINIO_BUCKET):
            minio_client.make_bucket(MINIO_BUCKET)
            logger.info(f"Created bucket: {MINIO_BUCKET}")
    except S3Error as exc:
        logger.error(f"MinIO bucket error: {exc}")
        raise


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_chunk(data: bytes, password: str) -> bytes:
    """
    Encrypt data with AES-256-GCM.
    Returns: salt(16) + nonce(12) + ciphertext+tag
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt_chunk(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    Expects: salt(16) + nonce(12) + ciphertext+tag
    """
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


@app.route("/upload", methods=["POST"])
def upload_file() -> tuple:
    """
    Upload a file in encrypted chunks to MinIO.
    Expects multipart form: file, password, file_id
    """
    try:
        ensure_bucket()

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        if "password" not in request.form:
            return jsonify({"error": "No password provided"}), 400
        if "file_id" not in request.form:
            return jsonify({"error": "No file_id provided"}), 400

        uploaded_file = request.files["file"]
        password = request.form["password"]
        file_id = request.form["file_id"]
        _MAX_STORAGE = int(os.getenv("MAX_UPLOAD_FILE_BYTES", str(500 * 1024 * 1024)))
        file_data = uploaded_file.read()
        if len(file_data) > _MAX_STORAGE:
            return jsonify({"error": "File too large"}), 413
        file_name = uploaded_file.filename or "unknown"

        logger.info(f"Uploading file: {file_name}, id: {file_id}, size: {len(file_data)} bytes")

        chunks = [file_data[i:i + CHUNK_SIZE] for i in range(0, len(file_data), CHUNK_SIZE)]
        if not chunks:
            chunks = [b""]

        chunk_metadata = []
        for idx, chunk_data in enumerate(chunks):
            chunk_id = f"{file_id}/chunk_{idx:04d}"
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            encrypted = encrypt_chunk(chunk_data, password)

            minio_client.put_object(
                MINIO_BUCKET,
                chunk_id,
                io.BytesIO(encrypted),
                length=len(encrypted),
                content_type="application/octet-stream"
            )

            chunk_metadata.append({
                "chunk_id": chunk_id,
                "chunk_hash": chunk_hash,
                "chunk_size": len(chunk_data),
                "chunk_location": f"minio://{MINIO_BUCKET}/{chunk_id}"
            })
            logger.info(f"Uploaded chunk {idx + 1}/{len(chunks)}: {chunk_id}")

        response = {
            "file_id": file_id,
            "file_name": file_name,
            "total_size": len(file_data),
            "num_chunks": len(chunks),
            "chunks": chunk_metadata,
            "chunk_ids": [c["chunk_id"] for c in chunk_metadata],
            "chunk_hashes": [c["chunk_hash"] for c in chunk_metadata],
            "chunk_sizes": [c["chunk_size"] for c in chunk_metadata],
            "chunk_locations": [c["chunk_location"] for c in chunk_metadata]
        }
        logger.info(f"Upload complete for file_id: {file_id}, chunks: {len(chunks)}")
        return jsonify(response), 200

    except S3Error as exc:
        logger.error(f"MinIO error during upload: {exc}")
        return jsonify({"error": f"Storage error: {str(exc)}"}), 500
    except Exception as exc:
        logger.error(f"Upload error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/download/<file_id>", methods=["POST"])
def download_file(file_id: str) -> tuple:
    """
    Download and decrypt all chunks for a file.
    Expects JSON body: { password, num_chunks }
    Returns base64-encoded file data.
    """
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        password = body.get("password")
        num_chunks = body.get("num_chunks")
        if not password:
            return jsonify({"error": "password required"}), 400
        if num_chunks is None:
            return jsonify({"error": "num_chunks required"}), 400

        logger.info(f"Downloading file_id: {file_id}, num_chunks: {num_chunks}")
        file_data = bytearray()

        for idx in range(int(num_chunks)):
            chunk_id = f"{file_id}/chunk_{idx:04d}"
            try:
                response = minio_client.get_object(MINIO_BUCKET, chunk_id)
                encrypted_data = response.read()
                response.close()
                response.release_conn()
            except S3Error as exc:
                logger.error(f"Failed to retrieve chunk {chunk_id}: {exc}")
                return jsonify({"error": f"Chunk not found: {chunk_id}"}), 404

            try:
                decrypted = decrypt_chunk(encrypted_data, password)
                file_data.extend(decrypted)
            except Exception as exc:
                logger.error(f"Decryption failed for chunk {chunk_id}: {exc}")
                return jsonify({"error": "Decryption failed — wrong password or corrupted data"}), 400

        encoded = base64.b64encode(bytes(file_data)).decode("utf-8")
        logger.info(f"Download complete for file_id: {file_id}, total bytes: {len(file_data)}")
        return jsonify({"file_id": file_id, "data": encoded, "size": len(file_data)}), 200

    except Exception as exc:
        logger.error(f"Download error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/verify/<file_id>", methods=["POST"])
def verify_file(file_id: str) -> tuple:
    """
    Verify SHA-256 hashes of all stored chunks.
    Expects JSON body: { password, expected_hashes: [str] }
    """
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "JSON body required"}), 400
        password = body.get("password")
        expected_hashes = body.get("expected_hashes", [])
        if not password:
            return jsonify({"error": "password required"}), 400

        results = []
        all_valid = True

        for idx, expected_hash in enumerate(expected_hashes):
            chunk_id = f"{file_id}/chunk_{idx:04d}"
            try:
                response = minio_client.get_object(MINIO_BUCKET, chunk_id)
                encrypted_data = response.read()
                response.close()
                response.release_conn()
                decrypted = decrypt_chunk(encrypted_data, password)
                actual_hash = hashlib.sha256(decrypted).hexdigest()
                valid = actual_hash == expected_hash
                if not valid:
                    all_valid = False
                results.append({
                    "chunk_id": chunk_id,
                    "valid": valid,
                    "expected": expected_hash,
                    "actual": actual_hash
                })
            except S3Error:
                all_valid = False
                results.append({"chunk_id": chunk_id, "valid": False, "error": "Chunk not found"})
            except Exception as exc:
                all_valid = False
                results.append({"chunk_id": chunk_id, "valid": False, "error": str(exc)})

        return jsonify({"file_id": file_id, "all_valid": all_valid, "chunks": results}), 200

    except Exception as exc:
        logger.error(f"Verify error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/delete/<file_id>", methods=["DELETE"])
def delete_file(file_id: str) -> tuple:
    """Remove all chunks for a file from MinIO."""
    try:
        objects = minio_client.list_objects(MINIO_BUCKET, prefix=f"{file_id}/")
        deleted = []
        for obj in objects:
            minio_client.remove_object(MINIO_BUCKET, obj.object_name)
            deleted.append(obj.object_name)
            logger.info(f"Deleted object: {obj.object_name}")

        logger.info(f"Deleted {len(deleted)} chunks for file_id: {file_id}")
        return jsonify({"file_id": file_id, "deleted_chunks": deleted, "count": len(deleted)}), 200

    except S3Error as exc:
        logger.error(f"MinIO delete error: {exc}")
        return jsonify({"error": f"Storage error: {str(exc)}"}), 500
    except Exception as exc:
        logger.error(f"Delete error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/stats", methods=["GET"])
def storage_stats() -> tuple:
    """Return total bytes stored and object count in the bucket."""
    try:
        total_bytes = 0
        total_objects = 0
        for obj in minio_client.list_objects(MINIO_BUCKET, recursive=True):
            total_bytes += obj.size or 0
            total_objects += 1
        return jsonify({
            "total_bytes":   total_bytes,
            "total_objects": total_objects,
        }), 200
    except Exception as exc:
        logger.error(f"Storage stats error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health() -> tuple:
    """Health check — verify MinIO connectivity."""
    try:
        ensure_bucket()
        return jsonify({"status": "ok", "service": "storage"}), 200
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting storage service on port 5001 (debug={debug})")
    app.run(host="0.0.0.0", port=5001, debug=debug, use_reloader=debug)
