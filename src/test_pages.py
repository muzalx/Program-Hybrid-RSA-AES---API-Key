import tempfile
from pathlib import Path

from flask import Blueprint, jsonify

try:
    from src.security_engine import HybridSecurityEngine
except ModuleNotFoundError:
    from security_engine import HybridSecurityEngine

test_bp = Blueprint("test", __name__)


@test_bp.get("/test/success")
def success():
    try:
        from src.app import create_app
    except ModuleNotFoundError:
        from app import create_app

    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "private_key.pem"
        key_path.write_bytes(
            HybridSecurityEngine.serialize_private_key(private_key)
        )

        app = create_app(key_path)
        client = app.test_client()

        request_data = {"message": "success test"}
        secure_payload = HybridSecurityEngine.build_secure_payload(
            request_data,
            public_key
        )

        response = client.post("/api/v1/secure-data", json=secure_payload)
        return jsonify({
            "response": response.get_json(),
            "request": secure_payload
        }), response.status_code


@test_bp.get("/test/error-400")
def error_400():
    try:
        from src.app import create_app
    except ModuleNotFoundError:
        from app import create_app

    private_key, _ = HybridSecurityEngine.generate_rsa_key_pair()

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "private_key.pem"
        key_path.write_bytes(
            HybridSecurityEngine.serialize_private_key(private_key)
        )

        app = create_app(key_path)
        client = app.test_client()

        request_data = {}
        response = client.post("/api/v1/secure-data", json=request_data)
        return jsonify({
            "response": response.get_json(),
            "request": request_data
        }), response.status_code


@test_bp.get("/test/error-500")
def error_500():
    try:
        from src.app import create_app
    except ModuleNotFoundError:
        from app import create_app

    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "nonexistent.pem"

        app = create_app(key_path)
        client = app.test_client()

        secure_payload = HybridSecurityEngine.build_secure_payload(
            {"message": "test"},
            public_key
        )

        response = client.post("/api/v1/secure-data", json=secure_payload)
        return jsonify({
            "response": response.get_json(),
            "request": secure_payload
        }), response.status_code
