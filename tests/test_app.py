import base64

from src.app import create_app
from src.security_engine import HybridSecurityEngine


def create_key_pair(tmp_path):
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    private_key_path = tmp_path / "private_key.pem"
    private_key_path.write_bytes(
        HybridSecurityEngine.serialize_private_key(private_key)
    )
    return private_key_path, public_key


def test_documentation_page_returns_api_details(tmp_path):
    private_key_path, _ = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()

    response = client.get("/")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "POST /api/v1/secure-data" in body
    assert "encrypted_key" in body
    assert "encrypted_payload" in body


def test_secure_data_returns_decrypted_json(tmp_path):
    private_key_path, public_key = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()
    secure_payload = HybridSecurityEngine.build_secure_payload(
        {"message": "hello"},
        public_key
    )

    response = client.post("/api/v1/secure-data", json=secure_payload)

    assert response.status_code == 200
    assert response.get_json() == {"data": {"message": "hello"}}


def test_secure_data_rejects_missing_fields(tmp_path):
    private_key_path, _ = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()

    response = client.post("/api/v1/secure-data", json={})

    assert response.status_code == 400


def test_secure_data_rejects_invalid_payload(tmp_path):
    private_key_path, public_key = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()
    aes_key = HybridSecurityEngine.generate_aes_key()
    encrypted_key = HybridSecurityEngine.encrypt_aes_key(aes_key, public_key)

    response = client.post(
        "/api/v1/secure-data",
        json={
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_payload": "not-base64"
        }
    )

    assert response.status_code == 400
