from src.app import create_app
from src.security_engine import HybridSecurityEngine


def create_key_pair(tmp_path):
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    private_key_path = tmp_path / "private_key.pem"
    private_key_path.write_bytes(
        HybridSecurityEngine.serialize_private_key(private_key)
    )
    return private_key_path, public_key


def test_test_success_returns_real_decrypted_data(tmp_path):
    private_key_path, _ = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()

    response = client.get("/test/success")

    assert response.status_code == 200
    body = response.get_json()
    assert body["response"]["data"]["message"] == "success test"
    assert "encrypted_key" in body["request"]
    assert "encrypted_payload" in body["request"]


def test_test_error_400_returns_real_400(tmp_path):
    private_key_path, _ = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()

    response = client.get("/test/error-400")

    assert response.status_code == 400
    body = response.get_json()
    assert body["response"] == {"error": "Missing encrypted_key or encrypted_payload"}
    assert body["request"] == {}


def test_test_error_500_returns_real_500(tmp_path):
    private_key_path, _ = create_key_pair(tmp_path)
    app = create_app(private_key_path)
    client = app.test_client()

    response = client.get("/test/error-500")

    assert response.status_code == 500
    body = response.get_json()
    assert body["response"] == {"error": "Private key not found"}
    assert "encrypted_key" in body["request"]
    assert "encrypted_payload" in body["request"]
