import base64
import json

from src.security_engine import HybridSecurityEngine


def test_generate_aes_key_returns_256_bit_key():
    aes_key = HybridSecurityEngine.generate_aes_key()

    assert len(aes_key) == 32


def test_encrypt_payload_can_be_decrypted():
    aes_key = HybridSecurityEngine.generate_aes_key()
    encrypted_payload = HybridSecurityEngine.encrypt_payload("hello", aes_key)

    decrypted_payload = HybridSecurityEngine.decrypt_payload(
        encrypted_payload,
        aes_key
    )

    assert decrypted_payload == "hello"


def test_encrypt_aes_key_can_be_decrypted():
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    aes_key = HybridSecurityEngine.generate_aes_key()

    encrypted_key = HybridSecurityEngine.encrypt_aes_key(aes_key, public_key)
    decrypted_key = HybridSecurityEngine.decrypt_aes_key(
        encrypted_key,
        private_key
    )

    assert decrypted_key == aes_key


def test_build_secure_payload_returns_valid_json_fields():
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    secure_payload = HybridSecurityEngine.build_secure_payload(
        {"message": "hello"},
        public_key
    )

    assert set(secure_payload) == {"encrypted_key", "encrypted_payload"}

    aes_key = HybridSecurityEngine.decrypt_aes_key(
        base64.b64decode(secure_payload["encrypted_key"]),
        private_key
    )
    decrypted_payload = HybridSecurityEngine.decrypt_payload(
        secure_payload["encrypted_payload"],
        aes_key
    )

    assert json.loads(decrypted_payload) == {"message": "hello"}


def test_decrypt_secure_payload_returns_plaintext():
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    secure_payload = HybridSecurityEngine.build_secure_payload(
        {"message": "hello"},
        public_key
    )

    plaintext = HybridSecurityEngine.decrypt_secure_payload(
        secure_payload["encrypted_key"],
        secure_payload["encrypted_payload"],
        private_key
    )

    assert plaintext == '{"message": "hello"}'
