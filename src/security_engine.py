import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class HybridSecurityEngine:
    """
    Engine untuk menangani enkripsi hybrid RSA-AES.
    - AES-GCM digunakan untuk enkripsi payload.
    - RSA-OAEP digunakan untuk enkripsi AES-Key.
    """

    @staticmethod
    def generate_aes_key():
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_private_key(path):
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    @staticmethod
    def load_public_key(path):
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    @staticmethod
    def encrypt_payload(data: str, aes_key: bytes):
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    @staticmethod
    def decrypt_payload(encrypted_payload: str, aes_key: bytes):
        raw_payload = base64.b64decode(encrypted_payload)
        nonce = raw_payload[:12]
        ciphertext = raw_payload[12:]
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    @staticmethod
    def encrypt_aes_key(aes_key: bytes, rsa_public_key):
        return rsa_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_aes_key(encrypted_aes_key: bytes, rsa_private_key):
        return rsa_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def build_secure_payload(data, rsa_public_key):
        plaintext = data if isinstance(data, str) else json.dumps(data)
        aes_key = HybridSecurityEngine.generate_aes_key()
        encrypted_key = HybridSecurityEngine.encrypt_aes_key(
            aes_key,
            rsa_public_key
        )
        return {
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_payload": HybridSecurityEngine.encrypt_payload(
                plaintext,
                aes_key
            )
        }

    @staticmethod
    def decrypt_secure_payload(encrypted_key: str, encrypted_payload: str, rsa_private_key):
        aes_key = HybridSecurityEngine.decrypt_aes_key(
            base64.b64decode(encrypted_key),
            rsa_private_key
        )
        return HybridSecurityEngine.decrypt_payload(encrypted_payload, aes_key)
