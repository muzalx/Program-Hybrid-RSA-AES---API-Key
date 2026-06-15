from pathlib import Path

try:
    from src.security_engine import HybridSecurityEngine
except ModuleNotFoundError:
    from security_engine import HybridSecurityEngine


KEYS_DIR = Path("keys")
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def main():
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        print("RSA key pair already exists.")
        return

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_key, public_key = HybridSecurityEngine.generate_rsa_key_pair()
    PRIVATE_KEY_PATH.write_bytes(
        HybridSecurityEngine.serialize_private_key(private_key)
    )
    PUBLIC_KEY_PATH.write_bytes(
        HybridSecurityEngine.serialize_public_key(public_key)
    )
    print("RSA key pair generated in keys/.")


if __name__ == "__main__":
    main()
