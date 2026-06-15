import json
from pathlib import Path

from flask import Flask, jsonify, request

try:
    from src.security_engine import HybridSecurityEngine
except ModuleNotFoundError:
    from security_engine import HybridSecurityEngine


DEFAULT_PRIVATE_KEY_PATH = Path("keys/private_key.pem")
DOCUMENTATION_HTML = """
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hybrid RSA-AES API Documentation</title>
    <style>
        body {
            color: #17202a;
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px auto;
            max-width: 880px;
            padding: 0 20px;
        }
        code, pre {
            background: #f4f6f7;
            border-radius: 6px;
            padding: 2px 6px;
        }
        pre {
            overflow-x: auto;
            padding: 16px;
        }
    </style>
</head>
<body>
    <h1>Hybrid RSA-AES API Documentation</h1>
    <p>API ini menerima payload terenkripsi dengan AES-GCM dan AES key yang dienkripsi memakai RSA-OAEP SHA-256.</p>

    <h2>Endpoint</h2>
    <p><code>POST /api/v1/secure-data</code></p>

    <h2>Request JSON</h2>
    <pre>{
  "encrypted_key": "base64-rsa-encrypted-aes-key",
  "encrypted_payload": "base64-aes-gcm-nonce-plus-ciphertext"
}</pre>

    <h2>Success Response</h2>
    <pre>{
  "data": {
    "message": "hello"
  }
}</pre>

    <h2>Error Response</h2>
    <p>Request invalid akan mengembalikan status <code>400</code>. Private key yang tidak ditemukan akan mengembalikan status <code>500</code>.</p>

    <h2>Local Commands</h2>
    <pre>python -m src.generate_keys
flask --app src.app run --debug
python src/app.py</pre>

    <h2>Key Path</h2>
    <p>Secara default server membaca private key dari <code>keys/private_key.pem</code> relatif terhadap root project.</p>
</body>
</html>
"""


def create_app(private_key_path=DEFAULT_PRIVATE_KEY_PATH):
    app = Flask(__name__)

    @app.get("/")
    def documentation():
        return DOCUMENTATION_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.post("/api/v1/secure-data")
    def secure_data():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON payload"}), 400

        encrypted_key = payload.get("encrypted_key")
        encrypted_payload = payload.get("encrypted_payload")
        if not encrypted_key or not encrypted_payload:
            return jsonify({"error": "Missing encrypted_key or encrypted_payload"}), 400

        key_path = Path(private_key_path)
        if not key_path.exists():
            return jsonify({"error": "Private key not found"}), 500

        try:
            private_key = HybridSecurityEngine.load_private_key(key_path)
            decrypted_payload = HybridSecurityEngine.decrypt_secure_payload(
                encrypted_key,
                encrypted_payload,
                private_key
            )
        except Exception:
            return jsonify({"error": "Unable to decrypt payload"}), 400

        try:
            data = json.loads(decrypted_payload)
        except json.JSONDecodeError:
            data = decrypted_payload

        return jsonify({"data": data})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
