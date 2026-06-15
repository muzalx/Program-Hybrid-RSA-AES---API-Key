# Dokumentasi Program Hybrid RSA-AES

## Gambaran Umum

Program ini memakai kriptografi hybrid RSA-AES untuk mengamankan data API. AES-GCM dipakai untuk mengenkripsi isi payload karena cepat dan mendukung validasi integritas data. RSA-OAEP SHA-256 dipakai untuk mengenkripsi AES key agar hanya server dengan private key yang bisa membuka payload.

Alur utamanya:

1. Klien membuat AES-256 key sementara.
2. Klien mengenkripsi plaintext memakai AES-GCM.
3. Klien mengenkripsi AES key memakai RSA public key.
4. Klien mengirim `encrypted_key` dan `encrypted_payload` ke server.
5. Server membuka `encrypted_key` memakai RSA private key.
6. Server memakai AES key hasil decrypt untuk membuka payload menjadi plaintext.

## Struktur File Penting

- `src/security_engine.py`: fungsi utama untuk generate key, encrypt, dan decrypt.
- `src/generate_keys.py`: script untuk membuat RSA key pair lokal.
- `src/app.py`: Flask app dan endpoint API.
- `keys/private_key.pem`: private key server, tidak boleh dibagikan.
- `keys/public_key.pem`: public key untuk enkripsi dari sisi klien.

## Setup Program

Install dependency:

```bash
pip install -r requirements.txt
```

Generate RSA key pair:

```bash
python -m src.generate_keys
```

Perintah ini membuat:

```text
keys/private_key.pem
keys/public_key.pem
```

Jalankan server Flask:

```bash
flask --app src.app run --debug
```

Atau:

```bash
python src/app.py
```

## Cara Kerja Enkripsi

Fungsi `build_secure_payload(data, rsa_public_key)` dipakai untuk membuat payload terenkripsi.

Contoh:

```python
from src.security_engine import HybridSecurityEngine

public_key = HybridSecurityEngine.load_public_key("keys/public_key.pem")
payload = HybridSecurityEngine.build_secure_payload(
    {"message": "hello"},
    public_key
)
```

Hasilnya berbentuk JSON:

```json
{
  "encrypted_key": "base64-rsa-encrypted-aes-key",
  "encrypted_payload": "base64-aes-gcm-nonce-plus-ciphertext"
}
```

`encrypted_key` berisi AES key yang sudah dienkripsi dengan RSA public key. `encrypted_payload` berisi gabungan nonce AES-GCM dan ciphertext yang di-encode ke Base64.

## Cara Kerja Dekripsi

Fungsi `decrypt_secure_payload(encrypted_key, encrypted_payload, rsa_private_key)` dipakai untuk mengubah hasil kriptografi kembali menjadi plaintext.

Contoh:

```python
from src.security_engine import HybridSecurityEngine

private_key = HybridSecurityEngine.load_private_key("keys/private_key.pem")
plaintext = HybridSecurityEngine.decrypt_secure_payload(
    payload["encrypted_key"],
    payload["encrypted_payload"],
    private_key
)
```

Jika payload awal adalah `{"message": "hello"}`, hasil plaintext adalah:

```json
{"message": "hello"}
```

## Cara Memakai API

Endpoint utama:

```text
POST /api/v1/secure-data
```

Request body:

```json
{
  "encrypted_key": "base64-rsa-encrypted-aes-key",
  "encrypted_payload": "base64-aes-gcm-nonce-plus-ciphertext"
}
```

Response sukses:

```json
{
  "data": {
    "message": "hello"
  }
}
```

Jika plaintext bukan JSON valid, server tetap mengembalikan string plaintext:

```json
{
  "data": "hello"
}
```

## Endpoint Dokumentasi Web

Buka halaman berikut di browser setelah server berjalan:

```text
http://127.0.0.1:5000/
```

Halaman `/` berisi ringkasan endpoint, contoh payload, command lokal, dan lokasi private key default.

## Menjalankan Test

Jalankan:

```bash
python -m pytest
```

Test memastikan AES key valid, payload bisa dienkripsi dan didekripsi, RSA key bisa membuka AES key, secure payload bisa kembali menjadi plaintext, dan endpoint Flask berjalan benar.

## Catatan Keamanan

Jangan membagikan `keys/private_key.pem`. Public key boleh diberikan ke klien untuk enkripsi, tetapi private key hanya boleh ada di server. AES key dibuat sementara untuk setiap payload, sehingga key simetris tidak perlu disimpan permanen.
