# Project Plan: Implementasi Keamanan API-Key Hybrid (RSA-AES) - Versi Python

## Deskripsi Teknis
- **Bahasa**: Python 3.10+
- **Backend Framework**: Flask (untuk API endpoint)
- **Library Kriptografi**: 
  - `cryptography`: Standar industri untuk operasi kriptografi (AES-GCM, RSA-OAEP).
  - `PyCryptodome`: Alternatif untuk manipulasi data tingkat rendah jika diperlukan.
- **Data Exchange**: JSON dengan pengkodean Base64 untuk payload terenkripsi.

## Fase Pengerjaan (Implementasi Spesifik)
1. **Fase Persiapan**:
   - Install dependensi: `pip install flask cryptography pycryptodome`
   - Generate RSA-2048 keys menggunakan `cryptography.hazmat.primitives.asymmetric.rsa`.
2. **Fase Konstruksi Klien**:
   - Generate `AES-256` ephemeral key menggunakan `os.urandom(32)`.
   - Gunakan `AES-GCM` (Galois/Counter Mode) untuk enkripsi payload (rekomendasi untuk integritas data).
   - Enkripsi AES key dengan RSA Public Key (Padding: `OAEP`).
3. **Fase Konstruksi Server**:
   - Implementasi Flask route `/api/v1/secure-data` untuk menerima JSON.
   - Dekripsi AES key dengan RSA Private Key.
   - Dekripsi payload dengan AES key.
4. **Fase Pengujian**:
   - Unit test untuk setiap fungsi enkripsi/dekripsi.
   - Verifikasi payload setelah dekripsi.