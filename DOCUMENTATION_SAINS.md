# Dokumentasi Algoritma Kriptografi Hybrid RSA-AES untuk Keamanan API

## 1. Pendahuluan

Sistem ini mengimplementasikan skema kriptografi hybrid yang mengkombinasikan algoritma simetris *Advanced Encryption Standard* dalam mode *Galois/Counter Mode* (AES-GCM) dan algoritma asimetris *Rivest–Shamir–Adleman* dengan skema *padding Optimal Asymmetric Encryption Padding* (RSA-OAEP). Tujuan dari skema hybrid adalah untuk memanfaatkan kecepatan AES dalam mengenkripsi data bervolume besar sekaligus memanfaatkan keamanan RSA dalam distribusi kunci simetris (AES key) tanpa perlu *key exchange* secara manual.

Secara umum, alur kriptografi hybrid terdiri dari tiga entitas:

- **Kunci simetris sementara (ephemeral AES-256 key)**: Dibangkitkan untuk setiap sesi enkripsi dan tidak disimpan secara permanen.
- **Kunci publik RSA (RSA public key)**: Digunakan untuk mengenkripsi AES key agar hanya pemilik kunci privat yang dapat membukanya.
- **Kunci privat RSA (RSA private key)**: Digunakan untuk mendekripsi AES key dan selanjutnya digunakan untuk membuka payload.

---

## 2. Algoritma Enkripsi (Encryption Scheme)

### 2.1 Pembangkitan AES Key Ephemeral

AES-GCM memerlukan kunci simetris sepanjang 256 bit (32 byte). Kunci ini dibangkitkan menggunakan *Cryptographically Secure Pseudo-Random Number Generator* (CSPRNG) yang diimplementasikan oleh pustaka `cryptography`. Kunci bersifat *ephemeral* — hanya berlaku untuk satu kali proses enkripsi dan tidak pernah disimpan dalam bentuk *plaintext*.

```
Langkah 1: aes_key ← AESGCM.generate_key(bit_length = 256)
```

**Output**: `aes_key` sepanjang 32 byte.

### 2.2 Enkripsi Payload dengan AES-GCM

AES dalam mode *Galois/Counter Mode* (GCM) memberikan dua jaminan keamanan sekaligus: **kerahasiaan** (confidentiality) melalui enkripsi blok dan **integritas** (authenticity) melalui *authentication tag* yang dihasilkan oleh operasi Galois *field multiplication*. Mode GCM mengubah AES blok cipher menjadi *stream cipher* dengan menggunakan nilai *counter* yang bertambah secara inkremental.

Proses:

**Langkah 2.1**: Bangkitkan *nonce* (IV) sepanjang 96 bit (12 byte) menggunakan CSPRNG.

```
nonce ← random_bytes(12)
```

**Langkah 2.2**: Enkripsi *plaintext* menggunakan AES-GCM dengan kunci `aes_key` dan *nonce* yang telah dibangkitkan.

```
(authentication_tag, ciphertext) ← AES_GCM_encrypt(aes_key, nonce, plaintext)
```

**Langkah 2.3**: Gabungkan *nonce* dan *ciphertext* (beserta *authentication tag*) menjadi satu struktur biner, lalu *encode* ke dalam format Base64 untuk keperluan transpor JSON.

```
raw_payload ← nonce || ciphertext
encrypted_payload ← base64_encode(raw_payload)
```

Catatan: Pada implementasi pustaka `cryptography`, fungsi `AESGCM.encrypt()` secara otomatis menyisipkan *authentication tag* di akhir *ciphertext*, sehingga `ciphertext` yang dikembalikan sudah mencakup tag tersebut.

### 2.3 Enkripsi AES Key dengan RSA-OAEP

AES key yang bersifat *ephemeral* perlu diamankan saat dikirimkan bersama payload. RSA-OAEP dengan fungsi hash SHA-256 digunakan untuk mengenkripsi AES key sehingga hanya entitas yang memiliki kunci privat RSA yang dapat mendekripsinya.

Skema OAEP (*Optimal Asymmetric Encryption Padding*) adalah skema padding yang terbukti aman secara *IND-CCA2* (*Indistinguishability under Adaptive Chosen Ciphertext Attack*). Parameter yang digunakan:

- **Algoritma hash**: SHA-256
- **Mask generation function**: MGF1 dengan SHA-256
- **Label**: *null* (tidak digunakan)
- **Eksponen publik**: 65537
- **Panjang kunci**: 2048 bit

Proses:

```
encrypted_aes_key ← RSA_OAEP_encrypt(rsa_public_key, aes_key, hash = SHA256, mgf = MGF1(SHA256))
```

**Output** hasil enkripsi RSA dalam bentuk *bytes* mentah, kemudian di-encode ke Base64:

```
encrypted_key ← base64_encode(encrypted_aes_key)
```

### 2.4 Penyusunan Payload Terenkripsi

Payload akhir yang dikirimkan melalui API berbentuk JSON dengan dua field:

```
{
    "encrypted_key": "<base64_rsa_encrypted_aes_key>",
    "encrypted_payload": "<base64_nonce_||_ciphertext>"
}
```

### 2.5 Pseudocode Enkripsi (Formal)

```
FUNCTION encrypt_secure(data, rsa_public_key) → JSON
    plaintext ← json_encode(data)                     ▷ jika data berupa objek
    aes_key ← AESGCM.generate_key(256)                ▷ 32 byte
    nonce ← random_bytes(12)                          ▷ 96 bit
    ciphertext ← AESGCM.encrypt(aes_key, nonce, plaintext)
    encrypted_payload ← base64_encode(nonce || ciphertext)
    encrypted_key ← base64_encode(
        RSA_OAEP_encrypt(rsa_public_key, aes_key,
            hash = SHA256,
            mgf = MGF1(SHA256))
    )
    RETURN {"encrypted_key": encrypted_key,
            "encrypted_payload": encrypted_payload}
END FUNCTION
```

---

## 3. Algoritma Dekripsi (Decryption Scheme)

### 3.1 Dekripsi AES Key dengan RSA-OAEP

Penerima payload melakukan dekripsi AES key terlebih dahulu menggunakan kunci privat RSA.

```
aes_key ← RSA_OAEP_decrypt(rsa_private_key, base64_decode(encrypted_key),
            hash = SHA256,
            mgf = MGF1(SHA256))
```

Pada tahap ini, hanya pemilik kunci privat RSA yang sah yang dapat memperoleh AES key. Jika dekripsi gagal (misalnya karena kunci tidak sesuai atau payload telah dimodifikasi), fungsi akan melempar *exception*.

### 3.2 Ekstraksi Nonce dan Dekripsi Payload dengan AES-GCM

Setelah AES key berhasil diperoleh, payload didekripsi sebagai berikut:

**Langkah 3.2.1**: *Decode* `encrypted_payload` dari Base64 menjadi *bytes* mentah.

```
raw_payload ← base64_decode(encrypted_payload)
```

**Langkah 3.2.2**: Ekstrak 12 byte pertama sebagai *nonce*, sisanya adalah *ciphertext* (yang sudah mencakup *authentication tag*).

```
nonce ← raw_payload[0:12]
ciphertext ← raw_payload[12:]
```

**Langkah 3.2.3**: Dekripsi menggunakan AES-GCM. Jika *authentication tag* tidak valid (menandakan modifikasi data), maka fungsi akan melempar *exception* dan dekripsi gagal.

```
plaintext ← AESGCM.decrypt(aes_key, nonce, ciphertext)
plaintext_string ← plaintext.decode("utf-8")
```

### 3.3 Pseudocode Dekripsi (Formal)

```
FUNCTION decrypt_secure(encrypted_key, encrypted_payload, rsa_private_key) → string
    aes_key ← RSA_OAEP_decrypt(
        rsa_private_key,
        base64_decode(encrypted_key),
        hash = SHA256,
        mgf = MGF1(SHA256)
    )
    raw_payload ← base64_decode(encrypted_payload)
    nonce ← raw_payload[0:12]
    ciphertext ← raw_payload[12:]
    plaintext ← AESGCM.decrypt(aes_key, nonce, ciphertext)
    RETURN plaintext.decode("utf-8")
END FUNCTION
```

---

## 4. Parameter Keamanan dan Analisis

### 4.1 AES-256-GCM

| Parameter | Nilai | Keterangan |
|---|---|---|
| Algoritma | AES-256 | Standar NIST FIPS 197 |
| Mode Operasi | GCM | NIST SP 800-38D |
| Panjang Kunci | 256 bit (32 byte) | Tingkat keamanan 128-bit (kuantum: 128-bit) |
| Panjang Nonce | 96 bit (12 byte) | Direkomendasikan oleh NIST untuk interoperabilitas |
| Authentication Tag | 128 bit (16 byte) | Dihasilkan secara implisit oleh GCM |

**Rasional**: AES-256 dipilih untuk memberikan *security margin* terhadap serangan *brute-force* dan potensi ancaman komputasi kuantum. Mode GCM dipilih karena menyediakan *authenticated encryption* dalam satu operasi, menghilangkan kebutuhan akan skema *Encrypt-then-MAC* terpisah.

### 4.2 RSA-2048 OAEP SHA-256

| Parameter | Nilai | Keterangan |
|---|---|---|
| Algoritma | RSA | Standar PKCS #1 v2.2 (RFC 8017) |
| Panjang Kunci | 2048 bit | Setara dengan keamanan 112-bit |
| Eksponen Publik | 65537 (2¹⁶ + 1) | Standar industri, aman terhadap serangan *low-exponent* |
| Skema Padding | OAEP | IND-CCA2 *security* |
| Fungsi Hash | SHA-256 | Digunakan untuk *hash* dan MGF |
| Label | *null* | Tidak ada informasi konteks tambahan |

**Rasional**: RSA-2048 merupakan minimum standar industri yang diterima secara luas (NIST, PCI DSS, dan lainnya). OAEP dengan SHA-256 memberikan keamanan *IND-CCA2* yang melindungi terhadap serangan *chosen ciphertext*.

### 4.3 Nonce dan Keamanan Probabilistik

Setiap proses enkripsi menghasilkan *nonce* baru sepanjang 12 byte melalui CSPRNG. Hal ini menjamin bahwa:

1. Setiap ciphertext AES-GCM bersifat unik meskipun pesan yang sama dienkripsi berulang kali (*probabilistic encryption*).
2. Risiko tabrakan *nonce* (yang dapat mengakibatkan bocornya *authentication key* GCM) dapat diabaikan dengan panjang 96 bit dan pembangkitan acak.

### 4.4 Keamanan Ephemeral AES Key

AES key dibangkitkan untuk satu kali penggunaan (*one-time key*) dan tidak pernah disimpan. Dengan demikian, meskipun suatu saat kunci privat RSA bocor, hanya pesan yang terenkripsi dengan AES key yang masih terkait yang dapat dibuka — bukan seluruh riwayat pesan (*forward secrecy* pada tingkat sesi).

### 4.5 Enkripsi Payload di Luar JSON

Fungsi ini mendukung enkripsi data mentah (*string*) langsung tanpa perlu dibungkus ke dalam struktur JSON. Ini memberikan fleksibilitas tambahan saat plaintext pada sisi klien bukan merupakan objek JSON.

---

## 5. Diagram Alur Algoritma

### 5.1 Enkripsi

```
[Plaintext]
     |
     v
[JSON encode] ←── jika input berupa objek
     |
     v
[AES-256 key generation] ──→ aes_key (32 byte)
     |
     v
[Nonce generation] ──→ nonce (12 byte)
     |
     v
[AES-GCM encrypt] ──→ ciphertext || auth_tag
     |
     v
[Concatenate: nonce || ciphertext]
     |
     v
[Base64 encode] ──→ encrypted_payload
                          |
[aes_key]                 |
     |                    |
     v                    |
[RSA-OAEP encrypt]        |
     |                    |
     v                    |
[Base64 encode]           |
     |                    |
     v                    v
{ "encrypted_key": "...", "encrypted_payload": "..." }
```

### 5.2 Dekripsi

```
{ "encrypted_key": "...", "encrypted_payload": "..." }
     |                          |
     v                          |
[Base64 decode]                 |
     |                          |
     v                          |
[RSA-OAEP decrypt]              |
     |                          |
     v                          |
  aes_key                       |
     |                          |
     +──────────┬───────────────+
                |
                v
       [Base64 decode]
                |
                v
       [Extract nonce (12 byte) | ciphertext]
                |
                v
          [AES-GCM decrypt]
                |
                v
    [Verify auth tag] ──→ gagal → exception
                |
            sukses
                |
                v
          [Plaintext string]
```

---

## 6. Kesimpulan

Skema kriptografi hybrid AES-GCM dan RSA-OAEP SHA-256 yang diimplementasikan dalam sistem ini memberikan keseimbangan antara kecepatan enkripsi data bervolume besar (AES) dan keamanan distribusi kunci (RSA). AES-GCM menjamin kerahasiaan dan integritas data dalam satu operasi kriptografi, sementara RSA-OAEP memberikan keamanan *IND-CCA2* pada proses pertukaran kunci simetris. Penggunaan AES key yang bersifat *ephemeral* dan *nonce* probabilistik memastikan bahwa setiap ciphertext bersifat unik dan aman terhadap serangan *replay* serta analisis statistik.

---

## 7. Daftar Pustaka

1. National Institute of Standards and Technology. (2001). *FIPS 197: Advanced Encryption Standard (AES)*.
2. National Institute of Standards and Technology. (2007). *NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
3. Jonsson, J., & Kaliski, B. (2003). *Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1*. RFC 3447.
4. Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). *PKCS #1: RSA Cryptography Specifications Version 2.2*. RFC 8017.
5. Bellare, M., & Rogaway, P. (1994). *Optimal Asymmetric Encryption*. Advances in Cryptology — EUROCRYPT '94.
6. McGrew, D., & Viega, J. (2004). *The Galois/Counter Mode of Operation (GCM)*.
