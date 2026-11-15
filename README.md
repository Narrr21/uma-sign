# uma-sign

`umasign` adalah CLI untuk menandatangani dan memverifikasi artefak rilis perangkat lunak. Penerbit membuat pasangan kunci, lalu menandatangani artefak. Hasilnya berupa *bundle* yang berisi manifest kanonik dan tanda tangan. Pengguna memverifikasi artefak terhadap bundle dan *trust store* yang menentukan kunci mana yang dipercaya untuk paket mana.

Tiga profil algoritma didukung: **RSA-PSS 3072 / SHA-256**, **ECDSA P-256 / SHA-256**, dan **Ed25519**.

**Dokumentasi API:** https://narrr21.github.io/uma-sign/

## Daftar isi

- [Instalasi](#instalasi)
- [Penggunaan CLI](#penggunaan-cli)
- [Status dan exit code](#status-dan-exit-code)
- [Format berkas](#format-berkas)
- [Pemetaan profil algoritma ke API pustaka](#pemetaan-profil-algoritma-ke-api-pustaka)
- [Struktur repositori](#struktur-repositori)
- [Pengujian](#pengujian)
- [Dokumentasi API](#dokumentasi-api)
- [Pustaka yang digunakan](#pustaka-yang-digunakan)

## Instalasi

Butuh Python 3.10 atau lebih baru.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python cmd/umasign/main.py --help
```

Dengan Docker:

```bash
docker compose build
docker compose run --rm uma-sign --help
```

Folder `./artifacts` di-*mount* ke `/data` di dalam kontainer.

## Penggunaan CLI

Contoh di bawah adalah satu alur lengkap: buat kunci, tanda tangani, percayai kunci, lalu verifikasi.

### 1. `keygen`: buat pasangan kunci

```bash
python cmd/umasign/main.py keygen --algorithm ed25519 --out_prefix keys/alice
```

| Opsi | Keterangan |
| --- | --- |
| `--algorithm` | `rsa-pss-sha256`, `ecdsa-p256-sha256`, atau `ed25519` |
| `--out_prefix` | Prefix path. Menghasilkan `<prefix>.key.pem` dan `<prefix>.pub.pem` |

Perintah ini mencetak keyid (fingerprint) ke stdout. Kalau salah satu file sudah ada, perintah gagal dan tidak menimpanya.

```
5751d752faf44afa4c2e6db07d384aece26ac7a1fd10daa206834b332a86d9f6
```

### 2. `sign`: tanda tangani artefak

```bash
python cmd/umasign/main.py sign --file app-1.0.0.tar.gz --package app --version 1.0.0 \
    --key keys/alice.key.pem --out app-1.0.0.bundle.json
```

| Opsi | Keterangan |
| --- | --- |
| `--file` | Artefak yang ditandatangani |
| `--package` | Nama paket, pola `[a-z0-9][a-z0-9._-]{0,63}` |
| `--version` | Versi, pola `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `--key` | Kunci privat PEM (PKCS#8, tidak terenkripsi) |
| `--out` | Path bundle keluaran |

Profil algoritma dan keyid diambil dari kunci privat. Manifest dibuat dalam bentuk kanonik lalu ditandatangani, dan hasilnya disimpan sebagai bundle.

### 3. `trust`: kelola trust store

```bash
python cmd/umasign/main.py trust add    --store trust.json --key keys/alice.pub.pem --package app
python cmd/umasign/main.py trust list   --store trust.json
python cmd/umasign/main.py trust remove --store trust.json --keyid <64 hex>
```

- `trust add` mencetak keyid. Kalau kunci sudah ada, paket baru digabungkan ke entri yang sama. Kalau kunci dan paket sudah ada, file tidak ditulis ulang. Kalau `trust.json` belum ada, file baru dibuat.
- `trust list` mencetak satu baris per kunci: `<keyid> <algorithm> [<paket>, ...]`.
- `trust remove` menghapus satu entri berdasarkan keyid.

### 4. `verify`: verifikasi artefak

```bash
python cmd/umasign/main.py verify --file app-1.0.0.tar.gz --bundle app-1.0.0.bundle.json \
    --trust-store trust.json --package app --version 1.0.0 --json
```

```json
{"valid": true, "status": "OK", "message": "all checks passed", "algorithm": "ed25519", "keyid": "5751d752...d9f6", "package": "app", "version": "1.0.0"}
```

Tanpa `--json`, keluarannya satu baris `STATUS: pesan`, misalnya `OK: all checks passed`.

## Status dan exit code

`verify` berhenti di pengecekan pertama yang gagal. Urutan pengecekannya: opsi lengkap dan file bisa dibaca, bundle, manifest, panjang tanda tangan, trust store, algoritma, kepercayaan kunci, tanda tangan, metadata, lalu isi artefak.

| Status | Exit code | Arti |
| --- | --- | --- |
| `OK` | 0 | Semua pengecekan lolos |
| `INPUT_ERROR` | 2 | Opsi kurang, atau file tidak ada/tidak bisa dibaca |
| `FORMAT_ERROR` | 1 | Bundle, manifest, atau trust store tidak sesuai format, atau panjang tanda tangan salah |
| `UNSUPPORTED_ALGORITHM` | 1 | `algorithm` di manifest bukan salah satu dari tiga profil |
| `KEY_NOT_TRUSTED` | 1 | Keyid tidak ada di trust store, profilnya berbeda, atau kunci tidak dipercaya untuk paket ini |
| `INVALID_SIGNATURE` | 1 | Tanda tangan tidak cocok dengan byte manifest |
| `METADATA_MISMATCH` | 1 | `--package`, `--version`, atau nama file berbeda dari manifest |
| `ARTIFACT_MISMATCH` | 1 | Ukuran atau SHA-256 artefak berbeda dari manifest |

Untuk perintah lain:

| Perintah | Berhasil | Gagal |
| --- | --- | --- |
| `keygen` | 0 | 1 |
| `sign` | 0 | 2 |
| `trust add/list/remove` | 0 | 2 untuk `INPUT_ERROR` (termasuk keyid tidak ditemukan), 1 untuk `FORMAT_ERROR` |

## Format berkas

Semua berkas JSON memakai UTF-8. Bundle dan trust store menolak field duplikat, field tambahan, field yang hilang, dan nilai `null`.

### Kunci

| Berkas | Isi |
| --- | --- |
| `<prefix>.key.pem` | Kunci privat, PEM PKCS#8 tidak terenkripsi (`BEGIN PRIVATE KEY`), mode `0600` |
| `<prefix>.pub.pem` | Kunci publik, PEM SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`), mode `0644` |

**keyid** = `hex_lower(SHA-256(DER SPKI))`. DER diambil dari hasil ekspor ulang kunci publik, jadi keyid tidak bergantung pada line ending atau pemenggalan baris PEM.

Kunci publik di trust store harus memakai label `PUBLIC KEY` dan *encoding* DER kanonik. Contohnya, titik EC *compressed*, RSA dengan OID selain `rsaEncryption`, atau Ed25519 dengan parameter ditolak. Parameter juga harus sesuai profil: RSA tepat 3072 bit dengan e = 65537, dan EC memakai kurva P-256.

### Manifest (`umasign-manifest/v1`)

Manifest adalah data yang ditandatangani. Bentuknya **kanonik**: urutan field tetap, tanpa whitespace, hanya ASCII, maksimal 16 384 byte.

```json
{"schema":"umasign-manifest/v1","package":"app","version":"1.0.0","algorithm":"ed25519","keyid":"5751d752faf44afa4c2e6db07d384aece26ac7a1fd10daa206834b332a86d9f6","artifact":{"name":"app-1.0.0.tar.gz","size":14,"sha256":"7601f7e4058ad017e5cab0b775ee8a3bc6e7bd36f763001855b268ebcf97ae17"}}
```

| Field | Tipe | Aturan |
| --- | --- | --- |
| `schema` | string | Tepat `umasign-manifest/v1` |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `algorithm` | string | 1–64 karakter ASCII tercetak, tanpa `"` dan `\` |
| `keyid` | string | `[0-9a-f]{64}` |
| `artifact.name` | string | `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, nama file tanpa folder |
| `artifact.size` | integer | 0 sampai 2^53 − 1 |
| `artifact.sha256` | string | `[0-9a-f]{64}` |

Parser menolak BOM, byte non-ASCII, field duplikat, bilangan pecahan, `NaN`/`Infinity`, dan setiap input yang byte-nya tidak sama persis dengan hasil serialisasi ulang.

### Bundle (`umasign-bundle/v1`)

Bundle hanya membawa byte manifest dan byte tanda tangan. Isi manifest dicek oleh modul manifest.

```json
{
  "schema": "umasign-bundle/v1",
  "manifest_b64": "eyJzY2hlbWEiOiJ1bWFzaWduLW1hbmlmZXN0L3YxIiwi...",
  "signature_b64": "ir7aesk3Gy/zbsMoTRXbKdhHLSMy/2tQNh/25k0iaisV1CRlvfH62eCH659/qjr9oCFAXOrk2hz1nYGM/tbVBw=="
}
```

| Field | Tipe | Isi |
| --- | --- | --- |
| `schema` | string | Tepat `umasign-bundle/v1` |
| `manifest_b64` | string | Base64 standar dari byte manifest kanonik |
| `signature_b64` | string | Base64 standar dari byte tanda tangan |

- Ukuran maksimal 64 KiB. Bundle tidak boleh memakai BOM dan harus berupa JSON valid dengan tepat tiga field di atas.
- Urutan field dan whitespace bebas.
- Base64 harus kanonik: alfabet standar `A–Z a–z 0–9 + /`, padding `=` yang benar, tanpa whitespace, dan sama persis dengan hasil encode ulang.
- Saat ditulis, bundle memakai indentasi 2 spasi. File ditulis atomik: file sementara, lalu `fsync`, lalu `os.replace`.

### Trust store (`umasign-trust/v1`)

```json
{
  "schema": "umasign-trust/v1",
  "keys": [
    {
      "keyid": "5751d752faf44afa4c2e6db07d384aece26ac7a1fd10daa206834b332a86d9f6",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
      "packages": ["app"]
    }
  ]
}
```

| Field | Tipe | Aturan |
| --- | --- | --- |
| `schema` | string | Tepat `umasign-trust/v1` |
| `keys` | array | Boleh kosong. `keyid` tiap entri harus unik |
| `keys[].keyid` | string | Harus sama dengan keyid hasil hitung dari `public_key_pem` |
| `keys[].algorithm` | string | Salah satu profil, dan harus sama dengan profil kunci |
| `keys[].public_key_pem` | string | Teks PEM SPKI (isi kunci, bukan path) |
| `keys[].packages` | array of string | Tidak kosong, unik, pola nama paket sama dengan manifest. Dibandingkan persis, tanpa wildcard |

Trust store yang rusak menghasilkan `FORMAT_ERROR`. `trust add` pada file yang rusak juga gagal dan tidak menimpa file tersebut. Penulisan file bersifat atomik.

## Pemetaan profil algoritma ke API pustaka

Semua operasi kriptografi memakai pustaka [`cryptography`](https://cryptography.io/en/latest/) (pyca), versi 50.0.2. Hash yang dipakai di semua profil adalah SHA-256. Data yang ditandatangani adalah byte manifest kanonik.

| Profil | Pembuatan kunci | Tanda tangan | Verifikasi | Format tanda tangan |
| --- | --- | --- | --- | --- |
| `rsa-pss-sha256` | `rsa.generate_private_key(public_exponent=65537, key_size=3072)` | `private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())` | `public_key.verify(sig, data, <padding yang sama>, hashes.SHA256())` | 384 byte |
| `ecdsa-p256-sha256` | `ec.generate_private_key(ec.SECP256R1())` | `private_key.sign(data, ec.ECDSA(hashes.SHA256()))` menghasilkan DER, lalu `decode_dss_signature` diubah ke `r ‖ s` | `encode_dss_signature(r, s)` lalu `public_key.verify(der, data, ec.ECDSA(hashes.SHA256()))` | 64 byte: `r` dan `s` masing-masing 32 byte big-endian |
| `ed25519` | `ed25519.Ed25519PrivateKey.generate()` | `private_key.sign(data)` | `public_key.verify(sig, data)` | 64 byte |

Serialisasi kunci yang dipakai di semua profil:

| Kebutuhan | API |
| --- | --- |
| Simpan kunci privat | `private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())` |
| Simpan kunci publik | `public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)` |
| DER untuk keyid | `public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)`, lalu `hashlib.sha256(...).hexdigest()` |
| Muat kunci privat | `serialization.load_pem_private_key(data, password=None)` |
| Muat kunci publik | `serialization.load_pem_public_key` (verifier) dan `serialization.load_der_public_key` (trust store) |

Referensi dokumentasi pustaka:
[RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) ·
[Elliptic curve](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/) ·
[Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) ·
[Serialisasi kunci](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/) ·
[Utils (DSS encode/decode)](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/)

## Struktur repositori

```
cmd/umasign/main.py        titik masuk CLI
internal/crypto/           profil algoritma, keygen, sign
internal/manifest/         model, serialisasi kanonik, dan parser manifest
internal/bundle/           model, parser, dan I/O bundle
internal/trust/            trust store: model, validasi kunci, I/O, operasi, CLI trust
internal/verifier/         pipeline verifikasi dan CLI verify
internal/common/           parser JSON strict dan Base64 strict
test/                      unit test dan tes skenario
docs/                      sumber situs dokumentasi API
```

## Pengujian

```bash
pip install -r requirements.txt
python -m pytest test -q
```

## Dokumentasi API

Dokumentasi API modul internal di-*host* di **GitHub Pages**: https://narrr21.github.io/uma-sign/

Isinya mencakup deskripsi tiap modul, parameter masukan dan keluaran beserta tipe datanya, error yang dilempar, dan contoh penggunaan.

Kakas yang digunakan:

| Kakas | Kegunaan |
| --- | --- |
| [MkDocs](https://www.mkdocs.org/) | Generator situs statis dari berkas Markdown di folder `docs/` |
| [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) | Tema MkDocs: navigasi, pencarian, dan *syntax highlighting* |
| GitHub Actions (`.github/workflows/docs.yml`) | Membangun situs setiap ada *push* ke `main` yang mengubah `docs/` atau `mkdocs.yml` |
| GitHub Pages | Hosting situs hasil build |

Membangun dan melihat dokumentasi secara lokal:

```bash
pip install -r docs/requirements.txt
mkdocs serve          # buka http://127.0.0.1:8000
mkdocs build --strict # hasil di folder site/
```

Aktifkan sekali di GitHub: **Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Pustaka yang digunakan

| Pustaka | Versi | Kegunaan |
| --- | --- | --- |
| [cryptography](https://cryptography.io/en/latest/) | 50.0.2 | Semua primitif kriptografi dan serialisasi kunci |
| [pytest](https://docs.pytest.org/) | 9.2.0 | Pengujian |
| [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) | lihat `docs/requirements.txt` | Situs dokumentasi API |
