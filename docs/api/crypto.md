# internal.crypto

Konstanta profil algoritma, pembuatan kunci, dan tanda tangan. Semua primitif berasal dari pustaka [`cryptography`](https://cryptography.io/en/latest/).

## `internal.crypto.common`

### Konstanta

| Nama | Tipe | Nilai |
| --- | --- | --- |
| `ALG_RSA_PSS` | `str` | `"rsa-pss-sha256"` |
| `ALG_ECDSA` | `str` | `"ecdsa-p256-sha256"` |
| `ALG_ED25519` | `str` | `"ed25519"` |
| `ALGORITHMS` | `list[str]` | Tiga nilai di atas, dengan urutan yang sama |
| `RSA_BITS` | `int` | `3072` |
| `RSA_EXPONENT` | `int` | `65537` |
| `PSS_SALT_LENGTH` | `int` | `32` |
| `ECDSA_COORD_LENGTH` | `int` | `32`, panjang `r` dan `s` |
| `ECDSA_SIGNATURE_LENGTH` | `int` | `64` |
| `SIGNATURE_LENGTHS` | `dict[str, int]` | `{"rsa-pss-sha256": 384, "ecdsa-p256-sha256": 64, "ed25519": 64}` |

### `pss_padding()`

Membuat padding RSA-PSS untuk profil `rsa-pss-sha256`: MGF1 dengan SHA-256 dan salt 32 byte.

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `padding.PSS` | `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)` |

### `get_algorithm_from_key(private_key)`

Menentukan profil dari kunci privat dan memastikan parameternya sesuai profil.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `private_key` | `RSAPrivateKey \| EllipticCurvePrivateKey \| Ed25519PrivateKey` | Kunci privat dari `cryptography` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `str` | Salah satu nilai `ALGORITHMS` |
| **Error** | `ValueError` | RSA bukan 3072 bit atau e ≠ 65537, EC bukan P-256, atau tipe kunci lain |

### `der_to_raw(der_signature)`

Mengubah tanda tangan ECDSA DER (keluaran `cryptography`) menjadi format mentah `r ‖ s`.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `der_signature` | `bytes` | Tanda tangan ECDSA dalam DER (`SEQUENCE { r, s }`) |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | 64 byte: `r` dan `s` masing-masing 32 byte big-endian |

### `raw_to_der(raw_signature)`

Kebalikan dari `der_to_raw`.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `raw_signature` | `bytes` | Tepat 64 byte `r ‖ s` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | Tanda tangan ECDSA DER |
| **Error** | `ValueError` | Panjang bukan 64 byte |

```python
from internal.crypto.common import der_to_raw, raw_to_der

raw = der_to_raw(der_signature)
assert len(raw) == 64
assert raw_to_der(raw) == der_signature   # untuk DER minimal hasil cryptography
```

### `public_der(public_key)`

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `public_key` | Kunci publik `cryptography` | RSA, EC, atau Ed25519 |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | DER SubjectPublicKeyInfo hasil ekspor ulang |

### `key_id(public_key)`

Menghitung keyid (fingerprint) kunci publik.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `public_key` | Kunci publik `cryptography` | RSA, EC, atau Ed25519 |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `str` | `hex_lower(SHA-256(public_der(public_key)))`, 64 karakter |

### `load_private_key(path)`

Memuat kunci privat PEM yang tidak terenkripsi, lalu menentukan profilnya.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `path` | `str \| os.PathLike` | Path file PEM |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `tuple[PrivateKey, str]` | `(kunci_privat, profil)` |
| **Error** | `OSError` | File tidak bisa dibaca |
| | `ValueError`, `TypeError` | PEM rusak, terenkripsi, atau parameter kunci di luar profil |

### `load_public_key(pem_data)`

Memuat kunci publik PEM tanpa validasi profil. Pemanggilnya yang harus memvalidasi. Untuk validasi ketat, pakai [`internal.trust.key_validation.load_public_key`](trust.md#load_public_keypem).

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `pem_data` | `bytes` | Teks PEM |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | Kunci publik `cryptography` | |
| **Error** | `ValueError` | PEM tidak valid |

## `internal.crypto.keygen`

### `generate_key(algorithm)`

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `algorithm` | `str` | Salah satu nilai `ALGORITHMS` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `RSAPrivateKey \| EllipticCurvePrivateKey \| Ed25519PrivateKey` | Kunci privat baru |
| **Error** | `ValueError` | Algoritma tidak didukung |

### `save_key(private_key, out_prefix)`

Menyimpan `<out_prefix>.key.pem` (PKCS#8, tidak terenkripsi, mode `0600`) dan `<out_prefix>.pub.pem` (SPKI, mode `0644`). Folder induk dibuat kalau belum ada. File yang sudah ada tidak pernah ditimpa.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `private_key` | Kunci privat `cryptography` | |
| `out_prefix` | `str` | Prefix path, tidak boleh kosong atau diakhiri pemisah folder |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `None` | |
| **Error** | `ValueError` | Prefix tidak valid |
| | `FileExistsError` | Salah satu file sudah ada |
| | `OSError` | Gagal menulis |

### `key_gen(algorithm, out_prefix)`

Gabungan `generate_key` dan `save_key`.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `algorithm` | `str` | Salah satu nilai `ALGORITHMS` |
| `out_prefix` | `str` | Prefix path |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `str` | keyid kunci publik |
| **Error** | Sama dengan `generate_key` dan `save_key` | |

```python
from internal.crypto.keygen import key_gen

keyid = key_gen("ed25519", "keys/alice")
print(keyid)   # 64 karakter hex; keys/alice.key.pem dan keys/alice.pub.pem dibuat
```

## `internal.crypto.sign`

### `sign_manifest(algorithm, private_key, manifest_data)`

Menandatangani byte manifest dengan profil yang diberikan.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `algorithm` | `str` | Salah satu nilai `ALGORITHMS` |
| `private_key` | Kunci privat `cryptography` | Harus sesuai `algorithm` |
| `manifest_data` | `bytes` | Byte manifest kanonik |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | RSA-PSS: 384 byte. ECDSA: 64 byte `r ‖ s`. Ed25519: 64 byte |
| **Error** | `ValueError` | Algoritma tidak didukung |

### `sign(file_path, package, version, key_path, output_path)`

Alur lengkap perintah `sign`:

1. Muat kunci privat dan tentukan profil serta keyid-nya.
2. Hitung ukuran dan SHA-256 artefak.
3. Buat manifest kanonik, lalu pastikan manifest itu lolos `parse_and_check`.
4. Tanda tangani manifest dan simpan bundle.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `file_path` | `str` | Path artefak. Nama file (tanpa folder) menjadi `artifact.name` |
| `package` | `str` | Nama paket |
| `version` | `str` | Versi |
| `key_path` | `str` | Path kunci privat PEM |
| `output_path` | `str` | Path bundle keluaran. Ditulis atomik dan menimpa file lama |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `None` | |
| **Error** | `OSError`, `ValueError`, `ManifestValidationError`, `InputError` | Diteruskan dari langkah-langkah di atas |

```python
from internal.crypto.sign import sign

sign("app-1.0.0.tar.gz", "app", "1.0.0", "keys/alice.key.pem", "app-1.0.0.bundle.json")
```
