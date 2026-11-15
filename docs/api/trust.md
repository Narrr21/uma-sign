# internal.trust

Trust store menentukan kunci publik mana yang dipercaya dan untuk paket apa saja. Format berkasnya ada di [README → Trust store](https://github.com/Narrr21/uma-sign#trust-store-umasign-trustv1).

Modul ini dipecah menjadi tiga bagian:

- **data:** `trust_store_structure`;
- **validasi kunci:** `key_validation`;
- **I/O** dan **operasi murni:** `trust_store_file_management` dan `trust_store`.

Operasi murni tidak membaca atau menulis file, dan tidak mengubah objek masukan.

## `internal.trust.trust_store_structure`

| Konstanta | Tipe | Nilai |
| --- | --- | --- |
| `SCHEMA` | `str` | `"umasign-trust/v1"` |

### `TrustStoreKey`

Dataclass `frozen`.

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `keyid` | `str` | 64 karakter hex huruf kecil |
| `algorithm` | `str` | Salah satu profil |
| `public_key_pem` | `str` | Teks PEM SPKI |
| `packages` | `tuple[str, ...]` | Tidak kosong, unik |

### `TrustStore`

Dataclass `frozen`.

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `schema` | `str` | `"umasign-trust/v1"` |
| `keys` | `tuple[TrustStoreKey, ...]` | keyid unik; boleh kosong |

### `empty_store()`

| | Tipe |
| --- | --- |
| **Keluaran** | `TrustStore` dengan `keys=()` |

### `find(store, keyid)`

| Parameter | Tipe |
| --- | --- |
| `store` | `TrustStore` |
| `keyid` | `str` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `TrustStoreKey \| None` | `None` jika keyid tidak ditemukan |

## `internal.trust.key_validation`

### `load_public_key(pem)`

Memuat kunci publik dengan aturan ketat:

- input harus ASCII dan berupa tepat satu blok berlabel `PUBLIC KEY`;
- isi base64-nya harus valid;
- DER asli harus **sama persis** dengan DER hasil ekspor ulang.

Aturan terakhir menolak titik EC *compressed*, RSA dengan OID selain `rsaEncryption`, dan Ed25519 dengan parameter.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `pem` | `str \| bytes` | Teks PEM |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | Kunci publik `cryptography` | |
| **Error** | `FormatError` | Bukan ASCII, label salah, base64 rusak, kunci tidak bisa dimuat, atau DER tidak kanonik |

### `profile_of(public_key)`

| Parameter | Tipe |
| --- | --- |
| `public_key` | Kunci publik `cryptography` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `str` | `"rsa-pss-sha256"`, `"ecdsa-p256-sha256"`, atau `"ed25519"` |
| **Error** | `FormatError` | RSA bukan 3072 bit atau e ≠ 65537, EC bukan P-256, atau tipe lain |

### `compute_keyid(public_key)`

| Parameter | Tipe |
| --- | --- |
| `public_key` | Kunci publik `cryptography` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `str` | `hex_lower(SHA-256(DER SPKI))` |

### `verify_key(keyid, public_key_pem, algorithm)`

Memvalidasi satu entri trust store.

| Parameter | Tipe |
| --- | --- |
| `keyid` | `str` |
| `public_key_pem` | `str \| bytes` |
| `algorithm` | `str` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | Kunci publik `cryptography` | Kunci yang sudah tervalidasi |
| **Error** | `FormatError` | PEM rusak, profil ≠ `algorithm`, atau keyid ≠ hasil hitung |

```python
from internal.trust.key_validation import load_public_key, profile_of, compute_keyid

key = load_public_key(open("keys/alice.pub.pem").read())
print(profile_of(key), compute_keyid(key))
```

## `internal.trust.trust_store_file_management`

### `parse_store(raw)`

Parsing strict tanpa I/O.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `raw` | `bytes` | Isi file trust store |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `TrustStore` | Selalu valid |
| **Error** | `FormatError` | Bukan UTF-8, JSON rusak, field duplikat/tambahan/hilang, tipe salah, `schema` salah, `packages` kosong/duplikat/pola salah, keyid ganda, atau `verify_key` gagal |

### `serialize_store(store)`

| Parameter | Tipe |
| --- | --- |
| `store` | `TrustStore` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | JSON dengan urutan field tetap dan indentasi 2 spasi |

### `load_store(path)`

| Parameter | Tipe |
| --- | --- |
| `path` | `str \| os.PathLike` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `TrustStore` | |
| **Error** | `InputError` | File tidak ada atau tidak bisa dibaca |
| | `FormatError` | Dari `parse_store` |

### `load_store_or_empty(path)`

Sama seperti `load_store`, tetapi mengembalikan `empty_store()` jika file **belum ada**. File yang ada tetapi rusak tetap menghasilkan `FormatError`.

### `save_store(path, store)`

Menulis secara atomik: file sementara, `fsync`, lalu `os.replace`.

| Parameter | Tipe |
| --- | --- |
| `path` | `str \| os.PathLike` |
| `store` | `TrustStore` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `None` | |
| **Error** | `InputError` | Gagal menulis. File lama tetap utuh |

## `internal.trust.trust_store`

### `AddResult`

Dataclass `frozen`.

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `store` | `TrustStore` | Store setelah operasi |
| `entry` | `TrustStoreKey` | Entri kunci setelah operasi |
| `changed` | `bool` | `False` jika kunci dan paket sudah ada |

### `add(store, public_key_pem, package)`

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `store` | `TrustStore` | Store awal (tidak diubah) |
| `public_key_pem` | `str \| bytes` | Teks PEM kunci publik |
| `package` | `str` | Nama paket |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `AddResult` | Lihat perilaku di bawah |
| **Error** | `FormatError` | Nama paket atau kunci tidak valid |

Perilaku:

- **Kunci baru:** entri baru dengan `packages=(package,)`, dan `changed=True`.
- **Kunci sudah ada, paket baru:** paket ditambahkan ke entri yang sama, dan `changed=True`.
- **Kunci dan paket sudah ada:** store tidak berubah, dan `changed=False`.

### `list_keys(store)`

| | Tipe |
| --- | --- |
| **Keluaran** | `tuple[TrustStoreKey, ...]` |

### `remove(store, keyid)`

| Parameter | Tipe |
| --- | --- |
| `store` | `TrustStore` |
| `keyid` | `str` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `TrustStore` | Store baru tanpa entri tersebut |
| **Error** | `KeyIdNotFound` | keyid tidak ada |

### `authorize(store, keyid, algorithm, package)`

Langkah otorisasi kunci saat verifikasi. Fungsi ini mengecek berurutan dan berhenti di kegagalan pertama:

1. keyid ada di store;
2. `algorithm` entri sama dengan `algorithm` manifest;
3. `package` ada di `packages` entri (dibandingkan persis).

Fungsi ini tidak pernah mencoba entri lain dan tidak mengubah store.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `store` | `TrustStore` | Hasil `parse_store` |
| `keyid` | `str` | Dari manifest |
| `algorithm` | `str` | Dari manifest |
| `package` | `str` | Dari opsi `--package` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | Kunci publik `cryptography` | Siap dipakai untuk verifikasi tanda tangan |
| **Error** | `KeyNotTrusted` | Salah satu pengecekan gagal |

```python
from internal.trust import trust_store
from internal.trust.trust_store_file_management import load_store_or_empty, save_store

store = load_store_or_empty("trust.json")
result = trust_store.add(store, open("keys/alice.pub.pem").read(), "app")
if result.changed:
    save_store("trust.json", result.store)

public_key = trust_store.authorize(result.store, result.entry.keyid, result.entry.algorithm, "app")
```
