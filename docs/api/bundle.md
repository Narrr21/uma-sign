# internal.bundle

Model bundle (pembawa byte manifest dan byte tanda tangan), parser strict, dan baca/tulis file. Format lengkapnya ada di [README → Bundle](https://github.com/Narrr21/uma-sign#bundle-umasign-bundlev1).

Bundle **tidak** mem-*parse* manifest dan **tidak** mengecek panjang tanda tangan. Keduanya ditangani modul manifest dan verifier.

## `internal.bundle.bundle_structure`

| Konstanta | Tipe | Nilai |
| --- | --- | --- |
| `SCHEMA` | `str` | `"umasign-bundle/v1"` |

### `Bundle`

Dataclass `frozen`. Menyimpan **byte hasil decode**, bukan string Base64.

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `schema` | `str` | `"umasign-bundle/v1"` |
| `manifest` | `bytes` | Byte manifest kanonik |
| `signature` | `bytes` | Byte tanda tangan |

### `BundleBuilder(schema)`

| Parameter | Tipe |
| --- | --- |
| `schema` | `str` |

#### `build(manifest, signature)`

| Parameter | Tipe |
| --- | --- |
| `manifest` | `bytes` |
| `signature` | `bytes` |

| | Tipe |
| --- | --- |
| **Keluaran** | `Bundle` |

## `internal.bundle.bundle_file_management`

| Konstanta | Tipe | Nilai |
| --- | --- | --- |
| `MAX_BUNDLE_SIZE` | `int` | `65536` (64 KiB) |

### `parse_bundle(raw)`

Mem-*parse* byte bundle. Pengecekannya berurutan: ukuran ≤ 64 KiB, tanpa BOM, UTF-8 valid, JSON tanpa field duplikat, objek dengan tepat tiga field bertipe string, `schema` benar, lalu Base64 kanonik untuk kedua field. Urutan field dan whitespace bebas.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `raw` | `bytes` | Isi file bundle |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `Bundle` | |
| **Error** | `FormatError` | Salah satu pengecekan di atas gagal |

```python
from internal.bundle.bundle_file_management import parse_bundle

raw = b'{ "signature_b64": "AA==", "schema": "umasign-bundle/v1", "manifest_b64": "e30=" }'
bundle = parse_bundle(raw)
print(bundle.manifest, bundle.signature)   # b'{}' b'\x00'
```

### `serialize_bundle(bundle)`

| Parameter | Tipe |
| --- | --- |
| `bundle` | `Bundle` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | JSON UTF-8 dengan urutan `schema`, `manifest_b64`, `signature_b64`, indentasi 2 spasi |

### `load_bundle(path)`

Membaca paling banyak 64 KiB + 1 byte, lalu memanggil `parse_bundle`. File raksasa tidak dibaca seluruhnya.

| Parameter | Tipe |
| --- | --- |
| `path` | `str \| os.PathLike` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `Bundle` | |
| **Error** | `InputError` | File tidak ada atau tidak bisa dibaca |
| | `FormatError` | Dari `parse_bundle` |

### `save_bundle(path, bundle)`

Menulis secara atomik: file sementara di folder yang sama, `fsync`, lalu `os.replace`. Kalau gagal, file sementara dihapus dan file lama tetap utuh.

| Parameter | Tipe |
| --- | --- |
| `path` | `str \| os.PathLike` |
| `bundle` | `Bundle` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `None` | |
| **Error** | `InputError` | Gagal menulis |

```python
from internal.bundle.bundle_file_management import load_bundle, save_bundle
from internal.bundle.bundle_structure import Bundle, SCHEMA

save_bundle("out.bundle.json", Bundle(SCHEMA, b"manifest-bytes", b"signature-bytes"))
assert load_bundle("out.bundle.json").manifest == b"manifest-bytes"
```
