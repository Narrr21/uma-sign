# internal.manifest

Model manifest rilis, serialisasi kanonik, dan parser strict. Manifest adalah data yang ditandatangani. Format lengkapnya ada di [README → Manifest](https://github.com/Narrr21/uma-sign#manifest-umasign-manifestv1).

!!! warning "Tanda tangan diverifikasi pada byte asli"
    Verifikasi tanda tangan harus memakai byte manifest asli dari bundle, bukan hasil serialisasi ulang objek `ReleaseManifest`.

## `internal.manifest.builder`

### `Artifact`

Dataclass (bisa diubah).

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `name` | `str` | Nama file artefak tanpa folder |
| `size` | `int` | Ukuran dalam byte |
| `sha256` | `str` | SHA-256 hex huruf kecil |

### `ReleaseManifest`

Dataclass (bisa diubah).

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `schema` | `str` | `"umasign-manifest/v1"` |
| `package` | `str` | Nama paket |
| `version` | `str` | Versi |
| `algorithm` | `str` | Profil algoritma |
| `keyid` | `str` | keyid penanda tangan |
| `artifact` | `Artifact` | Metadata artefak |

### `ManifestBuilder(schema, package, version, algorithm, keyid)`

Menyimpan field manifest yang tidak bergantung pada artefak.

| Parameter | Tipe |
| --- | --- |
| `schema` | `str` |
| `package` | `str` |
| `version` | `str` |
| `algorithm` | `str` |
| `keyid` | `str` |

#### `build(artifact_name, artifact_size, artifact_sha256)`

| Parameter | Tipe |
| --- | --- |
| `artifact_name` | `str` |
| `artifact_size` | `int` |
| `artifact_sha256` | `str` |

| | Tipe |
| --- | --- |
| **Keluaran** | `ReleaseManifest` |

Metode ini tidak memvalidasi nilai. Validasi terjadi saat `serialize_manifest`.

#### `build_from_file(path)`

Membaca artefak sekali untuk mendapatkan ukuran dan SHA-256, lalu memanggil `build` dengan nama file dari `path`.

| Parameter | Tipe |
| --- | --- |
| `path` | `str` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `ReleaseManifest` | |
| **Error** | `OSError` | Artefak tidak bisa dibaca |

```python
from internal.manifest.builder import ManifestBuilder
from internal.manifest.serializer import serialize_manifest

builder = ManifestBuilder("umasign-manifest/v1", "app", "1.0.0", "ed25519", "a" * 64)
manifest = builder.build_from_file("app-1.0.0.tar.gz")
data = serialize_manifest(manifest)   # bytes kanonik
```

## `internal.manifest.hash`

### `hash_artifact(path)`

Membaca file per blok 1 MiB.

| Parameter | Tipe |
| --- | --- |
| `path` | `str` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `tuple[int, str]` | `(ukuran_byte, sha256_hex_huruf_kecil)` |
| **Error** | `OSError` | File tidak bisa dibaca |

## `internal.manifest.serializer`

| Konstanta | Tipe | Nilai |
| --- | --- | --- |
| `MAX_MANIFEST_SIZE` | `int` | `16384` |
| `MAX_SAFE_INTEGER` | `int` | `9007199254740991` (2^53 − 1) |

### `validate_manifest(m)`

Mengecek semua field terhadap aturan format tanpa menserialisasi.

| Parameter | Tipe |
| --- | --- |
| `m` | `ReleaseManifest` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `None` | |
| **Error** | `ManifestValidationError` | Ada field yang tidak valid |

### `serialize_manifest(m)`

Menghasilkan byte kanonik: urutan field tetap, tanpa whitespace, UTF-8/ASCII.

| Parameter | Tipe |
| --- | --- |
| `m` | `ReleaseManifest` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | Maksimal 16 384 byte |
| **Error** | `ManifestValidationError` | Field tidak valid atau hasil terlalu besar |

## `internal.manifest.parser`

### `parse_manifest(data)`

Parsing strict, lalu validasi nilai.

| Parameter | Tipe |
| --- | --- |
| `data` | `bytes` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `ReleaseManifest` | |
| **Error** | `ManifestFormatError` | Bukan `bytes`, lebih dari 16 KiB, ada BOM, bukan UTF-8/ASCII, JSON rusak, field duplikat/tambahan/hilang, bilangan pecahan, `NaN`/`Infinity`, atau nilai tidak valid |

## `internal.manifest.canonical`

### `is_canonical(data, m)`

| Parameter | Tipe |
| --- | --- |
| `data` | `bytes` |
| `m` | `ReleaseManifest` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bool` | `True` jika `data == serialize_manifest(m)` |

### `parse_and_check(data)`

Fungsi yang dipakai verifier. Isinya `parse_manifest`, lalu memastikan byte input sama persis dengan bentuk kanonik.

| Parameter | Tipe |
| --- | --- |
| `data` | `bytes` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `ReleaseManifest` | |
| **Error** | `ManifestFormatError` | Semua error `parse_manifest`, ditambah `"non-canonical"` |

```python
from internal.manifest.canonical import parse_and_check
from internal.manifest.errors import ManifestFormatError

try:
    manifest = parse_and_check(bundle.manifest)
except ManifestFormatError as error:
    print("FORMAT_ERROR:", error)
```
