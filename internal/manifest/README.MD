# Manifest
Modul ini menyediakan utilitas untuk membuat, membaca, dan memvalidasi manifest rilis. Manifest adalah file JSON kanonik yang berisi metadata tentang artifact rilis, termasuk ukuran, hash SHA-256, dan algoritma tanda tangan.

## Membuat Manifest
```python
from pathlib import Path

from internal.manifest.builder import ManifestBuilder
from internal.manifest.serializer import serialize_manifest

builder = ManifestBuilder(
	schema="umasign-manifest/v1",
	package="uma-sign",
	version="1.2.3",
	algorithm="ed25519",
	keyid="a" * 64,  # Ganti dengan key ID aktual: 64 karakter hex lowercase.
)

manifest = builder.build_from_file("dist/uma-sign.tar.gz")
manifest_bytes = serialize_manifest(manifest)
Path("dist/uma-sign.manifest.json").write_bytes(manifest_bytes)
```

`build_from_file(path)` mengambil nama file dari path, lalu membaca artifact dalam mode biner untuk mendapatkan ukuran dan SHA-256 dalam satu pass.

Jika metadata artifact sudah tersedia, gunakan `build()`:

```python
manifest = builder.build(
	artifact_name="uma-sign.tar.gz",
	artifact_size=12345,
	artifact_sha256="b" * 64,
)
```

`serialize_manifest()` memvalidasi semua field sebelum menghasilkan byte JSON kanonik.

## Membaca Manifest

Gunakan `parse_and_check()`:

```python
from pathlib import Path

from internal.manifest.canonical import parse_and_check
from internal.manifest.errors import ManifestFormatError

try:
	manifest_bytes = Path("dist/uma-sign.manifest.json").read_bytes()
	manifest = parse_and_check(manifest_bytes)
except OSError as error:
	print(f"Gagal membaca manifest: {error}")
except ManifestFormatError as error:
	print(f"Format manifest tidak valid: {error}")
```

`parse_manifest(data)` melakukan parsing strict dan validasi nilai. `parse_and_check(data)` juga membandingkan byte input dengan serialisasi kanonik; whitespace, urutan field berbeda, escape JSON alternatif, atau representasi angka nonkanonik akan ditolak dengan `ManifestFormatError("non-canonical")`.

`ManifestFormatError` ditujukan untuk sisi verifier. `ManifestValidationError` ditujukan untuk sisi pembuat/signing. Keduanya mewarisi `ManifestError`.

## Integrasi Verifikasi Tanda Tangan

Verifikasi tanda tangan harus memakai byte manifest asli yang dibaca dari disk. Jangan menserialisasi ulang objek `manifest` sebelum memeriksa tanda tangan. Objek hasil parsing berguna untuk membaca field, sedangkan input byte asli adalah data yang ditandatangani:

```python
manifest_bytes = Path("dist/uma-sign.manifest.json").read_bytes()
manifest = parse_and_check(manifest_bytes)

# Teruskan manifest_bytes ke fungsi verifier untuk pemeriksaan tanda tangan.
# Gunakan manifest.algorithm untuk memilih profil yang didukung oleh verifier.
```

Parser sengaja tidak membatasi `algorithm` pada daftar algoritma tertentu. Karena itu verifier tetap harus menolak algoritma yang tidak didukung sebelum verifikasi kriptografi.

## API Lain

- `validate_manifest(manifest)`: validasi field tanpa menserialisasi.
- `is_canonical(data, manifest)`: kembalikan `True` jika byte sama persis dengan serialisasi kanonik manifest tersebut.
- `hash_artifact(path)`: kembalikan tuple `(ukuran_byte, sha256_hex_lowercase)`; kesalahan baca diteruskan sebagai `OSError`.
- `Artifact`, `ReleaseManifest`, `ManifestBuilder`: model dan pembangun manifest.

Jalankan tes modul:

```powershell
py -m pytest tests/manifest/test_manifest.py -q
```
