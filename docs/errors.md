# Status dan error

## Status verifikasi

`internal.verifier.verify.verify()` tidak melempar exception. Semua kegagalan dikembalikan sebagai `VerifyResult.status`, lalu `exit_code(result)` memetakannya ke exit code proses.

| Status | Exit code | Penyebab |
| --- | --- | --- |
| `OK` | 0 | Semua pengecekan lolos |
| `INPUT_ERROR` | 2 | Opsi kurang, file tidak ada/tidak bisa dibaca, atau error tak terduga |
| `FORMAT_ERROR` | 1 | Bundle, manifest, atau trust store tidak sesuai format, atau panjang tanda tangan salah untuk profilnya |
| `UNSUPPORTED_ALGORITHM` | 1 | `algorithm` di manifest bukan salah satu profil yang didukung |
| `KEY_NOT_TRUSTED` | 1 | Keyid tidak ada di trust store, profil berbeda, kunci tidak cocok, atau paket tidak diizinkan |
| `INVALID_SIGNATURE` | 1 | Tanda tangan tidak cocok dengan byte manifest |
| `METADATA_MISMATCH` | 1 | Paket, versi, atau nama file berbeda dari manifest |
| `ARTIFACT_MISMATCH` | 1 | Ukuran atau SHA-256 artefak berbeda dari manifest |

## Exception trust store, bundle, dan common

Didefinisikan di `internal.trust.errors`. Selain dipakai trust store, kelas ini juga dipakai `internal.bundle` dan `internal.common`. Setiap kelas punya atribut kelas `status: str` dan `exit_code: int`.

| Kelas | Turunan dari | `status` | `exit_code` | Dilempar saat |
| --- | --- | --- | --- | --- |
| `TrustError` | `Exception` | `None` | `None` | Kelas dasar; tidak dilempar langsung |
| `InputError` | `TrustError` | `INPUT_ERROR` | 2 | File tidak bisa dibaca atau ditulis |
| `KeyIdNotFound` | `InputError` | `INPUT_ERROR` | 2 | `remove()` dengan keyid yang tidak ada |
| `FormatError` | `TrustError` | `FORMAT_ERROR` | 1 | Isi trust store, bundle, kunci publik, JSON, atau Base64 tidak sesuai kontrak |
| `KeyNotTrusted` | `TrustError` | `KEY_NOT_TRUSTED` | 1 | `authorize()` gagal |

```python
from internal.trust.errors import TrustError
from internal.trust.trust_store_file_management import load_store

try:
    store = load_store("trust.json")
except TrustError as error:
    print(error.status, error.exit_code, error)
```

```text
INPUT_ERROR 2 cannot read trust store trust.json: [Errno 2] No such file or directory: 'trust.json'
```

## Exception manifest

Didefinisikan di `internal.manifest.errors`.

| Kelas | Turunan dari | Dilempar saat |
| --- | --- | --- |
| `ManifestError` | `Exception` | Kelas dasar |
| `ManifestValidationError` | `ManifestError` | Sisi pembuat: nilai field tidak valid saat `validate_manifest` atau `serialize_manifest` |
| `ManifestFormatError` | `ManifestError` | Sisi verifier: byte manifest rusak atau tidak kanonik saat `parse_manifest` atau `parse_and_check` |

## Exception lain

| Fungsi | Exception |
| --- | --- |
| `generate_key`, `get_algorithm_from_key`, `raw_to_der`, `sign_manifest` | `ValueError` |
| `save_key` | `ValueError` (prefix kosong), `FileExistsError` (file sudah ada), `OSError` |
| `load_private_key` | `OSError`, `ValueError`, `TypeError` |
| `hash_artifact` | `OSError` |
