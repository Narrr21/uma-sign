# internal.verifier

Pipeline verifikasi lengkap untuk perintah `verify`.

## `internal.verifier.verify`

### Konstanta status

`OK`, `INPUT_ERROR`, `FORMAT_ERROR`, `UNSUPPORTED_ALGORITHM`, `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH`, `ARTIFACT_MISMATCH`. Semuanya `str` dengan nilai sama seperti namanya. Artinya dijelaskan di [Status dan error](../errors.md).

### `VerifyResult`

Dataclass.

| Field | Tipe | Keterangan |
| --- | --- | --- |
| `valid` | `bool` | `True` hanya jika `status == "OK"` |
| `status` | `str` | Salah satu konstanta status |
| `message` | `str` | Penjelasan singkat |
| `algorithm` | `str \| None` | Dari manifest. `None` jika manifest belum terbaca |
| `keyid` | `str \| None` | Dari manifest |
| `package` | `str \| None` | Dari manifest |
| `version` | `str \| None` | Dari manifest |

#### `to_dict()`

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `dict` | Ketujuh field di atas, dipakai untuk keluaran `--json` |

### `verify(file_path, bundle_path, trust_path, package, version)`

Menjalankan semua pengecekan secara berurutan dan berhenti di kegagalan pertama. Fungsi ini **tidak melempar exception**: semua kegagalan, termasuk error tak terduga, dikembalikan sebagai `VerifyResult`.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `file_path` | `str \| None` | Path artefak |
| `bundle_path` | `str \| None` | Path bundle |
| `trust_path` | `str \| None` | Path trust store |
| `package` | `str \| None` | Paket yang diharapkan |
| `version` | `str \| None` | Versi yang diharapkan |

Parameter bernilai `None` menghasilkan `INPUT_ERROR`.

| | Tipe |
| --- | --- |
| **Keluaran** | `VerifyResult` |

Urutan pengecekan:

| # | Pengecekan | Status jika gagal |
| --- | --- | --- |
| 1 | Semua parameter ada, dan ketiga file bisa dibaca | `INPUT_ERROR` |
| 2 | `load_bundle` | `INPUT_ERROR` / `FORMAT_ERROR` |
| 3 | `parse_and_check` pada byte manifest | `FORMAT_ERROR` |
| 4 | Panjang tanda tangan sesuai `SIGNATURE_LENGTHS` | `FORMAT_ERROR` |
| 5 | `load_store` | `INPUT_ERROR` / `FORMAT_ERROR` |
| 6 | `algorithm` termasuk `ALGORITHMS` | `UNSUPPORTED_ALGORITHM` |
| 7 | keyid ada, profil sama, kunci cocok dengan keyid, paket diizinkan | `KEY_NOT_TRUSTED` |
| 8 | Tanda tangan valid atas byte manifest asli | `INVALID_SIGNATURE` |
| 9 | `package`, `version`, dan nama file sama dengan manifest | `METADATA_MISMATCH` |
| 10 | Ukuran dan SHA-256 artefak sama dengan manifest | `ARTIFACT_MISMATCH` |

```python
from internal.verifier.verify import verify, exit_code

result = verify("app-1.0.0.tar.gz", "app-1.0.0.bundle.json", "trust.json", "app", "1.0.0")
print(result.to_dict())
print(exit_code(result))
```

```text
{'valid': True, 'status': 'OK', 'message': 'all checks passed', 'algorithm': 'ed25519', 'keyid': '5751d752...d9f6', 'package': 'app', 'version': '1.0.0'}
0
```

Contoh jika artefak diubah setelah ditandatangani:

```text
{'valid': False, 'status': 'ARTIFACT_MISMATCH', 'message': 'artifact size differs from the manifest', ...}
1
```

### `exit_code(result)`

| Parameter | Tipe |
| --- | --- |
| `result` | `VerifyResult` |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `int` | `0` untuk `OK`, `2` untuk `INPUT_ERROR`, dan `1` untuk status lain |
