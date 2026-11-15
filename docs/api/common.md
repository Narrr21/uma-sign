# internal.common

Utilitas parsing ketat yang dipakai bersama oleh trust store dan bundle.

## `internal.common.strict_json`

### `loads(text)`

Sama seperti `json.loads`, tetapi menolak field duplikat. Pengecekannya dilakukan lewat `object_pairs_hook`, karena setelah menjadi `dict`, duplikatnya sudah hilang.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `text` | `str` | Teks JSON |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `dict \| list \| str \| int \| float \| bool \| None` | Hasil parse |
| **Error** | `FormatError` | JSON tidak valid (`"invalid JSON: ..."`) atau ada field duplikat (`"duplicate field: <nama>"`) |

```python
from internal.common.strict_json import loads

loads('{"a": 1}')          # {'a': 1}
loads('{"a": 1, "a": 2}')  # FormatError: duplicate field: a
```

## `internal.common.b64`

### `strict_b64decode(s)`

Decode Base64 standar dengan validasi ketat. String di-*decode*, di-*encode* ulang, lalu dibandingkan dengan input. Kalau berbeda, decode ditolak.

| Parameter | Tipe | Keterangan |
| --- | --- | --- |
| `s` | `str` | String Base64 |

| | Tipe | Keterangan |
| --- | --- | --- |
| **Keluaran** | `bytes` | Hasil decode |
| **Error** | `FormatError` | Karakter non-ASCII atau di luar alfabet standar, padding salah, ada whitespace, alfabet URL-safe, atau bit sisa bukan nol (tidak kanonik) |

```python
from internal.common.b64 import strict_b64decode

strict_b64decode("AA==")   # b'\x00'
strict_b64decode("AB==")   # FormatError: Base64 is not in canonical form
strict_b64decode("AA AA")  # FormatError: invalid Base64: ...
```
