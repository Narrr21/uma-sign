# uma-sign API

Dokumentasi ini menjelaskan modul internal Python yang dipakai CLI `umasign`. CLI-nya sendiri dibahas di [README repositori](https://github.com/Narrr21/uma-sign#readme).

`umasign` menandatangani artefak rilis dengan salah satu dari tiga profil (`rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`). Hasilnya berupa **bundle** berisi manifest kanonik dan tanda tangan. Artefak lalu diverifikasi terhadap bundle dan **trust store**.

## Peta modul

| Modul | Tanggung jawab |
| --- | --- |
| [`internal.crypto`](api/crypto.md) | Konstanta profil, pembuatan kunci, tanda tangan, konversi tanda tangan ECDSA, keyid |
| [`internal.manifest`](api/manifest.md) | Model manifest, serialisasi kanonik, parser strict, hash artefak |
| [`internal.bundle`](api/bundle.md) | Model bundle, parser strict, serialisasi, baca/tulis file |
| [`internal.trust`](api/trust.md) | Model trust store, validasi kunci publik, parser dan I/O, operasi add/list/remove/authorize |
| [`internal.verifier`](api/verifier.md) | Pipeline verifikasi lengkap dan hasilnya |
| [`internal.common`](api/common.md) | Parser JSON tanpa field duplikat dan decoder Base64 kanonik |

## Alur data

```text
keygen ──► <prefix>.key.pem ──► sign ──► bundle.json ─┐
       └─► <prefix>.pub.pem ──► trust add ──► trust.json ─┼─► verify ──► VerifyResult
                                         artefak ───────┘
```

## Menjalankan contoh

Semua contoh di dokumentasi ini dijalankan dari akar repositori, supaya paket `internal` bisa diimpor:

```bash
pip install -r requirements.txt
python -c "import internal.crypto.common as c; print(c.ALGORITHMS)"
```

```text
['rsa-pss-sha256', 'ecdsa-p256-sha256', 'ed25519']
```

## Konvensi

- **Tipe data** ditulis dengan notasi Python, misalnya `bytes`, `str | None`, `tuple[str, ...]`.
- **bytes vs str:** data yang ditandatangani dan isi berkas mentah selalu `bytes`, sedangkan field teks (keyid, nama paket, PEM di trust store) bertipe `str`.
- **Error:** modul bawah melempar exception, lalu CLI mengubahnya menjadi status dan exit code. Lihat [Status dan error](errors.md).
- **Objek data** (`Bundle`, `TrustStore`, `TrustStoreKey`, `AddResult`) adalah dataclass `frozen`, jadi tidak bisa diubah setelah dibuat. Fungsi yang "mengubah" store mengembalikan objek baru.
