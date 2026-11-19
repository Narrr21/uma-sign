# Hasil Pengujian Skenario U01-U14

Dijalankan: 2026-11-16 07:07:01  
Lingkungan: Python 3.11.9, cryptography 50.0.2, Windows-10-10.0.26300-SP0  
Total: 153/153 kasus lulus.

Kunci di folder `keys/` dibuat khusus untuk pengujian ini dan tidak dipakai di tempat lain.

## Kunci

| Pemilik | Algoritma | keyid |
|---|---|---|
| publisher | rsa-pss-sha256 | `9c103e5be3908b8d371fa2a0edcfe192e4343888913bfca8ccd04d37dabddab8` |
| publisher | ecdsa-p256-sha256 | `91d130517117762870c501342a985abbb54035e432f538e2967f458ab4fe5647` |
| publisher | ed25519 | `b6761a99b18fca918b86a02f798b8bfbd6af6b6ac78d3f2b1a71cf5796db58d5` |
| lain | rsa-pss-sha256 | `de23071f4031275e8ec0cc02e474cea31ed1c6bad6aa2a3c58dadf154f216a07` |
| lain | ecdsa-p256-sha256 | `554627cf8c7bbd7afb9ab6efcd3f05833167b72e5c2ebb101f30ef89d7834798` |
| lain | ed25519 | `c89c41cb713404e1acd048ca594e414e68f6e4f690f9a7acb7aa8fe5b16a429b` |

## Isi folder tiap kasus

- artefak (nama sesuai kasus)
- `bundle.json`: bundle yang diverifikasi (sudah dimanipulasi bila skenarionya begitu)
- `manifest.json`: byte manifest hasil decode dari `bundle.json`
- `trust.json`: trust store yang dipakai
- `hasil.json`: perintah sign/verify, exit code, keluaran verify, status yang diharapkan

## Ringkasan

| Skenario | Variasi | Algoritma | Status | Exit | Diharapkan | Hasil | Pesan |
|---|---|---|---|---|---|---|---|
| U01 | teks | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | teks | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | teks | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | biner | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | biner | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | biner | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | kosong | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | kosong | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U01 | kosong | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U02 | awal | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | awal | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | awal | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | tengah | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | tengah | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | tengah | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | akhir | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | akhir | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U02 | akhir | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact SHA-256 differs from the manifest |
| U03 | tambah_di_akhir | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | tambah_di_akhir | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | tambah_di_akhir | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | tambah_di_awal | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | tambah_di_awal | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | tambah_di_awal | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_byte_terakhir | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_byte_terakhir | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_byte_terakhir | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_bagian_tengah | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_bagian_tengah | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_bagian_tengah | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_semua | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_semua | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | hapus_semua | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | kosong_ditambah_satu_byte | rsa-pss-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | kosong_ditambah_satu_byte | ecdsa-p256-sha256 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U03 | kosong_ditambah_satu_byte | ed25519 | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH / 1 | LULUS | artifact size differs from the manifest |
| U04 | verify_versi_baru | rsa-pss-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U04 | verify_versi_baru | ecdsa-p256-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U04 | verify_versi_baru | ed25519 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U04 | verify_versi_lama | rsa-pss-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U04 | verify_versi_lama | ecdsa-p256-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U04 | verify_versi_lama | ed25519 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | awal | rsa-pss-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | awal | ecdsa-p256-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | awal | ed25519 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | tengah | rsa-pss-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | tengah | ecdsa-p256-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | tengah | ed25519 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | akhir | rsa-pss-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | akhir | ecdsa-p256-sha256 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U05 | akhir | ed25519 | INVALID_SIGNATURE | 1 | INVALID_SIGNATURE / 1 | LULUS | signature does not match the manifest |
| U06 | trust_kosong | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | trust_kosong | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | trust_kosong | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_profil_lain | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_profil_lain | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_profil_lain | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_lain_profil_sama | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_lain_profil_sama | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U06 | hanya_kunci_lain_profil_sama | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U07 | paket_lain | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | paket_lain | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | paket_lain | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | awalan_sama | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | awalan_sama | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | awalan_sama | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | potongan_nama | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | potongan_nama | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | potongan_nama | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | nama_mirip | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | nama_mirip | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | nama_mirip | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | dua_paket_lain | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | dua_paket_lain | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | dua_paket_lain | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | key is not allowed for package app |
| U07 | kontrol_paket_diizinkan | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U07 | kontrol_paket_diizinkan | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U07 | kontrol_paket_diizinkan | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U08 | versi_1.0.1 | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_1.0.1 | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_1.0.1 | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_2.0.0 | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_2.0.0 | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_2.0.0 | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_1.0.0-rc1 | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_1.0.0-rc1 | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U08 | versi_1.0.0-rc1 | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | version differs from the manifest |
| U09 | nama_app-1.0.1.tar.gz | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_app-1.0.1.tar.gz | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_app-1.0.1.tar.gz | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_App-1.0.0.tar.gz | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_App-1.0.0.tar.gz | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_App-1.0.0.tar.gz | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_app.tar.gz | rsa-pss-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_app.tar.gz | ecdsa-p256-sha256 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U09 | nama_app.tar.gz | ed25519 | METADATA_MISMATCH | 1 | METADATA_MISMATCH / 1 | LULUS | artifact name differs from the file name |
| U10 | bundle_field_duplikat | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: duplicate field: signature_b64 |
| U10 | bundle_field_duplikat | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: duplicate field: signature_b64 |
| U10 | bundle_field_duplikat | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: duplicate field: signature_b64 |
| U10 | manifest_field_duplikat | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: duplicate object key: package |
| U10 | manifest_field_duplikat | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: duplicate object key: package |
| U10 | manifest_field_duplikat | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: duplicate object key: package |
| U10 | bundle_tipe_salah | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: signature_b64 must be a string |
| U10 | bundle_tipe_salah | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: signature_b64 must be a string |
| U10 | bundle_tipe_salah | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: signature_b64 must be a string |
| U10 | manifest_tipe_salah | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: artifact.size must be an integer |
| U10 | manifest_tipe_salah | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: artifact.size must be an integer |
| U10 | manifest_tipe_salah | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: artifact.size must be an integer |
| U10 | base64_karakter_asing | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_karakter_asing | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_karakter_asing | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_padding_salah | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Incorrect padding |
| U10 | base64_padding_salah | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Incorrect padding |
| U10 | base64_padding_salah | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Incorrect padding |
| U10 | base64_whitespace | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_whitespace | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_whitespace | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_url_safe | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_url_safe | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | base64_url_safe | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | bundle: invalid Base64: Only base64 data is allowed |
| U10 | manifest_melebihi_16KiB | rsa-pss-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: manifest exceeds 16384 bytes |
| U10 | manifest_melebihi_16KiB | ecdsa-p256-sha256 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: manifest exceeds 16384 bytes |
| U10 | manifest_melebihi_16KiB | ed25519 | FORMAT_ERROR | 1 | FORMAT_ERROR / 1 | LULUS | manifest: manifest exceeds 16384 bytes |
| U11 | algorithm_rsa-pkcs1-sha256 | rsa-pss-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: rsa-pkcs1-sha256 |
| U11 | algorithm_rsa-pkcs1-sha256 | ecdsa-p256-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: rsa-pkcs1-sha256 |
| U11 | algorithm_rsa-pkcs1-sha256 | ed25519 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: rsa-pkcs1-sha256 |
| U11 | algorithm_ecdsa-p384-sha384 | rsa-pss-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ecdsa-p384-sha384 |
| U11 | algorithm_ecdsa-p384-sha384 | ecdsa-p256-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ecdsa-p384-sha384 |
| U11 | algorithm_ecdsa-p384-sha384 | ed25519 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ecdsa-p384-sha384 |
| U11 | algorithm_ED25519 | rsa-pss-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ED25519 |
| U11 | algorithm_ED25519 | ecdsa-p256-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ED25519 |
| U11 | algorithm_ED25519 | ed25519 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: ED25519 |
| U11 | algorithm_none | rsa-pss-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: none |
| U11 | algorithm_none | ecdsa-p256-sha256 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: none |
| U11 | algorithm_none | ed25519 | UNSUPPORTED_ALGORITHM | 1 | UNSUPPORTED_ALGORITHM / 1 | LULUS | unsupported algorithm: none |
| U12 | kunci_lain_profil_sama | rsa-pss-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U12 | kunci_lain_profil_sama | ecdsa-p256-sha256 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U12 | kunci_lain_profil_sama | ed25519 | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED / 1 | LULUS | keyid is not in the trust store |
| U13 | urutan_terbalik | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | urutan_terbalik | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | urutan_terbalik | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | indentasi_4 | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | indentasi_4 | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | indentasi_4 | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | satu_baris_rapat | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | satu_baris_rapat | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | satu_baris_rapat | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | crlf_tab_dan_spasi | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | crlf_tab_dan_spasi | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U13 | crlf_tab_dan_spasi | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U14 | sign_dua_kali | rsa-pss-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U14 | sign_dua_kali | ecdsa-p256-sha256 | OK | 0 | OK / 0 | LULUS | all checks passed |
| U14 | sign_dua_kali | ed25519 | OK | 0 | OK / 0 | LULUS | all checks passed |
