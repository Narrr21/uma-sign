# Hasil Benchmark uma-sign

Dijalankan: 2026-11-16 07:02:56  
Lingkungan: Python 3.11.9, cryptography 50.0.2, OpenSSL 4.0.3 29 Sep 2026, Windows-10-10.0.26300-SP0, 12th Gen Intel(R) Core(TM) i5-12450H (12 logical CPU)  
Pengulangan: 20 per kombinasi, 2 pemanasan; nilai = median (ms).

## Sign dan verify

| Algoritma | Ukuran masukan | Sign (ms) | Verify (ms) | Ukuran signature (byte) |
|---|---|---|---|---|
| RSA-PSS | 1 KiB | 302.168 | 10.513 | 384 |
| RSA-PSS | 1 MiB | 300.545 | 10.791 | 384 |
| RSA-PSS | 10 MiB | 313.761 | 23.084 | 384 |
| RSA-PSS | 100 MiB | 421.267 | 130.739 | 384 |
| ECDSA P-256 | 1 KiB | 2.872 | 8.616 | 64 |
| ECDSA P-256 | 1 MiB | 3.781 | 9.533 | 64 |
| ECDSA P-256 | 10 MiB | 13.143 | 18.948 | 64 |
| ECDSA P-256 | 100 MiB | 102.367 | 105.656 | 64 |
| Ed25519 | 1 KiB | 2.664 | 2.377 | 64 |
| Ed25519 | 1 MiB | 3.516 | 3.074 | 64 |
| Ed25519 | 10 MiB | 11.832 | 11.577 | 64 |
| Ed25519 | 100 MiB | 143.506 | 132.946 | 64 |

## Rincian (median, ms)

| Algoritma | Ukuran | Sign total | Verify total | Hash artefak | Kripto sign | Kripto verify | Simpangan baku sign | Simpangan baku verify |
|---|---|---|---|---|---|---|---|---|
| RSA-PSS | 1 KiB | 302.168 | 10.513 | 0.821 | 4.667 | 0.184 | 7.800 | 0.989 |
| RSA-PSS | 1 MiB | 300.545 | 10.791 | 1.496 | 4.727 | 0.182 | 4.471 | 1.132 |
| RSA-PSS | 10 MiB | 313.761 | 23.084 | 13.031 | 4.740 | 0.180 | 3.298 | 1.593 |
| RSA-PSS | 100 MiB | 421.267 | 130.739 | 121.013 | 4.652 | 0.171 | 64.248 | 9.567 |
| ECDSA P-256 | 1 KiB | 2.872 | 8.616 | 0.548 | 0.085 | 0.072 | 0.287 | 0.603 |
| ECDSA P-256 | 1 MiB | 3.781 | 9.533 | 1.203 | 0.100 | 0.074 | 0.205 | 0.723 |
| ECDSA P-256 | 10 MiB | 13.143 | 18.948 | 10.398 | 0.121 | 0.081 | 0.581 | 0.996 |
| ECDSA P-256 | 100 MiB | 102.367 | 105.656 | 97.926 | 0.123 | 0.079 | 3.076 | 3.438 |
| Ed25519 | 1 KiB | 2.664 | 2.377 | 0.479 | 0.046 | 0.083 | 0.268 | 0.435 |
| Ed25519 | 1 MiB | 3.516 | 3.074 | 1.101 | 0.058 | 0.080 | 0.375 | 0.322 |
| Ed25519 | 10 MiB | 11.832 | 11.577 | 9.420 | 0.072 | 0.082 | 0.512 | 0.593 |
| Ed25519 | 100 MiB | 143.506 | 132.946 | 135.187 | 0.086 | 0.120 | 29.918 | 26.725 |

## Keygen (10 pengulangan, ms)

| Algoritma | Median | Rata-rata | Simpangan baku | Min | Maks |
|---|---|---|---|---|---|
| RSA-PSS | 234.435 | 291.027 | 232.821 | 85.177 | 777.971 |
| ECDSA P-256 | 0.028 | 0.710 | 2.144 | 0.027 | 6.812 |
| Ed25519 | 0.043 | 0.571 | 1.661 | 0.043 | 5.298 |
