import argparse
import csv
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import cryptography
from internal.crypto.common import (
    ALG_ECDSA,
    ALG_ED25519,
    ALG_RSA_PSS,
    ALGORITHMS,
    pss_padding,
    raw_to_der,
)
from internal.crypto.keygen import generate_key, save_key
from internal.crypto.sign import sign, sign_manifest
from internal.bundle.bundle_file_management import load_bundle
from internal.manifest.hash import hash_artifact
from internal.trust import trust_store
from internal.trust.trust_store_file_management import save_store
from internal.trust.trust_store_structure import empty_store
from internal.verifier.verify import verify

PACKAGE, VERSION = "bench", "1.0.0"
SIZES = [("1 KiB", 1024), ("1 MiB", 1024 ** 2), ("10 MiB", 10 * 1024 ** 2), ("100 MiB", 100 * 1024 ** 2)]
LABEL = {ALG_RSA_PSS: "RSA-PSS", ALG_ECDSA: "ECDSA P-256", ALG_ED25519: "Ed25519"}


def ms(start_ns, end_ns):
    return (end_ns - start_ns) / 1e6


def environment():
    cpu = platform.processor()
    if sys.platform == "win32":
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
                capture_output=True, text=True, timeout=30,
            )
            cpu = r.stdout.strip() or cpu
        except (OSError, subprocess.SubprocessError):
            pass
    return {
        "waktu": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "os": platform.platform(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
    }


def crypto_verify(public_key, algorithm, data, signature):
    if algorithm == ALG_RSA_PSS:
        public_key.verify(signature, data, pss_padding(), hashes.SHA256())
    elif algorithm == ALG_ECDSA:
        public_key.verify(raw_to_der(signature), data, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, data)


def write_input(path, size, seed):
    rng = random.Random(seed)
    remaining = size
    with open(path, "wb") as f:
        while remaining:
            chunk = min(remaining, 1024 * 1024)
            f.write(rng.randbytes(chunk))
            remaining -= chunk


def summarize(values):
    return {
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Benchmark sign dan verify uma-sign.")
    p.add_argument("--out", default="hasil_benchmark", help="folder keluaran")
    p.add_argument("--reps", type=int, default=20, help="jumlah pengulangan per kombinasi")
    p.add_argument("--warmup", type=int, default=2, help="jumlah pemanasan per kombinasi")
    p.add_argument("--keygen-reps", type=int, default=10, help="jumlah pengulangan keygen")
    args = p.parse_args(argv)

    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        print(f"error: folder keluaran sudah berisi berkas: {out}", file=sys.stderr)
        return 2
    for sub in ("keys", "inputs", "bundles"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    env = environment()
    print(f"Folder keluaran: {out}")
    print(json.dumps(env, indent=2))

    keygen_rows = []
    for alg in ALGORITHMS:
        times = []
        for _ in range(args.keygen_reps):
            t0 = time.perf_counter_ns()
            generate_key(alg)
            times.append(ms(t0, time.perf_counter_ns()))
        keygen_rows.append({"algorithm": alg, **summarize(times)})
        print(f"keygen {alg:<18} median {statistics.median(times):9.3f} ms")

    store = empty_store()
    keys = {}
    for alg in ALGORITHMS:
        private_key = generate_key(alg)
        save_key(private_key, str(out / "keys" / alg))
        pem = (out / "keys" / f"{alg}.pub.pem").read_bytes()
        store = trust_store.add(store, pem, PACKAGE).store
        keys[alg] = private_key
    trust_path = out / "keys" / "trust.json"
    save_store(trust_path, store)

    inputs = {}
    for index, (label, size) in enumerate(SIZES):
        path = out / "inputs" / f"input-{size}.bin"
        write_input(path, size, seed=index)
        inputs[label] = (path, size)

    raw_rows = []
    summary_rows = []
    for alg in ALGORITHMS:
        key_path = str(out / "keys" / f"{alg}.key.pem")
        private_key = keys[alg]
        public_key = private_key.public_key()
        for label, (path, size) in inputs.items():
            bundle_path = out / "bundles" / f"{alg}-{size}.bundle.json"
            sign_args = (str(path), PACKAGE, VERSION, key_path, str(bundle_path))
            verify_args = (str(path), str(bundle_path), str(trust_path), PACKAGE, VERSION)

            for _ in range(args.warmup):
                sign(*sign_args)
                assert verify(*verify_args).status == "OK"

            sign_ms, verify_ms, hash_ms, csign_ms, cverify_ms = [], [], [], [], []
            for rep in range(1, args.reps + 1):
                t0 = time.perf_counter_ns()
                sign(*sign_args)
                t1 = time.perf_counter_ns()
                result = verify(*verify_args)
                t2 = time.perf_counter_ns()
                if result.status != "OK":
                    print(f"error: verify {alg} {label}: {result.status} {result.message}", file=sys.stderr)
                    return 1

                bundle = load_bundle(bundle_path)
                t3 = time.perf_counter_ns()
                hash_artifact(str(path))
                t4 = time.perf_counter_ns()
                signature = sign_manifest(alg, private_key, bundle.manifest)
                t5 = time.perf_counter_ns()
                crypto_verify(public_key, alg, bundle.manifest, signature)
                t6 = time.perf_counter_ns()

                row = {
                    "algorithm": alg,
                    "input": label,
                    "size_bytes": size,
                    "rep": rep,
                    "sign_ms": round(ms(t0, t1), 4),
                    "verify_ms": round(ms(t1, t2), 4),
                    "hash_ms": round(ms(t3, t4), 4),
                    "crypto_sign_ms": round(ms(t4, t5), 4),
                    "crypto_verify_ms": round(ms(t5, t6), 4),
                    "signature_bytes": len(bundle.signature),
                    "manifest_bytes": len(bundle.manifest),
                }
                raw_rows.append(row)
                sign_ms.append(row["sign_ms"])
                verify_ms.append(row["verify_ms"])
                hash_ms.append(row["hash_ms"])
                csign_ms.append(row["crypto_sign_ms"])
                cverify_ms.append(row["crypto_verify_ms"])

            s, v = summarize(sign_ms), summarize(verify_ms)
            summary_rows.append({
                "algorithm": alg,
                "input": label,
                "size_bytes": size,
                "sign_median_ms": s["median"],
                "sign_stdev_ms": s["stdev"],
                "verify_median_ms": v["median"],
                "verify_stdev_ms": v["stdev"],
                "hash_median_ms": statistics.median(hash_ms),
                "crypto_sign_median_ms": statistics.median(csign_ms),
                "crypto_verify_median_ms": statistics.median(cverify_ms),
                "signature_bytes": raw_rows[-1]["signature_bytes"],
            })
            print(f"{alg:<18} {label:>8}  sign {s['median']:9.3f} ms  verify {v['median']:9.3f} ms")

    for path, _ in inputs.values():
        path.unlink()

    with open(out / "raw.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(raw_rows[0]))
        w.writeheader()
        w.writerows(raw_rows)
    with open(out / "ringkasan.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary_rows[0]))
        w.writeheader()
        w.writerows(summary_rows)
    (out / "lingkungan.json").write_text(json.dumps(env, indent=2), encoding="utf-8")

    md = [
        "# Hasil Benchmark uma-sign", "",
        f"Dijalankan: {env['waktu']}  ",
        f"Lingkungan: Python {env['python']}, cryptography {env['cryptography']}, {env['openssl']}, "
        f"{env['os']}, {env['cpu']} ({env['logical_cpus']} logical CPU)  ",
        f"Pengulangan: {args.reps} per kombinasi, {args.warmup} pemanasan; nilai = median (ms).", "",
        "## Sign dan verify", "",
        "| Algoritma | Ukuran masukan | Sign (ms) | Verify (ms) | Ukuran signature (byte) |",
        "|---|---|---|---|---|",
    ]
    for r in summary_rows:
        md.append(f"| {LABEL[r['algorithm']]} | {r['input']} | {r['sign_median_ms']:.3f} | "
                  f"{r['verify_median_ms']:.3f} | {r['signature_bytes']} |")
    md += ["", "## Rincian (median, ms)", "",
           "| Algoritma | Ukuran | Sign total | Verify total | Hash artefak | Kripto sign | Kripto verify | Simpangan baku sign | Simpangan baku verify |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in summary_rows:
        md.append(f"| {LABEL[r['algorithm']]} | {r['input']} | {r['sign_median_ms']:.3f} | "
                  f"{r['verify_median_ms']:.3f} | {r['hash_median_ms']:.3f} | "
                  f"{r['crypto_sign_median_ms']:.3f} | {r['crypto_verify_median_ms']:.3f} | "
                  f"{r['sign_stdev_ms']:.3f} | {r['verify_stdev_ms']:.3f} |")
    md += ["", f"## Keygen ({args.keygen_reps} pengulangan, ms)", "",
           "| Algoritma | Median | Rata-rata | Simpangan baku | Min | Maks |", "|---|---|---|---|---|---|"]
    for r in keygen_rows:
        md.append(f"| {LABEL[r['algorithm']]} | {r['median']:.3f} | {r['mean']:.3f} | {r['stdev']:.3f} | "
                  f"{r['min']:.3f} | {r['max']:.3f} |")
    (out / "hasil_benchmark.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\nSelesai. Ringkasan: {out / 'hasil_benchmark.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
