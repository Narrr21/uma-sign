import argparse
import base64
import csv
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLI = ROOT / "cmd" / "umasign" / "main.py"
ALGS = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
PACKAGE, VERSION = "app", "1.0.0"
ARTIFACT = "app-1.0.0.tar.gz"
BASE = bytes(range(256)) * 16

DESCRIPTIONS = {
    "U01": "Tandatangani dan verifikasi berkas teks, biner, dan kosong dengan kunci dan metadata yang sesuai.",
    "U02": "Ubah satu byte artefak tanpa mengubah ukuran atau nama berkas.",
    "U03": "Tambahkan atau hapus byte pada artefak.",
    "U04": "Ubah versi pada manifest dengan serialisasi kanonik, gunakan tanda tangan lama.",
    "U05": "Ubah satu bit tanda tangan, panjang dan Base64 tetap valid.",
    "U06": "Trust store kosong atau kunci penerbit tidak ada di trust store.",
    "U07": "Kunci hanya diizinkan untuk paket lain.",
    "U08": "Bundle sah, paket sesuai, versi berbeda dari manifest.",
    "U09": "Nama berkas artefak diubah tanpa mengubah isinya.",
    "U10": "Field duplikat, tipe salah, Base64 tidak valid, dan manifest melebihi batas ukuran (masing-masing terpisah).",
    "U11": "String algorithm yang tidak didukung pada manifest.",
    "U12": "Ditandatangani kunci lain pada profil yang sama; kunci itu tidak ada di trust store.",
    "U13": "Whitespace dan urutan field bundle diubah, kedua string Base64 tetap.",
    "U14": "Manifest identik ditandatangani dua kali dengan kunci yang sama.",
}


def b64(data):
    return base64.b64encode(data).decode("ascii")


class Runner:
    def __init__(self, cli, out):
        self.cli, self.out = cli, out

    def rel(self, path):
        return Path(path).relative_to(self.out).as_posix()

    def __call__(self, *args):
        args = [self.rel(a) if isinstance(a, Path) else str(a) for a in args]
        r = subprocess.run([sys.executable, str(self.cli)] + args,
                           capture_output=True, text=True, cwd=self.out)
        return "umasign " + " ".join(args), r


class Case:

    def __init__(self, run, keys, folder, alg, content=BASE, name=ARTIFACT):
        self.run, self.keys, self.dir, self.alg = run, keys, folder, alg
        self.dir.mkdir(parents=True)
        self.file = self.dir / name
        self.file.write_bytes(content)
        self.bundle = self.dir / "bundle.json"
        self.trust = self.dir / "trust.json"
        self.commands = []
        self.sign(keys["publisher"][alg], self.bundle)
        self.set_trust([(keys["publisher"][alg], alg, [PACKAGE])])

    def sign(self, key, out):
        cmd, r = self.run("sign", "--file", self.file, "--package", PACKAGE, "--version", VERSION,
                          "--key", key["private"], "--out", out)
        self.commands.append({"perintah": cmd, "exit": r.returncode, "stderr": r.stderr.strip()})
        if r.returncode != 0:
            raise RuntimeError(f"sign gagal: {r.stderr}")

    def set_trust(self, entries):
        keys = [{
            "keyid": k["keyid"],
            "algorithm": alg,
            "public_key_pem": k["public"].read_text(encoding="ascii"),
            "packages": list(packages),
        } for k, alg, packages in entries]
        self.trust.write_text(json.dumps({"schema": "umasign-trust/v1", "keys": keys}, indent=2),
                              encoding="utf-8")

    def read_bundle(self, path=None):
        b = json.loads((path or self.bundle).read_text(encoding="utf-8"))
        return b, base64.b64decode(b["manifest_b64"]), base64.b64decode(b["signature_b64"])

    def rewrite_bundle(self, manifest=None, signature=None):
        b, m, s = self.read_bundle()
        b["manifest_b64"] = b64(manifest if manifest is not None else m)
        b["signature_b64"] = b64(signature if signature is not None else s)
        self.bundle.write_text(json.dumps(b, indent=2), encoding="utf-8")

    def verify(self, file=None, bundle=None, version=VERSION, package=PACKAGE):
        cmd, r = self.run("verify", "--file", file or self.file, "--bundle", bundle or self.bundle,
                          "--trust-store", self.trust, "--package", package,
                          "--version", version, "--json")
        try:
            body = json.loads(r.stdout)
        except ValueError:
            body = {"raw": r.stdout.strip(), "stderr": r.stderr.strip()}
        self.commands.append({"perintah": cmd, "exit": r.returncode, "keluaran": body})
        return r.returncode, body


def u01(case):
    return case.verify()


def flip_artifact_byte(index):
    def run(case):
        data = bytearray(case.file.read_bytes())
        data[index] ^= 0x01
        case.file.write_bytes(bytes(data))
        return case.verify()
    return run


def mutate_artifact(fn):
    def run(case):
        case.file.write_bytes(fn(case.file.read_bytes()))
        return case.verify()
    return run


def u04(verify_version):
    def run(case):
        _, manifest, _ = case.read_bundle()
        case.rewrite_bundle(manifest=manifest.replace(b'"version":"1.0.0"', b'"version":"1.0.1"'))
        return case.verify(version=verify_version)
    return run


def u05(where):
    def run(case):
        _, _, sig = case.read_bundle()
        index = {"awal": 0, "tengah": len(sig) // 2, "akhir": len(sig) - 1}[where]
        flipped = bytearray(sig)
        flipped[index] ^= 0x01
        case.rewrite_bundle(signature=bytes(flipped))
        return case.verify()
    return run


def u06(kind):
    def run(case):
        alg = case.alg
        if kind == "trust_kosong":
            case.set_trust([])
        elif kind == "hanya_kunci_profil_lain":
            other = ALGS[(ALGS.index(alg) + 1) % len(ALGS)]
            case.set_trust([(case.keys["publisher"][other], other, [PACKAGE])])
        else:
            case.set_trust([(case.keys["lain"][alg], alg, [PACKAGE])])
        return case.verify()
    return run


def u07(allowed):
    def run(case):
        case.set_trust([(case.keys["publisher"][case.alg], case.alg, allowed)])
        return case.verify()
    return run


def u08(version):
    return lambda case: case.verify(version=version)


def u09(new_name):
    def run(case):
        renamed = case.file.with_name(new_name)
        case.file.rename(renamed)
        case.file = renamed
        return case.verify()
    return run


def _q(text):
    return '"' + text + '"'


def _bundle_json(manifest_value, signature_value):
    return ('{"schema":"umasign-bundle/v1","manifest_b64":' + manifest_value
            + ',"signature_b64":' + signature_value + "}")


U10_BUILDERS = {
    "bundle_field_duplikat": lambda m, s: _bundle_json(
        _q(b64(m)), _q(b64(s)) + ',"signature_b64":' + _q(b64(s))),
    "manifest_field_duplikat": lambda m, s: _bundle_json(
        _q(b64(m.replace(b'"package":"app",', b'"package":"app","package":"app",'))), _q(b64(s))),
    "bundle_tipe_salah": lambda m, s: _bundle_json(_q(b64(m)), "12345"),
    "manifest_tipe_salah": lambda m, s: _bundle_json(
        _q(b64(m.replace(b'"size":4096', b'"size":"4096"'))), _q(b64(s))),
    "base64_karakter_asing": lambda m, s: _bundle_json(_q(b64(m)), _q("*" + b64(s)[1:])),
    "base64_padding_salah": lambda m, s: _bundle_json(_q(b64(m)), _q(b64(s)[:-1])),
    "base64_whitespace": lambda m, s: _bundle_json(_q(b64(m)), _q(b64(s)[:8] + " " + b64(s)[8:])),
    "base64_url_safe": lambda m, s: _bundle_json(_q(b64(m)), _q("-_" + b64(s)[2:])),
    "manifest_melebihi_16KiB": lambda m, s: _bundle_json(_q(b64(m + b" " * 16384)), _q(b64(s))),
}


def u10(label):
    def run(case):
        _, manifest, signature = case.read_bundle()
        case.bundle.write_text(U10_BUILDERS[label](manifest, signature), encoding="utf-8")
        return case.verify()
    return run


def u11(unsupported):
    def run(case):
        _, manifest, _ = case.read_bundle()
        old = f'"algorithm":"{case.alg}"'.encode()
        case.rewrite_bundle(manifest=manifest.replace(old, f'"algorithm":"{unsupported}"'.encode()))
        return case.verify()
    return run


def u12(case):
    case.sign(case.keys["lain"][case.alg], case.bundle)
    return case.verify()


U13_LAYOUTS = {
    "urutan_terbalik": lambda b: json.dumps(dict(reversed(list(b.items())))),
    "indentasi_4": lambda b: json.dumps(b, indent=4),
    "satu_baris_rapat": lambda b: json.dumps(b, separators=(",", ":")),
    "crlf_tab_dan_spasi": lambda b: (
        '\r\n\t{ "signature_b64" :\t"' + b["signature_b64"] + '" ,\r\n'
        '   "manifest_b64":"' + b["manifest_b64"] + '",\r\n'
        '"schema"  :  "' + b["schema"] + '" }\r\n'),
}


def u13(label):
    def run(case):
        original, _, _ = case.read_bundle()
        with open(case.bundle, "w", encoding="utf-8", newline="") as f:
            f.write(U13_LAYOUTS[label](original))
        return case.verify()
    return run


def u14(case):
    second = case.dir / "bundle-2.json"
    case.sign(case.keys["publisher"][case.alg], second)
    _, m1, s1 = case.read_bundle()
    _, m2, s2 = case.read_bundle(second)
    code1, body1 = case.verify()
    code2, body2 = case.verify(bundle=second)
    case.extra = {
        "manifest_identik": m1 == m2,
        "tanda_tangan_identik": s1 == s2,
        "signature_1_hex": s1.hex(),
        "signature_2_hex": s2.hex(),
        "verify_bundle_2": {"exit": code2, "status": body2.get("status")},
    }
    (case.dir / "manifest-2.json").write_bytes(m2)
    ok = code2 == 0 and body2.get("status") == "OK"
    return (code1 if ok else code2), (body1 if ok else body2)


def scenarios():
    s = []
    for kind, name, content in [("teks", "catatan-rilis.txt", "Halo dunia\nIni berkas teks.\n".encode()),
                                ("biner", "app.bin", bytes(range(256)) * 64),
                                ("kosong", "kosong.dat", b"")]:
        s.append(("U01", kind, u01, {"content": content, "name": name}, "OK", 0))
    for label, index in [("awal", 0), ("tengah", len(BASE) // 2), ("akhir", len(BASE) - 1)]:
        s.append(("U02", label, flip_artifact_byte(index), {}, "ARTIFACT_MISMATCH", 1))
    for label, base, fn in [("tambah_di_akhir", BASE, lambda d: d + b"\x00"),
                            ("tambah_di_awal", BASE, lambda d: b"\x00" + d),
                            ("hapus_byte_terakhir", BASE, lambda d: d[:-1]),
                            ("hapus_bagian_tengah", BASE, lambda d: d[:100] + d[200:]),
                            ("hapus_semua", BASE, lambda d: b""),
                            ("kosong_ditambah_satu_byte", b"", lambda d: b"x")]:
        s.append(("U03", label, mutate_artifact(fn), {"content": base}, "ARTIFACT_MISMATCH", 1))
    for label, v in [("verify_versi_baru", "1.0.1"), ("verify_versi_lama", VERSION)]:
        s.append(("U04", label, u04(v), {}, "INVALID_SIGNATURE", 1))
    for where in ["awal", "tengah", "akhir"]:
        s.append(("U05", where, u05(where), {}, "INVALID_SIGNATURE", 1))
    for kind in ["trust_kosong", "hanya_kunci_profil_lain", "hanya_kunci_lain_profil_sama"]:
        s.append(("U06", kind, u06(kind), {}, "KEY_NOT_TRUSTED", 1))
    for label, allowed in [("paket_lain", ["other"]), ("awalan_sama", ["app-extra"]),
                           ("potongan_nama", ["ap"]), ("nama_mirip", ["application"]),
                           ("dua_paket_lain", ["other", "app-extra"])]:
        s.append(("U07", label, u07(allowed), {}, "KEY_NOT_TRUSTED", 1))
    s.append(("U07", "kontrol_paket_diizinkan", u07(["other", PACKAGE]), {}, "OK", 0))
    for v in ["1.0.1", "2.0.0", "1.0.0-rc1"]:
        s.append(("U08", "versi_" + v, u08(v), {}, "METADATA_MISMATCH", 1))
    for n in ["app-1.0.1.tar.gz", "App-1.0.0.tar.gz", "app.tar.gz"]:
        s.append(("U09", "nama_" + n, u09(n), {}, "METADATA_MISMATCH", 1))
    for label in U10_BUILDERS:
        s.append(("U10", label, u10(label), {}, "FORMAT_ERROR", 1))
    for a in ["rsa-pkcs1-sha256", "ecdsa-p384-sha384", "ED25519", "none"]:
        s.append(("U11", "algorithm_" + a, u11(a), {}, "UNSUPPORTED_ALGORITHM", 1))
    s.append(("U12", "kunci_lain_profil_sama", u12, {}, "KEY_NOT_TRUSTED", 1))
    for label in U13_LAYOUTS:
        s.append(("U13", label, u13(label), {}, "OK", 0))
    s.append(("U14", "sign_dua_kali", u14, {}, "OK", 0))
    return s


def save_case_files(case, info):
    try:
        _, manifest, _ = case.read_bundle()
        (case.dir / "manifest.json").write_bytes(manifest)
    except (ValueError, KeyError, TypeError):
        (case.dir / "manifest.json").write_text("(manifest tidak dapat didekode dari bundle ini)\n",
                                                encoding="utf-8")
    (case.dir / "hasil.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")


def make_keys(run, out):
    keys = {"publisher": {}, "lain": {}}
    for owner in keys:
        for alg in ALGS:
            prefix = out / "keys" / owner / alg
            cmd, r = run("keygen", "--algorithm", alg, "--out_prefix", prefix)
            if r.returncode != 0:
                raise RuntimeError(f"keygen gagal: {r.stderr}")
            keys[owner][alg] = {
                "private": Path(f"{prefix}.key.pem"),
                "public": Path(f"{prefix}.pub.pem"),
                "keyid": r.stdout.strip(),
                "perintah": cmd,
            }
    return keys


def versions():
    info = {"python": platform.python_version(), "os": platform.platform()}
    try:
        from importlib.metadata import version
        info["cryptography"] = version("cryptography")
    except Exception:
        info["cryptography"] = "tidak diketahui"
    return info


def write_summary(out, rows, keys, env):
    with open(out / "ringkasan.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    passed = sum(r["hasil"] == "LULUS" for r in rows)
    md = ["# Hasil Pengujian Skenario U01-U14", "",
          f"Dijalankan: {env['waktu']}  ",
          f"Lingkungan: Python {env['python']}, cryptography {env['cryptography']}, {env['os']}  ",
          f"Total: {passed}/{len(rows)} kasus lulus.", "",
          "Kunci di folder `keys/` dibuat khusus untuk pengujian ini dan tidak dipakai di tempat lain.", "",
          "## Kunci", "", "| Pemilik | Algoritma | keyid |", "|---|---|---|"]
    for owner, by_alg in keys.items():
        for alg, k in by_alg.items():
            md.append(f"| {owner} | {alg} | `{k['keyid']}` |")
    md += ["", "## Isi folder tiap kasus", "",
           "- artefak (nama sesuai kasus)",
           "- `bundle.json`: bundle yang diverifikasi (sudah dimanipulasi bila skenarionya begitu)",
           "- `manifest.json`: byte manifest hasil decode dari `bundle.json`",
           "- `trust.json`: trust store yang dipakai",
           "- `hasil.json`: perintah sign/verify, exit code, keluaran verify, status yang diharapkan",
           "", "## Ringkasan", "",
           "| Skenario | Variasi | Algoritma | Status | Exit | Diharapkan | Hasil | Pesan |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['skenario']} | {r['variasi']} | {r['algoritma']} | {r['status']} | {r['exit']} | "
                  f"{r['status_diharapkan']} / {r['exit_diharapkan']} | {r['hasil']} | {r['pesan']} |")
    (out / "README.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return passed


def main(argv=None):
    p = argparse.ArgumentParser(description="Bukti pengujian skenario U01-U14.")
    p.add_argument("--out", default="hasil_skenario", help="folder keluaran")
    p.add_argument("--cli", default=str(DEFAULT_CLI), help="path cmd/umasign/main.py")
    p.add_argument("--zip", action="store_true", help="buat juga berkas .zip dari folder keluaran")
    args = p.parse_args(argv)

    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        print(f"error: folder keluaran sudah berisi berkas: {out}", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    run = Runner(Path(args.cli).resolve(), out)

    env = versions()
    env["waktu"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    keys = make_keys(run, out)

    rows = []
    for sid, variant, fn, kwargs, exp_status, exp_exit in scenarios():
        for alg in ALGS:
            case = Case(run, keys, out / sid / f"{alg}__{variant}", alg, **kwargs)
            case.extra = None
            code, body = fn(case)
            ok = code == exp_exit and body.get("status") == exp_status and body.get("valid") is (exp_status == "OK")
            info = {
                "skenario": sid,
                "deskripsi": DESCRIPTIONS[sid],
                "variasi": variant,
                "algoritma": alg,
                "status_diharapkan": exp_status,
                "exit_diharapkan": exp_exit,
                "exit": code,
                "keluaran_verify": body,
                "hasil": "LULUS" if ok else "GAGAL",
                "perintah": case.commands,
            }
            if case.extra:
                info["u14"] = case.extra
            save_case_files(case, info)
            rows.append({
                "skenario": sid, "variasi": variant, "algoritma": alg,
                "status": body.get("status"), "exit": code,
                "status_diharapkan": exp_status, "exit_diharapkan": exp_exit,
                "hasil": info["hasil"], "pesan": body.get("message", ""),
                "folder": case.dir.relative_to(out).as_posix(),
            })
            print(f"[{sid}] {variant:<32} {alg:<18} {body.get('status')!s:<22} exit={code}  {info['hasil']}")

    passed = write_summary(out, rows, keys, env)
    print(f"\n{passed}/{len(rows)} kasus lulus. Ringkasan: {out / 'README.md'}")
    if args.zip:
        archive = shutil.make_archive(str(out), "zip", root_dir=out.parent, base_dir=out.name)
        print(f"Zip: {archive}")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
