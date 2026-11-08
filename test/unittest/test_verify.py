"""Uji verify lewat CLI (black-box): setiap status Tabel 2.8, urutan pemeriksaan,
keluaran --json Tabel 2.9, kode keluar, dan interoperabilitas dengan OpenSSL.

Jalankan dari root proyek:  pytest test/test_verify.py -v
"""
import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
CLI = [sys.executable, str(ROOT / "cmd" / "umasign" / "main.py")]
ALGS = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
JSON_FIELDS = {"valid", "status", "message", "algorithm", "keyid", "package", "version"}

PACKAGE = "app"
VERSION = "1.0.0"
ARTIFACT_NAME = "app-1.0.0.tar.gz"


def run(*args):
    return subprocess.run(
        CLI + [str(a) for a in args], capture_output=True, text=True
    )


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.fixture(scope="session")
def keypairs(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    out = {}
    for alg in ALGS:
        prefix = d / alg
        r = run("keygen", "--algorithm", alg, "--out", prefix)
        assert r.returncode == 0, r.stderr
        out[alg] = {
            "private": Path(f"{prefix}.key.pem"),
            "public": Path(f"{prefix}.pub.pem"),
            "keyid": r.stdout.strip(),
        }
    return out


def write_trust(path: Path, entries):
    keys = [
        {
            "keyid": kp["keyid"],
            "algorithm": alg,
            "public_key_pem": kp["public"].read_text(),
            "packages": list(packages),
        }
        for kp, alg, packages in entries
    ]
    path.write_text(json.dumps({"schema": "umasign-trust/v1", "keys": keys}))


class Env:
    def __init__(self, root: Path, keypairs, alg, packages=(PACKAGE,)):
        self.keypairs = keypairs
        self.alg = alg
        self.root = root
        self.file = root / ARTIFACT_NAME
        self.file.write_bytes(b"isi artefak uji " * 1000)
        self.bundle = root / "app.bundle.json"
        self.trust = root / "trust.json"
        kp = keypairs[alg]
        r = run(
            "sign", "--file", self.file, "--package", PACKAGE, "--version", VERSION,
            "--key", kp["private"], "--out", self.bundle,
        )
        assert r.returncode == 0, r.stderr
        write_trust(self.trust, [(kp, alg, packages)])

    def verify(self, **override):
        opts = {
            "--file": self.file,
            "--bundle": self.bundle,
            "--trust-store": self.trust,
            "--package": PACKAGE,
            "--version": VERSION,
        }
        for key, value in override.items():
            opts["--" + key.replace("_", "-")] = value
        args = ["verify"]
        for flag, value in opts.items():
            if value is not None:
                args += [flag, value]
        args.append("--json")
        r = run(*args)
        return r.returncode, json.loads(r.stdout)
    
    def read_bundle(self):
        b = json.loads(self.bundle.read_text())
        return (
            b,
            base64.b64decode(b["manifest_b64"]),
            base64.b64decode(b["signature_b64"]),
        )

    def rewrite_bundle(self, manifest=None, signature=None):
        b, m, s = self.read_bundle()
        b["manifest_b64"] = b64(manifest if manifest is not None else m)
        b["signature_b64"] = b64(signature if signature is not None else s)
        self.bundle.write_text(json.dumps(b))


@pytest.fixture
def make_env(tmp_path, keypairs):
    def _make(alg, packages=(PACKAGE,)):
        return Env(tmp_path, keypairs, alg, packages)

    return _make


def expect(result, status, code):
    exit_code, body = result
    assert set(body) == JSON_FIELDS
    assert body["status"] == status, body
    assert body["valid"] is (status == "OK")
    assert exit_code == code, (exit_code, body)
    return body


# OK
@pytest.mark.parametrize("alg", ALGS)
def test_ok(make_env, keypairs, alg):
    env = make_env(alg)
    body = expect(env.verify(), "OK", 0)
    assert body["algorithm"] == alg
    assert body["keyid"] == keypairs[alg]["keyid"]
    assert body["package"] == PACKAGE and body["version"] == VERSION


def test_text_output_without_json(make_env):
    env = make_env("ed25519")
    r = run("verify", "--file", env.file, "--bundle", env.bundle,
            "--trust-store", env.trust, "--package", PACKAGE, "--version", VERSION)
    assert r.returncode == 0 and "OK" in r.stdout


# 1. INPUT_ERROR (kode keluar 2, field manifest null)
@pytest.mark.parametrize("missing", ["file", "bundle", "trust_store", "package", "version"])
def test_input_error_missing_option(make_env, missing):
    env = make_env("ed25519")
    body = expect(env.verify(**{missing: None}), "INPUT_ERROR", 2)
    assert body["algorithm"] is None and body["keyid"] is None
    assert body["package"] is None and body["version"] is None


@pytest.mark.parametrize("name", ["file", "bundle", "trust_store"])
def test_input_error_unreadable_file(make_env, tmp_path, name):
    env = make_env("ed25519")
    expect(env.verify(**{name: tmp_path / "tidak-ada"}), "INPUT_ERROR", 2)


def test_input_error_comes_before_format_error(make_env, tmp_path):
    env = make_env("ed25519")
    env.bundle.write_text("bukan json")  # rusak, tetapi trust store tidak terbaca
    expect(env.verify(trust_store=tmp_path / "tidak-ada"), "INPUT_ERROR", 2)


# 2. FORMAT_ERROR (kode keluar 1)
def test_format_error_bundle_not_json(make_env):
    env = make_env("ed25519")
    env.bundle.write_text("bukan json")
    expect(env.verify(), "FORMAT_ERROR", 1)


def test_format_error_bad_base64(make_env):
    env = make_env("ed25519")
    b, _, _ = env.read_bundle()
    b["manifest_b64"] = "!!!bukan-base64!!!"
    env.bundle.write_text(json.dumps(b))
    expect(env.verify(), "FORMAT_ERROR", 1)


@pytest.mark.parametrize("variant", ["trailing_newline", "spaces", "field_order"])
def test_format_error_manifest_not_canonical(make_env, variant):
    env = make_env("ed25519")
    _, manifest, _ = env.read_bundle()
    obj = json.loads(manifest)
    if variant == "trailing_newline":
        bad = manifest + b"\n"
    elif variant == "spaces":
        bad = json.dumps(obj).encode() 
    else:
        reordered = {k: obj[k] for k in reversed(list(obj))}
        bad = json.dumps(reordered, separators=(",", ":")).encode()
    env.rewrite_bundle(manifest=bad)
    expect(env.verify(), "FORMAT_ERROR", 1)


def test_format_error_wrong_signature_length(make_env):
    env = make_env("ed25519")
    _, _, sig = env.read_bundle()
    env.rewrite_bundle(signature=sig[:-1])
    expect(env.verify(), "FORMAT_ERROR", 1)


def test_format_error_trust_store(make_env):
    env = make_env("ed25519")
    env.trust.write_text(json.dumps({"schema": "umasign-trust/v1", "keys": "x"}))
    body = expect(env.verify(), "FORMAT_ERROR", 1)
    # manifest sudah terbaca, jadi field manifest terisi
    assert body["algorithm"] == "ed25519" and body["package"] == PACKAGE


# 3. UNSUPPORTED_ALGORITHM
def test_unsupported_algorithm(make_env):
    env = make_env("ed25519")
    _, manifest, _ = env.read_bundle()
    obj = json.loads(manifest)
    obj["algorithm"] = "rsa-pss-sha512"
    env.rewrite_bundle(manifest=json.dumps(obj, separators=(",", ":")).encode())
    body = expect(env.verify(), "UNSUPPORTED_ALGORITHM", 1)
    assert body["algorithm"] == "rsa-pss-sha512"


# 4. KEY_NOT_TRUSTED
def test_key_not_trusted_empty_store(make_env):
    env = make_env("ed25519")
    env.trust.write_text(json.dumps({"schema": "umasign-trust/v1", "keys": []}))
    expect(env.verify(), "KEY_NOT_TRUSTED", 1)


def test_key_not_trusted_other_key_only(make_env, keypairs):
    env = make_env("ed25519")
    write_trust(env.trust, [(keypairs["ecdsa-p256-sha256"], "ecdsa-p256-sha256", [PACKAGE])])
    expect(env.verify(), "KEY_NOT_TRUSTED", 1)


def test_key_not_trusted_package_not_allowed(make_env):
    env = make_env("ed25519", packages=("other",))
    expect(env.verify(), "KEY_NOT_TRUSTED", 1)


# 5. INVALID_SIGNATURE
@pytest.mark.parametrize("alg", ALGS)
def test_invalid_signature_flipped_byte(make_env, alg):
    env = make_env(alg)
    _, _, sig = env.read_bundle()
    env.rewrite_bundle(signature=bytes([sig[0] ^ 0x01]) + sig[1:])
    expect(env.verify(), "INVALID_SIGNATURE", 1)


def test_invalid_signature_manifest_tampered_but_canonical(make_env):
    env = make_env("ed25519")
    _, manifest, _ = env.read_bundle()
    obj = json.loads(manifest)
    sha = obj["artifact"]["sha256"]
    obj["artifact"]["sha256"] = sha[:-1] + ("0" if sha[-1] != "0" else "1")
    env.rewrite_bundle(manifest=json.dumps(obj, separators=(",", ":")).encode())
    # tanda tangan diperiksa sebelum artefak
    expect(env.verify(), "INVALID_SIGNATURE", 1)


# 6. METADATA_MISMATCH
def test_metadata_mismatch_version(make_env):
    env = make_env("ed25519")
    expect(env.verify(version="2.0.0"), "METADATA_MISMATCH", 1)


def test_metadata_mismatch_package(make_env):
    env = make_env("ed25519", packages=(PACKAGE, "other"))
    expect(env.verify(package="other"), "METADATA_MISMATCH", 1)


def test_metadata_mismatch_artifact_name(make_env, tmp_path):
    env = make_env("ed25519")
    renamed = tmp_path / "nama-lain.tar.gz"
    shutil.copy(env.file, renamed)
    expect(env.verify(file=renamed), "METADATA_MISMATCH", 1)


# 7. ARTIFACT_MISMATCH
def test_artifact_mismatch_same_size(make_env):
    env = make_env("ed25519")
    data = bytearray(env.file.read_bytes())
    data[0] ^= 0x01
    env.file.write_bytes(bytes(data))
    expect(env.verify(), "ARTIFACT_MISMATCH", 1)


def test_artifact_mismatch_size(make_env):
    env = make_env("ed25519")
    env.file.write_bytes(env.file.read_bytes() + b"x")
    expect(env.verify(), "ARTIFACT_MISMATCH", 1)


def test_metadata_checked_before_artifact(make_env):
    env = make_env("ed25519")
    env.file.write_bytes(b"diubah")
    expect(env.verify(version="2.0.0"), "METADATA_MISMATCH", 1)


def _openssl_supports_rawin():
    if shutil.which("openssl") is None:
        return False
    r = subprocess.run(["openssl", "pkeyutl", "-help"], capture_output=True, text=True)
    return "-rawin" in (r.stdout + r.stderr)


def _openssl_sign(alg, key: Path, manifest_path: Path, tmp: Path) -> bytes:
    sig_path = tmp / "openssl.sig"
    if alg == "rsa-pss-sha256":
        cmd = ["openssl", "dgst", "-sha256", "-sign", str(key),
               "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
               "-sigopt", "rsa_mgf1_md:sha256", "-out", str(sig_path), str(manifest_path)]
    elif alg == "ecdsa-p256-sha256":
        cmd = ["openssl", "dgst", "-sha256", "-sign", str(key),
               "-out", str(sig_path), str(manifest_path)]
    else:
        cmd = ["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
               "-in", str(manifest_path), "-out", str(sig_path)]
    subprocess.run(cmd, check=True, capture_output=True)
    sig = sig_path.read_bytes()
    if alg == "ecdsa-p256-sha256": 
        r, s = decode_dss_signature(sig)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return sig


@pytest.mark.skipif(not _openssl_supports_rawin(), reason="OpenSSL dengan -rawin tidak tersedia")
@pytest.mark.parametrize("alg", ALGS)
def test_bundle_signed_by_openssl_is_ok(make_env, keypairs, tmp_path, alg):
    env = make_env(alg)
    _, manifest, _ = env.read_bundle()
    manifest_path = tmp_path / "manifest.bin"
    manifest_path.write_bytes(manifest)
    env.rewrite_bundle(signature=_openssl_sign(alg, keypairs[alg]["private"], manifest_path, tmp_path))
    expect(env.verify(), "OK", 0)