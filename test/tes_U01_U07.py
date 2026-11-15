import base64
import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(ROOT / "cmd" / "umasign" / "main.py")]
ALGS = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
JSON_FIELDS = {"valid", "status", "message", "algorithm", "keyid", "package", "version"}

PACKAGE = "app"
VERSION = "1.0.0"
BASE = bytes(range(256)) * 16 

SCENARIO_DESCRIPTIONS = {
    "U01": "sign and verify valid artifacts",
    "U02": "one artifact byte changed",
    "U03": "artifact bytes added or removed",
    "U04": "manifest version changed",
    "U05": "one signature bit flipped",
    "U06": "publisher key is not trusted",
    "U07": "key is not authorized for package",
}


def run(*args):
    return subprocess.run(CLI + [str(a) for a in args], capture_output=True, text=True)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _make_keys(directory: Path):
    out = {}
    for alg in ALGS:
        prefix = directory / alg
        r = run("keygen", "--algorithm", alg, "--out", prefix)
        assert r.returncode == 0, r.stderr
        out[alg] = {
            "private": Path(f"{prefix}.key.pem"),
            "public": Path(f"{prefix}.pub.pem"),
            "keyid": r.stdout.strip(),
        }
    return out


@pytest.fixture(scope="session")
def keypairs(tmp_path_factory):
    return _make_keys(tmp_path_factory.mktemp("publisher-keys"))


@pytest.fixture(scope="session")
def other_keypairs(tmp_path_factory):
    return _make_keys(tmp_path_factory.mktemp("other-keys"))


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
    def __init__(self, root: Path, keypairs, alg, content: bytes, name: str):
        self.root, self.keypairs, self.alg = root, keypairs, alg
        self.kp = keypairs[alg]
        self.file = root / name
        self.file.write_bytes(content)
        self.bundle = root / "release.bundle.json"
        self.trust = root / "trust.json"
        r = run(
            "sign", "--file", self.file, "--package", PACKAGE, "--version", VERSION,
            "--key", self.kp["private"], "--out", self.bundle,
        )
        assert r.returncode == 0, r.stderr
        self.set_trust([(self.kp, alg, [PACKAGE])])

    def set_trust(self, entries):
        write_trust(self.trust, entries)

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
            args += [flag, value]
        args.append("--json")
        r = run(*args)
        return r.returncode, json.loads(r.stdout)

    def read_bundle(self):
        b = json.loads(self.bundle.read_text())
        return b, base64.b64decode(b["manifest_b64"]), base64.b64decode(b["signature_b64"])

    def rewrite_bundle(self, manifest=None, signature=None):
        b, m, s = self.read_bundle()
        b["manifest_b64"] = b64(manifest if manifest is not None else m)
        b["signature_b64"] = b64(signature if signature is not None else s)
        self.bundle.write_text(json.dumps(b))


@pytest.fixture
def make_env(tmp_path, keypairs):
    def _make(alg, content=BASE, name="app-1.0.0.tar.gz"):
        return Env(tmp_path, keypairs, alg, content, name)

    return _make


def expect(result, status, code):
    exit_code, body = result
    test_name = inspect.currentframe().f_back.f_code.co_name
    scenario = test_name.split("_", 2)[1].upper()
    print(
        f"[{scenario}] {SCENARIO_DESCRIPTIONS[scenario]}: "
        f"status={body.get('status')!r} "
        f"valid={body.get('valid')!r} exit_code={exit_code} "
        f"algorithm={body.get('algorithm')!r} "
        f"package={body.get('package')!r} "
        f"version={body.get('version')!r} "
        f"message={body.get('message')!r}"
    )
    assert set(body) == JSON_FIELDS
    assert body["status"] == status, body
    assert body["valid"] is (status == "OK"), body
    assert exit_code == code, (exit_code, body)
    return body


# U01: berkas teks, biner, dan kosong, dengan kunci dan metadata yang sesuai
U01_FILES = [
    ("teks", "catatan-rilis.txt", "Halo dunia\nIni berkas teks.\n".encode()),
    ("biner", "app.bin", bytes(range(256)) * 64),
    ("kosong", "kosong.dat", b""),
]


@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("kind,name,content", U01_FILES, ids=[f[0] for f in U01_FILES])
def test_u01_sign_and_verify_ok(make_env, keypairs, alg, kind, name, content):
    env = make_env(alg, content=content, name=name)
    body = expect(env.verify(), "OK", 0)
    assert body["algorithm"] == alg
    assert body["keyid"] == keypairs[alg]["keyid"]
    assert body["package"] == PACKAGE and body["version"] == VERSION


    _, manifest, _ = env.read_bundle()
    artifact = json.loads(manifest)["artifact"]
    assert artifact == {
        "name": name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


# U02: ubah satu byte, ukuran dan nama berkas tidak berubah
@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("index", [0, len(BASE) // 2, len(BASE) - 1], ids=["awal", "tengah", "akhir"])
def test_u02_one_byte_changed(make_env, alg, index):
    env = make_env(alg)
    data = bytearray(env.file.read_bytes())
    data[index] ^= 0x01
    env.file.write_bytes(bytes(data))
    assert len(data) == len(BASE)  
    expect(env.verify(), "ARTIFACT_MISMATCH", 1)


# U03: tambah atau hapus byte (ukuran berubah)
U03_CASES = [
    ("tambah_di_akhir", BASE, lambda d: d + b"\x00"),
    ("tambah_di_awal", BASE, lambda d: b"\x00" + d),
    ("hapus_byte_terakhir", BASE, lambda d: d[:-1]),
    ("hapus_bagian_tengah", BASE, lambda d: d[:100] + d[200:]),
    ("hapus_semua", BASE, lambda d: b""),
    ("kosong_ditambah_satu_byte", b"", lambda d: b"x"),
]


@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("label,base,mutate", U03_CASES, ids=[c[0] for c in U03_CASES])
def test_u03_bytes_added_or_removed(make_env, alg, label, base, mutate):
    env = make_env(alg, content=base)
    changed = mutate(env.file.read_bytes())
    assert len(changed) != len(base)
    env.file.write_bytes(changed)
    expect(env.verify(), "ARTIFACT_MISMATCH", 1)


# U04: versi di manifest diubah (serialisasi kanonik dipertahankan),
#      tanda tangan lama dipakai
@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize("verify_version", ["1.0.1", VERSION], ids=["versi-baru", "versi-lama"])
def test_u04_manifest_version_changed(make_env, alg, verify_version):
    env = make_env(alg)
    _, manifest, _ = env.read_bundle()
    old, new = b'"version":"1.0.0"', b'"version":"1.0.1"'
    assert old in manifest
    tampered = manifest.replace(old, new)

    assert json.dumps(json.loads(tampered), separators=(",", ":")).encode() == tampered

    env.rewrite_bundle(manifest=tampered)  #
    body = expect(env.verify(version=verify_version), "INVALID_SIGNATURE", 1)
    assert body["version"] == "1.0.1" 


# U05: ubah satu bit tanda tangan, panjang dan Base64 tetap valid
@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize(
    "where", ["awal", "tengah", "akhir"],
)
def test_u05_one_signature_bit_flipped(make_env, alg, where):
    env = make_env(alg)
    _, _, signature = env.read_bundle()
    index = {"awal": 0, "tengah": len(signature) // 2, "akhir": len(signature) - 1}[where]
    flipped = bytearray(signature)
    flipped[index] ^= 0x01
    assert len(flipped) == len(signature) and bytes(flipped) != signature
    env.rewrite_bundle(signature=bytes(flipped))
    expect(env.verify(), "INVALID_SIGNATURE", 1)


# U06: trust store kosong, atau kunci penerbit tidak ada di trust store
@pytest.mark.parametrize("alg", ALGS)
def test_u06_empty_trust_store(make_env, alg):
    env = make_env(alg)
    env.set_trust([])
    body = expect(env.verify(), "KEY_NOT_TRUSTED", 1)
    assert body["keyid"] is not None  


@pytest.mark.parametrize("alg", ALGS)
def test_u06_publisher_key_removed_other_profile_remains(make_env, keypairs, alg):
    env = make_env(alg)
    other_alg = ALGS[(ALGS.index(alg) + 1) % len(ALGS)]
    env.set_trust([(keypairs[other_alg], other_alg, [PACKAGE])])
    expect(env.verify(), "KEY_NOT_TRUSTED", 1)


@pytest.mark.parametrize("alg", ALGS)
def test_u06_publisher_key_removed_other_key_same_profile(make_env, other_keypairs, alg):
    env = make_env(alg)
    env.set_trust([(other_keypairs[alg], alg, [PACKAGE])])
    expect(env.verify(), "KEY_NOT_TRUSTED", 1)


# U07: kunci hanya diizinkan untuk paket lain
@pytest.mark.parametrize("alg", ALGS)
@pytest.mark.parametrize(
    "allowed",
    [["other"], ["app-extra"], ["ap"], ["application"], ["other", "app-extra"]],
    ids=["paket-lain", "awalan-sama", "potongan-nama", "nama-mirip", "dua-paket-lain"],
)
def test_u07_key_allowed_only_for_other_package(make_env, keypairs, alg, allowed):
    env = make_env(alg)
    env.set_trust([(keypairs[alg], alg, allowed)])
    body = expect(env.verify(), "KEY_NOT_TRUSTED", 1)
    assert body["package"] == PACKAGE 


@pytest.mark.parametrize("alg", ALGS)
def test_u07_control_key_allowed_for_package_is_ok(make_env, keypairs, alg):
    env = make_env(alg)
    env.set_trust([(keypairs[alg], alg, ["other", PACKAGE])])
    expect(env.verify(), "OK", 0)