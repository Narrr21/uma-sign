import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "cmd" / "umasign" / "main.py"
OPENSSL = shutil.which("openssl")

pytestmark = pytest.mark.skipif(
    OPENSSL is None,
    reason="openssl tidak ditemukan",
)


def _openssl_supports_ed25519_rawin():
    if OPENSSL is None:
        return False
    result = subprocess.run(
        [OPENSSL, "pkeyutl", "-help"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "-rawin" in result.stdout or "-rawin" in result.stderr


def _openssl_verify(algorithm, public_key, signature, manifest):
    if algorithm == "rsa-pss-sha256":
        command = [
            OPENSSL,
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:32",
            "-sigopt",
            "rsa_mgf1_md:sha256",
            "-signature",
            str(signature),
            str(manifest),
        ]
    elif algorithm == "ecdsa-p256-sha256":
        command = [
            OPENSSL,
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(manifest),
        ]
    else:
        command = [
            OPENSSL,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key),
            "-rawin",
            "-in",
            str(manifest),
            "-sigfile",
            str(signature),
        ]

    return subprocess.run(command, capture_output=True, text=True, check=False)


@pytest.mark.parametrize(
    "algorithm,signature_length",
    [
        ("rsa-pss-sha256", 384),
        ("ecdsa-p256-sha256", 64),
        ("ed25519", 64),
    ],
)
def test_openssl_crosscheck(tmp_path, algorithm, signature_length):
    if algorithm == "ed25519" and not _openssl_supports_ed25519_rawin():
        pytest.skip("openssl pkeyutl tidak mendukung -rawin")

    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"uma-sign cross-implementation test\n")

    key_prefix = tmp_path / algorithm
    keygen = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "keygen",
            "--algorithm",
            algorithm,
            "--out",
            str(key_prefix),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert keygen.returncode == 0, keygen.stderr

    bundle_path = tmp_path / "bundle.json"
    sign = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "sign",
            "--file",
            str(artifact),
            "--package",
            "uma-sign",
            "--version",
            "1.0.0",
            "--key",
            str(key_prefix) + ".key.pem",
            "--out",
            str(bundle_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert sign.returncode == 0, sign.stderr

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    manifest_data = base64.b64decode(bundle["manifest_b64"], validate=True)
    signature_data = base64.b64decode(bundle["signature_b64"], validate=True)

    manifest_path = tmp_path / "manifest.bin"
    signature_path = tmp_path / "signature.bin"
    manifest_path.write_bytes(manifest_data)
    signature_path.write_bytes(signature_data)
    assert len(signature_data) == signature_length

    if algorithm == "ecdsa-p256-sha256":
        # Membuktikan konversi r||s ke DER benar sebelum OpenSSL memverifikasi.
        signature_path.write_bytes(
            encode_dss_signature(
                int.from_bytes(signature_data[:32], "big"),
                int.from_bytes(signature_data[32:], "big"),
            )
        )
    elif algorithm == "rsa-pss-sha256":
        # Membuktikan tidak ada double hashing dan parameter PSS yang dipakai tepat.
        pass
    else:
        # Membuktikan PureEdDSA diverifikasi, bukan varian Ed25519ph.
        pass

    public_key = key_prefix.with_suffix(".pub.pem")
    valid = _openssl_verify(algorithm, public_key, signature_path, manifest_path)
    assert valid.returncode == 0, valid.stderr

    # Membuktikan perubahan satu byte pada manifest selalu ditolak.
    changed_manifest = tmp_path / "manifest-changed.bin"
    changed_manifest.write_bytes(bytes([manifest_data[0] ^ 0x01]) + manifest_data[1:])
    invalid_manifest = _openssl_verify(
        algorithm, public_key, signature_path, changed_manifest
    )
    assert invalid_manifest.returncode != 0

    # Membuktikan perubahan satu byte pada signature selalu ditolak.
    changed_signature = tmp_path / "signature-changed.bin"
    changed_signature.write_bytes(
        bytes([signature_path.read_bytes()[0] ^ 0x01]) + signature_path.read_bytes()[1:]
    )
    invalid_signature = _openssl_verify(
        algorithm, public_key, changed_signature, manifest_path
    )
    assert invalid_signature.returncode != 0
