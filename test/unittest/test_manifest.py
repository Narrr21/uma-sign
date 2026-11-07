import hashlib

import pytest  # type: ignore
from internal.manifest.builder import Artifact, ManifestBuilder, ReleaseManifest
from internal.manifest.canonical import is_canonical, parse_and_check
from internal.manifest.errors import (
    ManifestFormatError,
    ManifestValidationError,
)
from internal.manifest.hash import hash_artifact
from internal.manifest.parser import parse_manifest
from internal.manifest.serializer import serialize_manifest, validate_manifest

KEY_ID = "a" * 64
SHA256 = "b" * 64


@pytest.fixture
def example_manifest():
    return ReleaseManifest(
        schema="minisign-manifest/v1",
        package="uma-sign",
        version="1.2.3-rc.1+build.5",
        algorithm="future-profile-unknown-to-this-parser",
        keyid=KEY_ID,
        artifact=Artifact(name="uma-sign.tar.gz", size=5, sha256=SHA256),
    )


def test_serialize_parse_serialize_round_trip(example_manifest):
    encoded = serialize_manifest(example_manifest)
    parsed = parse_manifest(encoded)
    assert serialize_manifest(parsed) == encoded
    assert parse_and_check(encoded) == example_manifest
    assert is_canonical(encoded, example_manifest)


def test_spec_example_has_exact_field_order(example_manifest):
    assert serialize_manifest(example_manifest) == (
        b'{"schema":"minisign-manifest/v1","package":"uma-sign",'
        b'"version":"1.2.3-rc.1+build.5",'
        b'"algorithm":"future-profile-unknown-to-this-parser",'
        b'"keyid":"' + KEY_ID.encode() + b'","artifact":{"name":"uma-sign.tar.gz",'
        b'"size":5,"sha256":"' + SHA256.encode() + b'"}}'
    )


def test_manifest_builder_builds_from_file(tmp_path):
    artifact_path = tmp_path / "release.bin"
    artifact_path.write_bytes(b"abc")
    builder = ManifestBuilder(
        "minisign-manifest/v1", "pkg", "1.0", "profile", KEY_ID
    )

    manifest = builder.build_from_file(str(artifact_path))

    assert manifest.artifact == Artifact(
        name="release.bin", size=3, sha256=hashlib.sha256(b"abc").hexdigest()
    )


@pytest.mark.parametrize(
    "data",
    [
        b'{"schema":"minisign-manifest/v1","schema":"minisign-manifest/v1"}',
        b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1",'
        b'"algorithm":"profile","keyid":"' + KEY_ID.encode()
        + b'","artifact":{"name":"file","size":0,"size":0,"sha256":"'
        + SHA256.encode() + b'"}}',
    ],
)
def test_duplicate_keys_are_rejected_at_every_object_level(data):
    with pytest.raises(ManifestFormatError, match="duplicate"):
        parse_manifest(data)


@pytest.mark.parametrize(
    "data",
    [
        b'{"schema":"minisign-manifest/v1"}',
        b'[]',
        b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1",'
        b'"algorithm":"profile","keyid":"' + KEY_ID.encode()
        + b'","artifact":{"name":"file","size":0,"sha256":"'
        + SHA256.encode() + b'"},"extra":0}',
        b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1",'
        b'"algorithm":"profile","keyid":"' + KEY_ID.encode()
        + b'","artifact":{"name":"file","size":0,"sha256":"'
        + SHA256.encode() + b'","extra":0}}',
        b'{"schema":"minisign-manifest/v1","package":"pkg","version":"1",'
        b'"algorithm":"profile","keyid":"' + KEY_ID.encode()
        + b'","artifact":{"name":"file","size":0}}',
    ],
)
def test_missing_or_additional_fields_are_rejected(data):
    with pytest.raises(ManifestFormatError):
        parse_manifest(data)


@pytest.mark.parametrize("value", ["null", "true", "[]", '"text"'])
def test_artifact_must_be_an_object(value, example_manifest):
    raw = serialize_manifest(example_manifest).replace(
        b'{"name":"uma-sign.tar.gz","size":5,"sha256":"' + SHA256.encode() + b'"}',
        value.encode(),
    )
    with pytest.raises(ManifestFormatError):
        parse_manifest(raw)


@pytest.mark.parametrize(
    "size_literal",
    ["true", "1.0", "1e3", "-0", "01", "+1", '"5"', "-1", str(2**53)],
)
def test_invalid_size_values_are_rejected_by_canonical_parse(size_literal, example_manifest):
    raw = serialize_manifest(example_manifest).replace(b'"size":5', b'"size":' + size_literal.encode())
    with pytest.raises(ManifestFormatError):
        parse_and_check(raw)


@pytest.mark.parametrize("suffix", [b" ", b"\n"])
def test_trailing_whitespace_is_noncanonical(suffix, example_manifest):
    with pytest.raises(ManifestFormatError, match="non-canonical"):
        parse_and_check(serialize_manifest(example_manifest) + suffix)


def test_bom_is_rejected(example_manifest):
    with pytest.raises(ManifestFormatError, match="BOM"):
        parse_manifest(b"\xef\xbb\xbf" + serialize_manifest(example_manifest))


def test_non_ascii_input_is_rejected(example_manifest):
    raw = serialize_manifest(example_manifest).replace(b"uma-sign", "umä-sign".encode())
    with pytest.raises(ManifestFormatError, match="ASCII"):
        parse_manifest(raw)


def test_invalid_utf8_is_rejected():
    with pytest.raises(ManifestFormatError, match="UTF-8"):
        parse_manifest(b"\xff")


def test_unicode_escape_is_valid_json_but_noncanonical(example_manifest):
    raw = serialize_manifest(example_manifest).replace(b'"name":"uma-sign', b'"name":"\\u0075ma-sign')
    with pytest.raises(ManifestFormatError, match="non-canonical"):
        parse_and_check(raw)


def test_wrong_field_order_is_noncanonical(example_manifest):
    raw = serialize_manifest(example_manifest)
    reordered = raw.replace(
        b'{"schema":"minisign-manifest/v1","package":"uma-sign"',
        b'{"package":"uma-sign","schema":"minisign-manifest/v1"',
    )
    assert parse_manifest(reordered) == example_manifest
    with pytest.raises(ManifestFormatError, match="non-canonical"):
        parse_and_check(reordered)


def test_unknown_algorithm_passes_parse_and_canonical_check(example_manifest):
    encoded = serialize_manifest(example_manifest)
    assert parse_manifest(encoded).algorithm == example_manifest.algorithm
    assert parse_and_check(encoded).algorithm == example_manifest.algorithm


@pytest.mark.parametrize("field,value", [("keyid", "A" * 64), ("keyid", "a" * 63), ("sha256", "B" * 64), ("sha256", "b" * 63)])
def test_uppercase_or_wrong_length_digests_are_rejected(field, value, example_manifest):
    if field == "keyid":
        manifest = ReleaseManifest(
            example_manifest.schema, example_manifest.package, example_manifest.version,
            example_manifest.algorithm, value, example_manifest.artifact
        )
    else:
        artifact = Artifact(example_manifest.artifact.name, example_manifest.artifact.size, value)
        manifest = ReleaseManifest(
            example_manifest.schema, example_manifest.package, example_manifest.version,
            example_manifest.algorithm, example_manifest.keyid, artifact
        )
    with pytest.raises(ManifestValidationError):
        validate_manifest(manifest)


def test_manifest_over_16_kib_is_rejected():
    with pytest.raises(ManifestFormatError, match="exceeds"):
        parse_manifest(b" " * (16 * 1024 + 1))


def test_extremely_long_integer_is_a_format_error(example_manifest):
    raw = serialize_manifest(example_manifest).replace(b'"size":5', b'"size":' + b"9" * 5000)
    with pytest.raises(ManifestFormatError):
        parse_manifest(raw)


def test_json_null_in_field_is_rejected(example_manifest):
    raw = serialize_manifest(example_manifest).replace(
        b'"algorithm":"future-profile-unknown-to-this-parser"', b'"algorithm":null'
    )
    with pytest.raises(ManifestFormatError):
        parse_manifest(raw)


@pytest.mark.parametrize("content", [b"", b"x"])
def test_hash_artifact_small_files(tmp_path, content):
    path = tmp_path / "artifact.bin"
    path.write_bytes(content)
    assert hash_artifact(str(path)) == (len(content), hashlib.sha256(content).hexdigest())


def test_hash_artifact_empty_file_digest(tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert hash_artifact(str(path)) == (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_hash_artifact_across_multiple_chunks(tmp_path):
    content = bytes(range(256)) * (8192 + 23)
    path = tmp_path / "large.bin"
    path.write_bytes(content)
    assert hash_artifact(str(path)) == (len(content), hashlib.sha256(content).hexdigest())