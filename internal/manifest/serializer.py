import re

from .builder import ReleaseManifest
from .errors import ManifestValidationError

MAX_MANIFEST_SIZE = 16384
MAX_SAFE_INTEGER = 9007199254740991

_PACKAGE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_KEYID_PATTERN = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _require_string(value, field_name: str) -> str:
	if not isinstance(value, str):
		raise ManifestValidationError(f"{field_name} must be a string")
	return value


def _require_pattern(value: str, pattern: re.Pattern, field_name: str) -> None:
	if re.fullmatch(pattern, value) is None:
		raise ManifestValidationError(f"{field_name} has an invalid format")


def validate_manifest(m: ReleaseManifest) -> None:
	if not isinstance(m, ReleaseManifest):
		raise ManifestValidationError("manifest must be a ReleaseManifest")

	if _require_string(m.schema, "schema") != "umasign-manifest/v1":
		raise ManifestValidationError('schema must be "umasign-manifest/v1"')

	package = _require_string(m.package, "package")
	_require_pattern(package, _PACKAGE_PATTERN, "package")

	version = _require_string(m.version, "version")
	_require_pattern(version, _VERSION_PATTERN, "version")

	algorithm = _require_string(m.algorithm, "algorithm")
	if not 1 <= len(algorithm) <= 64 or any(
		not 0x20 <= ord(character) <= 0x7E or character in '"\\'
		for character in algorithm
	):
		raise ManifestValidationError(
			'algorithm must be 1-64 printable ASCII characters without " or \\'
		)

	keyid = _require_string(m.keyid, "keyid")
	_require_pattern(keyid, _KEYID_PATTERN, "keyid")

	if m.artifact is None:
		raise ManifestValidationError("artifact must be an Artifact")
	artifact_name = _require_string(m.artifact.name, "artifact.name")
	_require_pattern(artifact_name, _ARTIFACT_NAME_PATTERN, "artifact.name")

	if type(m.artifact.size) is not int:
		raise ManifestValidationError("artifact.size must be an integer")
	if not 0 <= m.artifact.size <= MAX_SAFE_INTEGER:
		raise ManifestValidationError(
			f"artifact.size must be between 0 and {MAX_SAFE_INTEGER}"
		)

	artifact_sha256 = _require_string(m.artifact.sha256, "artifact.sha256")
	_require_pattern(artifact_sha256, _SHA256_PATTERN, "artifact.sha256")


def serialize_manifest(m: ReleaseManifest) -> bytes:
	validate_manifest(m)
	artifact = m.artifact
	serialized = (
		'{"schema":"' + m.schema
		+ '","package":"' + m.package
		+ '","version":"' + m.version
		+ '","algorithm":"' + m.algorithm
		+ '","keyid":"' + m.keyid
		+ '","artifact":{"name":"' + artifact.name
		+ '","size":' + str(artifact.size)
		+ ',"sha256":"' + artifact.sha256 + '"}}'
	)
	encoded = serialized.encode("utf-8")
	if len(encoded) > MAX_MANIFEST_SIZE:
		raise ManifestValidationError(
			f"serialized manifest exceeds {MAX_MANIFEST_SIZE} bytes"
		)
	return encoded
