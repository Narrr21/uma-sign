import json

from .builder import Artifact, ReleaseManifest
from .errors import ManifestFormatError, ManifestValidationError
from .serializer import MAX_MANIFEST_SIZE, validate_manifest

_ROOT_FIELDS = {"schema", "package", "version", "algorithm", "keyid", "artifact"}
_ARTIFACT_FIELDS = {"name", "size", "sha256"}


def _reject_duplicate_keys(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise ManifestFormatError(f"duplicate object key: {key}")
		result[key] = value
	return result


def _reject_float(value: str):
	raise ManifestFormatError(f"floating-point number is not allowed: {value}")


def _reject_constant(value: str):
	raise ManifestFormatError(f"non-standard JSON constant is not allowed: {value}")


def _require_fields(value, expected: set, location: str) -> None:
	if not isinstance(value, dict):
		raise ManifestFormatError(f"{location} must be an object")
	actual = set(value)
	missing = expected - actual
	additional = actual - expected
	if missing:
		raise ManifestFormatError(
			f"{location} is missing field(s): {', '.join(sorted(missing))}"
		)
	if additional:
		raise ManifestFormatError(
			f"{location} has unexpected field(s): {', '.join(sorted(additional))}"
		)


def parse_manifest(data: bytes) -> ReleaseManifest:
	if not isinstance(data, bytes):
		raise ManifestFormatError("manifest data must be bytes")
	if len(data) > MAX_MANIFEST_SIZE:
		raise ManifestFormatError(f"manifest exceeds {MAX_MANIFEST_SIZE} bytes")
	if data.startswith(b"\xef\xbb\xbf"):
		raise ManifestFormatError("UTF-8 BOM is not allowed")

	try:
		text = data.decode("utf-8")
	except UnicodeDecodeError as error:
		raise ManifestFormatError("manifest is not valid UTF-8") from error
	if any(byte > 0x7F for byte in data):
		raise ManifestFormatError("manifest must contain only ASCII bytes")

	try:
		value = json.loads(
			text,
			object_pairs_hook=_reject_duplicate_keys,
			parse_float=_reject_float,
			parse_constant=_reject_constant,
		)
	except ManifestFormatError:
		raise
	except (ValueError, RecursionError) as error:
		raise ManifestFormatError(f"invalid JSON: {error}") from error

	_require_fields(value, _ROOT_FIELDS, "root")
	artifact_value = value["artifact"]
	_require_fields(artifact_value, _ARTIFACT_FIELDS, "artifact")

	manifest = ReleaseManifest(
		schema=value["schema"],
		package=value["package"],
		version=value["version"],
		algorithm=value["algorithm"],
		keyid=value["keyid"],
		artifact=Artifact(
			name=artifact_value["name"],
			size=artifact_value["size"],
			sha256=artifact_value["sha256"],
		),
	)
	try:
		validate_manifest(manifest)
	except ManifestValidationError as error:
		raise ManifestFormatError(str(error)) from error
	return manifest
