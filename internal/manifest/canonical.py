from .builder import ReleaseManifest
from .errors import ManifestFormatError
from .parser import parse_manifest
from .serializer import serialize_manifest


def is_canonical(data: bytes, m: ReleaseManifest) -> bool:
	return data == serialize_manifest(m)


def parse_and_check(data: bytes) -> ReleaseManifest:
	manifest = parse_manifest(data)
	if not is_canonical(data, manifest):
		raise ManifestFormatError("non-canonical")
	return manifest
