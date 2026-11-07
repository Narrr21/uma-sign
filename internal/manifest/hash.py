import hashlib

CHUNK_SIZE = 1024 * 1024


def hash_artifact(path: str) -> tuple[int, str]:
	digest = hashlib.sha256()
	size = 0
	with open(path, "rb") as artifact_file:
		while chunk := artifact_file.read(CHUNK_SIZE):
			size += len(chunk)
			digest.update(chunk)
	return size, digest.hexdigest()
