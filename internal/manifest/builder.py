import os
from dataclasses import dataclass

from .hash import hash_artifact


@dataclass
class Artifact:
    name: str
    size: int
    sha256: str

@dataclass
class ReleaseManifest:
    schema: str
    package: str
    version: str
    algorithm: str
    keyid: str
    artifact: Artifact

class ManifestBuilder:
    def __init__(self, schema: str, package: str, version: str, algorithm: str, keyid: str):
        self.schema = schema
        self.package = package
        self.version = version
        self.algorithm = algorithm
        self.keyid = keyid

    def build(self, artifact_name: str, artifact_size: int, artifact_sha256: str) -> ReleaseManifest:
        artifact = Artifact(name=artifact_name, size=artifact_size, sha256=artifact_sha256)
        return ReleaseManifest(
            schema=self.schema,
            package=self.package,
            version=self.version,
            algorithm=self.algorithm,
            keyid=self.keyid,
            artifact=artifact
        )

    def build_from_file(self, path: str) -> ReleaseManifest:
        artifact_size, artifact_sha256 = hash_artifact(path)
        return self.build(os.path.basename(path), artifact_size, artifact_sha256)
