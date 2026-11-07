from dataclasses import dataclass

SCHEMA = "minisign-bundle/v1"


@dataclass(frozen=True)
class Bundle:
    schema: str
    manifest: bytes
    signature: bytes
