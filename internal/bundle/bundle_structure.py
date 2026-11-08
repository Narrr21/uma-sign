from dataclasses import dataclass

SCHEMA = "umasign-bundle/v1"

@dataclass(frozen=True)
class Bundle:
    schema: str
    manifest: bytes
    signature: bytes

class BundleBuilder:
    def __init__(self, schema: str):
        self.schema = schema

    def build(self, manifest: bytes, signature: bytes) -> Bundle:
        return Bundle(
            schema=self.schema,
            manifest=manifest,
            signature=signature
        )




