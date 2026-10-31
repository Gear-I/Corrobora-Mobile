"""Write-once evidence packages (docs/ARCHITECTURE.md, Sections 5.1-5.5)."""

from corrobora_mobile.evidence.hashing import ChunkedHasher, ChunkHash, StreamDigest, hash_file
from corrobora_mobile.evidence.package import (
    EvidencePackage,
    FileRecord,
    FinalizedPackage,
    StreamWriter,
    validate_acquisition_id,
    validate_package_path,
)

__all__ = [
    "ChunkHash",
    "ChunkedHasher",
    "EvidencePackage",
    "FileRecord",
    "FinalizedPackage",
    "StreamDigest",
    "StreamWriter",
    "hash_file",
    "validate_acquisition_id",
    "validate_package_path",
]
