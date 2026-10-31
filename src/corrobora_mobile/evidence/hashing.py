"""Streaming SHA-256 with fixed-size chunk hashes (docs/ARCHITECTURE.md, 5.5).

``ChunkedHasher`` hashes a byte stream as it arrives, producing the hash of
the whole stream and of every fixed-size chunk. ``hash_file`` computes the
same values from a file on disk, so the two can be compared (check C5).
Chunk boundaries depend only on byte offsets, never on how the stream was
split into ``update`` calls.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from corrobora_mobile.core.errors import ModelValidationError

_READ_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ChunkHash:
    index: int
    offset: int
    length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class StreamDigest:
    size: int
    sha256: str
    chunks: tuple[ChunkHash, ...]


class ChunkedHasher:
    """Incremental SHA-256 of a stream and of each ``chunk_size`` chunk.

    ``on_chunk`` is called with each chunk hash as soon as the chunk is
    complete. The final, possibly shorter, chunk is reported by
    ``finish``.
    """

    def __init__(
        self, chunk_size: int, on_chunk: Callable[[ChunkHash], None] | None = None
    ) -> None:
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ModelValidationError("chunk_size must be a positive integer")
        self._chunk_size = chunk_size
        self._on_chunk = on_chunk
        self._total = hashlib.sha256()
        self._chunk = hashlib.sha256()
        self._chunk_len = 0
        self._size = 0
        self._chunks: list[ChunkHash] = []
        self._finished = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def chunks(self) -> tuple[ChunkHash, ...]:
        """Chunks completed so far."""
        return tuple(self._chunks)

    def update(self, data: bytes) -> None:
        if self._finished:
            raise ModelValidationError("hasher already finished")
        view = memoryview(data)
        self._total.update(view)
        while view:
            take = min(len(view), self._chunk_size - self._chunk_len)
            self._chunk.update(view[:take])
            self._chunk_len += take
            self._size += take
            view = view[take:]
            if self._chunk_len == self._chunk_size:
                self._close_chunk()

    def finish(self) -> StreamDigest:
        """Close the final partial chunk (if any) and return the digest."""
        if not self._finished:
            if self._chunk_len:
                self._close_chunk()
            self._finished = True
        return StreamDigest(size=self._size, sha256=self._total.hexdigest(), chunks=tuple(self._chunks))

    def _close_chunk(self) -> None:
        chunk = ChunkHash(
            index=len(self._chunks),
            offset=self._size - self._chunk_len,
            length=self._chunk_len,
            sha256=self._chunk.hexdigest(),
        )
        self._chunks.append(chunk)
        self._chunk = hashlib.sha256()
        self._chunk_len = 0
        if self._on_chunk is not None:
            self._on_chunk(chunk)


def hash_file(path: Path, chunk_size: int) -> StreamDigest:
    """Hash a file on disk exactly as ``ChunkedHasher`` hashes a stream."""
    hasher = ChunkedHasher(chunk_size)
    with open(path, "rb") as handle:
        while block := handle.read(_READ_SIZE):
            hasher.update(block)
    return hasher.finish()
