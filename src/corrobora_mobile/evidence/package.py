"""Evidence package writer (docs/ARCHITECTURE.md, Sections 5.1, 5.4, 5.5).

Layout
------

::

    <output_dir>/<acquisition_id>/
        audit.jsonl          hash-chained audit log (created first)
        identity/ plan/ enumeration/ data/ errors/   written by the caller
        reconciliation.json  written by the caller
        hashes/files.sha256  SHA-256 of every file above (sha256sum format)
        hashes/chunks.sha256 per-chunk SHA-256 of every stream (tab-separated)
        manifest.json        written at finalization
        SEAL                 chain head and manifest SHA-256 (written last)

Rules enforced here
-------------------

* The package directory and every file in it are created exclusively;
  nothing is ever overwritten, appended to after closing, or deleted.
* Every write is announced in the audit log (INTENT) and its outcome
  recorded (RESULT), including the file's size and SHA-256.
* Streams are hashed while they are written (whole stream and fixed-size
  chunks); each chunk is ``fsync``-ed before its CHUNK entry is logged.
  When a stream closes, it is re-hashed from disk; any difference raises
  ``IntegrityError`` (completeness check C5).
* A stream interrupted by an exception is closed, kept, and recorded as
  incomplete, with the hashes of every byte that reached the disk.
* ``finalize`` writes the hash files and manifest, seals the audit log,
  writes ``SEAL``, and marks every file read-only (best effort; this is a
  host safeguard, not tamper-proofing).
* A package that is closed without ``finalize`` stays UNSEALED and is never
  deleted (Section 5.6).

Paths inside the package are restricted to ASCII letters, digits, ``.``,
``_`` and ``-`` in each component, so they are portable to Windows and
cannot escape the package directory.

One writer per package; this class is not thread-safe.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from corrobora_mobile import __version__
from corrobora_mobile.audit.log import AuditLog
from corrobora_mobile.core.clock import Clock, SystemClock, format_rfc3339
from corrobora_mobile.core.errors import EvidencePackageError, IntegrityError, ModelValidationError
from corrobora_mobile.evidence.hashing import ChunkedHasher, ChunkHash, StreamDigest, hash_file

PACKAGE_FORMAT = "corrobora-mobile/evidence-package"
PACKAGE_FORMAT_VERSION = 1

AUDIT_LOG = "audit.jsonl"
MANIFEST = "manifest.json"
SEAL_FILE = "SEAL"
FILES_SHA256 = "hashes/files.sha256"
CHUNKS_SHA256 = "hashes/chunks.sha256"

# Where callers may write. Everything else is written only by this module.
CALLER_DIRECTORIES = frozenset({"identity", "plan", "enumeration", "data", "errors"})
CALLER_TOP_LEVEL_FILES = frozenset({"reconciliation.json"})

_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def _check_component(component: str, what: str) -> None:
    if not _COMPONENT.match(component) or component.endswith("."):
        raise ModelValidationError(f"invalid {what}: {component!r}")
    if component.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        raise ModelValidationError(f"{what} is a reserved Windows name: {component!r}")


def validate_acquisition_id(acquisition_id: str) -> str:
    """An acquisition ID is also the package directory name."""
    if not isinstance(acquisition_id, str) or len(acquisition_id) > 64:
        raise ModelValidationError("acquisition_id must be a string of at most 64 characters")
    _check_component(acquisition_id, "acquisition_id")
    return acquisition_id


def validate_package_path(relpath: str) -> str:
    """Validate a package-relative path that a caller may write."""
    if not isinstance(relpath, str) or not relpath:
        raise ModelValidationError("package path must be a non-empty string")
    parts = relpath.split("/")
    for part in parts:
        _check_component(part, "package path component")
    if len(parts) == 1:
        if relpath not in CALLER_TOP_LEVEL_FILES:
            raise ModelValidationError(f"callers may not write top-level file {relpath!r}")
    elif parts[0] not in CALLER_DIRECTORIES:
        raise ModelValidationError(
            f"callers may write only under {sorted(CALLER_DIRECTORIES)}: {relpath!r}"
        )
    return relpath


@dataclass(frozen=True, slots=True)
class FileRecord:
    """A file written into the package, as verified from disk."""

    path: str
    kind: str  # "artifact", "stream", or "package"
    size: int
    sha256: str
    complete: bool
    chunks: tuple[ChunkHash, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "complete": self.complete,
            "chunk_count": len(self.chunks),
        }


@dataclass(frozen=True, slots=True)
class FinalizedPackage:
    """Returned by ``finalize``. The operator must record ``chain_head``."""

    root: Path
    chain_head: str
    manifest_sha256: str
    readonly_failures: tuple[str, ...] = field(default=())


class EvidencePackage:
    """Write-once evidence package. Create with ``EvidencePackage.create``."""

    def __init__(
        self, *, root: Path, audit: AuditLog, clock: Clock, chunk_size: int, created_at: str,
        acquisition_id: str, tool_commit: str | None,
    ) -> None:
        # Use EvidencePackage.create(); the constructor does not write anything.
        self._root = root
        self._audit = audit
        self._clock = clock
        self._chunk_size = chunk_size
        self._created_at = created_at
        self._acquisition_id = acquisition_id
        self._tool_commit = tool_commit
        self._records: dict[str, FileRecord] = {}
        self._open_streams: dict[str, StreamWriter] = {}
        self._finalized = False
        self._closed = False

    # -- construction -------------------------------------------------------

    @classmethod
    def create(
        cls,
        output_dir: Path,
        acquisition_id: str,
        *,
        chunk_size: int,
        tool_commit: str | None = None,
        retry_of: str | None = None,
        clock: Clock | None = None,
        host: Mapping[str, str] | None = None,
    ) -> EvidencePackage:
        """Create ``output_dir/acquisition_id`` and its audit log.

        Raises ``EvidencePackageError`` if the package directory exists.
        """
        validate_acquisition_id(acquisition_id)
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ModelValidationError("chunk_size must be a positive integer")
        clock = clock or SystemClock()
        output_dir.mkdir(parents=True, exist_ok=True)
        root = output_dir / acquisition_id
        try:
            os.mkdir(root)
        except FileExistsError as exc:
            raise EvidencePackageError(f"package already exists, refusing to reuse: {root}") from exc
        created_at = format_rfc3339(clock.now())
        audit = AuditLog.create(
            root / AUDIT_LOG,
            acquisition_id=acquisition_id,
            tool_commit=tool_commit,
            retry_of=retry_of,
            clock=clock,
            host=host,
        )
        return cls(
            root=root, audit=audit, clock=clock, chunk_size=chunk_size, created_at=created_at,
            acquisition_id=acquisition_id, tool_commit=tool_commit,
        )

    # -- public API ---------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def audit(self) -> AuditLog:
        """The package's audit log, for recording actions on the device."""
        return self._audit

    @property
    def records(self) -> tuple[FileRecord, ...]:
        return tuple(self._records[p] for p in sorted(self._records))

    def write_artifact(self, relpath: str, data: bytes, *, description: str) -> FileRecord:
        """Write a small file in one call (raw outputs, plans, listings)."""
        validate_package_path(relpath)
        return self._write_whole_file(relpath, data, description=description, kind="artifact")

    def open_stream(self, relpath: str, *, description: str) -> StreamWriter:
        """Open a large file to be written incrementally (e.g. ``data/ffs.tar``)."""
        validate_package_path(relpath)
        self._require_writable(relpath)
        if not isinstance(description, str) or not description.strip():
            raise ModelValidationError("description must be a non-empty string")
        path = self._prepare(relpath)
        intent = self._audit.intent("capture stream", {"path": relpath, "description": description})
        try:
            handle = open(path, "xb")
        except OSError as exc:
            self._audit.result(intent, succeeded=False, data={"path": relpath, "error": str(exc)})
            raise
        writer = StreamWriter(package=self, relpath=relpath, path=path, handle=handle, intent=intent)
        self._open_streams[relpath] = writer
        return writer

    def finalize(self, content: Mapping[str, Any]) -> FinalizedPackage:
        """Write hash files and the manifest, seal the audit log, write SEAL.

        ``content`` is the acquisition-specific part of the manifest
        (identity, plan, class, completeness, validation status, ...).
        """
        self._require_open()
        if self._open_streams:
            raise EvidencePackageError(f"streams still open: {sorted(self._open_streams)}")
        if self._audit.open_intents:
            raise EvidencePackageError(f"audit INTENT entries still open: {self._audit.open_intents}")
        if not isinstance(content, Mapping):
            raise ModelValidationError("manifest content must be a mapping")
        try:  # check before writing anything, so a bad manifest leaves no partial output
            json.dumps(dict(content), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ModelValidationError(f"manifest content is not plain JSON: {exc}") from exc

        data_records = self.records
        self._write_whole_file(FILES_SHA256, _files_sha256(data_records), description="file hashes", kind="package")
        self._write_whole_file(CHUNKS_SHA256, _chunks_tsv(data_records), description="chunk hashes", kind="package")

        manifest = {
            "format": PACKAGE_FORMAT,
            "format_version": PACKAGE_FORMAT_VERSION,
            "acquisition_id": self._acquisition_id,
            "tool": {"name": "corrobora-mobile", "version": __version__, "commit": self._tool_commit},
            "created_at": self._created_at,
            "finalized_at": format_rfc3339(self._clock.now()),
            "chunk_size": self._chunk_size,
            "files": [r.to_dict() for r in self.records],
            "content": dict(content),
        }
        try:
            manifest_bytes = (
                json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
            ).encode("ascii")
        except (TypeError, ValueError) as exc:
            raise ModelValidationError(f"manifest content is not plain JSON: {exc}") from exc
        manifest_record = self._write_whole_file(MANIFEST, manifest_bytes, description="manifest", kind="package", record=False)

        chain_head = self._audit.seal(manifest_sha256=manifest_record.sha256)
        seal_bytes = f"chain_head {chain_head}\nmanifest_sha256 {manifest_record.sha256}\n".encode("ascii")
        _write_new_file(self._root / SEAL_FILE, seal_bytes)
        self._finalized = True
        self._closed = True

        failures = []
        for relpath in [*self._records, MANIFEST, AUDIT_LOG, SEAL_FILE]:
            try:
                os.chmod(self._root / relpath, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            except OSError as exc:
                failures.append(f"{relpath}: {exc}")
        return FinalizedPackage(
            root=self._root,
            chain_head=chain_head,
            manifest_sha256=manifest_record.sha256,
            readonly_failures=tuple(failures),
        )

    def close(self) -> None:
        """Close without finalizing. Open streams are recorded as incomplete.

        The package stays UNSEALED and is kept.
        """
        if self._closed:
            return
        for writer in list(self._open_streams.values()):
            writer.abort("package closed before the stream was finished")
        self._audit.close()
        self._closed = True

    def __enter__(self) -> EvidencePackage:
        return self

    def __exit__(self, *exc: object) -> None:
        # Never finalizes implicitly.
        self.close()

    # -- internals ----------------------------------------------------------

    def _require_open(self) -> None:
        if self._finalized:
            raise EvidencePackageError("package is finalized")
        if self._closed:
            raise EvidencePackageError("package is closed")

    def _require_writable(self, relpath: str) -> None:
        self._require_open()
        if relpath in self._records or relpath in self._open_streams:
            raise EvidencePackageError(f"already written: {relpath}")

    def _prepare(self, relpath: str) -> Path:
        path = self._root.joinpath(*relpath.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _write_whole_file(
        self, relpath: str, data: bytes, *, description: str, kind: str, record: bool = True
    ) -> FileRecord:
        self._require_writable(relpath)
        if not isinstance(data, (bytes, bytearray)):
            raise ModelValidationError("data must be bytes")
        if not isinstance(description, str) or not description.strip():
            raise ModelValidationError("description must be a non-empty string")
        path = self._prepare(relpath)
        intent = self._audit.intent("write file", {"path": relpath, "description": description})
        try:
            _write_new_file(path, bytes(data))
            on_disk = hash_file(path, self._chunk_size)
        except OSError as exc:
            self._audit.result(intent, succeeded=False, data={"path": relpath, "error": str(exc)})
            raise
        expected = ChunkedHasher(self._chunk_size)
        expected.update(data)
        expected_digest = expected.finish()
        if on_disk != expected_digest:
            self._audit.result(
                intent, succeeded=False,
                data={"path": relpath, "error": "file on disk differs from data written"},
            )
            raise IntegrityError(f"{relpath}: file on disk differs from data written")
        self._audit.result(
            intent, succeeded=True, data={"path": relpath, "size": on_disk.size, "sha256": on_disk.sha256}
        )
        result = FileRecord(path=relpath, kind=kind, size=on_disk.size, sha256=on_disk.sha256, complete=True)
        if record:
            self._records[relpath] = result
        return result

    def _stream_closed(self, writer: StreamWriter, record: FileRecord) -> None:
        del self._open_streams[writer.relpath]
        self._records[writer.relpath] = record


class StreamWriter:
    """Incremental writer for one package file. Obtain via ``open_stream``."""

    def __init__(
        self, *, package: EvidencePackage, relpath: str, path: Path, handle: Any, intent: int
    ) -> None:
        self._package = package
        self.relpath = relpath
        self._path = path
        self._fh = handle
        self._intent = intent
        self._hasher = ChunkedHasher(package._chunk_size, on_chunk=self._chunk_done)
        self._done = False

    @property
    def size(self) -> int:
        return self._hasher.size

    def write(self, data: bytes) -> None:
        if self._done:
            raise EvidencePackageError(f"stream is closed: {self.relpath}")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ModelValidationError("data must be bytes")
        self._fh.write(data)
        self._hasher.update(bytes(data))

    def close(self) -> FileRecord:
        """Finish the stream, verify it from disk, and record it."""
        if self._done:
            raise EvidencePackageError(f"stream is closed: {self.relpath}")
        streamed = self._finish()
        on_disk = hash_file(self._path, self._package._chunk_size)
        if on_disk != streamed:
            self._package._audit.result(
                self._intent, succeeded=False,
                data={"path": self.relpath, "error": "stream on disk differs from stream received",
                      "streamed_sha256": streamed.sha256, "disk_sha256": on_disk.sha256},
            )
            self._package._stream_closed(self, _record(self.relpath, on_disk, complete=False))
            raise IntegrityError(f"{self.relpath}: stream on disk differs from stream received")
        self._package._audit.result(
            self._intent, succeeded=True,
            data={"path": self.relpath, "size": on_disk.size, "sha256": on_disk.sha256,
                  "chunk_count": len(on_disk.chunks), "verified_from_disk": True},
        )
        record = _record(self.relpath, on_disk, complete=True)
        self._package._stream_closed(self, record)
        return record

    def abort(self, reason: str) -> FileRecord:
        """Stop the stream after a failure. The partial file is kept and recorded."""
        if self._done:
            raise EvidencePackageError(f"stream is closed: {self.relpath}")
        streamed = self._finish()
        on_disk = hash_file(self._path, self._package._chunk_size)
        self._package._audit.result(
            self._intent, succeeded=False,
            data={"path": self.relpath, "error": reason, "size": on_disk.size, "sha256": on_disk.sha256,
                  "matches_streamed": on_disk == streamed},
        )
        record = _record(self.relpath, on_disk, complete=False)
        self._package._stream_closed(self, record)
        return record

    def __enter__(self) -> StreamWriter:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if not self._done:
            if exc is None:
                self.close()
            else:
                self.abort(f"{type(exc).__name__}: {exc}")

    def _finish(self) -> StreamDigest:
        digest = self._hasher.finish()  # logs the final partial chunk
        self._fh.close()
        self._done = True
        return digest

    def _chunk_done(self, chunk: ChunkHash) -> None:
        # Make the chunk durable before claiming it in the audit log.
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._package._audit.chunk(
            stream=self.relpath, index=chunk.index, offset=chunk.offset,
            length=chunk.length, sha256=chunk.sha256,
        )


def _record(relpath: str, digest: StreamDigest, *, complete: bool) -> FileRecord:
    return FileRecord(
        path=relpath, kind="stream", size=digest.size, sha256=digest.sha256,
        complete=complete, chunks=digest.chunks,
    )


def _write_new_file(path: Path, data: bytes) -> None:
    with open(path, "xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Persist new directory entries on POSIX. Not available on Windows."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _files_sha256(records: tuple[FileRecord, ...]) -> bytes:
    """``sha256sum``-compatible list: ``<hex>  <path>`` per line."""
    return "".join(f"{r.sha256}  {r.path}\n" for r in records).encode("ascii")


def _chunks_tsv(records: tuple[FileRecord, ...]) -> bytes:
    lines = ["# path\tindex\toffset\tlength\tsha256\n"]
    for r in records:
        for c in r.chunks:
            lines.append(f"{r.path}\t{c.index}\t{c.offset}\t{c.length}\t{c.sha256}\n")
    return "".join(lines).encode("ascii")
