"""Reading the members of an acquired tar archive (M1.11).

``read_archive`` lists every member of a tar file already written to the
evidence package, mapping each member name to an absolute device path
(``base`` + ``/`` + name). It reads the file; it never extracts anything.

End of archive: the stream must end with an end-of-archive marker of at
least two 512-byte zero blocks after the last member, with nothing but
zeros after it. toybox ``tar`` was observed (2026-11-09) to write exactly
1024 zero bytes and no further padding. An archive that stops anywhere
else is reported as not parsed to its end (check C4).

Member names are taken as raw bytes (``surrogateescape``), so names that
are not valid UTF-8 survive unchanged. A name that does not form a
canonical device path (for example one containing ``..``) is reported as an
invalid member rather than repaired.
"""

from __future__ import annotations

import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from corrobora_mobile.acquisition.reconcile import ArchivedMember
from corrobora_mobile.core.enums import EntryType
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.paths import validate_device_path

BLOCK = 512
END_MARKER = 2 * BLOCK


@dataclass(frozen=True, slots=True)
class ArchiveListing:
    members: tuple[ArchivedMember, ...]
    parsed_to_end: bool
    truncated_members: tuple[bytes, ...] = ()
    invalid_member_names: tuple[bytes, ...] = ()
    duplicate_members: tuple[bytes, ...] = ()
    selinux_labelled: int = 0
    sparse_members: int = 0
    notes: tuple[str, ...] = field(default=())


def _entry_type(m: tarfile.TarInfo) -> EntryType:
    if m.isdir():
        return EntryType.DIRECTORY
    if m.issym():
        return EntryType.SYMLINK
    if m.islnk():
        return EntryType.HARDLINK
    if m.isfifo():
        return EntryType.FIFO
    if m.ischr():
        return EntryType.CHAR_DEVICE
    if m.isblk():
        return EntryType.BLOCK_DEVICE
    if m.isreg():
        return EntryType.REGULAR
    return EntryType.UNKNOWN


def _device_path(base: bytes, name: bytes) -> bytes:
    name = name.rstrip(b"/")
    return validate_device_path(base + b"/" + name, "archive member")


def read_archive(path: Path, *, base: bytes) -> ArchiveListing:
    """List the members of the tar file at ``path`` (see the module docstring)."""
    validate_device_path(base, "archive base")
    size = path.stat().st_size
    members: list[ArchivedMember] = []
    seen: set[bytes] = set()
    duplicates: list[bytes] = []
    invalid: list[bytes] = []
    truncated: list[bytes] = []
    notes: list[str] = []
    labelled = sparse = 0
    parsed_to_end = False
    last: tarfile.TarInfo | None = None
    with open(path, "rb") as fh:
        try:
            with tarfile.open(fileobj=fh, mode="r|", encoding="utf-8",
                              errors="surrogateescape") as tf:
                for m in tf:
                    raw = m.name.encode("utf-8", "surrogateescape")
                    last = m
                    if "RHT.security.selinux" in m.pax_headers:
                        labelled += 1
                    if m.issparse():
                        sparse += 1
                    try:
                        device_path = _device_path(base, raw)
                    except ModelValidationError:
                        invalid.append(raw)
                        continue
                    if device_path in seen:
                        duplicates.append(device_path)
                        continue
                    seen.add(device_path)
                    kind = _entry_type(m)
                    members.append(ArchivedMember(
                        path=device_path, entry_type=kind,
                        size=m.size if kind is EntryType.REGULAR else None))
                end = tf.offset
            fh.seek(end)
            rest = fh.read()
            parsed_to_end = len(rest) >= END_MARKER and not rest.strip(b"\0")
            if not parsed_to_end:
                notes.append(f"no valid end-of-archive marker: {len(rest)} bytes after the last "
                             f"member at offset {end} of {size}")
        except (tarfile.TarError, EOFError) as exc:
            notes.append(f"archive could not be read to its end: {type(exc).__name__}: {exc}")
            # Name a member only if its own data is incomplete; a cut inside the
            # next header leaves the previous member whole.
            if last is not None and last.offset_data + last.size > size:
                truncated.append(_safe(base, last.name.encode("utf-8", "surrogateescape")))
    if duplicates:
        notes.append(f"{len(duplicates)} member paths appear more than once; the first is used")
    if invalid:
        notes.append(f"{len(invalid)} member names do not form a canonical device path")
    return ArchiveListing(
        members=tuple(members), parsed_to_end=parsed_to_end, truncated_members=tuple(truncated),
        invalid_member_names=tuple(invalid), duplicate_members=tuple(duplicates),
        selinux_labelled=labelled, sparse_members=sparse, notes=tuple(notes))


def _safe(base: bytes, name: bytes) -> bytes:
    try:
        return _device_path(base, name)
    except ModelValidationError:
        return base
