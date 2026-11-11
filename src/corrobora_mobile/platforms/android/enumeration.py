"""Parsing and merging the two-pass Android enumeration (M1.11).

Pass 1 (``find -printf``, NUL-separated, see ``commands.FIND_FORMAT``) gives
for each entry: type and mode string, octal mode, uid, gid, size, inode,
SELinux label, symlink target and the raw path. It is safe for any file
name.

Pass 2 (``find -exec stat``, see ``commands.STAT_FORMAT``) gives, one line
per entry with no name: inode, link count, and mtime, ctime and atime, each
as unix seconds and in full form. Lines are matched to pass 1 by position,
and every position must carry the same inode. If the counts differ or any
inode disagrees (for example because something changed between the
passes), pass 2 is not used at all: times and link counts are recorded as
unknown and the reason is noted. Pass 2 values are never matched by guess.

Nanoseconds are taken from the full form only when it carries exactly nine
fractional digits; otherwise the whole-second value is used and the entry
is counted as second-precision. (``find``'s ``%T@`` was observed to drop
leading zeros of the fraction, which is why it is not used; whether
``stat``'s full form can do the same is checked here, not assumed.)

Nothing here talks to a device.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from corrobora_mobile.core.enums import EntryType
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import EnumeratedEntry
from corrobora_mobile.platforms.android.commands import FIND_FIELDS, FIND_FORMAT, STAT_FORMAT

ENUMERATION_FORMAT = "corrobora-mobile/enumeration"
ENUMERATION_FORMAT_VERSION = 1

TYPE_CHARS = {
    "-": EntryType.REGULAR, "d": EntryType.DIRECTORY, "l": EntryType.SYMLINK,
    "p": EntryType.FIFO, "s": EntryType.SOCKET, "c": EntryType.CHAR_DEVICE,
    "b": EntryType.BLOCK_DEVICE,
}
_INT = re.compile(rb"^-?[0-9]+$")
_OCTAL = re.compile(rb"^[0-7]{1,7}$")
_FULL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.(\d+))? [+-]\d{4}$")


@dataclass(frozen=True, slots=True)
class FindRecord:
    path: bytes
    entry_type: EntryType
    mode: int
    uid: int
    gid: int
    size: int
    inode: int
    selinux_label: str | None
    symlink_target: bytes | None


@dataclass(frozen=True, slots=True)
class StatRecord:
    inode: int
    link_count: int
    mtime_ns: int
    ctime_ns: int
    atime_ns: int
    second_precision_fields: int  # how many of the three times lacked 9 fractional digits


@dataclass(frozen=True, slots=True)
class Enumeration:
    """A merged enumeration, ready for ``reconcile`` and for the package."""

    entries: tuple[EnumeratedEntry, ...]
    symlink_targets: dict[bytes, bytes]
    stat_pass_used: bool
    notes: tuple[str, ...] = field(default=())
    second_precision_entries: int = 0

    def header(self, *, label: str) -> dict[str, Any]:
        return {
            "format": ENUMERATION_FORMAT,
            "format_version": ENUMERATION_FORMAT_VERSION,
            "label": label,
            "mechanism": {
                "pass_1": f"find <root> -printf '{FIND_FORMAT}'",
                "pass_2": f"find <root> -exec stat -c '{STAT_FORMAT}' {{}} +",
                "pass_2_used": self.stat_pass_used,
            },
            "entry_count": len(self.entries),
            "timestamp_precision": (
                "nanoseconds where the stat full form had 9 fractional digits; "
                f"{self.second_precision_entries} entries fell back to whole seconds"
                if self.stat_pass_used else "not available (pass 2 not used)"),
            "notes": list(self.notes),
        }

    def to_jsonl(self, *, label: str) -> bytes:
        lines = [json.dumps(self.header(label=label), sort_keys=True)]
        for e in self.entries:
            row = e.to_dict()
            target = self.symlink_targets.get(e.path)
            row["symlink_target"] = encode_target(target) if target is not None else None
            lines.append(json.dumps(row, sort_keys=True))
        return ("\n".join(lines) + "\n").encode("ascii")


def encode_target(raw: bytes) -> dict[str, str]:
    """Like ``encode_path``, for symlink targets, which may be relative or non-canonical."""
    return {"b64": base64.b64encode(raw).decode("ascii"),
            "display": raw.decode("utf-8", errors="backslashreplace")}


def _int(value: bytes, name: str) -> int:
    if not _INT.match(value):
        raise ModelValidationError(f"pass 1: {name} is not an integer: {value!r}")
    return int(value)


def parse_find(data: bytes) -> list[FindRecord]:
    """Parse pass 1. Raises ``ModelValidationError`` on any malformed record."""
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise ModelValidationError("pass 1 output does not end with a NUL separator")
    fields = data[:-1].split(b"\0")
    if len(fields) % FIND_FIELDS:
        raise ModelValidationError(
            f"pass 1 has {len(fields)} fields, not a multiple of {FIND_FIELDS}")
    records = []
    for i in range(0, len(fields), FIND_FIELDS):
        type_mode, mode, uid, gid, size, inode, label, target, path = fields[i:i + FIND_FIELDS]
        kind = TYPE_CHARS.get(type_mode[:1].decode("ascii", "replace"), EntryType.UNKNOWN)
        if not _OCTAL.match(mode):
            raise ModelValidationError(f"pass 1: mode is not octal: {mode!r}")
        text_label = label.decode("utf-8", "replace")
        records.append(FindRecord(
            path=path, entry_type=kind, mode=int(mode, 8),
            uid=_int(uid, "uid"), gid=_int(gid, "gid"), size=_int(size, "size"),
            inode=_int(inode, "inode"),
            selinux_label=text_label if text_label.strip() and text_label != "?" else None,
            symlink_target=target if kind is EntryType.SYMLINK else None,
        ))
    return records


def _time_ns(seconds: str, full: str) -> tuple[int, bool]:
    """(nanoseconds, True if nanoseconds were available)."""
    secs = int(seconds)
    match = _FULL_TIME.match(full)
    if not match:
        raise ModelValidationError(f"pass 2: unrecognised time {full!r}")
    frac = match.group(1)
    if frac is not None and len(frac) == 9:
        return secs * 1_000_000_000 + int(frac), True
    return secs * 1_000_000_000, False


def parse_stat(data: bytes) -> list[StatRecord]:
    """Parse pass 2. Raises ``ModelValidationError`` on any malformed line."""
    text = data.decode("ascii")  # pass 2 contains no names, so it must be ASCII
    records = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 8:
            raise ModelValidationError(f"pass 2: expected 8 fields: {line!r}")
        inode, links, y, y_full, z, z_full, x, x_full = parts
        if not all(_INT.match(v.encode()) for v in (inode, links, y, z, x)):
            raise ModelValidationError(f"pass 2: non-integer field: {line!r}")
        m, m_ok = _time_ns(y, y_full)
        c, c_ok = _time_ns(z, z_full)
        a, a_ok = _time_ns(x, x_full)
        records.append(StatRecord(inode=int(inode), link_count=int(links), mtime_ns=m,
                                  ctime_ns=c, atime_ns=a,
                                  second_precision_fields=3 - sum((m_ok, c_ok, a_ok))))
    return records


def merge(find_records: Sequence[FindRecord], stat_records: Sequence[StatRecord] | None,
          *, stat_unavailable_reason: str | None = None) -> Enumeration:
    """Combine the passes. Pass 2 is used only if it lines up entry by entry."""
    notes: list[str] = []
    use_stat = stat_records is not None
    if stat_records is None:
        notes.append(f"pass 2 not used: {stat_unavailable_reason or 'not available'}")
    elif len(stat_records) != len(find_records):
        use_stat = False
        notes.append(f"pass 2 not used: {len(stat_records)} lines for {len(find_records)} "
                     "entries (the filesystem may have changed between the passes)")
    else:
        bad = [i for i, (f, s) in enumerate(zip(find_records, stat_records)) if f.inode != s.inode]
        if bad:
            use_stat = False
            notes.append(f"pass 2 not used: inode differs from pass 1 at {len(bad)} positions "
                         f"(first at entry {bad[0]})")

    entries: list[EnumeratedEntry] = []
    targets: dict[bytes, bytes] = {}
    second_precision = 0
    seen: set[bytes] = set()
    for i, f in enumerate(find_records):
        if f.path in seen:
            raise ModelValidationError(f"pass 1 lists a path twice: {f.path!r}")
        seen.add(f.path)
        s = stat_records[i] if use_stat else None
        if s is not None and s.second_precision_fields:
            second_precision += 1
        entries.append(EnumeratedEntry(
            path=f.path, entry_type=f.entry_type, size=f.size, mode=f.mode, uid=f.uid,
            gid=f.gid, inode=f.inode, selinux_label=f.selinux_label,
            mtime_ns=s.mtime_ns if s else None, ctime_ns=s.ctime_ns if s else None,
            atime_ns=s.atime_ns if s else None, link_count=s.link_count if s else None))
        if f.symlink_target is not None:
            targets[f.path] = f.symlink_target
    if any(e.entry_type is EntryType.UNKNOWN for e in entries):
        notes.append("some entries have a type character this parser does not know")
    return Enumeration(entries=tuple(entries), symlink_targets=targets, stat_pass_used=use_stat,
                       notes=tuple(notes), second_precision_entries=second_precision)
