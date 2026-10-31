"""Audit-log writer (docs/ARCHITECTURE.md, Section 5.6).

Line format
-----------

Each entry is one line: a JSON object encoded as UTF-8 and terminated by a
single ``\\n`` (no ``\\r``). The object has exactly these keys:

* ``seq``  -- integer, 0 for the first line, increasing by 1 with no gaps;
* ``ts``   -- canonical UTC timestamp, ``YYYY-MM-DDTHH:MM:SS.ffffffZ``;
* ``type`` -- one of SESSION_START, INTENT, RESULT, CHUNK, NOTE, SEAL;
* ``data`` -- a JSON object;
* ``prev`` -- lowercase hex SHA-256 of the **exact bytes** of the previous
  line, including its ``\\n``; 64 zeros for line 0.

The writer serializes with sorted keys, compact separators, and ASCII-only
output, but verification never depends on that: the chain is computed over
the bytes as written. The **chain head** is the SHA-256 of the last line.

Rules enforced by the writer
----------------------------

* The log file is created exclusively. An existing file is never appended
  to; a retry after an interruption uses a new acquisition ID.
* Line 0 is SESSION_START, with a random 128-bit session nonce.
* Every line is flushed and ``fsync``-ed before the call returns, so an
  INTENT is on disk before the action it announces starts.
* A RESULT must close an open INTENT, exactly once.
* SEAL is refused while any INTENT is open, and nothing may follow it.

One writer per log; this class is not thread-safe.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import socket
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from corrobora_mobile import __version__
from corrobora_mobile.core.clock import Clock, SystemClock, format_rfc3339
from corrobora_mobile.core.enums import AuditEntryType
from corrobora_mobile.core.errors import AuditLogError, ModelValidationError

GENESIS_PREV = "0" * 64
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One written entry: its sequence number and the SHA-256 of its line."""

    seq: int
    entry_type: AuditEntryType
    line_sha256: str


def serialize_line(
    *, seq: int, ts: str, entry_type: AuditEntryType, data: Mapping[str, Any], prev: str
) -> bytes:
    """Serialize one entry to its exact line bytes, including ``\\n``."""
    if not isinstance(data, Mapping):
        raise ModelValidationError("audit data must be a mapping")
    obj = {"seq": seq, "ts": ts, "type": entry_type.value, "data": dict(data), "prev": prev}
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ModelValidationError(f"audit data is not plain JSON: {exc}") from exc
    return text.encode("ascii") + b"\n"


def collect_host_info() -> dict[str, str]:
    """Host details recorded in SESSION_START.

    Values come from the Python standard library and are recorded as
    reported; they are not independently verified.
    """
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
    }


class AuditLog:
    """Append-only, hash-chained audit log. Create with ``AuditLog.create``."""

    def __init__(self, *, path: Path, handle: Any, clock: Clock) -> None:
        # Use AuditLog.create(); the constructor does not write anything.
        self._path = path
        self._fh = handle
        self._clock = clock
        self._next_seq = 0
        self._prev = GENESIS_PREV
        self._open_intents: dict[int, str] = {}
        self._sealed = False
        self._closed = False

    # -- construction -------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        acquisition_id: str,
        tool_commit: str | None = None,
        retry_of: str | None = None,
        clock: Clock | None = None,
        host: Mapping[str, str] | None = None,
    ) -> AuditLog:
        """Create a new log file and write its SESSION_START line.

        Raises ``AuditLogError`` if the file already exists.

        Args:
            acquisition_id: the acquisition this log belongs to.
            tool_commit: git commit of the running tool, or None if unknown.
            retry_of: acquisition ID of an interrupted acquisition this one
                retries, if any.
            clock: time source (default: host system clock).
            host: host details (default: ``collect_host_info()``).
        """
        if not isinstance(acquisition_id, str) or not acquisition_id.strip():
            raise ModelValidationError("acquisition_id must be a non-empty string")
        clock = clock or SystemClock()
        try:
            handle = open(path, "xb")  # exclusive create: never reuse a log
        except FileExistsError as exc:
            raise AuditLogError(f"audit log already exists, refusing to append: {path}") from exc
        log = cls(path=path, handle=handle, clock=clock)
        try:
            log._write(
                AuditEntryType.SESSION_START,
                {
                    "acquisition_id": acquisition_id,
                    "tool": "corrobora-mobile",
                    "tool_version": __version__,
                    "tool_commit": tool_commit,
                    "retry_of": retry_of,
                    "clock_source": getattr(clock, "source", "unknown"),
                    "host": dict(host) if host is not None else collect_host_info(),
                    "session_nonce": secrets.token_hex(16),
                },
            )
        except BaseException:
            handle.close()
            raise
        _fsync_directory(path.parent)
        return log

    # -- public API ---------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def chain_head(self) -> str:
        """SHA-256 of the last line written."""
        return self._prev

    @property
    def open_intents(self) -> dict[int, str]:
        """Open INTENT entries as {seq: action}."""
        return dict(self._open_intents)

    @property
    def sealed(self) -> bool:
        return self._sealed

    def intent(self, action: str, data: Mapping[str, Any] | None = None) -> int:
        """Record an action before it starts. Returns the INTENT's seq."""
        if not isinstance(action, str) or not action.strip():
            raise ModelValidationError("action must be a non-empty string")
        payload = {"action": action, **_plain(data)}
        entry = self._write(AuditEntryType.INTENT, payload)
        self._open_intents[entry.seq] = action
        return entry.seq

    def result(
        self,
        intent_seq: int,
        *,
        succeeded: bool,
        exit_status: int | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> int:
        """Record the outcome of an announced action. Returns the RESULT's seq."""
        if intent_seq not in self._open_intents:
            raise AuditLogError(f"no open INTENT with seq {intent_seq}")
        if not isinstance(succeeded, bool):
            raise ModelValidationError("succeeded must be a bool")
        if exit_status is not None and (isinstance(exit_status, bool) or not isinstance(exit_status, int)):
            raise ModelValidationError("exit_status must be an integer or None")
        payload = {
            "intent_seq": intent_seq,
            "succeeded": succeeded,
            "exit_status": exit_status,
            **_plain(data),
        }
        entry = self._write(AuditEntryType.RESULT, payload)
        del self._open_intents[intent_seq]
        return entry.seq

    def chunk(self, *, stream: str, index: int, offset: int, length: int, sha256: str) -> int:
        """Record the hash of one completed chunk of a captured stream."""
        if not isinstance(stream, str) or not stream.strip():
            raise ModelValidationError("stream must be a non-empty string")
        for name, value in (("index", index), ("offset", offset), ("length", length)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ModelValidationError(f"{name} must be a non-negative integer")
        _require_sha256(sha256, "sha256")
        payload = {"stream": stream, "index": index, "offset": offset, "length": length, "sha256": sha256}
        return self._write(AuditEntryType.CHUNK, payload).seq

    def note(self, message: str, data: Mapping[str, Any] | None = None) -> int:
        """Record an observation that is not an action (e.g. a warning)."""
        if not isinstance(message, str) or not message.strip():
            raise ModelValidationError("message must be a non-empty string")
        return self._write(AuditEntryType.NOTE, {"message": message, **_plain(data)}).seq

    def seal(self, *, manifest_sha256: str) -> str:
        """Write the SEAL entry and close the log. Returns the chain head.

        The chain head must be recorded outside the package by the operator
        (docs/ARCHITECTURE.md, Section 5.6).
        """
        _require_sha256(manifest_sha256, "manifest_sha256")
        if self._open_intents:
            raise AuditLogError(
                f"cannot seal with open INTENT entries: {sorted(self._open_intents)}"
            )
        # entry_count includes the SEAL line itself.
        self._write(
            AuditEntryType.SEAL,
            {"manifest_sha256": manifest_sha256, "entry_count": self._next_seq + 1},
        )
        self._sealed = True
        self.close()
        return self._prev

    def close(self) -> None:
        """Close the file without sealing (the log stays UNSEALED)."""
        if not self._closed:
            self._fh.close()
            self._closed = True

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        # Never seals implicitly; an exception leaves the log UNSEALED.
        self.close()

    # -- internals ----------------------------------------------------------

    def _write(self, entry_type: AuditEntryType, data: Mapping[str, Any]) -> LogEntry:
        if self._sealed:
            raise AuditLogError("log is sealed; no further entries may be written")
        if self._closed:
            raise AuditLogError("log is closed")
        line = serialize_line(
            seq=self._next_seq,
            ts=format_rfc3339(self._clock.now()),
            entry_type=entry_type,
            data=data,
            prev=self._prev,
        )
        self._fh.write(line)
        self._fh.flush()
        os.fsync(self._fh.fileno())
        entry = LogEntry(
            seq=self._next_seq, entry_type=entry_type, line_sha256=hashlib.sha256(line).hexdigest()
        )
        self._prev = entry.line_sha256
        self._next_seq += 1
        return entry


def _plain(data: Mapping[str, Any] | None) -> dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ModelValidationError("data must be a mapping")
    reserved = {"action", "intent_seq", "succeeded", "exit_status", "message"} & set(data)
    if reserved:
        raise ModelValidationError(f"data uses reserved keys: {sorted(reserved)}")
    return dict(data)


def _require_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or not _SHA256_HEX.match(value):
        raise ModelValidationError(f"{name} must be 64 lowercase hex characters")


def _fsync_directory(directory: Path) -> None:
    """Persist the new directory entry on POSIX. Not available on Windows."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
