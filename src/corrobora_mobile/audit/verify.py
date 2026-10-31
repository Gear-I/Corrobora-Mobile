"""Audit-log verification (docs/ARCHITECTURE.md, Section 5.6).

``verify_audit_log`` reads a log read-only and classifies it:

* SEALED   -- every line verifies and the last line is SEAL;
* UNSEALED -- every complete line verifies but there is no SEAL (the
  acquisition was interrupted). A torn final line is reported, never
  repaired;
* BROKEN   -- any hash mismatch, sequence gap, malformed or out-of-place
  line, or a mismatch with an externally supplied value.

What verification cannot detect without an external anchor
---------------------------------------------------------

The hash chain links each line to the one before it, so nothing protects
the *last* line from being edited, and nothing reveals lines removed from
the *end*. Removing a SEAL line makes a sealed log look UNSEALED. Passing
the chain head recorded by the operator (``expected_chain_head``) detects
both. Without it, the result says so in ``anchor_checked``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from corrobora_mobile.audit.log import GENESIS_PREV
from corrobora_mobile.core.clock import parse_rfc3339
from corrobora_mobile.core.enums import AuditEntryType, AuditLogState
from corrobora_mobile.core.errors import IntegrityError, ModelValidationError

_KEYS = frozenset({"seq", "ts", "type", "data", "prev"})
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class OpenIntent:
    seq: int
    action: str


@dataclass(frozen=True, slots=True)
class AuditVerification:
    """The outcome of verifying one audit log.

    ``chain_head`` is the SHA-256 of the last complete line, or None if no
    line verified. ``errors`` explain a BROKEN result; ``warnings`` are
    observations that do not break the chain (e.g. the clock going
    backwards). ``anchor_checked`` is False when no external chain head was
    supplied, in which case tail edits and truncation are undetectable.
    """

    state: AuditLogState
    entry_count: int
    chain_head: str | None
    sealed_manifest_sha256: str | None
    manifest_checked: bool
    anchor_checked: bool
    open_intents: tuple[OpenIntent, ...]
    last_completed_seq: int | None
    torn_tail_bytes: int
    errors: tuple[str, ...] = field(default=())
    warnings: tuple[str, ...] = field(default=())

    def raise_if_broken(self) -> None:
        """Raise ``IntegrityError`` for a BROKEN log (Section 5.6)."""
        if self.state is AuditLogState.BROKEN:
            raise IntegrityError("audit log BROKEN: " + "; ".join(self.errors))


def verify_audit_log(
    path: Path,
    *,
    expected_chain_head: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> AuditVerification:
    """Verify an audit log without modifying it.

    Args:
        expected_chain_head: the chain head recorded outside the package.
            If given and different from the log's, the log is BROKEN.
        expected_manifest_sha256: SHA-256 of the manifest file. If given,
            it must match the value in the SEAL entry.
    """
    for name, value in (
        ("expected_chain_head", expected_chain_head),
        ("expected_manifest_sha256", expected_manifest_sha256),
    ):
        if value is not None and (not isinstance(value, str) or not _SHA256_HEX.match(value)):
            raise ModelValidationError(f"{name} must be 64 lowercase hex characters")

    with open(path, "rb") as handle:  # read-only
        raw = handle.read()

    lines = raw.split(b"\n")
    torn = lines.pop()  # bytes after the final "\n"; empty if the file ends cleanly

    errors: list[str] = []
    warnings: list[str] = []
    prev = GENESIS_PREV
    chain_head: str | None = None
    open_intents: dict[int, str] = {}
    last_completed: int | None = None
    sealed_manifest: str | None = None
    seal_seen = False
    last_ts = None
    count = 0

    for index, body in enumerate(lines):
        line = body + b"\n"
        where = f"line {index}"
        if seal_seen:
            errors.append(f"{where}: entry after SEAL")
            break
        entry, problem = _parse(body)
        if problem:
            errors.append(f"{where}: {problem}")
            break
        if entry["seq"] != index:
            errors.append(f"{where}: seq {entry['seq']} (expected {index})")
            break
        if entry["prev"] != prev:
            errors.append(f"{where}: prev does not match the SHA-256 of line {index - 1}")
            break
        entry_type = entry["type"]
        if (index == 0) != (entry_type is AuditEntryType.SESSION_START):
            errors.append(f"{where}: SESSION_START must be the first line and only the first")
            break

        ts = entry["ts_parsed"]
        if last_ts is not None and ts < last_ts:
            warnings.append(f"{where}: timestamp earlier than the previous entry")
        last_ts = ts

        data = entry["data"]
        if entry_type is AuditEntryType.INTENT:
            action = data.get("action")
            if not isinstance(action, str) or not action:
                errors.append(f"{where}: INTENT without action")
                break
            open_intents[index] = action
        elif entry_type is AuditEntryType.RESULT:
            target = data.get("intent_seq")
            if isinstance(target, bool) or not isinstance(target, int) or target not in open_intents:
                errors.append(f"{where}: RESULT does not close an open INTENT")
                break
            del open_intents[target]
            last_completed = index
        elif entry_type is AuditEntryType.SEAL:
            manifest = data.get("manifest_sha256")
            count_claim = data.get("entry_count")
            if not isinstance(manifest, str) or not _SHA256_HEX.match(manifest):
                errors.append(f"{where}: SEAL without a valid manifest_sha256")
                break
            if count_claim != index + 1:
                errors.append(f"{where}: SEAL entry_count {count_claim!r} (expected {index + 1})")
                break
            if open_intents:
                errors.append(f"{where}: SEAL while INTENT entries are open: {sorted(open_intents)}")
                break
            sealed_manifest = manifest
            seal_seen = True

        prev = hashlib.sha256(line).hexdigest()
        chain_head = prev
        count = index + 1

    if not errors and count == 0:
        errors.append("no complete lines: SESSION_START missing")

    anchor_checked = expected_chain_head is not None
    if not errors and anchor_checked and chain_head != expected_chain_head:
        errors.append("chain head does not match the externally recorded value")

    manifest_checked = expected_manifest_sha256 is not None and seal_seen
    if not errors and manifest_checked and sealed_manifest != expected_manifest_sha256:
        errors.append("manifest SHA-256 does not match the SEAL entry")

    if errors:
        state = AuditLogState.BROKEN
    elif seal_seen and not torn:
        state = AuditLogState.SEALED
    elif seal_seen and torn:
        state = AuditLogState.BROKEN
        errors.append("bytes after SEAL")
    else:
        state = AuditLogState.UNSEALED

    if torn and state is not AuditLogState.BROKEN:
        warnings.append(f"torn final line: {len(torn)} byte(s) without a trailing newline (not repaired)")

    return AuditVerification(
        state=state,
        entry_count=count,
        chain_head=chain_head,
        sealed_manifest_sha256=sealed_manifest,
        manifest_checked=manifest_checked,
        anchor_checked=anchor_checked,
        open_intents=tuple(OpenIntent(seq=s, action=a) for s, a in sorted(open_intents.items())),
        last_completed_seq=last_completed,
        torn_tail_bytes=len(torn),
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _parse(body: bytes) -> tuple[dict[str, Any], str | None]:
    """Parse and structurally check one line (without its newline)."""
    if b"\r" in body:
        return {}, "carriage return in line (line endings may have been converted)"
    try:
        obj = json.loads(
            body.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        return {}, f"not valid JSON: {exc}"
    if not isinstance(obj, dict):
        return {}, "line is not a JSON object"
    if set(obj) != _KEYS:
        return {}, f"keys {sorted(obj)} (expected {sorted(_KEYS)})"
    seq = obj["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int):
        return {}, "seq is not an integer"
    if not isinstance(obj["prev"], str) or not _SHA256_HEX.match(obj["prev"]):
        return {}, "prev is not a SHA-256 hex digest"
    if not isinstance(obj["data"], dict):
        return {}, "data is not an object"
    try:
        obj["type"] = AuditEntryType(obj["type"])
    except ValueError:
        return {}, f"unknown type {obj['type']!r}"
    try:
        obj["ts_parsed"] = parse_rfc3339(obj["ts"])
    except ModelValidationError as exc:
        return {}, str(exc)
    return obj, None


def _reject_constant(name: str) -> None:
    # NaN and Infinity are not JSON; the writer never produces them.
    raise ValueError(f"non-standard JSON constant {name}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # A duplicate key would let two readers see different values.
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys in JSON object")
    return dict(pairs)
