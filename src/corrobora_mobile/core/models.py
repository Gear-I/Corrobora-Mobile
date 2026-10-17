"""Core data models (docs/ARCHITECTURE.md, Sections 3.2, 4.2, 5.2, 5.3).

Design rules applied to every model:

* Models are immutable (frozen dataclasses) and validate themselves on
  construction. Invalid evidence records are rejected, not repaired.
* A value that was not observed is recorded as unknown (``None`` or an
  ``UNKNOWN`` enum member). It is never guessed.
* Filesystem paths are raw ``bytes``. They may not be valid UTF-8 and are
  never normalized: non-canonical paths are rejected (``core.paths``).
  ``encode_path`` gives a lossless JSON form.
* Timestamps of Corrobora Mobile's own actions are aware ``datetime``
  values, serialized in one canonical UTC form (``core.clock``).
  Timestamps observed on the device are raw integer nanoseconds and may be
  negative (before 1970); they are evidence and are never rejected for
  being implausible.
* ``to_dict`` produces plain JSON-compatible data in a stable field order.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from corrobora_mobile.core.enums import (
    AcquisitionClass,
    BootState,
    ContentReliability,
    EntryOutcome,
    EntryType,
    LockState,
    Platform,
    RiskClass,
    Tristate,
)
from corrobora_mobile.core.clock import format_rfc3339, require_aware
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.paths import is_within, validate_device_path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def encode_path(raw: bytes) -> dict[str, str]:
    """Return a lossless JSON form of a raw path.

    ``b64`` is authoritative. ``display`` is for humans only: invalid UTF-8
    bytes are shown as backslash escapes and must not be parsed back.
    """
    if not isinstance(raw, bytes):
        raise ModelValidationError("path must be bytes")
    return {
        "b64": base64.b64encode(raw).decode("ascii"),
        "display": raw.decode("utf-8", errors="backslashreplace"),
    }


def decode_path(encoded: dict[str, str]) -> bytes:
    """Inverse of ``encode_path``. Only the ``b64`` field is used.

    The decoded path is validated, so a corrupted or hand-edited record
    cannot introduce a non-canonical path.
    """
    try:
        raw = base64.b64decode(encoded["b64"], validate=True)
    except (KeyError, TypeError, binascii.Error) as exc:
        raise ModelValidationError(f"invalid encoded path: {exc}") from exc
    return validate_device_path(raw)


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{name} must be a non-empty string")


def _require_optional_text(value: str | None, name: str) -> None:
    if value is not None:
        _require_text(value, name)


def _require_optional_int(value: int | None, name: str, *, nonneg: bool) -> None:
    if value is None:
        return
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{name} must be an integer or None")
    if nonneg and value < 0:
        raise ModelValidationError(f"{name} must be non-negative")


def _require_enum(value: object, enum_type: type, name: str) -> None:
    if not isinstance(value, enum_type):
        raise ModelValidationError(f"{name} must be a {enum_type.__name__}")


# --------------------------------------------------------------------------
# Device identity (Section 3.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class DeviceIdentity:
    """Read-only identification of a device. Unobserved fields stay unknown."""

    platform: Platform
    manufacturer: str | None = None
    model: str | None = None
    hardware_identifier: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_build: str | None = None
    build_type: str | None = None
    security_patch_level: str | None = None
    lock_state: LockState = LockState.UNKNOWN
    boot_state: BootState = BootState.UNKNOWN
    is_emulator: Tristate = Tristate.UNKNOWN
    raw_responses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_enum(self.platform, Platform, "platform")
        for name in (
            "manufacturer",
            "model",
            "hardware_identifier",
            "os_name",
            "os_version",
            "os_build",
            "build_type",
            "security_patch_level",
        ):
            _require_optional_text(getattr(self, name), name)
        _require_enum(self.lock_state, LockState, "lock_state")
        _require_enum(self.boot_state, BootState, "boot_state")
        _require_enum(self.is_emulator, Tristate, "is_emulator")
        if not isinstance(self.raw_responses, tuple):
            raise ModelValidationError("raw_responses must be a tuple")
        for ref in self.raw_responses:
            _require_text(ref, "raw_responses entry")

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "hardware_identifier": self.hardware_identifier,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "build_type": self.build_type,
            "security_patch_level": self.security_patch_level,
            "lock_state": self.lock_state.value,
            "boot_state": self.boot_state.value,
            "is_emulator": self.is_emulator.value,
            "raw_responses": list(self.raw_responses),
        }


# --------------------------------------------------------------------------
# Device modifications (Sections 4.2, 7.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class DeviceModification:
    """A change a method may make to the source device, declared in advance."""

    declared_by: str
    description: str
    risk_class: RiskClass
    reversible: Tristate = Tristate.UNKNOWN

    def __post_init__(self) -> None:
        _require_text(self.declared_by, "declared_by")
        _require_text(self.description, "description")
        _require_enum(self.risk_class, RiskClass, "risk_class")
        _require_enum(self.reversible, Tristate, "reversible")

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared_by": self.declared_by,
            "description": self.description,
            "risk_class": self.risk_class.value,
            "reversible": self.reversible.value,
        }


# --------------------------------------------------------------------------
# Mounts and plan (Sections 0.2, 3.1, 4.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class MountEntry:
    """One line of the device mount table, as parsed from the raw capture.

    ``mount_point`` must already be unescaped by the parser (the kernel
    escapes spaces and some other bytes in /proc/mounts as octal, e.g.
    ``\\040``). The raw capture is kept separately as evidence.
    """

    source: str
    mount_point: bytes
    fs_type: str
    options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.source, "source")
        validate_device_path(self.mount_point, "mount_point")
        _require_text(self.fs_type, "fs_type")
        if not isinstance(self.options, tuple):
            raise ModelValidationError("options must be a tuple")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "mount_point": encode_path(self.mount_point),
            "fs_type": self.fs_type,
            "options": list(self.options),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class ScopeExclusion:
    """A path excluded from scope by a documented rule."""

    path: bytes
    rule_id: str
    reason: str

    def __post_init__(self) -> None:
        validate_device_path(self.path, "path")
        _require_text(self.rule_id, "rule_id")
        _require_text(self.reason, "reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": encode_path(self.path),
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class AcquisitionPlan:
    """Declared scope and planned class, fixed before any data is read (C1).

    Scope rules enforced on construction:

    * included paths are canonical, unique, and do not overlap (no included
      path lies within another), so every in-scope entry belongs to exactly
      one included path;
    * every exclusion lies strictly within an included path (an exclusion
      outside the scope is meaningless; one equal to an included path would
      exclude that whole path and must instead be removed from scope);
    * exclusion paths are unique.
    """

    acquisition_id: str
    method_id: str
    planned_class: AcquisitionClass
    included_paths: tuple[bytes, ...]
    exclusions: tuple[ScopeExclusion, ...] = ()
    created_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.acquisition_id, "acquisition_id")
        _require_text(self.method_id, "method_id")
        _require_enum(self.planned_class, AcquisitionClass, "planned_class")
        if not isinstance(self.included_paths, tuple) or not self.included_paths:
            raise ModelValidationError("included_paths must be a non-empty tuple")
        for p in self.included_paths:
            validate_device_path(p, "included path")
        if len(set(self.included_paths)) != len(self.included_paths):
            raise ModelValidationError("included_paths must not contain duplicates")
        for a in self.included_paths:
            for b in self.included_paths:
                if a != b and is_within(a, b):
                    raise ModelValidationError(
                        f"included paths overlap: {a!r} lies within {b!r}"
                    )
        if not isinstance(self.exclusions, tuple):
            raise ModelValidationError("exclusions must be a tuple")
        seen: set[bytes] = set()
        for ex in self.exclusions:
            if not isinstance(ex, ScopeExclusion):
                raise ModelValidationError("exclusions must contain ScopeExclusion")
            if ex.path in seen:
                raise ModelValidationError(f"duplicate exclusion: {ex.path!r}")
            seen.add(ex.path)
            if ex.path in self.included_paths:
                raise ModelValidationError(
                    f"exclusion equals an included path: {ex.path!r}"
                )
            if not any(is_within(ex.path, inc) for inc in self.included_paths):
                raise ModelValidationError(
                    f"exclusion is outside the declared scope: {ex.path!r}"
                )
        require_aware(self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "acquisition_id": self.acquisition_id,
            "method_id": self.method_id,
            "planned_class": self.planned_class.value,
            "included_paths": [encode_path(p) for p in self.included_paths],
            "exclusions": [ex.to_dict() for ex in self.exclusions],
            "created_at": format_rfc3339(self.created_at),
        }


# --------------------------------------------------------------------------
# Enumeration and reconciliation (Sections 5.2, 5.2.1, 5.3.1)
# --------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class EnumeratedEntry:
    """One entry from the independent enumeration. Unobserved values are None.

    ``mtime_ns``, ``atime_ns`` and ``ctime_ns`` are integer nanoseconds since
    the Unix epoch exactly as observed. They may be negative and are not
    checked for plausibility: an implausible timestamp is itself evidence.
    Their precision depends on the enumeration tool and is recorded at the
    enumeration level, not here (ARCHITECTURE.md A-06).
    """

    path: bytes
    entry_type: EntryType
    size: int | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    mtime_ns: int | None = None
    atime_ns: int | None = None
    ctime_ns: int | None = None
    inode: int | None = None
    link_count: int | None = None
    selinux_label: str | None = None

    def __post_init__(self) -> None:
        validate_device_path(self.path, "path")
        _require_enum(self.entry_type, EntryType, "entry_type")
        for name in ("size", "mode", "uid", "gid", "inode", "link_count"):
            _require_optional_int(getattr(self, name), name, nonneg=True)
        for name in ("mtime_ns", "atime_ns", "ctime_ns"):
            _require_optional_int(getattr(self, name), name, nonneg=False)
        _require_optional_text(self.selinux_label, "selinux_label")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": encode_path(self.path),
            "entry_type": self.entry_type.value,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime_ns": self.mtime_ns,
            "atime_ns": self.atime_ns,
            "ctime_ns": self.ctime_ns,
            "inode": self.inode,
            "link_count": self.link_count,
            "selinux_label": self.selinux_label,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class EntryReconciliation:
    """The single reconciliation outcome for one in-scope entry (check C6).

    Rules enforced on construction:

    * ``ACQUIRED`` requires a ``content_reliability`` value.
    * Every other outcome must not carry one.
    * ``EXCLUDED_BY_RULE`` requires ``rule_id``.
    * ``ERROR`` and ``UNSUPPORTED_TYPE`` require ``detail``.
    """

    path: bytes
    outcome: EntryOutcome
    content_reliability: ContentReliability | None = None
    rule_id: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        validate_device_path(self.path, "path")
        _require_enum(self.outcome, EntryOutcome, "outcome")
        _require_optional_text(self.rule_id, "rule_id")
        _require_optional_text(self.detail, "detail")

        if self.outcome is EntryOutcome.ACQUIRED:
            if self.content_reliability is None:
                raise ModelValidationError("ACQUIRED entries require content_reliability")
            _require_enum(self.content_reliability, ContentReliability, "content_reliability")
        elif self.content_reliability is not None:
            raise ModelValidationError("only ACQUIRED entries may carry content_reliability")

        if self.outcome is EntryOutcome.EXCLUDED_BY_RULE and self.rule_id is None:
            raise ModelValidationError("EXCLUDED_BY_RULE entries require rule_id")
        if self.outcome is not EntryOutcome.EXCLUDED_BY_RULE and self.rule_id is not None:
            raise ModelValidationError("only EXCLUDED_BY_RULE entries may carry rule_id")
        if (
            self.outcome in (EntryOutcome.ERROR, EntryOutcome.UNSUPPORTED_TYPE)
            and self.detail is None
        ):
            raise ModelValidationError(f"{self.outcome.value} entries require detail")

    @property
    def change_observed(self) -> Tristate | None:
        """Whether a change was observed during acquisition.

        ``YES`` for ``CHANGED_DURING_ACQUISITION``, ``NO`` for
        ``NO_CHANGE_DETECTED``, ``UNKNOWN`` for ``UNKNOWN``, and ``None`` for
        entries that were not acquired.

        ``NO`` means only that the enumeration did not observe a change. It
        never certifies that the content is reliable, complete, or
        consistent with other files (ARCHITECTURE.md Section 5.2.1).
        """
        if self.content_reliability is None:
            return None
        return {
            ContentReliability.CHANGED_DURING_ACQUISITION: Tristate.YES,
            ContentReliability.NO_CHANGE_DETECTED: Tristate.NO,
            ContentReliability.UNKNOWN: Tristate.UNKNOWN,
        }[self.content_reliability]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": encode_path(self.path),
            "outcome": self.outcome.value,
            "content_reliability": (
                self.content_reliability.value if self.content_reliability else None
            ),
            "rule_id": self.rule_id,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Tool identity (Section 5.4)
# --------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolInfo:
    """An external tool used during acquisition, recorded in the manifest."""

    name: str
    version: str | None = None
    path: str | None = None
    sha256: str | None = None
    notes: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_optional_text(self.version, "version")
        _require_optional_text(self.path, "path")
        if self.sha256 is not None:
            if (
                not isinstance(self.sha256, str)
                or len(self.sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.sha256)
            ):
                raise ModelValidationError("sha256 must be 64 lowercase hex characters")
        if not isinstance(self.notes, tuple):
            raise ModelValidationError("notes must be a tuple")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "sha256": self.sha256,
            "notes": list(self.notes),
        }
