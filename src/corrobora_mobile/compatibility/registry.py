"""Method compatibility registry, assessment and gate (docs/ARCHITECTURE.md 3.1, 3.3).

Records are reviewable JSON data under ``compatibility/methods/``, one file
per method, named ``<method_id>.json``. Loading is strict: unknown or
missing keys, wrong types, and inconsistent statuses are rejected.

Rules this module enforces:

* A record may claim EXPERIMENTAL or VERIFIED only if it references at
  least one validation record (CLAUDE.md Section 6).
* Nothing here ever changes a status. A successful connection, pairing or
  backup never changes a compatibility status (Section 3.1).
* Matching (decided 2026-11-01) uses the platform, whether the device is
  an emulator, and the build type. Manufacturer and model are shown but
  not matched. An OS version that no record lists still matches, flagged
  as untested.
* Gate (Section 3.1, kept 2026-11-01): UNSUPPORTED never runs; UNVERIFIED
  runs only in research mode; EXPERIMENTAL and VERIFIED run with the
  operator's acknowledgement of the declared device modifications.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from corrobora_mobile.core.enums import AcquisitionClass, Platform, Tristate, ValidationStatus
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import DeviceIdentity

METHOD_ID = re.compile(r"^[a-z0-9]+(\.[a-z0-9_]+)+$", re.ASCII)

RECORD_KEYS = frozenset({
    "method_id", "platform", "applies_to", "physical_device", "security_configuration",
    "required_device_state", "required_privileges", "max_acquisition_class",
    "acquisition_scope", "device_modifications", "known_limitations", "notes",
    "validation_status", "validation_records",
})
APPLIES_TO_KEYS = frozenset({"manufacturer", "model", "os_versions", "build_type"})


def default_methods_dir() -> Path:
    """``compatibility/methods`` in a source checkout of the repository."""
    return Path(__file__).resolve().parents[3] / "compatibility" / "methods"


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{name} must be a non-empty string")
    return value


def _texts(value: Any, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ModelValidationError(f"{name} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise ModelValidationError(f"{name} must not be empty")
    if len(set(value)) != len(value):
        raise ModelValidationError(f"{name} must not contain duplicates")
    return tuple(value)


def _enum(value: Any, enum_type: type, name: str) -> Any:
    try:
        return enum_type(value)
    except ValueError:
        raise ModelValidationError(f"{name} has an unknown value: {value!r}") from None


@dataclass(frozen=True, kw_only=True, slots=True)
class MethodRecord:
    method_id: str
    platform: Platform
    manufacturer: str
    model: str
    os_versions: tuple[str, ...]
    build_types: tuple[str, ...]
    physical_device: bool
    security_configuration: str
    required_device_state: str
    required_privileges: str
    max_acquisition_class: AcquisitionClass
    acquisition_scope: str
    device_modifications: tuple[str, ...]
    known_limitations: tuple[str, ...]
    notes: tuple[str, ...]
    validation_status: ValidationStatus
    validation_records: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MethodRecord:
        if not isinstance(data, Mapping):
            raise ModelValidationError("record must be a JSON object")
        keys = set(data)
        if keys != RECORD_KEYS:
            missing, extra = sorted(RECORD_KEYS - keys), sorted(keys - RECORD_KEYS)
            raise ModelValidationError(f"record keys wrong: missing {missing}, unknown {extra}")
        applies = data["applies_to"]
        if not isinstance(applies, Mapping) or set(applies) != APPLIES_TO_KEYS:
            raise ModelValidationError(f"applies_to must have exactly {sorted(APPLIES_TO_KEYS)}")
        method_id = _text(data["method_id"], "method_id")
        if not METHOD_ID.match(method_id):
            raise ModelValidationError(f"invalid method_id: {method_id!r}")
        if not isinstance(data["physical_device"], bool):
            raise ModelValidationError("physical_device must be true or false")
        record = cls(
            method_id=method_id,
            platform=_enum(data["platform"], Platform, "platform"),
            manufacturer=_text(applies["manufacturer"], "applies_to.manufacturer"),
            model=_text(applies["model"], "applies_to.model"),
            os_versions=_texts(applies["os_versions"], "applies_to.os_versions"),
            build_types=_texts(applies["build_type"], "applies_to.build_type", allow_empty=False),
            physical_device=data["physical_device"],
            security_configuration=_text(data["security_configuration"], "security_configuration"),
            required_device_state=_text(data["required_device_state"], "required_device_state"),
            required_privileges=_text(data["required_privileges"], "required_privileges"),
            max_acquisition_class=_enum(data["max_acquisition_class"], AcquisitionClass,
                                        "max_acquisition_class"),
            acquisition_scope=_text(data["acquisition_scope"], "acquisition_scope"),
            device_modifications=_texts(data["device_modifications"], "device_modifications",
                                        allow_empty=False),
            known_limitations=_texts(data["known_limitations"], "known_limitations",
                                     allow_empty=False),
            notes=_texts(data["notes"], "notes"),
            validation_status=_enum(data["validation_status"], ValidationStatus, "validation_status"),
            validation_records=_texts(data["validation_records"], "validation_records"),
        )
        if record.validation_status in (ValidationStatus.VERIFIED, ValidationStatus.EXPERIMENTAL) \
                and not record.validation_records:
            raise ModelValidationError(
                f"{method_id}: {record.validation_status.value} requires at least one validation record")
        return record


class Registry(Mapping[str, MethodRecord]):
    """Read-only mapping of method_id to record."""

    def __init__(self, records: Mapping[str, MethodRecord]) -> None:
        self._records = dict(records)

    def __getitem__(self, key: str) -> MethodRecord:
        return self._records[key]

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._records))

    def __len__(self) -> int:
        return len(self._records)

    def assess(self, identity: DeviceIdentity) -> tuple[Assessment, ...]:
        """Assess every record for the identity's platform, in method_id order."""
        if not isinstance(identity, DeviceIdentity):
            raise ModelValidationError("identity must be a DeviceIdentity")
        return tuple(assess(self[m], identity) for m in self if self[m].platform is identity.platform)


def load_registry(directory: Path | None = None) -> Registry:
    """Load every ``*.json`` file in ``directory`` (default: ``default_methods_dir()``)."""
    directory = default_methods_dir() if directory is None else Path(directory)
    if not directory.is_dir():
        raise ModelValidationError(f"compatibility directory not found: {directory}")
    records: dict[str, MethodRecord] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ModelValidationError(f"{path.name}: invalid JSON: {exc}") from exc
        try:
            record = MethodRecord.from_dict(data)
        except ModelValidationError as exc:
            raise ModelValidationError(f"{path.name}: {exc}") from exc
        if path.stem != record.method_id:
            raise ModelValidationError(f"{path.name}: file name must be {record.method_id}.json")
        records[record.method_id] = record
    return Registry(records)


# -- assessment and gate ----------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class Assessment:
    method_id: str
    validation_status: ValidationStatus
    max_acquisition_class: AcquisitionClass
    matches: Tristate
    mismatches: tuple[str, ...]
    unknowns: tuple[str, ...]
    warnings: tuple[str, ...]
    device_modifications: tuple[str, ...]


def assess(record: MethodRecord, identity: DeviceIdentity) -> Assessment:
    """Compare one identity with one record. Read-only; changes no status."""
    mismatches: list[str] = []
    unknowns: list[str] = []
    warnings: list[str] = []

    if identity.platform is not record.platform:
        mismatches.append(f"platform is {identity.platform.value}, record is {record.platform.value}")

    wanted = Tristate.NO if record.physical_device else Tristate.YES
    if identity.is_emulator is Tristate.UNKNOWN:
        unknowns.append("whether the device is an emulator is unknown")
    elif identity.is_emulator is not wanted:
        kind = "an emulator" if identity.is_emulator is Tristate.YES else "a physical device"
        mismatches.append(f"device is {kind}; record requires "
                          f"{'a physical device' if record.physical_device else 'an emulator'}")

    if identity.build_type is None:
        unknowns.append("build type is unknown")
    elif identity.build_type not in record.build_types:
        mismatches.append(f"build type {identity.build_type!r} not in {list(record.build_types)}")

    if identity.os_version is None:
        warnings.append("OS version is unknown; not covered by any validation record")
    elif identity.os_version not in record.os_versions:
        warnings.append(f"OS version {identity.os_version!r} has not been tested for this method")

    if mismatches:
        matches = Tristate.NO
    elif unknowns:
        matches = Tristate.UNKNOWN
    else:
        matches = Tristate.YES
    return Assessment(
        method_id=record.method_id,
        validation_status=record.validation_status,
        max_acquisition_class=record.max_acquisition_class,
        matches=matches,
        mismatches=tuple(mismatches),
        unknowns=tuple(unknowns),
        warnings=tuple(warnings),
        device_modifications=record.device_modifications,
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class GateDecision:
    allowed: bool
    reason: str
    requires_acknowledgement: bool
    research_mode: bool


def gate(assessment: Assessment, *, research_mode: bool) -> GateDecision:
    """Decide whether a method may run (Section 3.1).

    ``research_mode`` here means only that the operator requested it. The
    other research-mode inputs (authorization reference, risk
    acknowledgement, RESEARCH labeling, Section 7.3) are enforced by the
    caller and are not implemented yet.
    """
    if not isinstance(research_mode, bool):
        raise ModelValidationError("research_mode must be a bool")

    def deny(reason: str) -> GateDecision:
        return GateDecision(allowed=False, reason=reason, requires_acknowledgement=False,
                            research_mode=research_mode)

    if assessment.matches is Tristate.NO:
        return deny("device does not match the method: " + "; ".join(assessment.mismatches))
    if assessment.matches is Tristate.UNKNOWN:
        return deny("match cannot be confirmed: " + "; ".join(assessment.unknowns))
    status = assessment.validation_status
    if status is ValidationStatus.UNSUPPORTED:
        return deny("method is UNSUPPORTED")
    if status is ValidationStatus.UNVERIFIED and not research_mode:
        return deny("method is UNVERIFIED and may run only in research mode")
    reason = f"method is {status.value}"
    if research_mode:
        reason += "; research mode: results are labeled RESEARCH and claim at most EXPERIMENTAL"
    return GateDecision(allowed=True, reason=reason, requires_acknowledgement=True,
                        research_mode=research_mode)
