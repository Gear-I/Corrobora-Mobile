"""Read-only Android device detection over adb (docs/ARCHITECTURE.md 3.1, 3.2).

Detection reads a fixed list of system properties, one ``getprop`` call
each, and builds a ``DeviceIdentity``. Every adb command is kept as a
``CommandRecord`` so its raw output can be stored in the evidence package.

Rules (decided 2026-11-01, from observations on Android 17 emulators):

* A device is identified by its properties, never by its adb serial;
  serials are recorded only as connection details.
* ``is_emulator`` is YES when ``ro.kernel.qemu`` or ``ro.boot.qemu`` is
  ``1``. Otherwise it is UNKNOWN, never NO: the absence of these values on
  physical devices has not been established.
* Lock and boot state are not detected yet and stay UNKNOWN.
* The device serial number property is not read: on a physical device it
  is a personal identifier, and detection does not need it.

Device-side effect: detection requires adb to be authorized on the
device (USB debugging enabled), which is itself a device state change
(Section 3.2). ``getprop`` only reads properties. ``adb`` also starts a
server process on the host if one is not running.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from corrobora_mobile.core.enums import Platform, Tristate
from corrobora_mobile.core.errors import AccessError, CorroboraError, PreconditionError
from corrobora_mobile.core.models import DeviceIdentity
from corrobora_mobile.platforms.android.adb import Adb, CommandRecord, parse_devices, validate_serial

PROPERTIES = (
    "ro.build.type",
    "ro.build.tags",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.hardware",
    "ro.kernel.qemu",
    "ro.boot.qemu",
)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    serial: str
    identity: DeviceIdentity
    properties: dict[str, str | None]
    records: tuple[tuple[str, CommandRecord], ...]  # (artifact name, record)
    notes: tuple[str, ...]


def select_serial(adb: Adb, serial: str | None) -> tuple[str, CommandRecord]:
    """Choose the device to detect; never guesses between several devices."""
    record = adb.devices()
    if record.exit_status != 0:
        raise AccessError(f"`adb devices` failed with status {record.exit_status}")
    devices = parse_devices(record.stdout)
    ready = [s for s, state in devices if state == "device"]
    if serial is not None:
        validate_serial(serial)
        states = dict(devices)
        if serial not in states:
            raise PreconditionError(f"device {serial} is not connected")
        if states[serial] != "device":
            raise PreconditionError(f"device {serial} is in state {states[serial]!r}, not 'device'")
        return serial, record
    if len(ready) == 1:
        return ready[0], record
    if not ready:
        listed = ", ".join(f"{s} ({st})" for s, st in devices) or "none"
        raise PreconditionError(f"no device ready for adb (connected: {listed})")
    raise PreconditionError(f"several devices connected ({', '.join(ready)}); choose one with --serial")


def _value(record: CommandRecord) -> str | None:
    if record.exit_status != 0:
        return None
    try:
        text = record.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.rstrip("\r\n")
    return text if text.strip() else None


def detect(adb: Adb, serial: str | None = None) -> DetectionResult:
    """Run read-only detection on one device and build its identity."""
    version = adb.version()
    serial, devices = select_serial(adb, serial)
    records: list[tuple[str, CommandRecord]] = [("00-adb-version", version), ("01-adb-devices", devices)]
    properties: dict[str, str | None] = {}
    notes: list[str] = []
    for i, name in enumerate(PROPERTIES, start=2):
        record = adb.getprop(serial, name)
        records.append((f"{i:02d}-getprop-{name}", record))
        properties[name] = _value(record)
        if record.exit_status != 0:
            notes.append(f"getprop {name} failed with status {record.exit_status}")

    qemu = (properties.get("ro.kernel.qemu"), properties.get("ro.boot.qemu"))
    is_emulator = Tristate.YES if "1" in qemu else Tristate.UNKNOWN
    if is_emulator is Tristate.UNKNOWN:
        notes.append("no emulator property found; device type is UNKNOWN (not assumed physical)")
    notes.append("lock state and boot state are not detected in this version")

    identity = DeviceIdentity(
        platform=Platform.ANDROID,
        manufacturer=properties["ro.product.manufacturer"],
        model=properties["ro.product.model"],
        os_name="Android",
        os_version=properties["ro.build.version.release"],
        os_build=properties["ro.build.fingerprint"] or properties["ro.build.id"],
        build_type=properties["ro.build.type"],
        security_patch_level=properties["ro.build.version.security_patch"],
        is_emulator=is_emulator,
        raw_responses=tuple(f"identity/{name}.stdout" for name, _ in records),
    )
    return DetectionResult(serial=serial, identity=identity, properties=properties,
                           records=tuple(records), notes=tuple(notes))


def save_to_package(package: Any, result: DetectionResult) -> None:
    """Store the raw outputs and the identity in an open EvidencePackage.

    Each command's stdout and stderr are written byte for byte; a
    ``commands.json`` lists every argv, exit status and hash.
    """
    commands = []
    for name, record in result.records:
        package.write_artifact(f"identity/{name}.stdout", record.stdout, description=f"{name} stdout")
        package.write_artifact(f"identity/{name}.stderr", record.stderr, description=f"{name} stderr")
        commands.append({
            "name": name,
            "argv": list(record.argv),
            "exit_status": record.exit_status,
            "stdout_sha256": record.stdout_sha256,
            "stderr_sha256": record.stderr_sha256,
        })
    package.write_artifact("identity/commands.json",
                           (json.dumps(commands, indent=2) + "\n").encode("utf-8"),
                           description="detection commands")
    summary = {"serial": result.serial, "identity": result.identity.to_dict(),
               "properties": result.properties, "notes": list(result.notes)}
    package.write_artifact("identity/identity.json",
                           (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                           description="detected identity")


# -- command line ------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    from corrobora_mobile.compatibility import gate, load_registry
    from corrobora_mobile.core.clock import SystemClock
    from corrobora_mobile.evidence import EvidencePackage

    parser = argparse.ArgumentParser(
        description="Read-only Android detection: identity, compatibility assessment and gate. "
                    "Never runs adb root and never writes to the device.")
    parser.add_argument("--adb", default="adb", help="path to adb")
    parser.add_argument("--serial", help="adb serial (required when several devices are connected)")
    parser.add_argument("--save", type=Path,
                        help="also write the raw outputs to a new evidence package in this folder")
    args = parser.parse_args(argv)

    try:
        result = detect(Adb(args.adb), args.serial)
    except CorroboraError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Device (adb serial {result.serial}; serials are not identifiers):")
    for key, value in result.identity.to_dict().items():
        if key != "raw_responses":
            print(f"  {key}: {value}")
    for note in result.notes:
        print(f"  note: {note}")

    registry = load_registry()
    assessments = registry.assess(result.identity)
    if not assessments:
        print("\nNo compatibility record for this platform: UNSUPPORTED.")
    for a in assessments:
        print(f"\nMethod {a.method_id}: status {a.validation_status.value}, match {a.matches.value}")
        for line in (*a.mismatches, *a.unknowns, *a.warnings):
            print(f"  - {line}")
        for research in (False, True):
            d = gate(a, research_mode=research)
            mode = "research mode requested" if research else "normal mode"
            print(f"  gate ({mode}): {'ALLOWED' if d.allowed else 'REFUSED'} -- {d.reason}")

    if args.save is not None:
        clock = SystemClock()
        acq_id = "detect-" + clock.now().strftime("%Y%m%dT%H%M%SZ")
        pkg = EvidencePackage.create(args.save, acq_id, chunk_size=64 * 1024 * 1024)
        save_to_package(pkg, result)
        fin = pkg.finalize({"purpose": "detection only (no acquisition)",
                            "method_validation_status": None, "completeness_status": None})
        print(f"\nSaved: {fin.root}\nChain head (record this): {fin.chain_head}")
    print("\nDetection is read-only. It does not validate any method.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
