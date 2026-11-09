"""The ``adb root`` access provider for userdebug builds (docs/ARCHITECTURE.md 4, M1).

Method: ``android.emulator.adb_root_userdebug`` (status UNVERIFIED).

This provider CHANGES DEVICE STATE: it restarts adbd as root, and at
teardown restarts it as non-root. The declared modifications are in the
method's compatibility record and must be acknowledged before it runs.

Order of operations, each step recorded in the audit log:

1. Gate (Section 3.1): no match, UNSUPPORTED, or UNVERIFIED without research
   mode -> refused before anything touches the device.
2. Research-mode acknowledgement must cover exactly the declared
   modifications.
3. Unlock precondition: ``sys.user.0.ce_available`` must read ``true`` AND
   the operator must confirm the device is unlocked. The property's meaning
   was observed only on an unlocked emulator, so the check is recorded as
   operator-attested. UNVERIFIED: whether the property reliably separates
   locked from unlocked devices.
4. Pre-state: ``id`` and ``service.adb.root``.
5. INTENT "adb root" -> ``adb root`` -> ``wait-for-device`` -> ``id``.
   Success is decided ONLY by ``id`` reporting uid 0. The exit status and
   message of ``adb root`` are recorded but never trusted: on a production
   build it exited 0 while refusing (observed 2026-11-09).
6. Teardown: INTENT "adb unroot" -> ``adb unroot`` -> ``wait-for-device`` ->
   ``id`` and ``service.adb.root``. Success requires a non-zero uid. Any
   difference from the pre-state is reported as a residual change (observed:
   ``service.adb.root`` went from unset to ``0``).

If adbd was already root before step 5, the provider neither roots nor
unroots, so teardown leaves the device as it found it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from corrobora_mobile.compatibility import Assessment, gate
from corrobora_mobile.core.enums import Tristate, ValidationStatus
from corrobora_mobile.core.errors import (
    AccessError,
    PreconditionError,
    ResearchModeRequiredError,
    UnsupportedDeviceError,
)
from corrobora_mobile.platforms.android.adb import Adb, CommandRecord
from corrobora_mobile.research import ResearchAuthorization

METHOD_ID = "android.emulator.adb_root_userdebug"
UID = re.compile(r"^uid=(\d+)\(")
UNLOCK_PROPERTY = "sys.user.0.ce_available"


def _text(record: CommandRecord) -> str:
    return record.stdout.decode("utf-8", errors="replace").strip()


def _record(record: CommandRecord) -> dict[str, Any]:
    return {
        "argv": list(record.argv),
        "exit_status": record.exit_status,
        "stdout": record.stdout.decode("utf-8", errors="replace"),
        "stderr": record.stderr.decode("utf-8", errors="replace"),
        "stdout_sha256": record.stdout_sha256,
    }


@dataclass(frozen=True, slots=True)
class AdbdState:
    uid: int | None
    adb_root_property: str | None
    id_record: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"uid": self.uid, "service.adb.root": self.adb_root_property, "id": self.id_record}


@dataclass(slots=True)
class RootSession:
    serial: str
    before: AdbdState
    after_root: AdbdState
    rooted_by_us: bool
    released: bool = False
    teardown_report: TeardownReport | None = None


@dataclass(frozen=True, slots=True)
class TeardownReport:
    restored: bool
    after: AdbdState | None
    residual_changes: tuple[str, ...] = field(default=())


class AdbRootProvider:
    def __init__(self, adb: Adb, audit: Any) -> None:
        self._adb = adb
        self._audit = audit

    # -- state -----------------------------------------------------------------------

    def _state(self, serial: str) -> AdbdState:
        id_rec = self._adb.shell_id(serial)
        match = UID.match(_text(id_rec)) if id_rec.exit_status == 0 else None
        prop = self._adb.getprop(serial, "service.adb.root")
        value = _text(prop) if prop.exit_status == 0 else None
        return AdbdState(uid=int(match.group(1)) if match else None,
                         adb_root_property=value or None, id_record=_record(id_rec))

    # -- establish -------------------------------------------------------------------

    def establish(self, serial: str, assessment: Assessment, *,
                  research: ResearchAuthorization | None,
                  operator_confirmed_unlocked: bool) -> RootSession:
        if assessment.method_id != METHOD_ID:
            raise UnsupportedDeviceError(f"assessment is for {assessment.method_id}, not {METHOD_ID}")
        decision = gate(assessment, research_mode=research is not None)
        if not decision.allowed:
            self._audit.note("provider refused by compatibility gate",
                             {"method_id": METHOD_ID, "reason": decision.reason})
            if assessment.matches is Tristate.YES and \
                    assessment.validation_status is ValidationStatus.UNVERIFIED:
                raise ResearchModeRequiredError(decision.reason)
            raise UnsupportedDeviceError(decision.reason)
        if research is not None:
            research.check_covers(assessment.device_modifications)
        self._audit.note("compatibility gate allowed provider",
                         {"method_id": METHOD_ID, "reason": decision.reason,
                          "research": research.manifest_fields() if research else None})

        unlock = self._adb.getprop(serial, UNLOCK_PROPERTY)
        value = _text(unlock) if unlock.exit_status == 0 else None
        self._audit.note("unlock precondition", {
            UNLOCK_PROPERTY: value, "getprop": _record(unlock),
            "operator_attested_unlocked": operator_confirmed_unlocked,
            "basis": "property reading plus operator attestation; the property's meaning on "
                     "locked devices is UNVERIFIED",
        })
        if value != "true":
            raise PreconditionError(f"{UNLOCK_PROPERTY} is {value!r}, not 'true': device not unlocked")
        if not operator_confirmed_unlocked:
            raise PreconditionError("the operator must confirm the device is unlocked")

        before = self._state(serial)
        self._audit.note("adbd state before provider", before.to_dict())
        if before.uid == 0:
            self._audit.note("adbd already runs as root; provider will neither root nor unroot")
            return RootSession(serial=serial, before=before, after_root=before, rooted_by_us=False)

        seq = self._audit.intent("adb root", {
            "serial": serial, "method_id": METHOD_ID,
            "declared_modifications": list(assessment.device_modifications)})
        try:
            root = self._adb.root(serial)
            wait = self._adb.wait_for_device(serial)
            after = self._state(serial)
        except Exception as exc:
            self._audit.result(seq, succeeded=False, data={"error": str(exc)})
            self._recover(serial, f"adb root step failed: {exc}")
            raise
        succeeded = after.uid == 0
        self._audit.result(seq, succeeded=succeeded, exit_status=root.exit_status, data={
            "adb_root": _record(root), "wait_for_device": _record(wait), "after": after.to_dict(),
            "success_criterion": "uid 0 reported by id (exit status of adb root is not trusted)"})
        if not succeeded:
            if after.uid is None:  # state unknown: adbd may be root
                self._recover(serial, "uid unknown after adb root")
            raise AccessError(f"adb root did not give root (uid {after.uid}); "
                              f"adb said: {_text(root) or '(nothing)'}")
        return RootSession(serial=serial, before=before, after_root=after, rooted_by_us=True)

    def _recover(self, serial: str, reason: str) -> None:
        """Best-effort ``adb unroot`` when establish failed after ``adb root`` ran.

        Errors are recorded, not raised, so the original failure is reported.
        """
        seq = self._audit.intent("adb unroot (recovery)", {"serial": serial, "reason": reason})
        try:
            unroot = self._adb.unroot(serial)
            self._adb.wait_for_device(serial)
            after = self._state(serial)
        except Exception as exc:  # noqa: BLE001 - recorded, original error re-raised by caller
            self._audit.result(seq, succeeded=False, data={"error": str(exc)})
            return
        self._audit.result(seq, succeeded=after.uid is not None and after.uid != 0,
                           exit_status=unroot.exit_status,
                           data={"adb_unroot": _record(unroot), "after": after.to_dict()})

    # -- teardown --------------------------------------------------------------------

    def teardown(self, session: RootSession) -> TeardownReport:
        if session.released:
            raise AccessError("session already released")
        session.released = True
        if not session.rooted_by_us:
            self._audit.note("teardown skipped: provider did not change adbd")
            session.teardown_report = TeardownReport(restored=True, after=session.before)
            return session.teardown_report

        seq = self._audit.intent("adb unroot", {"serial": session.serial, "method_id": METHOD_ID})
        try:
            unroot = self._adb.unroot(session.serial)
            wait = self._adb.wait_for_device(session.serial)
            after = self._state(session.serial)
        except Exception as exc:
            self._audit.result(seq, succeeded=False, data={"error": str(exc)})
            raise
        restored = after.uid is not None and after.uid != 0
        residual = []
        if after.adb_root_property != session.before.adb_root_property:
            def shown(v: str | None) -> str:
                return "unset" if v is None else repr(v)
            residual.append(f"service.adb.root: {shown(session.before.adb_root_property)} before, "
                            f"{shown(after.adb_root_property)} after teardown")
        if after.uid != session.before.uid:
            residual.append(f"adbd uid: {session.before.uid} before, {after.uid} after teardown")
        self._audit.result(seq, succeeded=restored, exit_status=unroot.exit_status, data={
            "adb_unroot": _record(unroot), "wait_for_device": _record(wait),
            "after": after.to_dict(), "residual_changes": residual})
        if not restored:
            raise AccessError(f"adb unroot did not restore a non-root adbd (uid {after.uid})")
        session.teardown_report = TeardownReport(restored=True, after=after,
                                                 residual_changes=tuple(residual))
        return session.teardown_report


@contextmanager
def root_access(provider: AdbRootProvider, serial: str, assessment: Assessment, *,
                research: ResearchAuthorization | None,
                operator_confirmed_unlocked: bool) -> Iterator[RootSession]:
    """Establish root, yield the session, and always attempt teardown."""
    session = provider.establish(serial, assessment, research=research,
                                 operator_confirmed_unlocked=operator_confirmed_unlocked)
    try:
        yield session
    finally:
        provider.teardown(session)


# -- command line: provider check only (no data is acquired) ------------------------------


def main(argv: list[str] | None = None) -> int:
    """Run detection, the gate, and establish + teardown, recording everything.

    No data is acquired. A refusal is recorded too, so the M1 refusal test
    leaves evidence. Exit status: 0 root established and released, 3 refused
    (nothing changed on the device), 4 failed after a device change was
    attempted, 2 could not start.
    """
    import argparse
    import sys
    from pathlib import Path

    from corrobora_mobile.compatibility import load_registry
    from corrobora_mobile.core.clock import SystemClock
    from corrobora_mobile.core.errors import CorroboraError
    from corrobora_mobile.evidence import EvidencePackage
    from corrobora_mobile.platforms.android.detection import detect, save_to_package

    parser = argparse.ArgumentParser(
        description="adb-root provider check (CHANGES DEVICE STATE: restarts adbd as root, then "
                    "non-root). Acquires no data. Use only on devices you own or are authorized to use.")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial")
    parser.add_argument("--output", type=Path, required=True, help="folder for the evidence package")
    parser.add_argument("--research", action="store_true", help="request research mode (per run)")
    parser.add_argument("--authorization-reference", help="ID of your ownership/consent record")
    parser.add_argument("--acknowledge-modifications", action="store_true",
                        help="acknowledge the method's declared device modifications (listed below)")
    parser.add_argument("--confirm-unlocked", action="store_true",
                        help="confirm the device is booted and unlocked")
    args = parser.parse_args(argv)

    registry = load_registry()
    record = registry[METHOD_ID]
    print(f"Method {METHOD_ID} ({record.validation_status.value}) declares these device modifications:")
    for m in record.device_modifications:
        print(f"  - {m}")

    research = None
    if args.research:
        if not args.authorization_reference or not args.acknowledge_modifications:
            print("error: --research needs --authorization-reference and --acknowledge-modifications",
                  file=sys.stderr)
            return 2
        try:
            research = ResearchAuthorization(args.authorization_reference, record.device_modifications)
        except CorroboraError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    adb = Adb(args.adb)
    try:
        detection = detect(adb, args.serial)
    except CorroboraError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    (assessment,) = [a for a in registry.assess(detection.identity) if a.method_id == METHOD_ID]

    acq_id = "provider-" + SystemClock().now().strftime("%Y%m%dT%H%M%SZ")
    pkg = EvidencePackage.create(args.output, acq_id, chunk_size=64 * 1024 * 1024)
    save_to_package(pkg, detection)
    provider = AdbRootProvider(adb, pkg.audit)
    content: dict[str, Any] = {
        "purpose": "provider check: establish and release root; no data acquired",
        "method_id": METHOD_ID, "method_validation_status": record.validation_status.value,
        "completeness_status": None,
        "research": research.manifest_fields() if research else None,
    }
    code = 0
    try:
        with root_access(provider, detection.serial, assessment, research=research,
                         operator_confirmed_unlocked=args.confirm_unlocked) as session:
            pkg.audit.note("root established; provider check acquires no data",
                           {"after_root": session.after_root.to_dict()})
        report = session.teardown_report
        content.update(outcome="ROOT_ESTABLISHED_AND_RELEASED",
                       residual_changes=list(report.residual_changes) if report else [])
        print("\nRoot established (uid 0 confirmed by id) and released (non-root uid confirmed).")
        for r in content["residual_changes"]:
            print(f"  residual change: {r}")
    except (UnsupportedDeviceError, ResearchModeRequiredError, PreconditionError) as exc:
        content.update(outcome="REFUSED", reason=str(exc))
        print(f"\nREFUSED (nothing changed on the device): {exc}")
        code = 3
    except CorroboraError as exc:
        content.update(outcome="FAILED", reason=str(exc))
        print(f"\nFAILED after a device change was attempted: {exc}")
        code = 4
    fin = pkg.finalize(content)
    print(f"\nSaved: {fin.root}\nChain head (record this): {fin.chain_head}")
    if research:
        print("Labeled RESEARCH. This does not validate the method.")
    return code


if __name__ == "__main__":
    import sys
    sys.exit(main())
