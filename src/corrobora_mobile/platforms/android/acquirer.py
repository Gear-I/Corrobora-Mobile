"""tar-over-exec-out acquisition of one folder under /data (M1.11).

Method: ``android.emulator.adb_root_userdebug`` (status UNVERIFIED), through
the adb-root provider. Class planned: ``PRIVILEGED_SELECTED_DIRECTORY``.

THIS CHANGES DEVICE STATE: the provider restarts adbd as root and back, and
the acquirer creates and deletes ``/data/local/tmp/<acquisition_id>`` for the
copy tool's error output and exit status (sidecar files, decision
2026-11-09), which also changes that parent folder's timestamps. Both are
declared in the method's compatibility record.

Order of operations, each recorded in the audit log:

1. Detection and the mount table, read as the ordinary shell user.
2. Scope check, before anything changes on the device. Refused when:
   the root is not ``/data/<folder>`` made of safe characters; another
   mount point lies inside it (whole-``/data`` acquisition, which needs
   exclusion rules for ``/data/user/0``, is not supported yet); or it
   contains, or lies inside, ``/data/local/tmp``, where the sidecar
   folder is created.
3. Provider: gate, research acknowledgement, unlock check, ``adb root``.
4. Plan written to the package (check C1) before any data is read.
5. Sidecar folder created (``mkdir``; fails if it already exists).
6. Pre-enumeration (two passes), the archive stream, post-enumeration.
7. Sidecar folder removed and its absence confirmed, then teardown.
8. The archive is read back from the package, tar's stderr is
   classified, and reconciliation (C1-C9) and classification are written.

tar stderr classification: only lines observed on 2026-11-09 are known.
"tar: unknown file type '140000'" is a socket skipped by tar; these lines
are expected only if their count equals the number of sockets in the
pre-enumeration. "tar: had errors" is the summary line. Every other line is
unclassified and fails C3, so the result is at best PARTIAL.

Not supported here: several roots, exclusions, nested mounts, sparse
holes (stored as zeros: --sparse had no effect when tested, A-07), device
major/minor numbers, extended attributes other than the SELinux label, and
ACLs. Content of entries is not hashed per entry (hashes/entries.sha256 is
deferred); the archive as a whole is hashed and chunk-hashed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from corrobora_mobile.acquisition.archive import ArchiveListing, read_archive
from corrobora_mobile.acquisition.reconcile import CopyReport, ReconciliationResult, reconcile
from corrobora_mobile.core.classification import (
    ClassificationEvidence,
    ClassDetermination,
    CriterionResult,
    assess_mount_coverage,
    determine_class,
)
from corrobora_mobile.core.clock import Clock, SystemClock
from corrobora_mobile.core.enums import AcquisitionClass, EntryType, Tristate
from corrobora_mobile.core.errors import AcquisitionError, ModelValidationError, PreconditionError
from corrobora_mobile.core.models import AcquisitionPlan, MountEntry
from corrobora_mobile.core.paths import is_within
from corrobora_mobile.platforms.android import commands
from corrobora_mobile.platforms.android.adb import Adb, CommandRecord
from corrobora_mobile.platforms.android.enumeration import (
    Enumeration,
    merge,
    parse_find,
    parse_stat,
)
from corrobora_mobile.platforms.android.providers.adb_root import METHOD_ID, RootSession

ACQUIRER_ID = "android.tar_exec_out"
PLANNED_CLASS = AcquisitionClass.PRIVILEGED_SELECTED_DIRECTORY
ENUMERATION_TIMEOUT_S = 3600
ARCHIVE = "data/archive.tar"
SOCKET_LINE = re.compile(r"^tar: unknown file type '140000'$")
SUMMARY_LINE = re.compile(r"^tar: had errors$")
EXIT_FILE = re.compile(rb"^(\d{1,3})\n$")

METADATA_FIDELITY = {
    "path (raw bytes)": "enumeration (pass 1) and archive member names",
    "entry type": "enumeration (pass 1) and archive",
    "size and regular-file content": "enumeration size; content in the archive",
    "symlink target": "enumeration (pass 1) and archive",
    "hard-link relationships": "archive (hard-link members) and enumeration inode",
    "mode": "enumeration (permission bits, octal) and archive",
    "numeric uid and gid": "enumeration and archive (--numeric-owner)",
    "mtime": "enumeration (nanoseconds where available); archive whole seconds only",
    "atime and ctime": "enumeration only (taken before reading, pass 2)",
    "birth time": "not captured",
    "SELinux label": "enumeration (pass 1) and archive (--selinux, pax RHT.security.selinux)",
    "other extended attributes": "not captured (toybox tar has no xattr support)",
    "POSIX ACLs": "not captured",
    "sparse layout": "not captured: holes are stored as zeros (--sparse had no effect, A-07)",
    "device major/minor": "not captured by the enumeration",
    "inode and link count": "enumeration (inode pass 1, link count pass 2)",
    "encryption state": "not captured",
}

LIMITATIONS = (
    "This acquisition does not demonstrate capability against any configuration other than "
    "the one recorded here.",
    "Emulator only: not a physical, ordinary, unmodified or locked device. Privileged access "
    "exists only because userdebug builds allow adb root.",
    "Class PRIVILEGED_SELECTED_DIRECTORY at most: one folder under /data, not FFS.",
    "No deleted-data or unallocated-space recovery.",
    "A live acquisition is not a point-in-time snapshot; files can change while being read.",
    "Completeness status is provisional until the verifier evaluates C10 (audit log sealed).",
)


def parse_mounts(data: bytes) -> list[MountEntry]:
    """Parse /proc/mounts, unescaping the kernel's octal escapes in mount points."""
    entries = []
    for line in data.splitlines():
        parts = line.split(b" ")
        if len(parts) < 4:
            continue
        point = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8)]), parts[1])
        try:
            entries.append(MountEntry(source=parts[0].decode("utf-8", "replace"),
                                      mount_point=point,
                                      fs_type=parts[2].decode("utf-8", "replace"),
                                      options=tuple(parts[3].decode("utf-8", "replace").split(","))))
        except ModelValidationError:
            continue  # recorded raw in plan/mounts.txt; not a canonical path
    return entries


def check_scope(root: bytes, mounts: list[MountEntry]) -> None:
    """Raise ``PreconditionError`` if the scope cannot be acquired by this version."""
    try:
        commands.validate_scope_root(root)
    except ModelValidationError as exc:
        raise PreconditionError(str(exc)) from exc
    nested = sorted({m.mount_point for m in mounts
                     if m.mount_point != root and is_within(m.mount_point, root)})
    if nested:
        raise PreconditionError(
            f"other mount points lie inside {root!r}: {nested[:5]!r}; this version cannot "
            "exclude them (whole-/data acquisition is not supported yet)")
    parent = commands.SIDECAR_PARENT.encode()
    if is_within(root, parent) or is_within(parent, root):
        raise PreconditionError(f"{root!r} overlaps {commands.SIDECAR_PARENT}, where the "
                                "sidecar folder is created")


def classify_tar_stderr(stderr: bytes, sockets_enumerated: int | None,
                        exit_status: int | None) -> tuple[list[str], list[str], str | None]:
    """(error lines, unclassified lines, explanation for a non-zero exit status)."""
    lines = [ln for ln in stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
    socket_lines = [ln for ln in lines if SOCKET_LINE.match(ln)]
    summary = [ln for ln in lines if SUMMARY_LINE.match(ln)]
    other = [ln for ln in lines if ln not in socket_lines and ln not in summary]
    unclassified = list(other)
    if socket_lines and sockets_enumerated != len(socket_lines):
        unclassified += [f"{ln} (expected {sockets_enumerated} such lines, found "
                         f"{len(socket_lines)})" for ln in socket_lines]
    errors = summary if unclassified else []
    explanation = None
    if exit_status not in (None, 0) and not unclassified and socket_lines:
        explanation = (f"tar reported {len(socket_lines)} socket(s) as 'unknown file type' "
                       "(sockets cannot be archived; recorded as UNSUPPORTED_TYPE) and nothing else")
    return errors, unclassified, explanation


def _json(data: Any) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _cmd_record(record: CommandRecord) -> dict[str, Any]:
    return {"argv": list(record.argv), "command_exit_status": record.exit_status,
            "stdout_bytes": len(record.stdout), "stdout_sha256": record.stdout_sha256,
            "stderr": record.stderr.decode("utf-8", "replace")}


@dataclass(frozen=True, slots=True)
class AcquisitionRun:
    plan: AcquisitionPlan
    reconciliation: ReconciliationResult
    classification: ClassDetermination
    listing: ArchiveListing
    archive_sha256: str | None
    sidecar_removed: bool


class TarAcquirer:
    def __init__(self, adb: Adb, package: Any, serial: str, acquisition_id: str, *,
                 clock: Clock | None = None) -> None:
        self._adb = adb
        self._pkg = package
        self._audit = package.audit
        self._serial = serial
        self._id = acquisition_id
        self._clock = clock or SystemClock()

    # -- step 1-2: before any device change ----------------------------------------------

    def capture_mounts(self) -> list[MountEntry]:
        record = self._adb.exec_out(self._serial, commands.read_mounts())
        self._audit.note("mount table captured", _cmd_record(record))
        self._pkg.write_artifact("plan/mounts.txt", record.stdout, description="mount table")
        return parse_mounts(record.stdout)

    # -- step 4 onwards: inside a root session -------------------------------------------

    def run(self, root: bytes, session: RootSession, mounts: list[MountEntry]) -> AcquisitionRun:
        if session.after_root.uid != 0:
            raise AcquisitionError("acquisition requires a root session (uid 0)")
        try:  # already checked before rooting; checked again so run() is safe on its own
            check_scope(root, mounts)
        except PreconditionError as exc:
            raise AcquisitionError(f"scope check failed inside the root session: {exc}") from exc
        self._pkg.write_artifact("plan/session-id.txt",
                                 session.after_root.id_record["stdout"].encode("utf-8"),
                                 description="id output in the root session")
        tool = self._adb.shell_command(self._serial, commands.toybox_version())
        self._pkg.write_artifact("plan/toybox-version.txt", tool.stdout, description="toybox version")
        self._audit.note("on-device tool version", _cmd_record(tool))

        plan = AcquisitionPlan(acquisition_id=self._id, method_id=METHOD_ID,
                               planned_class=PLANNED_CLASS, included_paths=(root,),
                               created_at=self._clock.now())
        self._pkg.write_artifact("plan/plan.json", _json({
            **plan.to_dict(), "acquirer_id": ACQUIRER_ID,
            "commands": {"tar": commands.tar_stream(root, self._id).text,
                         "find": commands.find_pass(root, self._id, "pre-find").text,
                         "stat": commands.stat_pass(root, self._id, "pre-stat").text}}),
            description="acquisition plan")
        self._audit.note("plan recorded before the first data read", {"plan": "plan/plan.json"})

        self._stat_parent("before")
        seq = self._audit.intent("create sidecar folder", {"path": commands.sidecar_dir(self._id)})
        made = self._adb.shell_command(self._serial, commands.make_sidecar_dir(self._id))
        self._audit.result(seq, succeeded=made.exit_status == 0, exit_status=made.exit_status,
                           data=_cmd_record(made))
        if made.exit_status != 0:
            raise AcquisitionError(f"could not create {commands.sidecar_dir(self._id)}: "
                                   f"{made.stdout.decode('utf-8', 'replace').strip()}")
        removed = False
        try:
            pre = self._enumerate(root, "pre")
            tar_exit, tar_err, adb_ok, archive_sha256 = self._archive(root)
            post = self._enumerate(root, "post")
        finally:
            removed = self._remove_sidecars()
            self._stat_parent("after")

        listing = read_archive(self._pkg.root / ARCHIVE, base=root.rsplit(b"/", 1)[0])
        sockets = (sum(1 for e in pre.entries if e.entry_type is EntryType.SOCKET)
                   if pre is not None else None)
        errors, unclassified, explanation = classify_tar_stderr(tar_err, sockets, tar_exit)
        report = CopyReport(
            plan_recorded_before_first_read=True, exit_status=tar_exit,
            stream_ended_cleanly=adb_ok, archive_parsed_to_end=listing.parsed_to_end,
            stream_hashes_match=True,  # close() verified the file from disk, or raised stderr_error_lines=tuple(errors),
            stderr_unclassified_lines=tuple(unclassified),
            truncated_members=listing.truncated_members, exit_status_explanation=explanation,
            archive_problems=tuple(
                [f"member name is not a device path: {n!r}" for n in listing.invalid_member_names]
                + [f"member appears more than once: {p!r}" for p in listing.duplicate_members]))
        result = reconcile(plan, report, pre=pre.entries if pre else None,
                           post=post.entries if post else None, members=listing.members,
                           entry_errors={p: "archive member truncated"
                                         for p in listing.truncated_members})
        self._pkg.write_artifact("reconciliation.json", _json(result.to_dict()),
                                 description="reconciliation (provisional until C10)")
        classification = determine_class(PLANNED_CLASS, self._class_evidence(plan, mounts))
        self._audit.note("acquisition reconciled", {
            "completeness_status": result.status.value, "provisional": result.provisional,
            "class": classification.to_dict()})
        return AcquisitionRun(plan=plan, reconciliation=result, classification=classification,
                              listing=listing, archive_sha256=archive_sha256,
                              sidecar_removed=removed)

    # -- helpers --------------------------------------------------------------------------

    def _stat_parent(self, when: str) -> None:
        rec = self._adb.shell_command(self._serial, commands.stat_sidecar_parent())
        self._pkg.write_artifact(f"plan/sidecar-parent-{when}.txt", rec.stdout,
                                 description=f"{commands.SIDECAR_PARENT} times {when}")
        self._audit.note(f"sidecar parent folder times {when}", _cmd_record(rec))

    def _sidecar(self, name: str) -> tuple[bytes, int | None]:
        err = self._adb.exec_out(self._serial, commands.read_sidecar(self._id, name, "err"))
        ext = self._adb.exec_out(self._serial, commands.read_sidecar(self._id, name, "exit"))
        self._pkg.write_artifact(f"errors/{name}.stderr", err.stdout,
                                 description=f"{name} stderr (sidecar)")
        self._pkg.write_artifact(f"errors/{name}.exit", ext.stdout,
                                 description=f"{name} exit status (sidecar)")
        match = EXIT_FILE.match(ext.stdout)
        status = int(match.group(1)) if match else None
        self._audit.note(f"sidecar {name}", {"reported_exit_status": status, "stderr_bytes": len(err.stdout),
                                              "exit_file": ext.stdout.decode("utf-8", "replace")})
        return err.stdout, status

    def _enumerate(self, root: bytes, label: str) -> Enumeration | None:
        found = self._adb.exec_out(self._serial, commands.find_pass(root, self._id, f"{label}-find"),
                                   timeout=ENUMERATION_TIMEOUT_S)
        self._pkg.write_artifact(f"enumeration/{label}-find.bin", found.stdout,
                                 description=f"{label} enumeration pass 1 (raw)")
        self._audit.note(f"{label}-enumeration pass 1", _cmd_record(found))
        find_err, find_exit = self._sidecar(f"{label}-find")
        stats = self._adb.exec_out(self._serial, commands.stat_pass(root, self._id, f"{label}-stat"),
                                   timeout=ENUMERATION_TIMEOUT_S)
        self._pkg.write_artifact(f"enumeration/{label}-stat.txt", stats.stdout,
                                 description=f"{label} enumeration pass 2 (raw)")
        self._audit.note(f"{label}-enumeration pass 2", _cmd_record(stats))
        stat_err, stat_exit = self._sidecar(f"{label}-stat")

        if find_exit != 0 or find_err.strip():
            self._audit.note(f"{label}-enumeration not used", {
                "reason": "pass 1 reported errors or no exit status",
                "pass_1_exit_status": find_exit})
            return None
        try:
            find_records = parse_find(found.stdout)
        except ModelValidationError as exc:
            self._audit.note(f"{label}-enumeration not used", {"reason": str(exc)})
            return None
        if not find_records or find_records[0].path != root or \
                find_records[0].entry_type is not EntryType.DIRECTORY:
            raise AcquisitionError(f"scope root {root!r} was not found as a folder on the device")
        stat_records, reason = None, None
        if stat_exit != 0 or stat_err.strip():
            reason = f"pass 2 reported errors (exit status {stat_exit})"
        else:
            try:
                stat_records = parse_stat(stats.stdout)
            except (ModelValidationError, UnicodeDecodeError) as exc:
                reason = f"pass 2 could not be parsed: {exc}"
        enumeration = merge(find_records, stat_records, stat_unavailable_reason=reason)
        self._pkg.write_artifact(f"enumeration/{label}.jsonl", enumeration.to_jsonl(label=label),
                                 description=f"{label} enumeration (merged)")
        self._audit.note(f"{label}-enumeration merged", enumeration.header(label=label))
        return enumeration

    def _archive(self, root: bytes) -> tuple[int | None, bytes, bool, str]:
        """Stream the archive into the package.

        The stream is closed and re-hashed from disk (C5); a mismatch raises
        ``IntegrityError``. If adb fails, the partial file is kept and
        recorded as incomplete, and the error propagates.
        """
        command = commands.tar_stream(root, self._id)
        with self._pkg.open_stream(ARCHIVE, description="tar archive of the scope root") as writer:
            argv, code, adb_err = self._adb.exec_out_stream(self._serial, command, writer.write)
            self._audit.note("archive stream ended", {
                "argv": list(argv), "adb_exit_status": code, "bytes": writer.size,
                "adb_stderr": adb_err.decode("utf-8", "replace")})
        record = next(r for r in self._pkg.records if r.path == ARCHIVE)
        tar_err, tar_exit = self._sidecar("tar")
        return tar_exit, tar_err, code == 0, record.sha256

    def _remove_sidecars(self) -> bool:
        seq = self._audit.intent("remove sidecar folder", {"path": commands.sidecar_dir(self._id)})
        try:
            rec = self._adb.shell_command(self._serial, commands.remove_sidecar_dir(self._id))
        except Exception as exc:
            self._audit.result(seq, succeeded=False, data={"error": str(exc)})
            return False
        self._audit.result(seq, succeeded=rec.exit_status == 0, exit_status=rec.exit_status,
                           data=_cmd_record(rec))
        return rec.exit_status == 0

    def _class_evidence(self, plan: AcquisitionPlan, mounts: list[MountEntry]) -> ClassificationEvidence:
        not_assessed = CriterionResult(
            result=Tristate.UNKNOWN,
            detail="not assessed: an acquisition of one selected folder cannot reach a higher class")
        return ClassificationEvidence(
            privileged_session=CriterionResult(result=Tristate.YES,
                                               evidence_refs=("plan/session-id.txt",)),
            full_mount_table_scope=assess_mount_coverage(
                plan, mounts, mount_table_ref="plan/mounts.txt", plan_ref="plan/plan.json"),
            f1_persistent_mounts_in_scope=not_assessed, f2_app_private_in_scope=not_assessed,
            f3_content_for_readable_files=not_assessed,
            f4_required_attributes_captured=CriterionResult(
                result=Tristate.NO, evidence_refs=("plan/plan.json",),
                detail="xattrs other than SELinux, ACLs, sparse layout, birth time and device "
                       "numbers are not captured"))


# -- command line ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Acquire one folder under /data from a userdebug emulator.

    Exit status: 0 acquisition ran and the package is sealed (see its
    completeness status); 3 refused before any device change; 4 failed after
    a device change was attempted (package sealed with the failure); 2 could
    not start.
    """
    import argparse
    import sys
    from pathlib import Path

    from corrobora_mobile.compatibility import load_registry
    from corrobora_mobile.core.errors import (
        CorroboraError,
        ResearchModeRequiredError,
        UnsupportedDeviceError,
    )
    from corrobora_mobile.evidence import EvidencePackage
    from corrobora_mobile.platforms.android.detection import detect, save_to_package
    from corrobora_mobile.platforms.android.providers.adb_root import AdbRootProvider, root_access
    from corrobora_mobile.research import ResearchAuthorization

    parser = argparse.ArgumentParser(
        prog="corrobora-mobile acquire",
        description="Acquire one folder under /data from a userdebug Android emulator. CHANGES "
                    "DEVICE STATE: restarts adbd as root and back, and creates and deletes "
                    f"{commands.SIDECAR_PARENT}/<acquisition id>. Use only on devices you own or "
                    "are authorized to use.")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial")
    parser.add_argument("--path", required=True, help="folder to acquire, e.g. /data/system/users")
    parser.add_argument("--output", type=Path, required=True, help="folder for the evidence package")
    parser.add_argument("--research", action="store_true", help="request research mode (per run)")
    parser.add_argument("--authorization-reference", help="ID of your ownership/consent record")
    parser.add_argument("--acknowledge-modifications", action="store_true",
                        help="acknowledge the method's declared device modifications (listed below)")
    parser.add_argument("--confirm-unlocked", action="store_true",
                        help="confirm the device is booted and unlocked")
    args = parser.parse_args(argv)
    root = args.path.encode("utf-8")

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

    clock = SystemClock()
    acq_id = "acq-" + clock.now().strftime("%Y%m%dT%H%M%SZ")
    pkg = EvidencePackage.create(args.output, acq_id, chunk_size=64 * 1024 * 1024, clock=clock)
    content: dict[str, Any] = {
        "purpose": "acquisition of one folder under /data (M1.11)",
        "method_id": METHOD_ID, "acquirer_id": ACQUIRER_ID,
        "method_validation_status": record.validation_status.value,
        "requested_scope": args.path, "completeness_status": None,
        "research": research.manifest_fields() if research else None,
        "identity": detection.identity.to_dict(),
        "declared_device_modifications": list(record.device_modifications),
        "metadata_fidelity": METADATA_FIDELITY, "limitations": list(LIMITATIONS),
    }
    try:
        save_to_package(pkg, detection)
        acquirer = TarAcquirer(adb, pkg, detection.serial, acq_id, clock=clock)
        provider = AdbRootProvider(adb, pkg.audit)
        code = 0
        try:
            mounts = acquirer.capture_mounts()
            check_scope(root, mounts)
            with root_access(provider, detection.serial, assessment, research=research,
                             operator_confirmed_unlocked=args.confirm_unlocked) as session:
                run = acquirer.run(root, session, mounts)
            result = run.reconciliation
            report = session.teardown_report
            content.update(
                outcome="ACQUIRED", completeness_status=result.status.value,
                completeness_provisional=result.provisional,
                completeness_checks=[c.to_dict() for c in result.checks],
                reconciliation_summary=result.to_dict()["summary"],
                acquisition_class=run.classification.to_dict(),
                archive={"path": ARCHIVE, "sha256": run.archive_sha256,
                         "members": len(run.listing.members),
                         "selinux_labelled_members": run.listing.selinux_labelled,
                         "parsed_to_end": run.listing.parsed_to_end},
                sidecar_folder_removed=run.sidecar_removed,
                observed_device_modifications=list(report.residual_changes) if report else [])
            print(f"\nCompleteness: {result.status.value} (provisional until the verifier checks "
                  f"the sealed audit log)\nClass: {run.classification.final.value}")
            for c in result.checks:
                if c.state.value == "FAIL":
                    print(f"  {c.check_id} FAIL: {'; '.join(c.details)[:300]}")
            if not run.sidecar_removed:
                print(f"WARNING: {commands.sidecar_dir(acq_id)} may still exist on the device")
        except (UnsupportedDeviceError, ResearchModeRequiredError, PreconditionError) as exc:
            content.update(outcome="REFUSED", reason=str(exc))
            print(f"\nREFUSED (nothing changed on the device): {exc}")
            code = 3
        except CorroboraError as exc:
            content.update(outcome="FAILED", reason=str(exc))
            print(f"\nFAILED after a device change was attempted: {exc}")
            code = 4
        fin = pkg.finalize(content)
    except BaseException:
        pkg.close()  # kept UNSEALED; the verifier classifies it as INTERRUPTED
        raise
    print(f"\nSaved: {fin.root}\nChain head (record this): {fin.chain_head}")
    if research:
        print("Labeled RESEARCH. This does not validate the method.")
    return code


if __name__ == "__main__":
    import sys
    sys.exit(main())
