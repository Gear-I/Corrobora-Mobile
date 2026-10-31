"""Reconciliation of an acquisition against its plan (docs/ARCHITECTURE.md 5.2).

``reconcile`` compares four things:

* the plan (declared scope and exclusions, check C1);
* the pre-acquisition enumeration of the device;
* the members found in the archive;
* the post-acquisition enumeration;

together with facts about the copy process (C2-C5) and, when known, the
audit-log state (C10). It gives every in-scope enumerated entry exactly one
outcome (C6), assigns ``content_reliability`` to every acquired entry
(Section 5.2.1), evaluates C1-C10, and derives the completeness status.

This module is generic. It parses nothing and talks to no device: the
platform acquirer supplies parsed archive members, enumerations, and
per-path errors. It never reports ``INTERRUPTED``; that status is assigned
by the verifier from the audit log (Section 5.6).

Decisions recorded with the project owner on 2026-10-31 for cases the
architecture document does not settle:

1. An in-scope entry absent from the archive and from the post-acquisition
   enumeration (deleted during acquisition) is ``ERROR``, so the result is
   at best ``PARTIAL``.
2. An archive member absent from the pre-acquisition enumeration but
   inside the scope is listed as an unenumerated member and counts as a
   change (at best ``COMPLETE_WITH_CHANGES``).
3. An archive member outside the declared scope, or under an exclusion,
   fails C6 (``PARTIAL``).
4. With no pre-acquisition enumeration, a failed check that can be
   evaluated gives ``PARTIAL``; otherwise ``COMPLETENESS_UNVERIFIED``.

A further rule: without a post-acquisition enumeration, changes cannot be
detected (C9 is not evaluated), so the best status is
``COMPLETENESS_UNVERIFIED``, never ``COMPLETE``.

No status certifies that content is reliable or consistent. In particular
``NO_CHANGE_DETECTED`` is limited by what the enumerations compare.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from corrobora_mobile.core.enums import (
    AuditLogState,
    CheckState,
    CompletenessStatus,
    ContentReliability,
    EntryOutcome,
    EntryType,
)
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import (
    AcquisitionPlan,
    EntryReconciliation,
    EnumeratedEntry,
    encode_path,
)
from corrobora_mobile.core.paths import is_within, validate_device_path

RECONCILIATION_FORMAT = "corrobora-mobile/reconciliation"
RECONCILIATION_FORMAT_VERSION = 1

CHECK_IDS = ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10")

#: Attributes compared between pre- and post-enumeration (Section 5.2.1).
COMPARED_ATTRIBUTES = ("size", "mtime_ns", "ctime_ns", "inode")

LIMITATIONS = (
    "NO_CHANGE_DETECTED means only that the pre- and post-acquisition "
    "enumerations agree on entry type, size, mtime, ctime and inode where "
    "available, at the enumeration's timestamp precision. A change that "
    "leaves those values unchanged, or is reverted between the two "
    "enumerations, is not detected.",
    "Cross-file consistency is not guaranteed for any entry. A live "
    "acquisition is not a point-in-time snapshot.",
    "Agreement between enumeration and archive does not prove that every "
    "byte of user data was captured; the enumeration can miss entries the "
    "operating system hides from it.",
)


def _require_bool(value: object, name: str) -> None:
    if not isinstance(value, bool):
        raise ModelValidationError(f"{name} must be a bool")


def _require_lines(value: object, name: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(v, str) for v in value):
        raise ModelValidationError(f"{name} must be a tuple of str")


@dataclass(frozen=True, kw_only=True, slots=True)
class ArchivedMember:
    """One member parsed from the acquired archive.

    ``size`` is the number of content bytes stored for the member (``None``
    when the parser did not report it). Sockets cannot be archive members.
    """

    path: bytes
    entry_type: EntryType
    size: int | None = None

    def __post_init__(self) -> None:
        validate_device_path(self.path, "path")
        if not isinstance(self.entry_type, EntryType):
            raise ModelValidationError("entry_type must be an EntryType")
        if self.entry_type is EntryType.SOCKET:
            raise ModelValidationError("a socket cannot be an archive member")
        if self.size is not None and (
            isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0
        ):
            raise ModelValidationError("size must be a non-negative integer or None")


@dataclass(frozen=True, kw_only=True, slots=True)
class CopyReport:
    """Facts about the copy process, observed by the acquirer.

    ``stderr_error_lines`` holds stderr lines the acquirer classified as
    errors; ``stderr_unclassified_lines`` holds lines it could not classify,
    which count as errors (C3). ``exit_status`` is ``None`` when it was not
    observed, which fails C2.
    """

    plan_recorded_before_first_read: bool
    exit_status: int | None
    stream_ended_cleanly: bool
    archive_parsed_to_end: bool
    stream_hashes_match: bool
    stderr_error_lines: tuple[str, ...] = ()
    stderr_unclassified_lines: tuple[str, ...] = ()
    truncated_members: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        for name in ("plan_recorded_before_first_read", "stream_ended_cleanly",
                     "archive_parsed_to_end", "stream_hashes_match"):
            _require_bool(getattr(self, name), name)
        if self.exit_status is not None and (
            isinstance(self.exit_status, bool) or not isinstance(self.exit_status, int)
        ):
            raise ModelValidationError("exit_status must be an int or None")
        _require_lines(self.stderr_error_lines, "stderr_error_lines")
        _require_lines(self.stderr_unclassified_lines, "stderr_unclassified_lines")
        if not isinstance(self.truncated_members, tuple):
            raise ModelValidationError("truncated_members must be a tuple")
        for p in self.truncated_members:
            validate_device_path(p, "truncated member")


@dataclass(frozen=True, kw_only=True, slots=True)
class CheckResult:
    check_id: str
    state: CheckState
    details: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check_id, "state": self.state.value, "details": list(self.details)}


@dataclass(frozen=True, kw_only=True, slots=True)
class UnenumeratedMember:
    """An in-scope archive member missing from the pre-acquisition enumeration."""

    path: bytes
    entry_type: EntryType
    in_post_enumeration: bool | None  # None when there is no post enumeration

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": encode_path(self.path),
            "entry_type": self.entry_type.value,
            "in_post_enumeration": self.in_post_enumeration,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class ReconciliationResult:
    status: CompletenessStatus
    checks: tuple[CheckResult, ...]
    entries: tuple[EntryReconciliation, ...]
    unenumerated_members: tuple[UnenumeratedMember, ...]
    out_of_scope_members: tuple[bytes, ...]
    enumerated_out_of_scope: tuple[bytes, ...]
    notes: tuple[str, ...] = field(default=())

    @property
    def provisional(self) -> bool:
        """True while C10 (audit log sealed) has not been evaluated.

        Reconciliation is written before the package is sealed, so its
        status is provisional until the verifier evaluates C10.
        """
        return self.check("C10").state is CheckState.NOT_EVALUATED

    def check(self, check_id: str) -> CheckResult:
        for c in self.checks:
            if c.check_id == check_id:
                return c
        raise KeyError(check_id)

    @property
    def changed_entry_count(self) -> int:
        """Entries changed during acquisition, including unenumerated members."""
        changed = sum(
            1 for e in self.entries
            if e.content_reliability is ContentReliability.CHANGED_DURING_ACQUISITION
        )
        return changed + len(self.unenumerated_members)

    def to_dict(self) -> dict[str, Any]:
        outcomes = {o.value: 0 for o in EntryOutcome}
        reliability = {r.value: 0 for r in ContentReliability}
        for e in self.entries:
            outcomes[e.outcome.value] += 1
            if e.content_reliability is not None:
                reliability[e.content_reliability.value] += 1
        return {
            "format": RECONCILIATION_FORMAT,
            "format_version": RECONCILIATION_FORMAT_VERSION,
            "status": self.status.value,
            "provisional": self.provisional,
            "summary": {
                "entries": len(self.entries),
                "outcomes": outcomes,
                "content_reliability": reliability,
                "changed_entries": self.changed_entry_count,
                "unenumerated_members": len(self.unenumerated_members),
                "out_of_scope_members": len(self.out_of_scope_members),
            },
            "checks": [c.to_dict() for c in self.checks],
            "entries": [e.to_dict() for e in self.entries],
            "unenumerated_members": [m.to_dict() for m in self.unenumerated_members],
            "out_of_scope_members": [encode_path(p) for p in self.out_of_scope_members],
            "enumerated_out_of_scope": [encode_path(p) for p in self.enumerated_out_of_scope],
            "notes": list(self.notes),
            "limitations": list(LIMITATIONS),
        }


# -- scope -----------------------------------------------------------------------


def _scope(plan: AcquisitionPlan, path: bytes) -> tuple[str, str | None]:
    """('in', None), ('excluded', rule_id) or ('out', None).

    When exclusions are nested, the most specific (longest) one applies.
    """
    if not any(is_within(path, inc) for inc in plan.included_paths):
        return "out", None
    matches = [ex for ex in plan.exclusions if is_within(path, ex.path)]
    if matches:
        return "excluded", max(matches, key=lambda ex: len(ex.path)).rule_id
    return "in", None


def _index(items: Sequence[Any] | None, name: str) -> dict[bytes, Any] | None:
    if items is None:
        return None
    out: dict[bytes, Any] = {}
    for item in items:
        if item.path in out:
            raise ModelValidationError(f"duplicate path in {name}: {item.path!r}")
        out[item.path] = item
    return out


# -- per-entry rules -----------------------------------------------------------------


def _types_compatible(member: EntryType, enumerated: EntryType) -> bool:
    # A second link to an already archived inode is stored as a hard-link member.
    return member is enumerated or (member is EntryType.HARDLINK and enumerated is EntryType.REGULAR)


def _reliability(pre: EnumeratedEntry, post: dict[bytes, EnumeratedEntry] | None) -> ContentReliability:
    if post is None:
        return ContentReliability.UNKNOWN
    after = post.get(pre.path)
    if after is None:
        return ContentReliability.CHANGED_DURING_ACQUISITION  # deleted after archiving
    if after.entry_type is not pre.entry_type:
        return ContentReliability.CHANGED_DURING_ACQUISITION
    compared = 0
    for attr in COMPARED_ATTRIBUTES:
        a, b = getattr(pre, attr), getattr(after, attr)
        if a is None or b is None:
            continue
        compared += 1
        if a != b:
            return ContentReliability.CHANGED_DURING_ACQUISITION
    return ContentReliability.NO_CHANGE_DETECTED if compared else ContentReliability.UNKNOWN


# -- reconciliation ------------------------------------------------------------------------


def reconcile(
    plan: AcquisitionPlan,
    report: CopyReport,
    *,
    pre: Sequence[EnumeratedEntry] | None,
    post: Sequence[EnumeratedEntry] | None,
    members: Sequence[ArchivedMember],
    entry_errors: Mapping[bytes, str] | None = None,
    audit_state: AuditLogState | None = None,
) -> ReconciliationResult:
    """Evaluate C1-C10 and assign one outcome to every in-scope entry.

    ``pre`` or ``post`` is ``None`` when that enumeration was not possible.
    ``entry_errors`` maps a path to the error the copy process reported for
    it. ``audit_state`` is ``None`` before the package is sealed; C10 is
    then NOT_EVALUATED and the result is provisional.
    """
    if not isinstance(plan, AcquisitionPlan):
        raise ModelValidationError("plan must be an AcquisitionPlan")
    if not isinstance(report, CopyReport):
        raise ModelValidationError("report must be a CopyReport")
    if audit_state is not None and not isinstance(audit_state, AuditLogState):
        raise ModelValidationError("audit_state must be an AuditLogState or None")
    if members is None:
        raise ModelValidationError("members must be a sequence (empty if nothing was archived)")
    pre_ix = _index(pre, "pre-enumeration")
    post_ix = _index(post, "post-enumeration")
    member_ix = _index(members, "archive members")
    errors = dict(entry_errors or {})
    for p, detail in errors.items():
        validate_device_path(p, "entry_errors path")
        if not isinstance(detail, str) or not detail.strip():
            raise ModelValidationError("entry_errors details must be non-empty strings")

    entries: list[EntryReconciliation] = []
    enumerated_out_of_scope: list[bytes] = []
    size_failures: list[str] = []
    notes: list[str] = []

    if pre_ix is not None:
        for path in sorted(pre_ix):
            entry = pre_ix[path]
            scope, rule_id = _scope(plan, path)
            if scope == "out":
                enumerated_out_of_scope.append(path)
                continue
            if scope == "excluded":
                entries.append(EntryReconciliation(
                    path=path, outcome=EntryOutcome.EXCLUDED_BY_RULE, rule_id=rule_id))
                continue
            entries.append(_reconcile_entry(entry, member_ix.get(path), post_ix, errors, size_failures))
        if enumerated_out_of_scope:
            notes.append(f"{len(enumerated_out_of_scope)} enumerated entries lie outside the "
                         "declared scope and were not reconciled")

    unenumerated: list[UnenumeratedMember] = []
    out_of_scope_members: list[bytes] = []
    for path in sorted(member_ix):
        scope, _ = _scope(plan, path)
        if scope != "in":
            out_of_scope_members.append(path)
        elif pre_ix is not None and path not in pre_ix:
            unenumerated.append(UnenumeratedMember(
                path=path,
                entry_type=member_ix[path].entry_type,
                in_post_enumeration=None if post_ix is None else path in post_ix,
            ))

    if pre_ix is None:
        notes.append("no pre-acquisition enumeration: C6-C9 not evaluated")
    elif post_ix is None:
        notes.append("no post-acquisition enumeration: changes cannot be detected (C9 not "
                     "evaluated); acquired entries have content_reliability UNKNOWN")

    checks = _evaluate_checks(report, audit_state, pre_ix, post_ix, entries,
                              unenumerated, out_of_scope_members, size_failures)
    status = _status(checks, member_ix, entries, unenumerated, pre_ix, post_ix)
    return ReconciliationResult(
        status=status,
        checks=checks,
        entries=tuple(entries),
        unenumerated_members=tuple(unenumerated),
        out_of_scope_members=tuple(out_of_scope_members),
        enumerated_out_of_scope=tuple(enumerated_out_of_scope),
        notes=tuple(notes),
    )


def _reconcile_entry(
    entry: EnumeratedEntry,
    member: ArchivedMember | None,
    post_ix: dict[bytes, EnumeratedEntry] | None,
    errors: dict[bytes, str],
    size_failures: list[str],
) -> EntryReconciliation:
    path = entry.path
    if entry.entry_type is EntryType.SOCKET:
        return EntryReconciliation(path=path, outcome=EntryOutcome.UNSUPPORTED_TYPE,
                                   detail="socket: not representable in a tar archive")
    if path in errors:
        return EntryReconciliation(path=path, outcome=EntryOutcome.ERROR, detail=errors[path])
    if member is None:
        if post_ix is not None and path not in post_ix:
            detail = ("not in archive; absent from post-acquisition enumeration "
                      "(deleted during acquisition)")
        else:
            detail = "not in archive"
        return EntryReconciliation(path=path, outcome=EntryOutcome.ERROR, detail=detail)

    reliability = _reliability(entry, post_ix)
    if not _types_compatible(member.entry_type, entry.entry_type):
        if reliability is not ContentReliability.CHANGED_DURING_ACQUISITION:
            return EntryReconciliation(
                path=path, outcome=EntryOutcome.ERROR,
                detail=(f"archived as {member.entry_type.value} but enumerated as "
                        f"{entry.entry_type.value}"),
            )
    elif entry.entry_type is EntryType.REGULAR and member.entry_type is EntryType.REGULAR:
        if reliability is not ContentReliability.CHANGED_DURING_ACQUISITION:
            if entry.size is None or member.size is None:
                size_failures.append(f"{path!r}: size not available for comparison")
            elif entry.size != member.size:
                size_failures.append(
                    f"{path!r}: archived {member.size} bytes, enumerated {entry.size} bytes, "
                    "no change detected")
    return EntryReconciliation(path=path, outcome=EntryOutcome.ACQUIRED,
                               content_reliability=reliability)


def _evaluate_checks(report, audit_state, pre_ix, post_ix, entries, unenumerated,
                     out_of_scope_members, size_failures) -> tuple[CheckResult, ...]:
    def result(check_id: str, failures: list[str], pass_detail: str = "") -> CheckResult:
        if failures:
            return CheckResult(check_id=check_id, state=CheckState.FAIL, details=tuple(failures))
        return CheckResult(check_id=check_id, state=CheckState.PASS,
                           details=(pass_detail,) if pass_detail else ())

    def not_evaluated(check_id: str, why: str) -> CheckResult:
        return CheckResult(check_id=check_id, state=CheckState.NOT_EVALUATED, details=(why,))

    checks = [
        result("C1", [] if report.plan_recorded_before_first_read
               else ["scope and planned class were not recorded before the first data read"]),
        result("C2", [] if report.exit_status == 0 else [
            "exit status not observed" if report.exit_status is None
            else f"copy process exited with status {report.exit_status}"]),
        result("C3", [f"error: {line}" for line in report.stderr_error_lines]
               + [f"unclassified: {line}" for line in report.stderr_unclassified_lines]),
        result("C4", ([] if report.stream_ended_cleanly else ["stream did not end cleanly"])
               + ([] if report.archive_parsed_to_end else ["archive did not parse to its end marker"])
               + [f"truncated member: {p!r}" for p in report.truncated_members]),
        result("C5", [] if report.stream_hashes_match
               else ["streaming and at-rest hashes differ"]),
    ]
    if pre_ix is None:
        why = "no pre-acquisition enumeration"
        checks += [not_evaluated(c, why) for c in ("C6", "C7", "C8", "C9")]
    else:
        checks.append(result(
            "C6", [f"archive member outside the declared scope: {p!r}" for p in out_of_scope_members],
            f"{len(entries)} in-scope entries each have exactly one outcome"))
        checks.append(result(
            "C7", [f"{e.path!r}: {e.detail}" for e in entries if e.outcome is EntryOutcome.ERROR]))
        checks.append(result("C8", size_failures))
        if post_ix is None:
            checks.append(not_evaluated("C9", "no post-acquisition enumeration"))
        else:
            changed = sum(1 for e in entries
                          if e.content_reliability is ContentReliability.CHANGED_DURING_ACQUISITION)
            checks.append(CheckResult(
                check_id="C9", state=CheckState.PASS,
                details=(f"{changed} acquired entries changed during acquisition; "
                         f"{len(unenumerated)} archive members were not in the "
                         "pre-acquisition enumeration",)))
    if audit_state is None:
        checks.append(not_evaluated("C10", "evaluated by the verifier after sealing"))
    else:
        checks.append(result("C10", [] if audit_state is AuditLogState.SEALED
                             else [f"audit log is {audit_state.value}"]))
    return tuple(checks)


def _status(checks, member_ix, entries, unenumerated, pre_ix, post_ix) -> CompletenessStatus:
    state = {c.check_id: c.state for c in checks}
    if any(state[c] is CheckState.FAIL for c in ("C1", "C5", "C10")):
        return CompletenessStatus.FAILED
    if not member_ix:
        return CompletenessStatus.FAILED  # no usable data
    if any(state[c] is CheckState.FAIL for c in ("C2", "C3", "C4", "C6", "C7", "C8")):
        return CompletenessStatus.PARTIAL
    if pre_ix is None or post_ix is None:
        return CompletenessStatus.COMPLETENESS_UNVERIFIED
    changed = unenumerated or any(
        e.content_reliability is ContentReliability.CHANGED_DURING_ACQUISITION for e in entries)
    return CompletenessStatus.COMPLETE_WITH_CHANGES if changed else CompletenessStatus.COMPLETE
