import json
import unittest
import zlib
from datetime import datetime, timezone

from corrobora_mobile.acquisition import ArchivedMember, CopyReport, reconcile
from corrobora_mobile.core.enums import (
    AcquisitionClass,
    AuditLogState,
    CheckState,
    CompletenessStatus,
    ContentReliability,
    EntryOutcome,
    EntryType,
)
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import AcquisitionPlan, EnumeratedEntry, ScopeExclusion

R, D, S, H, L = (EntryType.REGULAR, EntryType.DIRECTORY, EntryType.SOCKET,
                 EntryType.HARDLINK, EntryType.SYMLINK)


def plan(exclusions=()):
    return AcquisitionPlan(
        acquisition_id="acq-1",
        method_id="test.method",
        planned_class=AcquisitionClass.PRIVILEGED_SELECTED_DIRECTORY,
        included_paths=(b"/data",),
        exclusions=tuple(exclusions),
        created_at=datetime(2026, 10, 31, tzinfo=timezone.utc),
    )


def ent(path, t=R, size=10, mtime=1, ctime=1, inode=None):
    if inode is None:
        inode = zlib.crc32(path)
    return EnumeratedEntry(path=path, entry_type=t, size=size if t is R else None,
                           mtime_ns=mtime, ctime_ns=ctime, inode=inode)


def mem(path, t=R, size=10):
    return ArchivedMember(path=path, entry_type=t, size=size if t is R else 0)


def report(**overrides):
    values = dict(plan_recorded_before_first_read=True, exit_status=0, stream_ended_cleanly=True,
                  archive_parsed_to_end=True, stream_hashes_match=True)
    values.update(overrides)
    return CopyReport(**values)


BASE = [ent(b"/data", D), ent(b"/data/a"), ent(b"/data/b", size=20)]
BASE_MEMBERS = [mem(b"/data", D), mem(b"/data/a"), mem(b"/data/b", size=20)]


def run(pre=BASE, post=BASE, members=BASE_MEMBERS, **kw):
    rep = kw.pop("report", report())
    return reconcile(kw.pop("plan", plan()), rep, pre=pre, post=post, members=members, **kw)


def outcome(result, path):
    return next(e for e in result.entries if e.path == path)


class StatusTests(unittest.TestCase):
    def test_clean_acquisition_is_complete_and_provisional(self):
        r = run()
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)
        self.assertTrue(r.provisional)
        self.assertEqual(r.check("C10").state, CheckState.NOT_EVALUATED)
        for e in r.entries:
            self.assertEqual(e.outcome, EntryOutcome.ACQUIRED)
            self.assertEqual(e.content_reliability, ContentReliability.NO_CHANGE_DETECTED)

    def test_sealed_log_makes_result_final(self):
        r = run(audit_state=AuditLogState.SEALED)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)
        self.assertFalse(r.provisional)

    def test_integrity_failures_are_failed(self):
        for kw in ({"report": report(stream_hashes_match=False)},
                   {"report": report(plan_recorded_before_first_read=False)},
                   {"audit_state": AuditLogState.BROKEN},
                   {"audit_state": AuditLogState.UNSEALED}):
            with self.subTest(kw=kw):
                self.assertEqual(run(**kw).status, CompletenessStatus.FAILED)

    def test_no_members_is_failed(self):
        self.assertEqual(run(members=[]).status, CompletenessStatus.FAILED)

    def test_process_failures_are_partial(self):
        for rep in (report(exit_status=1), report(exit_status=None),
                    report(stderr_error_lines=("tar: can't open x",)),
                    report(stderr_unclassified_lines=("something odd",)),
                    report(stream_ended_cleanly=False), report(archive_parsed_to_end=False),
                    report(truncated_members=(b"/data/a",))):
            with self.subTest(rep=rep):
                self.assertEqual(run(report=rep).status, CompletenessStatus.PARTIAL)

    def test_exit_status_zero_is_not_sufficient(self):
        r = run(members=BASE_MEMBERS[:2])  # /data/b missing, exit status still 0
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)
        self.assertEqual(r.check("C2").state, CheckState.PASS)
        self.assertEqual(r.check("C7").state, CheckState.FAIL)


class EntryOutcomeTests(unittest.TestCase):
    def test_socket_is_unsupported_type_not_error(self):
        pre = BASE + [ent(b"/data/sock", S)]
        r = run(pre=pre, post=pre)
        self.assertEqual(outcome(r, b"/data/sock").outcome, EntryOutcome.UNSUPPORTED_TYPE)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)

    def test_unreadable_file_is_error_and_partial(self):
        r = run(members=BASE_MEMBERS[:2], entry_errors={b"/data/b": "tar: can't open"},
                report=report(stderr_error_lines=("tar: can't open '/data/b'",)))
        e = outcome(r, b"/data/b")
        self.assertEqual((e.outcome, e.detail), (EntryOutcome.ERROR, "tar: can't open"))
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)
        self.assertNotEqual(r.status, CompletenessStatus.COMPLETE)

    def test_excluded_entries_carry_rule_id(self):
        p = plan([ScopeExclusion(path=b"/data/b", rule_id="EX-1", reason="test")])
        r = run(plan=p, members=BASE_MEMBERS[:2])
        e = outcome(r, b"/data/b")
        self.assertEqual((e.outcome, e.rule_id), (EntryOutcome.EXCLUDED_BY_RULE, "EX-1"))
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)

    def test_most_specific_exclusion_applies(self):
        pre = BASE + [ent(b"/data/x", D), ent(b"/data/x/y", D), ent(b"/data/x/y/z")]
        p = plan([ScopeExclusion(path=b"/data/x", rule_id="OUTER", reason="r"),
                  ScopeExclusion(path=b"/data/x/y", rule_id="INNER", reason="r")])
        r = run(plan=p, pre=pre, post=pre)
        self.assertEqual(outcome(r, b"/data/x").rule_id, "OUTER")
        self.assertEqual(outcome(r, b"/data/x/y/z").rule_id, "INNER")

    def test_every_in_scope_entry_has_exactly_one_outcome(self):
        pre = BASE + [ent(b"/data/sock", S), ent(b"/data/gone"), ent(b"/elsewhere")]
        r = run(pre=pre, post=pre, entry_errors={b"/data/gone": "boom"})
        in_scope = [e.path for e in pre if e.path != b"/elsewhere"]
        self.assertEqual(sorted(e.path for e in r.entries), sorted(in_scope))
        self.assertEqual(r.enumerated_out_of_scope, (b"/elsewhere",))

    def test_second_hard_link_matches_regular_entry(self):
        pre = BASE + [ent(b"/data/link2")]
        members = BASE_MEMBERS + [mem(b"/data/link2", H)]
        r = run(pre=pre, post=pre, members=members)
        self.assertEqual(outcome(r, b"/data/link2").outcome, EntryOutcome.ACQUIRED)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)

    def test_type_mismatch_without_change_is_error(self):
        members = BASE_MEMBERS[:2] + [mem(b"/data/b", L)]
        r = run(members=members)
        self.assertEqual(outcome(r, b"/data/b").outcome, EntryOutcome.ERROR)
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)

    def test_type_change_during_acquisition_is_change(self):
        post = BASE[:2] + [ent(b"/data/b", L)]
        members = BASE_MEMBERS[:2] + [mem(b"/data/b", L)]
        r = run(post=post, members=members)
        e = outcome(r, b"/data/b")
        self.assertEqual(e.content_reliability, ContentReliability.CHANGED_DURING_ACQUISITION)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE_WITH_CHANGES)


class ChangeTests(unittest.TestCase):
    def test_changed_entry_gives_complete_with_changes(self):
        post = BASE[:2] + [ent(b"/data/b", size=25, mtime=2)]
        r = run(post=post, members=BASE_MEMBERS[:2] + [mem(b"/data/b", size=23)])
        self.assertEqual(outcome(r, b"/data/b").content_reliability,
                         ContentReliability.CHANGED_DURING_ACQUISITION)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE_WITH_CHANGES)
        self.assertEqual(r.check("C8").state, CheckState.PASS)  # size difference explained by C9
        self.assertEqual(r.changed_entry_count, 1)

    def test_each_compared_attribute_detects_change(self):
        for attr, kw in (("size", {"size": 11}), ("mtime", {"mtime": 2}),
                         ("ctime", {"ctime": 2}), ("inode", {"inode": 7})):
            with self.subTest(attr=attr):
                before = ent(b"/data/a", inode=5)
                after = ent(b"/data/a", **{"inode": 5, **kw})
                r = run(pre=[BASE[0], before], post=[BASE[0], after], members=BASE_MEMBERS[:2])
                self.assertEqual(outcome(r, b"/data/a").content_reliability,
                                 ContentReliability.CHANGED_DURING_ACQUISITION)

    def test_size_mismatch_without_change_fails_c8(self):
        r = run(members=BASE_MEMBERS[:2] + [mem(b"/data/b", size=19)])
        self.assertEqual(r.check("C8").state, CheckState.FAIL)
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)

    def test_deleted_during_acquisition_is_error(self):  # decision 1
        post = BASE[:2]
        r = run(post=post, members=BASE_MEMBERS[:2])
        e = outcome(r, b"/data/b")
        self.assertEqual(e.outcome, EntryOutcome.ERROR)
        self.assertIn("deleted during acquisition", e.detail)
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)

    def test_deleted_after_archiving_is_change(self):
        r = run(post=BASE[:2])  # archived, then gone from post
        self.assertEqual(outcome(r, b"/data/b").content_reliability,
                         ContentReliability.CHANGED_DURING_ACQUISITION)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE_WITH_CHANGES)

    def test_new_in_scope_member_is_change(self):  # decision 2
        post = BASE + [ent(b"/data/new")]
        r = run(post=post, members=BASE_MEMBERS + [mem(b"/data/new")])
        self.assertEqual([m.path for m in r.unenumerated_members], [b"/data/new"])
        self.assertTrue(r.unenumerated_members[0].in_post_enumeration)
        self.assertEqual(r.status, CompletenessStatus.COMPLETE_WITH_CHANGES)
        self.assertEqual(r.changed_entry_count, 1)

    def test_out_of_scope_member_fails_c6(self):  # decision 3
        p = plan([ScopeExclusion(path=b"/data/b", rule_id="EX-1", reason="r")])
        for members in (BASE_MEMBERS + [mem(b"/other")], BASE_MEMBERS):  # outside; excluded
            with self.subTest(members=[m.path for m in members]):
                r = run(plan=p, members=members)
                self.assertEqual(r.check("C6").state, CheckState.FAIL)
                self.assertEqual(r.status, CompletenessStatus.PARTIAL)

    def test_no_comparable_attributes_is_unknown(self):
        bare = [EnumeratedEntry(path=b"/data", entry_type=D)]
        r = run(pre=bare, post=bare, members=BASE_MEMBERS[:1])
        self.assertEqual(r.entries[0].content_reliability, ContentReliability.UNKNOWN)


class MissingEnumerationTests(unittest.TestCase):
    def test_no_pre_enumeration_is_unverified(self):
        r = run(pre=None)
        self.assertEqual(r.status, CompletenessStatus.COMPLETENESS_UNVERIFIED)
        for c in ("C6", "C7", "C8", "C9"):
            self.assertEqual(r.check(c).state, CheckState.NOT_EVALUATED)
        self.assertEqual(r.entries, ())

    def test_no_pre_enumeration_with_known_failure_is_partial(self):  # decision 4
        r = run(pre=None, report=report(exit_status=2))
        self.assertEqual(r.status, CompletenessStatus.PARTIAL)

    def test_no_post_enumeration_is_never_complete(self):
        r = run(post=None)
        self.assertEqual(r.status, CompletenessStatus.COMPLETENESS_UNVERIFIED)
        self.assertEqual(r.check("C9").state, CheckState.NOT_EVALUATED)
        for e in r.entries:
            self.assertEqual(e.content_reliability, ContentReliability.UNKNOWN)


class InputValidationTests(unittest.TestCase):
    def test_duplicate_paths_rejected(self):
        for kw in ({"pre": BASE + [BASE[1]]}, {"post": BASE + [BASE[1]]},
                   {"members": BASE_MEMBERS + [BASE_MEMBERS[1]]}):
            with self.subTest(kw=list(kw)):
                with self.assertRaisesRegex(ModelValidationError, "duplicate path"):
                    run(**kw)

    def test_bad_inputs_rejected(self):
        with self.assertRaises(ModelValidationError):
            ArchivedMember(path=b"/data/s", entry_type=S)
        with self.assertRaises(ModelValidationError):
            ArchivedMember(path=b"data/x", entry_type=R)
        with self.assertRaises(ModelValidationError):
            report(exit_status=True)
        with self.assertRaises(ModelValidationError):
            report(stream_hashes_match=1)
        with self.assertRaises(ModelValidationError):
            run(entry_errors={b"/data/a": " "})
        with self.assertRaises(ModelValidationError):
            run(members=None)


class SerializationTests(unittest.TestCase):
    def test_to_dict_is_json_and_counts_changes_in_summary(self):
        post = BASE[:2] + [ent(b"/data/b", size=25, mtime=2)]
        r = run(post=post, members=BASE_MEMBERS[:2] + [mem(b"/data/b", size=23)])
        d = json.loads(json.dumps(r.to_dict()))
        self.assertEqual(d["format"], "corrobora-mobile/reconciliation")
        self.assertEqual(d["status"], "COMPLETE_WITH_CHANGES")
        self.assertTrue(d["provisional"])
        self.assertEqual(d["summary"]["changed_entries"], 1)
        self.assertEqual([c["check"] for c in d["checks"]], [f"C{i}" for i in range(1, 11)])
        self.assertTrue(any("not a point-in-time snapshot" in s for s in d["limitations"]))

    def test_non_utf8_paths_survive(self):
        odd = b"/data/\xff\xfe"
        pre = BASE + [ent(odd)]
        r = run(pre=pre, post=pre, members=BASE_MEMBERS + [mem(odd)])
        self.assertEqual(r.status, CompletenessStatus.COMPLETE)
        json.dumps(r.to_dict())


if __name__ == "__main__":
    unittest.main()
