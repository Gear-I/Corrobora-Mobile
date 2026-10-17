import unittest
from datetime import datetime, timezone

from corrobora_mobile.core.classification import (
    CRITERIA,
    ClassificationEvidence,
    CriterionResult,
    assess_mount_coverage,
    class_covered_by_validation,
    determine_class,
    relabel,
)
from corrobora_mobile.core.enums import AcquisitionClass as AC
from corrobora_mobile.core.enums import Tristate
from corrobora_mobile.core.errors import ClassificationError, ModelValidationError
from corrobora_mobile.core.models import AcquisitionPlan, MountEntry, ScopeExclusion

YES = CriterionResult(result=Tristate.YES, evidence_refs=("reconciliation.json",))
NO = CriterionResult(result=Tristate.NO, evidence_refs=("reconciliation.json",), detail="not met")
UNKNOWN = CriterionResult(result=Tristate.UNKNOWN, detail="could not be established")


def evidence(**overrides):
    fields = {name: YES for name in CRITERIA}
    fields.update(overrides)
    return ClassificationEvidence(**fields)


class CriterionResultTests(unittest.TestCase):
    def test_yes_requires_evidence(self):
        with self.assertRaises(ModelValidationError):
            CriterionResult(result=Tristate.YES)

    def test_no_and_unknown_require_detail(self):
        for result in (Tristate.NO, Tristate.UNKNOWN):
            with self.subTest(result=result):
                with self.assertRaises(ModelValidationError):
                    CriterionResult(result=result)

    def test_unknown_is_not_met(self):
        self.assertFalse(UNKNOWN.met)
        self.assertFalse(NO.met)
        self.assertTrue(YES.met)

    def test_rejects_bool_result(self):
        with self.assertRaises(ModelValidationError):
            CriterionResult(result=True, evidence_refs=("x",))  # type: ignore[arg-type]

    def test_evidence_refs_must_be_package_relative(self):
        for bad in ("/etc/passwd", "\\\\server\\share", "../outside.json", "a/../../b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    CriterionResult(result=Tristate.YES, evidence_refs=(bad,))


class EvidenceTests(unittest.TestCase):
    def test_no_defaults_every_criterion_required(self):
        fields = {name: YES for name in CRITERIA}
        for name in CRITERIA:
            with self.subTest(missing=name):
                partial = {k: v for k, v in fields.items() if k != name}
                with self.assertRaises(TypeError):
                    ClassificationEvidence(**partial)

    def test_rejects_bare_booleans(self):
        with self.assertRaises(ModelValidationError):
            evidence(privileged_session=True)

    def test_to_dict_lists_all_criteria(self):
        self.assertEqual(list(evidence().to_dict()), list(CRITERIA))


class DetermineClassTests(unittest.TestCase):
    def test_all_criteria_met_is_ffs(self):
        d = determine_class(AC.FFS, evidence())
        self.assertEqual((d.highest_supported, d.final, d.limiting_criteria), (AC.FFS, AC.FFS, ()))

    def test_unprivileged_is_selected_directory(self):
        d = determine_class(AC.FFS, evidence(privileged_session=NO))
        self.assertEqual(d.final, AC.SELECTED_DIRECTORY)
        self.assertEqual(d.limiting_criteria, ("privileged_session",))

    def test_data_only_collection_is_never_ffs(self):
        d = determine_class(AC.FFS, evidence(full_mount_table_scope=NO))
        self.assertEqual(d.final, AC.PRIVILEGED_SELECTED_DIRECTORY)
        self.assertEqual(d.limiting_criteria, ("full_mount_table_scope",))

    def test_unknown_treated_as_not_met(self):
        for name in CRITERIA:
            with self.subTest(criterion=name):
                d = determine_class(AC.FFS, evidence(**{name: UNKNOWN}))
                self.assertNotEqual(d.final, AC.FFS)
                self.assertIn(name, d.limiting_criteria)

    def test_each_ffs_criterion_required(self):
        for name in CRITERIA[2:]:
            with self.subTest(criterion=name):
                d = determine_class(AC.FFS, evidence(**{name: NO}))
                self.assertEqual(d.final, AC.PRIVILEGED_FILESYSTEM)
                self.assertEqual(d.limiting_criteria, (name,))

    def test_never_exceeds_planned(self):
        d = determine_class(AC.PRIVILEGED_SELECTED_DIRECTORY, evidence())
        self.assertEqual(d.highest_supported, AC.FFS)
        self.assertEqual(d.final, AC.PRIVILEGED_SELECTED_DIRECTORY)

    def test_independent_of_validation(self):
        # determine_class takes no validation input at all (Section 0.3).
        self.assertEqual(determine_class(AC.FFS, evidence()).final, AC.FFS)

    def test_to_dict(self):
        d = determine_class(AC.FFS, evidence(f4_required_attributes_captured=NO)).to_dict()
        self.assertEqual(d["final"], "PRIVILEGED_FILESYSTEM")
        self.assertEqual(d["limiting_criteria"], ["f4_required_attributes_captured"])


class MountCoverageTests(unittest.TestCase):
    def _plan(self, included, exclusions=()):
        return AcquisitionPlan(
            acquisition_id="acq-1",
            method_id="m",
            planned_class=AC.PRIVILEGED_FILESYSTEM,
            included_paths=included,
            exclusions=exclusions,
            created_at=datetime(2026, 10, 16, tzinfo=timezone.utc),
        )

    def _mount(self, mp, fs="ext4"):
        return MountEntry(source="dev", mount_point=mp, fs_type=fs)

    def _assess(self, plan, mounts):
        return assess_mount_coverage(
            plan, mounts, mount_table_ref="plan/mounts.txt", plan_ref="plan/plan.json"
        )

    def test_all_mounts_covered(self):
        plan = self._plan(
            (b"/data", b"/system"),
            (),
        )
        r = self._assess(plan, [self._mount(b"/data"), self._mount(b"/system")])
        self.assertTrue(r.met)
        self.assertEqual(r.evidence_refs, ("plan/mounts.txt", "plan/plan.json"))

    def test_excluded_mount_counts_as_covered(self):
        plan = self._plan(
            (b"/",),
            (ScopeExclusion(path=b"/proc", rule_id="PSEUDO_FS", reason="procfs"),),
        )
        r = self._assess(plan, [self._mount(b"/"), self._mount(b"/proc", "proc")])
        self.assertTrue(r.met)

    def test_data_only_plan_does_not_cover_other_mounts(self):
        plan = self._plan((b"/data",))
        r = self._assess(plan, [self._mount(b"/data"), self._mount(b"/metadata")])
        self.assertIs(r.result, Tristate.NO)
        self.assertIn("/metadata", r.detail)

    def test_mount_inside_included_path_is_not_automatically_covered(self):
        # A mount nested under /data is a separate filesystem; it must be
        # listed or excluded explicitly, because a copy of /data may not
        # cross filesystem boundaries.
        plan = self._plan((b"/data",))
        r = self._assess(plan, [self._mount(b"/data"), self._mount(b"/data/media")])
        self.assertIs(r.result, Tristate.NO)

    def test_empty_mount_table_is_unknown(self):
        r = self._assess(self._plan((b"/data",)), [])
        self.assertIs(r.result, Tristate.UNKNOWN)
        self.assertFalse(r.met)


class RelabelTests(unittest.TestCase):
    def test_lowering_allowed(self):
        self.assertEqual(
            relabel(AC.PRIVILEGED_FILESYSTEM, AC.PRIVILEGED_SELECTED_DIRECTORY),
            AC.PRIVILEGED_SELECTED_DIRECTORY,
        )

    def test_same_allowed(self):
        self.assertEqual(relabel(AC.FFS, AC.FFS), AC.FFS)

    def test_raising_rejected(self):
        with self.assertRaises(ClassificationError):
            relabel(AC.PRIVILEGED_SELECTED_DIRECTORY, AC.FFS)


class ValidationCoverageTests(unittest.TestCase):
    def test_no_record_means_not_covered(self):
        self.assertFalse(class_covered_by_validation(AC.FFS, frozenset()))

    def test_lower_class_validation_does_not_cover_higher(self):
        self.assertFalse(
            class_covered_by_validation(AC.FFS, frozenset({AC.PRIVILEGED_SELECTED_DIRECTORY}))
        )

    def test_listed_class_is_covered(self):
        self.assertTrue(
            class_covered_by_validation(
                AC.PRIVILEGED_SELECTED_DIRECTORY, frozenset({AC.PRIVILEGED_SELECTED_DIRECTORY})
            )
        )


if __name__ == "__main__":
    unittest.main()
