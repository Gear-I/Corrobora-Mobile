import unittest

from corrobora_mobile.core.enums import (
    AcquisitionClass,
    CompletenessStatus,
    ContentReliability,
    EntryOutcome,
    IntegrityStatus,
    RiskClass,
    ValidationStatus,
)


class AcquisitionClassOrderTests(unittest.TestCase):
    def test_claim_strength_order(self):
        self.assertEqual(
            [c.value for c in sorted(AcquisitionClass, key=lambda c: c.rank)],
            [
                "SELECTED_DIRECTORY",
                "PRIVILEGED_SELECTED_DIRECTORY",
                "PRIVILEGED_FILESYSTEM",
                "FFS",
            ],
        )

    def test_ffs_is_highest(self):
        self.assertEqual(max(AcquisitionClass, key=lambda c: c.rank), AcquisitionClass.FFS)


class VocabularyTests(unittest.TestCase):
    """Enum values are written into evidence verbatim; pin them."""

    def test_validation_statuses_match_project_instructions(self):
        self.assertEqual(
            {s.value for s in ValidationStatus},
            {"VERIFIED", "EXPERIMENTAL", "UNVERIFIED", "UNSUPPORTED"},
        )

    def test_completeness_statuses(self):
        self.assertEqual(
            {s.value for s in CompletenessStatus},
            {
                "COMPLETE",
                "COMPLETE_WITH_CHANGES",
                "PARTIAL",
                "FAILED",
                "INTERRUPTED",
                "COMPLETENESS_UNVERIFIED",
            },
        )

    def test_integrity_statuses(self):
        self.assertEqual({s.value for s in IntegrityStatus}, {"PASS", "FAIL", "INCOMPLETE"})

    def test_entry_outcomes(self):
        self.assertEqual(
            {o.value for o in EntryOutcome},
            {"ACQUIRED", "EXCLUDED_BY_RULE", "UNSUPPORTED_TYPE", "ERROR"},
        )

    def test_content_reliability(self):
        self.assertEqual(
            {r.value for r in ContentReliability},
            {"NO_CHANGE_DETECTED", "CHANGED_DURING_ACQUISITION", "UNKNOWN"},
        )

    def test_risk_classes(self):
        self.assertEqual(
            [r.value for r in RiskClass],
            [
                "NONE",
                "STATE_CHANGE",
                "PERSISTENT_CHANGE",
                "POSSIBLE_DATA_LOSS",
                "POSSIBLE_DEVICE_DAMAGE",
            ],
        )

    def test_status_families_are_distinct_types(self):
        # Integrity, completeness and validation must never be interchangeable.
        self.assertNotIsInstance(IntegrityStatus.PASS, CompletenessStatus)
        self.assertNotIsInstance(CompletenessStatus.COMPLETE, ValidationStatus)
        self.assertNotIsInstance(ValidationStatus.VERIFIED, IntegrityStatus)


if __name__ == "__main__":
    unittest.main()
