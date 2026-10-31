import unittest

from corrobora_mobile.core import errors


class ErrorHierarchyTests(unittest.TestCase):
    def test_all_errors_derive_from_base(self):
        for name in (
            "ConfigError",
            "ModelValidationError",
            "ClassificationError",
            "UnsupportedDeviceError",
            "PreconditionError",
            "AccessError",
            "AcquisitionError",
            "IntegrityError",
            "ResearchModeRequiredError",
            "AuditLogError",
            "EvidencePackageError",
        ):
            with self.subTest(name=name):
                self.assertTrue(issubclass(getattr(errors, name), errors.CorroboraError))

    def test_integrity_error_is_not_a_precondition_error(self):
        self.assertFalse(issubclass(errors.IntegrityError, errors.PreconditionError))

    def test_audit_log_error_is_not_an_integrity_error(self):
        # Misuse of the writer must not be confused with evidence failing verification.
        self.assertFalse(issubclass(errors.AuditLogError, errors.IntegrityError))

    def test_evidence_package_error_is_not_an_integrity_error(self):
        self.assertFalse(issubclass(errors.EvidencePackageError, errors.IntegrityError))

    def test_model_validation_error_is_value_error(self):
        self.assertTrue(issubclass(errors.ModelValidationError, ValueError))


if __name__ == "__main__":
    unittest.main()
