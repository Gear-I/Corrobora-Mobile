import copy
import json
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.compatibility import assess, default_methods_dir, gate, load_registry
from corrobora_mobile.compatibility.registry import MethodRecord
from corrobora_mobile.core.enums import AcquisitionClass, Platform, Tristate, ValidationStatus
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import DeviceIdentity

EMULATOR_ID = "android.emulator.adb_root_userdebug"
RECORD_FILE = default_methods_dir() / f"{EMULATOR_ID}.json"


def raw_record():
    return json.loads(RECORD_FILE.read_text(encoding="utf-8"))


def identity(**kw):
    values = dict(platform=Platform.ANDROID, is_emulator=Tristate.YES, build_type="userdebug",
                  os_version="15")
    values.update(kw)
    return DeviceIdentity(**values)


class EmulatorRecordTests(unittest.TestCase):
    """The shipped record must say exactly what the architecture document allows."""

    def setUp(self):
        self.record = load_registry()[EMULATOR_ID]

    def test_record_is_unverified_with_no_validation_records(self):
        self.assertEqual(self.record.validation_status, ValidationStatus.UNVERIFIED)
        self.assertEqual(self.record.validation_records, ())

    def test_record_claims_at_most_privileged_selected_directory(self):
        self.assertEqual(self.record.max_acquisition_class, AcquisitionClass.PRIVILEGED_SELECTED_DIRECTORY)
        self.assertFalse(self.record.physical_device)
        self.assertEqual(self.record.build_types, ("userdebug",))
        self.assertEqual(self.record.os_versions, ())

    def test_unverified_side_effects_are_labeled(self):
        self.assertIn("adbd restarted as root", self.record.device_modifications)
        self.assertTrue(any(m.startswith("UNVERIFIED:") for m in self.record.device_modifications))

    def test_registry_contains_only_the_emulator_method(self):
        self.assertEqual(list(load_registry()), [EMULATOR_ID])


class LoadingTests(unittest.TestCase):
    def load_one(self, data, name=EMULATOR_ID):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
            return load_registry(Path(tmp))

    def test_valid_copy_loads(self):
        self.assertIn(EMULATOR_ID, self.load_one(raw_record()))

    def test_verified_or_experimental_without_records_rejected(self):
        for status in ("VERIFIED", "EXPERIMENTAL"):
            with self.subTest(status=status):
                data = raw_record(); data["validation_status"] = status
                with self.assertRaisesRegex(ModelValidationError, "requires at least one validation record"):
                    self.load_one(data)
                data["validation_records"] = ["docs/VALIDATION.md#example"]
                self.load_one(data)

    def test_strict_fields(self):
        cases = []
        d = raw_record(); d["extra"] = 1; cases.append(("unknown key", d))
        d = raw_record(); del d["notes"]; cases.append(("missing key", d))
        d = raw_record(); d["validation_status"] = "PROBABLY_FINE"; cases.append(("bad status", d))
        d = raw_record(); d["max_acquisition_class"] = "EVERYTHING"; cases.append(("bad class", d))
        d = raw_record(); d["physical_device"] = "no"; cases.append(("bad bool", d))
        d = raw_record(); d["applies_to"]["build_type"] = []; cases.append(("empty build types", d))
        d = raw_record(); d["applies_to"]["extra"] = "x"; cases.append(("applies_to key", d))
        d = raw_record(); d["device_modifications"] = []; cases.append(("no modifications", d))
        d = raw_record(); d["known_limitations"] = ["a", "a"]; cases.append(("duplicates", d))
        d = raw_record(); d["method_id"] = "Bad ID"; cases.append(("bad id", d))
        for name, data in cases:
            with self.subTest(name):
                with self.assertRaises(ModelValidationError):
                    self.load_one(data, name=data["method_id"] if name == "bad id" else EMULATOR_ID)

    def test_file_name_must_match_method_id(self):
        with self.assertRaisesRegex(ModelValidationError, "file name must be"):
            self.load_one(raw_record(), name="android.other")

    def test_invalid_json_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.json").write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ModelValidationError, "invalid JSON"):
                load_registry(Path(tmp))
            with self.assertRaisesRegex(ModelValidationError, "not found"):
                load_registry(Path(tmp) / "absent")


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.record = MethodRecord.from_dict(raw_record())

    def test_matching_emulator(self):
        a = assess(self.record, identity())
        self.assertEqual(a.matches, Tristate.YES)
        self.assertTrue(any("has not been tested" in w for w in a.warnings))

    def test_manufacturer_and_model_are_not_matched(self):
        a = assess(self.record, identity(manufacturer="Google", model="sdk_gphone64_x86_64"))
        self.assertEqual(a.matches, Tristate.YES)

    def test_mismatches(self):
        for kw, text in (({"is_emulator": Tristate.NO}, "physical device"),
                         ({"build_type": "user"}, "build type 'user'"),
                         ({"platform": Platform.IOS}, "platform is ios")):
            with self.subTest(kw=kw):
                a = assess(self.record, identity(**kw))
                self.assertEqual(a.matches, Tristate.NO)
                self.assertTrue(any(text in m for m in a.mismatches), a.mismatches)

    def test_unknowns(self):
        for kw in ({"is_emulator": Tristate.UNKNOWN}, {"build_type": None}):
            with self.subTest(kw=kw):
                self.assertEqual(assess(self.record, identity(**kw)).matches, Tristate.UNKNOWN)

    def test_unknown_os_version_still_matches_with_warning(self):
        a = assess(self.record, identity(os_version=None))
        self.assertEqual(a.matches, Tristate.YES)
        self.assertTrue(any("OS version is unknown" in w for w in a.warnings))

    def test_registry_assess_filters_by_platform(self):
        reg = load_registry()
        self.assertEqual([a.method_id for a in reg.assess(identity())], [EMULATOR_ID])
        self.assertEqual(reg.assess(identity(platform=Platform.IOS)), ())

    def test_assessment_never_changes_the_record(self):
        before = copy.deepcopy(raw_record())
        reg = load_registry()
        gate(reg.assess(identity())[0], research_mode=True)
        self.assertEqual(reg[EMULATOR_ID].validation_status, ValidationStatus.UNVERIFIED)
        self.assertEqual(raw_record(), before)


class GateTests(unittest.TestCase):
    def assessment(self, status="UNVERIFIED", **kw):
        data = raw_record(); data["validation_status"] = status
        if status in ("VERIFIED", "EXPERIMENTAL"):
            data["validation_records"] = ["docs/VALIDATION.md#example"]
        return assess(MethodRecord.from_dict(data), identity(**kw))

    def test_unverified_needs_research_mode(self):
        d = gate(self.assessment(), research_mode=False)
        self.assertFalse(d.allowed)
        self.assertIn("research mode", d.reason)
        d = gate(self.assessment(), research_mode=True)
        self.assertTrue(d.allowed and d.requires_acknowledgement)
        self.assertIn("RESEARCH", d.reason)

    def test_unsupported_never_runs(self):
        for research in (False, True):
            self.assertFalse(gate(self.assessment("UNSUPPORTED"), research_mode=research).allowed)

    def test_experimental_and_verified_need_acknowledgement(self):
        for status in ("EXPERIMENTAL", "VERIFIED"):
            with self.subTest(status=status):
                d = gate(self.assessment(status), research_mode=False)
                self.assertTrue(d.allowed and d.requires_acknowledgement)

    def test_no_match_or_unknown_match_never_runs(self):
        for kw in ({"build_type": "user"}, {"is_emulator": Tristate.UNKNOWN}):
            with self.subTest(kw=kw):
                d = gate(self.assessment("VERIFIED", **kw), research_mode=True)
                self.assertFalse(d.allowed)

    def test_user_build_refused(self):
        # M1 acceptance: a `user` build (Google Play image) is refused.
        d = gate(self.assessment(build_type="user"), research_mode=True)
        self.assertFalse(d.allowed)
        self.assertIn("does not match", d.reason)

    def test_research_mode_must_be_bool(self):
        with self.assertRaises(ModelValidationError):
            gate(self.assessment(), research_mode="yes")


if __name__ == "__main__":
    unittest.main()
