import dataclasses
import json
import unittest
from datetime import datetime, timedelta, timezone

from corrobora_mobile.core.enums import (
    AcquisitionClass,
    ContentReliability,
    EntryOutcome,
    EntryType,
    LockState,
    Platform,
    RiskClass,
    Tristate,
)
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.models import (
    AcquisitionPlan,
    DeviceIdentity,
    DeviceModification,
    EntryReconciliation,
    EnumeratedEntry,
    MountEntry,
    ScopeExclusion,
    ToolInfo,
    decode_path,
    encode_path,
)


class PathEncodingTests(unittest.TestCase):
    def test_round_trip_non_utf8(self):
        raw = b"/data/\xff\xfe/name"
        self.assertEqual(decode_path(encode_path(raw)), raw)

    def test_display_is_lossless_for_humans(self):
        self.assertEqual(encode_path(b"/a/\xff")["display"], "/a/\\xff")

    def test_rejects_str(self):
        with self.assertRaises(ModelValidationError):
            encode_path("/data")  # type: ignore[arg-type]

    def test_decode_rejects_bad_base64(self):
        with self.assertRaises(ModelValidationError):
            decode_path({"b64": "not base64!"})

    def test_decode_rejects_non_canonical_path(self):
        # A hand-edited record must not smuggle in a non-canonical path.
        with self.assertRaises(ModelValidationError):
            decode_path(encode_path(b"/data/../etc"))


class DeviceIdentityTests(unittest.TestCase):
    def test_defaults_are_unknown_not_guessed(self):
        ident = DeviceIdentity(platform=Platform.ANDROID)
        d = ident.to_dict()
        self.assertEqual(d["lock_state"], "unknown")
        self.assertEqual(d["boot_state"], "unknown")
        self.assertEqual(d["is_emulator"], "unknown")
        self.assertIsNone(d["model"])

    def test_json_serializable(self):
        ident = DeviceIdentity(
            platform=Platform.ANDROID,
            model="sdk_gphone64",
            build_type="userdebug",
            lock_state=LockState.UNLOCKED,
            is_emulator=Tristate.YES,
            raw_responses=("identity/getprop.txt",),
        )
        json.dumps(ident.to_dict())

    def test_immutable(self):
        ident = DeviceIdentity(platform=Platform.IOS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ident.model = "x"  # type: ignore[misc]

    def test_rejects_empty_string_instead_of_unknown(self):
        with self.assertRaises(ModelValidationError):
            DeviceIdentity(platform=Platform.ANDROID, model="  ")

    def test_rejects_plain_string_enum(self):
        with self.assertRaises(ModelValidationError):
            DeviceIdentity(platform="android")  # type: ignore[arg-type]


class DeviceModificationTests(unittest.TestCase):
    def test_requires_description(self):
        with self.assertRaises(ModelValidationError):
            DeviceModification(declared_by="m", description="", risk_class=RiskClass.NONE)

    def test_to_dict(self):
        mod = DeviceModification(
            declared_by="android.emulator.adb_root_userdebug",
            description="adbd restarted as root",
            risk_class=RiskClass.STATE_CHANGE,
            reversible=Tristate.YES,
        )
        self.assertEqual(mod.to_dict()["risk_class"], "STATE_CHANGE")


class PlanTests(unittest.TestCase):
    def _plan(self, **kw):
        base = dict(
            acquisition_id="acq-1",
            method_id="android.emulator.adb_root_userdebug",
            planned_class=AcquisitionClass.PRIVILEGED_SELECTED_DIRECTORY,
            included_paths=(b"/data",),
            created_at=datetime(2026, 10, 16, 21, 0, 0, tzinfo=timezone.utc),
        )
        base.update(kw)
        return AcquisitionPlan(**base)

    def test_valid_plan(self):
        d = self._plan().to_dict()
        self.assertEqual(d["planned_class"], "PRIVILEGED_SELECTED_DIRECTORY")
        self.assertEqual(decode_path(d["included_paths"][0]), b"/data")
        self.assertEqual(d["created_at"], "2026-10-16T21:00:00.000000Z")

    def test_created_at_serialized_in_utc(self):
        est = timezone(timedelta(hours=-4))
        d = self._plan(created_at=datetime(2026, 10, 16, 17, 0, 0, tzinfo=est)).to_dict()
        self.assertEqual(d["created_at"], "2026-10-16T21:00:00.000000Z")

    def test_created_at_rejects_naive_datetime(self):
        with self.assertRaises(ModelValidationError):
            self._plan(created_at=datetime(2026, 10, 16, 21, 0, 0))

    def test_created_at_rejects_string(self):
        with self.assertRaises(ModelValidationError):
            self._plan(created_at="2026-10-16T21:00:00.000000Z")

    def test_rejects_non_canonical_paths(self):
        for bad in (b"/data/", b"//data", b"/data/./app", b"/data/../etc"):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    self._plan(included_paths=(bad,))

    def test_rejects_overlapping_paths(self):
        with self.assertRaises(ModelValidationError):
            self._plan(included_paths=(b"/data", b"/data/app"))

    def test_sibling_prefix_is_not_overlap(self):
        plan = self._plan(included_paths=(b"/data", b"/database"))
        self.assertEqual(len(plan.included_paths), 2)

    def test_exclusion_must_be_within_scope(self):
        with self.assertRaises(ModelValidationError):
            self._plan(
                exclusions=(ScopeExclusion(path=b"/proc", rule_id="PSEUDO_FS", reason="procfs"),)
            )

    def test_exclusion_must_not_equal_included_path(self):
        with self.assertRaises(ModelValidationError):
            self._plan(
                exclusions=(ScopeExclusion(path=b"/data", rule_id="R", reason="whole scope"),)
            )

    def test_duplicate_exclusions_rejected(self):
        ex = ScopeExclusion(path=b"/data/cache", rule_id="R", reason="x")
        with self.assertRaises(ModelValidationError):
            self._plan(exclusions=(ex, ex))

    def test_requires_paths(self):
        with self.assertRaises(ModelValidationError):
            self._plan(included_paths=())

    def test_rejects_relative_path(self):
        with self.assertRaises(ModelValidationError):
            self._plan(included_paths=(b"data",))

    def test_rejects_duplicate_paths(self):
        with self.assertRaises(ModelValidationError):
            self._plan(included_paths=(b"/data", b"/data"))

    def test_rejects_nul_in_path(self):
        with self.assertRaises(ModelValidationError):
            self._plan(included_paths=(b"/da\x00ta",))

    def test_exclusions_serialize(self):
        plan = self._plan(
            included_paths=(b"/",),
            exclusions=(ScopeExclusion(path=b"/proc", rule_id="PSEUDO_FS", reason="procfs"),),
        )
        self.assertEqual(plan.to_dict()["exclusions"][0]["rule_id"], "PSEUDO_FS")


class MountEntryTests(unittest.TestCase):
    def test_valid(self):
        m = MountEntry(
            source="/dev/block/dm-5", mount_point=b"/data", fs_type="ext4", options=("rw",)
        )
        self.assertEqual(m.to_dict()["fs_type"], "ext4")

    def test_options_must_be_tuple(self):
        with self.assertRaises(ModelValidationError):
            MountEntry(source="x", mount_point=b"/data", fs_type="ext4", options=["rw"])  # type: ignore[arg-type]


class EnumeratedEntryTests(unittest.TestCase):
    def test_unknown_values_are_none(self):
        e = EnumeratedEntry(path=b"/data/a", entry_type=EntryType.REGULAR)
        self.assertIsNone(e.to_dict()["mtime_ns"])

    def test_rejects_negative_size(self):
        with self.assertRaises(ModelValidationError):
            EnumeratedEntry(path=b"/data/a", entry_type=EntryType.REGULAR, size=-1)

    def test_rejects_bool_as_int(self):
        with self.assertRaises(ModelValidationError):
            EnumeratedEntry(path=b"/data/a", entry_type=EntryType.REGULAR, size=True)

    def test_pre_1970_timestamps_are_recorded_not_rejected(self):
        e = EnumeratedEntry(
            path=b"/data/a",
            entry_type=EntryType.REGULAR,
            mtime_ns=-1,
            atime_ns=-86_400_000_000_000,
            ctime_ns=0,
        )
        self.assertEqual(e.to_dict()["mtime_ns"], -1)

    def test_timestamps_reject_float(self):
        with self.assertRaises(ModelValidationError):
            EnumeratedEntry(path=b"/data/a", entry_type=EntryType.REGULAR, mtime_ns=1.5)

    def test_non_utf8_name_accepted(self):
        e = EnumeratedEntry(path=b"/data/\xff\xfe", entry_type=EntryType.REGULAR)
        self.assertEqual(e.path, b"/data/\xff\xfe")

    def test_root_path_accepted(self):
        EnumeratedEntry(path=b"/", entry_type=EntryType.DIRECTORY)


class ReconciliationTests(unittest.TestCase):
    def test_acquired_requires_reliability(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(path=b"/data/a", outcome=EntryOutcome.ACQUIRED)

    def test_non_acquired_must_not_carry_reliability(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(
                path=b"/data/a",
                outcome=EntryOutcome.ERROR,
                detail="can't open",
                content_reliability=ContentReliability.UNKNOWN,
            )

    def test_error_requires_detail(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(path=b"/data/a", outcome=EntryOutcome.ERROR)

    def test_unsupported_type_requires_detail(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(path=b"/data/s", outcome=EntryOutcome.UNSUPPORTED_TYPE)

    def test_excluded_requires_rule_id(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(path=b"/proc", outcome=EntryOutcome.EXCLUDED_BY_RULE)

    def test_rule_id_only_for_excluded(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(
                path=b"/data/a",
                outcome=EntryOutcome.ACQUIRED,
                content_reliability=ContentReliability.NO_CHANGE_DETECTED,
                rule_id="X",
            )

    def test_change_observed_mapping(self):
        cases = {
            ContentReliability.CHANGED_DURING_ACQUISITION: Tristate.YES,
            ContentReliability.NO_CHANGE_DETECTED: Tristate.NO,
            ContentReliability.UNKNOWN: Tristate.UNKNOWN,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                r = EntryReconciliation(
                    path=b"/data/db", outcome=EntryOutcome.ACQUIRED, content_reliability=value
                )
                self.assertIs(r.change_observed, expected)

    def test_change_observed_none_when_not_acquired(self):
        r = EntryReconciliation(path=b"/data/a", outcome=EntryOutcome.ERROR, detail="x")
        self.assertIsNone(r.change_observed)

    def test_no_reliability_certifying_api(self):
        # Nothing on the model may certify content as reliable (Section 5.2.1).
        names = [n for n in dir(EntryReconciliation) if "reliable" in n.lower()]
        self.assertEqual(names, [])

    def test_rejects_non_canonical_path(self):
        with self.assertRaises(ModelValidationError):
            EntryReconciliation(path=b"/data//a", outcome=EntryOutcome.ERROR, detail="x")

    def test_to_dict(self):
        r = EntryReconciliation(path=b"/data/s", outcome=EntryOutcome.UNSUPPORTED_TYPE, detail="socket")
        d = r.to_dict()
        self.assertEqual(d["outcome"], "UNSUPPORTED_TYPE")
        self.assertIsNone(d["content_reliability"])


class ToolInfoTests(unittest.TestCase):
    def test_sha256_format(self):
        with self.assertRaises(ModelValidationError):
            ToolInfo(name="adb", sha256="ABC")
        ToolInfo(name="adb", sha256="0" * 64)

    def test_uppercase_hex_rejected(self):
        with self.assertRaises(ModelValidationError):
            ToolInfo(name="adb", sha256="A" * 64)


if __name__ == "__main__":
    unittest.main()
