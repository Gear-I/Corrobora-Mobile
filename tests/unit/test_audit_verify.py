import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from corrobora_mobile.audit import AuditLog, verify_audit_log
from corrobora_mobile.core.enums import AuditLogState
from corrobora_mobile.core.errors import IntegrityError, ModelValidationError

T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
HOST = {"os": "test-host"}
MANIFEST = "cd" * 32


class StepClock:
    """Advances one second per call, or follows a given list of instants."""

    source = "step-test-clock"

    def __init__(self, instants=None):
        self._instants = list(instants) if instants else None
        self._n = 0

    def now(self):
        if self._instants is not None:
            value = self._instants[self._n]
        else:
            value = T0 + timedelta(seconds=self._n)
        self._n += 1
        return value


class VerifyTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "audit.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def sealed_log(self):
        log = AuditLog.create(self.path, acquisition_id="acq-1", clock=StepClock(), host=HOST)
        i = log.intent("adb root")
        log.result(i, succeeded=True, exit_status=0)
        log.chunk(stream="data/ffs.tar", index=0, offset=0, length=4, sha256="0" * 64)
        return log.seal(manifest_sha256=MANIFEST)

    def lines(self):
        return self.path.read_bytes().split(b"\n")[:-1]

    def write_lines(self, lines, tail=b""):
        self.path.write_bytes(b"\n".join(lines) + b"\n" + tail)

    def rewrite_entry(self, index, mutate):
        """Edit one entry's JSON (re-serialized), leaving other bytes alone."""
        lines = self.lines()
        obj = json.loads(lines[index])
        mutate(obj)
        lines[index] = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        self.write_lines(lines)


class SealedTests(VerifyTestCase):
    def test_sealed_log_verifies(self):
        head = self.sealed_log()
        r = verify_audit_log(self.path, expected_chain_head=head, expected_manifest_sha256=MANIFEST)
        self.assertIs(r.state, AuditLogState.SEALED)
        self.assertEqual(r.entry_count, 5)
        self.assertEqual(r.chain_head, head)
        self.assertEqual(r.sealed_manifest_sha256, MANIFEST)
        self.assertTrue(r.anchor_checked)
        self.assertTrue(r.manifest_checked)
        self.assertEqual(r.open_intents, ())
        self.assertEqual(r.last_completed_seq, 2)
        self.assertEqual((r.errors, r.warnings), ((), ()))
        r.raise_if_broken()

    def test_verification_does_not_modify_file(self):
        self.sealed_log()
        before = self.path.read_bytes()
        verify_audit_log(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_without_anchor_result_says_so(self):
        self.sealed_log()
        r = verify_audit_log(self.path)
        self.assertIs(r.state, AuditLogState.SEALED)
        self.assertFalse(r.anchor_checked)
        self.assertFalse(r.manifest_checked)

    def test_independent_recomputation_matches(self):
        # The chain can be checked with nothing but hashlib (Section 5.7).
        head = self.sealed_log()
        prev = "0" * 64
        for line in self.lines():
            self.assertEqual(json.loads(line)["prev"], prev)
            prev = hashlib.sha256(line + b"\n").hexdigest()
        self.assertEqual(prev, head)


class TamperTests(VerifyTestCase):
    def assertBroken(self, r, fragment):
        self.assertIs(r.state, AuditLogState.BROKEN)
        self.assertTrue(any(fragment in e for e in r.errors), r.errors)
        with self.assertRaises(IntegrityError):
            r.raise_if_broken()

    def test_edited_middle_entry_detected(self):
        self.sealed_log()
        self.rewrite_entry(2, lambda o: o["data"].update(exit_status=1))
        self.assertBroken(verify_audit_log(self.path), "line 3: prev")

    def test_single_byte_flip_detected(self):
        self.sealed_log()
        raw = bytearray(self.path.read_bytes())
        pos = raw.index(b"adb root")
        raw[pos] = ord("A")
        self.path.write_bytes(bytes(raw))
        self.assertBroken(verify_audit_log(self.path), "line 2: prev")

    def test_deleted_line_detected(self):
        self.sealed_log()
        lines = self.lines()
        del lines[2]
        self.write_lines(lines)
        self.assertBroken(verify_audit_log(self.path), "seq 3 (expected 2)")

    def test_swapped_lines_detected(self):
        self.sealed_log()
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.write_lines(lines)
        self.assertBroken(verify_audit_log(self.path), "line 1")

    def test_line_after_seal_detected(self):
        self.sealed_log()
        lines = self.lines()
        lines.append(lines[-1])
        self.write_lines(lines)
        self.assertBroken(verify_audit_log(self.path), "entry after SEAL")

    def test_bytes_after_seal_detected(self):
        self.sealed_log()
        self.path.write_bytes(self.path.read_bytes() + b"{partial")
        self.assertBroken(verify_audit_log(self.path), "bytes after SEAL")

    def test_crlf_conversion_detected(self):
        self.sealed_log()
        self.path.write_bytes(self.path.read_bytes().replace(b"\n", b"\r\n"))
        self.assertBroken(verify_audit_log(self.path), "carriage return")

    def test_wrong_external_chain_head_detected(self):
        self.sealed_log()
        self.assertBroken(verify_audit_log(self.path, expected_chain_head="f" * 64), "chain head")

    def test_wrong_manifest_detected(self):
        self.sealed_log()
        self.assertBroken(
            verify_audit_log(self.path, expected_manifest_sha256="e" * 64), "manifest SHA-256"
        )

    def test_malformed_entries_detected(self):
        cases = {
            "non-canonical ts": (1, lambda o: o.update(ts="2026-10-31T12:00:01Z"), "canonical"),
            "unknown type": (1, lambda o: o.update(type="DELETE"), "unknown type"),
            "extra key": (1, lambda o: o.update(extra=1), "keys"),
            "data not object": (1, lambda o: o.update(data=[]), "data is not an object"),
            "seq not int": (1, lambda o: o.update(seq="1"), "seq is not an integer"),
            "second session start": (1, lambda o: o.update(type="SESSION_START"), "SESSION_START"),
        }
        for name, (index, mutate, fragment) in cases.items():
            with self.subTest(case=name):
                self.path.unlink(missing_ok=True)
                self.sealed_log()
                self.rewrite_entry(index, mutate)
                self.assertBroken(verify_audit_log(self.path), fragment)

    def test_invalid_json_constructs_rejected(self):
        for name, body, fragment in (
            ("NaN", b'{"seq":0,"ts":"x","type":"NOTE","data":{"v":NaN},"prev":"0"}', "NaN"),
            ("duplicate", b'{"seq":0,"seq":0,"ts":"x","type":"NOTE","data":{},"prev":"0"}', "duplicate"),
            ("not utf-8", b'{"seq":0,"data":"\xff"}', "not valid JSON"),
        ):
            with self.subTest(case=name):
                self.path.write_bytes(body + b"\n")
                self.assertBroken(verify_audit_log(self.path), fragment)

    def test_result_without_intent_detected(self):
        self.sealed_log()
        self.rewrite_entry(2, lambda o: o["data"].update(intent_seq=0))
        # Re-serializing line 2 also breaks line 3's prev, but line 2 fails first.
        self.assertBroken(verify_audit_log(self.path), "line 2: RESULT does not close an open INTENT")

    def test_empty_file_is_broken(self):
        self.path.write_bytes(b"")
        self.assertBroken(verify_audit_log(self.path), "SESSION_START missing")


class InterruptionTests(VerifyTestCase):
    def test_interrupted_during_action(self):
        log = AuditLog.create(self.path, acquisition_id="acq-1", clock=StepClock(), host=HOST)
        a = log.intent("adb root")
        log.result(a, succeeded=True, exit_status=0)
        log.intent("stream /data")
        log.chunk(stream="data/ffs.tar", index=0, offset=0, length=4, sha256="0" * 64)
        log.close()  # simulated crash: no RESULT, no SEAL
        r = verify_audit_log(self.path)
        self.assertIs(r.state, AuditLogState.UNSEALED)
        self.assertEqual([(o.seq, o.action) for o in r.open_intents], [(3, "stream /data")])
        self.assertEqual(r.last_completed_seq, 2)
        self.assertIsNone(r.sealed_manifest_sha256)
        r.raise_if_broken()  # UNSEALED is not an integrity failure

    def test_torn_final_line_reported_not_repaired(self):
        log = AuditLog.create(self.path, acquisition_id="acq-1", clock=StepClock(), host=HOST)
        log.intent("stream /data")
        log.close()
        self.path.write_bytes(self.path.read_bytes() + b'{"seq":2,"ts":"2026-')
        before = self.path.read_bytes()
        r = verify_audit_log(self.path)
        self.assertIs(r.state, AuditLogState.UNSEALED)
        self.assertEqual(r.entry_count, 2)
        self.assertEqual(r.torn_tail_bytes, 20)
        self.assertTrue(any("torn final line" in w for w in r.warnings))
        self.assertEqual(self.path.read_bytes(), before)

    def test_only_torn_first_line_is_broken(self):
        self.path.write_bytes(b'{"seq":0,"ts')
        r = verify_audit_log(self.path)
        self.assertIs(r.state, AuditLogState.BROKEN)


class AnchorLimitTests(VerifyTestCase):
    """Documents what the chain alone cannot detect (module docstring)."""

    def test_removed_seal_looks_unsealed_without_anchor(self):
        head = self.sealed_log()
        self.write_lines(self.lines()[:-1])
        self.assertIs(verify_audit_log(self.path).state, AuditLogState.UNSEALED)
        r = verify_audit_log(self.path, expected_chain_head=head)
        self.assertIs(r.state, AuditLogState.BROKEN)

    def test_edited_last_line_undetected_without_anchor(self):
        log = AuditLog.create(self.path, acquisition_id="acq-1", clock=StepClock(), host=HOST)
        log.note("original")
        head = log.chain_head
        log.close()
        self.rewrite_entry(1, lambda o: o["data"].update(message="edited"))
        self.assertIs(verify_audit_log(self.path).state, AuditLogState.UNSEALED)
        self.assertIs(
            verify_audit_log(self.path, expected_chain_head=head).state, AuditLogState.BROKEN
        )


class WarningTests(VerifyTestCase):
    def test_clock_going_backwards_is_a_warning_not_an_error(self):
        clock = StepClock([T0, T0 - timedelta(seconds=5), T0])
        log = AuditLog.create(self.path, acquisition_id="acq-1", clock=clock, host=HOST)
        log.note("a")
        log.close()
        r = verify_audit_log(self.path)
        self.assertIs(r.state, AuditLogState.UNSEALED)
        self.assertTrue(any("timestamp earlier" in w for w in r.warnings))

    def test_rejects_malformed_expected_values(self):
        self.sealed_log()
        with self.assertRaises(ModelValidationError):
            verify_audit_log(self.path, expected_chain_head="F" * 64)


if __name__ == "__main__":
    unittest.main()
