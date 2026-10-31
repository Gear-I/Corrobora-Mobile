import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from corrobora_mobile import __version__
from corrobora_mobile.audit import GENESIS_PREV, AuditLog
from corrobora_mobile.core.clock import FixedClock
from corrobora_mobile.core.errors import AuditLogError, ModelValidationError

CLOCK = FixedClock(datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc))
HOST = {"os": "test-host"}
MANIFEST = "ab" * 32


def read_lines(path: Path) -> list[bytes]:
    data = path.read_bytes()
    assert data.endswith(b"\n")
    return [line + b"\n" for line in data[:-1].split(b"\n")]


class AuditLogTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "audit.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def new_log(self, **kw):
        return AuditLog.create(self.path, acquisition_id="acq-1", clock=CLOCK, host=HOST, **kw)


class CreateTests(AuditLogTestCase):
    def test_session_start_is_line_zero(self):
        self.new_log().close()
        lines = read_lines(self.path)
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["seq"], 0)
        self.assertEqual(entry["type"], "SESSION_START")
        self.assertEqual(entry["prev"], GENESIS_PREV)
        self.assertEqual(entry["ts"], "2026-10-31T12:00:00.000000Z")
        data = entry["data"]
        self.assertEqual(data["acquisition_id"], "acq-1")
        self.assertEqual(data["tool_version"], __version__)
        self.assertIsNone(data["tool_commit"])
        self.assertEqual(data["host"], HOST)
        self.assertEqual(data["clock_source"], "fixed-test-clock")
        self.assertRegex(data["session_nonce"], r"^[0-9a-f]{32}$")  # 128 bits

    def test_nonce_differs_between_sessions(self):
        self.new_log().close()
        other = self.dir / "other.jsonl"
        AuditLog.create(other, acquisition_id="acq-1", clock=CLOCK, host=HOST).close()
        a = json.loads(read_lines(self.path)[0])["data"]["session_nonce"]
        b = json.loads(read_lines(other)[0])["data"]["session_nonce"]
        self.assertNotEqual(a, b)

    def test_refuses_existing_file(self):
        self.path.write_bytes(b"existing evidence\n")
        with self.assertRaises(AuditLogError):
            self.new_log()
        self.assertEqual(self.path.read_bytes(), b"existing evidence\n")

    def test_retry_of_recorded(self):
        self.new_log(retry_of="acq-0", tool_commit="abc123").close()
        data = json.loads(read_lines(self.path)[0])["data"]
        self.assertEqual(data["retry_of"], "acq-0")
        self.assertEqual(data["tool_commit"], "abc123")

    def test_default_host_info_collected(self):
        AuditLog.create(self.path, acquisition_id="acq-1", clock=CLOCK).close()
        host = json.loads(read_lines(self.path)[0])["data"]["host"]
        for key in ("hostname", "os", "machine", "python"):
            self.assertIn(key, host)

    def test_requires_acquisition_id(self):
        with self.assertRaises(ModelValidationError):
            AuditLog.create(self.path, acquisition_id=" ", clock=CLOCK, host=HOST)
        self.assertFalse(self.path.exists())


class ChainTests(AuditLogTestCase):
    def test_each_prev_is_sha256_of_previous_line(self):
        log = self.new_log()
        i = log.intent("adb root", {"command": ["adb", "root"]})
        log.result(i, succeeded=True, exit_status=0)
        log.chunk(stream="data/ffs.tar", index=0, offset=0, length=10, sha256="0" * 64)
        log.note("observation")
        head = log.seal(manifest_sha256=MANIFEST)

        lines = read_lines(self.path)
        expected_prev = GENESIS_PREV
        for seq, line in enumerate(lines):
            entry = json.loads(line)
            self.assertEqual(entry["seq"], seq)
            self.assertEqual(entry["prev"], expected_prev)
            expected_prev = hashlib.sha256(line).hexdigest()
        self.assertEqual(head, expected_prev)

    def test_lines_are_ascii_lf_terminated(self):
        log = self.new_log()
        log.note("unicode é \U0001f512")
        log.close()
        raw = self.path.read_bytes()
        raw.decode("ascii")  # ensure_ascii: no raw non-ASCII bytes
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_every_line_is_fsynced_before_returning(self):
        log = self.new_log()
        sizes_at_fsync = []
        real_fsync = __import__("os").fsync

        def recording_fsync(fd):
            sizes_at_fsync.append(self.path.stat().st_size)
            return real_fsync(fd)

        with mock.patch("corrobora_mobile.audit.log.os.fsync", side_effect=recording_fsync):
            i = log.intent("step")
            log.result(i, succeeded=True)
        log.close()
        # One fsync per line, each after that line's bytes reached the file.
        lines = read_lines(self.path)
        self.assertEqual(sizes_at_fsync, [sum(map(len, lines[:2])), sum(map(len, lines[:3]))])

    def test_chain_head_property_tracks_last_line(self):
        log = self.new_log()
        log.note("x")
        self.assertEqual(log.chain_head, hashlib.sha256(read_lines(self.path)[-1]).hexdigest())
        log.close()


class IntentResultTests(AuditLogTestCase):
    def test_result_closes_intent(self):
        log = self.new_log()
        i = log.intent("step")
        self.assertEqual(log.open_intents, {i: "step"})
        r = log.result(i, succeeded=False, exit_status=1, data={"stderr_ref": "errors/1.txt"})
        self.assertEqual(log.open_intents, {})
        entry = json.loads(read_lines(self.path)[r])
        self.assertEqual(entry["data"]["intent_seq"], i)
        self.assertIs(entry["data"]["succeeded"], False)
        self.assertEqual(entry["data"]["exit_status"], 1)
        log.close()

    def test_result_for_unknown_intent_rejected(self):
        log = self.new_log()
        with self.assertRaises(AuditLogError):
            log.result(99, succeeded=True)
        log.close()

    def test_result_cannot_close_twice(self):
        log = self.new_log()
        i = log.intent("step")
        log.result(i, succeeded=True)
        with self.assertRaises(AuditLogError):
            log.result(i, succeeded=True)
        log.close()

    def test_reserved_data_keys_rejected(self):
        log = self.new_log()
        with self.assertRaises(ModelValidationError):
            log.intent("step", {"action": "other"})
        i = log.intent("step")
        with self.assertRaises(ModelValidationError):
            log.result(i, succeeded=True, data={"intent_seq": 0})
        log.close()

    def test_bool_exit_status_rejected(self):
        log = self.new_log()
        i = log.intent("step")
        with self.assertRaises(ModelValidationError):
            log.result(i, succeeded=True, exit_status=True)
        log.close()

    def test_non_json_data_rejected_and_nothing_written(self):
        log = self.new_log()
        before = self.path.read_bytes()
        for bad in ({"x": b"bytes"}, {"x": float("nan")}, {"x": object()}):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    log.note("n", bad)
        self.assertEqual(self.path.read_bytes(), before)
        log.close()


class ChunkTests(AuditLogTestCase):
    def test_chunk_validation(self):
        log = self.new_log()
        with self.assertRaises(ModelValidationError):
            log.chunk(stream="s", index=0, offset=0, length=1, sha256="XYZ")
        with self.assertRaises(ModelValidationError):
            log.chunk(stream="s", index=-1, offset=0, length=1, sha256="0" * 64)
        log.close()


class SealTests(AuditLogTestCase):
    def test_seal_records_manifest_and_count(self):
        log = self.new_log()
        log.note("x")
        log.seal(manifest_sha256=MANIFEST)
        last = json.loads(read_lines(self.path)[-1])
        self.assertEqual(last["type"], "SEAL")
        self.assertEqual(last["data"], {"manifest_sha256": MANIFEST, "entry_count": 3})
        self.assertTrue(log.sealed)

    def test_seal_refused_with_open_intent(self):
        log = self.new_log()
        log.intent("unfinished")
        with self.assertRaises(AuditLogError):
            log.seal(manifest_sha256=MANIFEST)
        log.close()

    def test_nothing_after_seal(self):
        log = self.new_log()
        log.seal(manifest_sha256=MANIFEST)
        with self.assertRaisesRegex(AuditLogError, "sealed"):
            log.note("late")

    def test_seal_requires_hex_manifest(self):
        log = self.new_log()
        with self.assertRaises(ModelValidationError):
            log.seal(manifest_sha256="AB" * 32)
        log.close()

    def test_context_manager_never_seals(self):
        with self.assertRaises(RuntimeError):
            with self.new_log() as log:
                log.intent("step")
                raise RuntimeError("acquisition failed")
        types = [json.loads(line)["type"] for line in read_lines(self.path)]
        self.assertNotIn("SEAL", types)
        with self.assertRaises(AuditLogError):
            log.note("after close")


if __name__ == "__main__":
    unittest.main()
