import hashlib
import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from corrobora_mobile.audit import verify_audit_log
from corrobora_mobile.core.clock import FixedClock
from corrobora_mobile.core.enums import AuditLogState
from corrobora_mobile.core.errors import EvidencePackageError, IntegrityError, ModelValidationError
from corrobora_mobile.evidence import EvidencePackage, validate_acquisition_id, validate_package_path

CLOCK = FixedClock(datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc))
HOST = {"os": "test-host"}


def audit_entries(root: Path) -> list[dict]:
    return [json.loads(line) for line in (root / "audit.jsonl").read_bytes().splitlines()]


class PackageTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "evidence"

    def tearDown(self):
        # Finalized files are read-only; make them writable so cleanup works on Windows.
        for path in Path(self._tmp.name).rglob("*"):
            if path.is_file():
                path.chmod(stat.S_IWUSR | stat.S_IRUSR)
        self._tmp.cleanup()

    def new_package(self, acquisition_id="acq-1", chunk_size=4):
        return EvidencePackage.create(
            self.out, acquisition_id, chunk_size=chunk_size, clock=CLOCK, host=HOST
        )


class ValidationTests(unittest.TestCase):
    def test_acquisition_ids(self):
        for good in ("acq-1", "2026-10-31_case.7", "A" * 64):
            validate_acquisition_id(good)
        for bad in ("", ".hidden", "-x", "a/b", "a\\b", "..", "acq.", "CON", "nul.txt", "a" * 65, "caf\u00e9", "a b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    validate_acquisition_id(bad)

    def test_package_paths(self):
        for good in ("identity/getprop.txt", "data/ffs.tar", "errors/tar.stderr", "plan/a/b.json", "reconciliation.json"):
            self.assertEqual(validate_package_path(good), good)
        for bad in (
            "manifest.json", "audit.jsonl", "SEAL", "hashes/files.sha256", "other/x",
            "data", "data/", "/data/x", "data//x", "data/../SEAL", "data/./x", "data\\x",
            "C:/data/x", "data/COM1", "data/x.", "data/caf\u00e9", "",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    validate_package_path(bad)


class CreateTests(PackageTestCase):
    def test_creates_directory_and_audit_log(self):
        pkg = self.new_package()
        self.assertEqual(pkg.root, self.out / "acq-1")
        entries = audit_entries(pkg.root)
        self.assertEqual(entries[0]["type"], "SESSION_START")
        self.assertEqual(entries[0]["data"]["acquisition_id"], "acq-1")
        pkg.close()

    def test_refuses_existing_package(self):
        self.new_package().close()
        before = (self.out / "acq-1" / "audit.jsonl").read_bytes()
        with self.assertRaises(EvidencePackageError):
            self.new_package()
        self.assertEqual((self.out / "acq-1" / "audit.jsonl").read_bytes(), before)

    def test_invalid_chunk_size(self):
        with self.assertRaises(ModelValidationError):
            self.new_package(chunk_size=0)
        self.assertFalse((self.out / "acq-1").exists())


class ArtifactTests(PackageTestCase):
    def test_write_artifact_records_and_audits(self):
        pkg = self.new_package()
        rec = pkg.write_artifact("identity/getprop.txt", b"ro.build.type=userdebug\n", description="getprop")
        self.assertEqual((pkg.root / "identity" / "getprop.txt").read_bytes(), b"ro.build.type=userdebug\n")
        self.assertEqual(rec.sha256, hashlib.sha256(b"ro.build.type=userdebug\n").hexdigest())
        self.assertTrue(rec.complete)
        intent, result = audit_entries(pkg.root)[1:3]
        self.assertEqual((intent["type"], intent["data"]["path"]), ("INTENT", "identity/getprop.txt"))
        self.assertEqual(result["data"]["sha256"], rec.sha256)
        self.assertTrue(result["data"]["succeeded"])
        pkg.close()

    def test_never_writes_a_path_twice(self):
        pkg = self.new_package()
        pkg.write_artifact("plan/plan.json", b"{}", description="plan")
        with self.assertRaises(EvidencePackageError):
            pkg.write_artifact("plan/plan.json", b"{changed}", description="plan")
        self.assertEqual((pkg.root / "plan" / "plan.json").read_bytes(), b"{}")
        pkg.close()

    def test_existing_file_on_disk_is_not_overwritten(self):
        pkg = self.new_package()
        (pkg.root / "errors").mkdir()
        (pkg.root / "errors" / "x.txt").write_bytes(b"planted")
        with self.assertRaises(FileExistsError):
            pkg.write_artifact("errors/x.txt", b"new", description="x")
        self.assertEqual((pkg.root / "errors" / "x.txt").read_bytes(), b"planted")
        entries = audit_entries(pkg.root)
        self.assertFalse(entries[-1]["data"]["succeeded"])
        pkg.close()


class StreamTests(PackageTestCase):
    def test_stream_chunks_logged_and_verified(self):
        pkg = self.new_package(chunk_size=4)
        with pkg.open_stream("data/ffs.tar", description="tar") as s:
            s.write(b"0123")
            s.write(b"456789")
        rec = pkg.records[0]
        self.assertTrue(rec.complete)
        self.assertEqual(rec.sha256, hashlib.sha256(b"0123456789").hexdigest())
        chunks = [e["data"] for e in audit_entries(pkg.root) if e["type"] == "CHUNK"]
        self.assertEqual([(c["index"], c["offset"], c["length"]) for c in chunks], [(0, 0, 4), (1, 4, 4), (2, 8, 2)])
        self.assertEqual([c["sha256"] for c in chunks], [c.sha256 for c in rec.chunks])
        result = audit_entries(pkg.root)[-1]
        self.assertTrue(result["data"]["verified_from_disk"])
        pkg.close()

    def test_chunk_is_durable_before_it_is_logged(self):
        pkg = self.new_package(chunk_size=4)
        s = pkg.open_stream("data/ffs.tar", description="tar")
        stream_fd = s._fh.fileno()
        events = []
        real_chunk = pkg.audit.chunk
        real_fsync = __import__("os").fsync

        def logged_chunk(**kw):
            events.append(("chunk", kw["index"]))
            return real_chunk(**kw)

        def recording_fsync(fd):
            # os.fsync is process-wide; count only the stream file's own fsyncs.
            if fd == stream_fd:
                events.append(("fsync", None))
            return real_fsync(fd)

        with mock.patch.object(pkg.audit, "chunk", side_effect=logged_chunk), \
             mock.patch("corrobora_mobile.evidence.package.os.fsync", side_effect=recording_fsync):
            s.write(b"01234567")
        self.assertEqual(events, [("fsync", None), ("chunk", 0), ("fsync", None), ("chunk", 1)])
        s.close()
        pkg.close()

    def test_disk_mismatch_raises_integrity_error(self):
        pkg = self.new_package()
        s = pkg.open_stream("data/ffs.tar", description="tar")
        s.write(b"abcdef")
        s._fh.flush()
        with open(pkg.root / "data" / "ffs.tar", "ab") as other:  # simulated corruption
            other.write(b"X")
        with self.assertRaises(IntegrityError):
            s.close()
        rec = pkg.records[0]
        self.assertFalse(rec.complete)
        self.assertEqual(rec.size, 7)  # recorded as found on disk
        last = audit_entries(pkg.root)[-1]
        self.assertFalse(last["data"]["succeeded"])
        self.assertIn("differs", last["data"]["error"])
        pkg.close()

    def test_exception_keeps_partial_stream_as_incomplete(self):
        pkg = self.new_package(chunk_size=4)
        with self.assertRaises(RuntimeError):
            with pkg.open_stream("data/ffs.tar", description="tar") as s:
                s.write(b"012345")
                raise RuntimeError("transport lost")
        rec = pkg.records[0]
        self.assertEqual((rec.complete, rec.size), (False, 6))
        self.assertEqual((pkg.root / "data" / "ffs.tar").read_bytes(), b"012345")
        last = audit_entries(pkg.root)[-1]
        self.assertEqual(last["type"], "RESULT")
        self.assertFalse(last["data"]["succeeded"])
        self.assertIn("transport lost", last["data"]["error"])
        self.assertTrue(last["data"]["matches_streamed"])
        # The partial final chunk is logged, so the received prefix is verifiable.
        chunks = [e["data"] for e in audit_entries(pkg.root) if e["type"] == "CHUNK"]
        self.assertEqual([c["length"] for c in chunks], [4, 2])
        pkg.close()

    def test_close_aborts_open_streams_and_leaves_package_unsealed(self):
        pkg = self.new_package()
        s = pkg.open_stream("data/ffs.tar", description="tar")
        s.write(b"abc")
        pkg.close()
        self.assertFalse(pkg.records[0].complete)
        self.assertTrue((pkg.root / "data" / "ffs.tar").exists())  # never deleted
        self.assertFalse((pkg.root / "SEAL").exists())
        r = verify_audit_log(pkg.root / "audit.jsonl")
        self.assertIs(r.state, AuditLogState.UNSEALED)
        self.assertEqual(r.open_intents, ())
        with self.assertRaises(EvidencePackageError):
            s.write(b"more")

    def test_same_path_cannot_be_opened_twice(self):
        pkg = self.new_package()
        pkg.open_stream("data/ffs.tar", description="tar")
        with self.assertRaises(EvidencePackageError):
            pkg.open_stream("data/ffs.tar", description="tar")
        pkg.close()


class FinalizeTests(PackageTestCase):
    def build(self):
        pkg = self.new_package(chunk_size=4)
        pkg.write_artifact("identity/getprop.txt", b"ro.build.type=userdebug\n", description="getprop")
        with pkg.open_stream("data/ffs.tar", description="tar") as s:
            s.write(b"0123456789")
        return pkg, pkg.finalize({"acquisition_class": {"planned": "PRIVILEGED_SELECTED_DIRECTORY"}})

    def test_seal_file_and_audit_log_agree(self):
        pkg, fin = self.build()
        self.assertEqual(
            (fin.root / "SEAL").read_text(encoding="ascii"),
            f"chain_head {fin.chain_head}\nmanifest_sha256 {fin.manifest_sha256}\n",
        )
        self.assertEqual(hashlib.sha256((fin.root / "manifest.json").read_bytes()).hexdigest(), fin.manifest_sha256)
        r = verify_audit_log(
            fin.root / "audit.jsonl",
            expected_chain_head=fin.chain_head,
            expected_manifest_sha256=fin.manifest_sha256,
        )
        self.assertIs(r.state, AuditLogState.SEALED)
        self.assertEqual(fin.readonly_failures, ())

    def test_manifest_contents(self):
        pkg, fin = self.build()
        manifest = json.loads((fin.root / "manifest.json").read_bytes())
        self.assertEqual(manifest["format"], "corrobora-mobile/evidence-package")
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["acquisition_id"], "acq-1")
        self.assertEqual(manifest["chunk_size"], 4)
        self.assertEqual(manifest["content"], {"acquisition_class": {"planned": "PRIVILEGED_SELECTED_DIRECTORY"}})
        paths = [f["path"] for f in manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(
            set(paths),
            {"identity/getprop.txt", "data/ffs.tar", "hashes/files.sha256", "hashes/chunks.sha256"},
        )

    def test_files_sha256_is_checkable_independently(self):
        pkg, fin = self.build()
        lines = (fin.root / "hashes" / "files.sha256").read_text(encoding="ascii").splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            digest, rel = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((fin.root / rel).read_bytes()).hexdigest(), digest)

    def test_chunks_file(self):
        pkg, fin = self.build()
        rows = (fin.root / "hashes" / "chunks.sha256").read_text(encoding="ascii").splitlines()
        self.assertEqual(rows[0], "# path\tindex\toffset\tlength\tsha256")
        data = (fin.root / "data" / "ffs.tar").read_bytes()
        for row in rows[1:]:
            path, index, offset, length, digest = row.split("\t")
            self.assertEqual(path, "data/ffs.tar")
            chunk = data[int(offset) : int(offset) + int(length)]
            self.assertEqual(hashlib.sha256(chunk).hexdigest(), digest)

    def test_files_are_read_only_after_finalize(self):
        pkg, fin = self.build()
        for path in fin.root.rglob("*"):
            if path.is_file():
                with self.subTest(path=path.name):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o222, 0)

    def test_nothing_after_finalize(self):
        pkg, fin = self.build()
        with self.assertRaises(EvidencePackageError):
            pkg.write_artifact("errors/late.txt", b"x", description="late")
        with self.assertRaises(EvidencePackageError):
            pkg.finalize({})

    def test_refuses_with_open_stream(self):
        pkg = self.new_package()
        pkg.open_stream("data/ffs.tar", description="tar")
        with self.assertRaisesRegex(EvidencePackageError, "streams still open"):
            pkg.finalize({})
        pkg.close()

    def test_bad_manifest_content_writes_nothing(self):
        pkg = self.new_package()
        before = sorted(p.relative_to(pkg.root) for p in pkg.root.rglob("*"))
        with self.assertRaises(ModelValidationError):
            pkg.finalize({"x": float("nan")})
        self.assertEqual(sorted(p.relative_to(pkg.root) for p in pkg.root.rglob("*")), before)
        pkg.close()

    def test_incomplete_stream_is_listed_as_incomplete(self):
        pkg = self.new_package()
        with self.assertRaises(RuntimeError):
            with pkg.open_stream("data/ffs.tar", description="tar") as s:
                s.write(b"ab")
                raise RuntimeError("stop")
        fin = pkg.finalize({})
        files = {f["path"]: f for f in json.loads((fin.root / "manifest.json").read_bytes())["files"]}
        self.assertFalse(files["data/ffs.tar"]["complete"])


if __name__ == "__main__":
    unittest.main()
