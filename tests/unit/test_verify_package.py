"""Tests for tools/verify_package.py.

Packages are built with the real writer (corrobora_mobile.evidence); the
verifier itself never imports corrobora_mobile. All data is synthetic.
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.evidence import EvidencePackage

TOOL = Path(__file__).resolve().parents[2] / "tools" / "verify_package.py"
_spec = importlib.util.spec_from_file_location("verify_package", TOOL)
vp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = vp  # dataclasses need the module registered
_spec.loader.exec_module(vp)

STREAM = bytes(range(256)) * 5  # 1280 bytes: with 300-byte chunks, 4 full chunks and one of 80


def _writable(root: Path) -> None:
    for p in root.rglob("*"):
        try:
            p.chmod(0o700 if p.is_dir() else 0o600)
        except OSError:
            pass


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.addCleanup(_writable, self.tmp)

    def build(self, *, content=None, stream=STREAM, chunk_size=300, out="out"):
        pkg = EvidencePackage.create(self.tmp / out, "acq-1", chunk_size=chunk_size)
        pkg.write_artifact("plan/plan.json", b'{"scope": ["/data"]}', description="plan")
        with pkg.open_stream("data/ffs.tar", description="archive") as s:
            s.write(stream)
        fin = pkg.finalize(content if content is not None else {
            "completeness_status": "COMPLETE", "method_validation_status": "UNVERIFIED"})
        _writable(fin.root)  # so tests can tamper; the verifier only reads
        return fin

    def verify(self, root, **kw):
        return vp.verify(root, **kw)

    def assertFailsWith(self, report, text):
        self.assertEqual(report.integrity, "FAIL", report.failures)
        self.assertTrue(any(text in f for f in report.failures), report.failures)


class SealedPackageTests(Base):
    def test_untouched_package_passes_integrity(self):
        fin = self.build()
        r = self.verify(fin.root)
        self.assertEqual((r.integrity, r.audit_state), ("PASS", "SEALED"), r.failures)
        self.assertEqual(r.chain_head, fin.chain_head)
        self.assertTrue(any("not compared with an external record" in n for n in r.notes))

    def test_external_chain_head(self):
        fin = self.build()
        self.assertEqual(self.verify(fin.root, expected_chain_head=fin.chain_head).integrity, "PASS")
        r = self.verify(fin.root, expected_chain_head="0" * 64)
        self.assertFailsWith(r, "externally recorded")

    def test_one_byte_change_in_data_fails(self):
        fin = self.build()
        p = fin.root / "data" / "ffs.tar"
        b = bytearray(p.read_bytes()); b[700] ^= 1; p.write_bytes(bytes(b))
        r = self.verify(fin.root)
        self.assertFailsWith(r, "data/ffs.tar: SHA-256 differs from manifest")
        self.assertTrue(any("chunk 2 SHA-256 differs" in f for f in r.failures))

    def test_changed_artifact_fails(self):
        fin = self.build()
        (fin.root / "plan" / "plan.json").write_bytes(b'{"scope": ["/DATA"]}')
        self.assertFailsWith(self.verify(fin.root), "plan/plan.json")

    def test_edited_manifest_fails(self):
        fin = self.build()
        p = fin.root / "manifest.json"
        p.write_bytes(p.read_bytes().replace(b'"COMPLETE"', b'"COMPLETF"'))
        self.assertFailsWith(self.verify(fin.root), "manifest.json SHA-256 does not match")

    def test_edited_hash_lists_fail(self):
        for rel, needle in (("hashes/files.sha256", "hashes/files.sha256: SHA-256 differs from manifest"),
                            ("hashes/chunks.sha256", "hashes/chunks.sha256: SHA-256 differs from manifest")):
            with self.subTest(rel=rel):
                fin = self.build(out=rel.replace("/", "_"))
                p = fin.root / rel
                text = p.read_bytes()
                digit = text.index(b"\t0\t" if "chunks" in rel else b"  ") - 1
                b = bytearray(text); b[digit] = ord("0") if b[digit] != ord("0") else ord("1")
                p.write_bytes(bytes(b))
                self.assertFailsWith(self.verify(fin.root), needle)

    def test_edited_audit_line_is_broken(self):
        fin = self.build()
        p = fin.root / "audit.jsonl"
        p.write_bytes(p.read_bytes().replace(b'"description":"plan"', b'"description":"PLAN"'))
        r = self.verify(fin.root)
        self.assertEqual(r.audit_state, "BROKEN")
        self.assertFailsWith(r, "prev does not match")

    def test_rechained_log_with_seq_gap_is_broken(self):
        # A forger who removes a line and recomputes every prev still leaves a seq gap.
        fin = self.build()
        p = fin.root / "audit.jsonl"
        objs = [json.loads(line) for line in p.read_bytes().splitlines()]
        del objs[1]
        prev, out = "0" * 64, b""
        for o in objs:
            o["prev"] = prev
            line = json.dumps(o, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            out += line
            prev = hashlib.sha256(line).hexdigest()
        p.write_bytes(out)
        r = self.verify(fin.root)
        self.assertEqual(r.audit_state, "BROKEN")
        self.assertFailsWith(r, "seq 2, expected 1")

    def test_files_list_entry_must_match_disk(self):
        # In a consistent package this check is redundant with the manifest check,
        # so it is exercised directly.
        fin = self.build()
        report = vp.Report(package="x")
        listed = {"data/ffs.tar": {"kind": "stream"}, "plan/plan.json": {"kind": "artifact"},
                  "hashes/files.sha256": {"kind": "package"}}
        disk = {"data/ffs.tar": "0" * 64, "plan/plan.json": hashlib.sha256(b'{"scope": ["/data"]}').hexdigest(),
                "hashes/files.sha256": "x"}
        vp.verify_files_sha256(fin.root, listed, disk, report)
        self.assertEqual(report.failures, ["hashes/files.sha256: data/ffs.tar SHA-256 differs from the file on disk"])

    def test_edited_seal_file_fails(self):
        fin = self.build()
        (fin.root / "SEAL").write_bytes(b"chain_head " + b"0" * 64 + b"\nmanifest_sha256 " + b"0" * 64 + b"\n")
        self.assertFailsWith(self.verify(fin.root), "SEAL file does not match")

    def test_removed_seal_line_detected(self):
        fin = self.build()
        p = fin.root / "audit.jsonl"
        p.write_bytes(b"".join(p.read_bytes().splitlines(keepends=True)[:-1]))
        r = self.verify(fin.root)
        self.assertEqual(r.audit_state, "UNSEALED")
        self.assertFailsWith(r, "SEAL file present but the audit log has no SEAL entry")

    def test_bytes_after_seal_are_broken(self):
        fin = self.build()
        with open(fin.root / "audit.jsonl", "ab") as f:
            f.write(b"{}")
        self.assertEqual(self.verify(fin.root).audit_state, "BROKEN")

    def test_extra_and_missing_files_fail(self):
        fin = self.build()
        (fin.root / "data" / "extra.bin").write_bytes(b"x")
        self.assertFailsWith(self.verify(fin.root), "data/extra.bin: file not listed")
        (fin.root / "data" / "extra.bin").unlink()
        (fin.root / "plan" / "plan.json").unlink()
        self.assertFailsWith(self.verify(fin.root), "plan/plan.json: listed in manifest but missing")

    def test_missing_hash_list_is_a_failure_not_a_crash(self):
        fin = self.build()
        (fin.root / "hashes" / "chunks.sha256").unlink()
        self.assertFailsWith(self.verify(fin.root), "chunks.sha256")

    def test_unsafe_manifest_path_rejected(self):
        self.assertFalse(vp.safe_relpath("../x"))
        self.assertFalse(vp.safe_relpath("/etc/passwd"))
        self.assertFalse(vp.safe_relpath("a\\b"))
        self.assertTrue(vp.safe_relpath("data/ffs.tar"))


class InterruptedPackageTests(Base):
    def interrupted(self, chunks=3):
        """Simulate a crash: a child process writes part of a stream, then exits abruptly.

        The operating system closes the child's files, as in a real crash, so
        nothing stays open in this process (Windows cannot delete open files).
        """
        out = self.tmp / "out"
        child = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "from corrobora_mobile.evidence import EvidencePackage\n"
            "pkg = EvidencePackage.create(Path(sys.argv[1]), 'acq-2', chunk_size=256)\n"
            "stream = pkg.open_stream('data/ffs.tar', description='archive')\n"
            "stream.write(bytes.fromhex(sys.argv[2]))\n"
            "os._exit(137)\n"
        )
        proc = subprocess.run([sys.executable, "-c", child, str(out), STREAM[: 256 * chunks + 100].hex()],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 137, proc.stderr)
        root = out / "acq-2"
        _writable(root)
        return root

    def test_unsealed_package_is_incomplete_with_verified_prefix(self):
        r = self.verify(self.interrupted())
        self.assertEqual((r.integrity, r.audit_state), ("INCOMPLETE", "UNSEALED"), r.failures)
        self.assertEqual(r.interrupted["chunks_verified"], 3)
        self.assertEqual([i["action"] for i in r.interrupted["open_intents"]], ["capture stream"])

    def test_torn_final_line_reported_not_repaired(self):
        root = self.interrupted()
        before = (root / "audit.jsonl").read_bytes()
        with open(root / "audit.jsonl", "ab") as f:
            f.write(b'{"seq":')
        r = self.verify(root)
        self.assertEqual(r.integrity, "INCOMPLETE")
        self.assertEqual(r.interrupted["torn_final_line_bytes"], 7)
        self.assertEqual((root / "audit.jsonl").read_bytes(), before + b'{"seq":')

    def test_corrupted_prefix_fails(self):
        root = self.interrupted()
        p = root / "data" / "ffs.tar"
        b = bytearray(p.read_bytes()); b[10] ^= 1; p.write_bytes(bytes(b))
        r = self.verify(root)
        self.assertFailsWith(r, "logged chunk 0 does not match")


class FindingsAndExitCodeTests(Base):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                              capture_output=True, text=True, timeout=120)

    def test_findings_are_separate_and_exit_code_is_a_bit_field(self):
        fin = self.build()
        proc = self.run_tool(fin.root, "--chain-head", fin.chain_head)
        self.assertEqual(proc.returncode, 2 | 4, proc.stdout + proc.stderr)  # integrity PASS
        self.assertIn("INTEGRITY:     PASS", proc.stdout)
        self.assertIn("COMPLETENESS:  NOT RECOMPUTED (recorded: COMPLETE)", proc.stdout)
        self.assertIn("method UNVERIFIED", proc.stdout)
        self.assertIn("Forensic validation is not assessed by this tool.", proc.stdout)

    def test_integrity_failure_sets_bit_1(self):
        fin = self.build()
        (fin.root / "data" / "ffs.tar").write_bytes(b"x")
        self.assertEqual(self.run_tool(fin.root).returncode, 1 | 2 | 4)

    def test_verified_status_clears_bit_4_but_completeness_bit_stays(self):
        fin = self.build(content={"completeness_status": "COMPLETE", "method_validation_status": "VERIFIED"})
        self.assertEqual(self.run_tool(fin.root).returncode, 2)

    def test_completeness_bit_set_unless_recomputed_as_complete(self):
        for completeness, bit in (({"recomputed": False, "status": "COMPLETE"}, 2),
                                  ({"recomputed": True, "status": "PARTIAL"}, 2),
                                  ({"recomputed": True, "status": "COMPLETE_WITH_CHANGES"}, 0),
                                  ({"recomputed": True, "status": "COMPLETE"}, 0)):
            with self.subTest(completeness=completeness):
                r = vp.Report(package="x", completeness=completeness,
                              validation={"recorded_status": "VERIFIED"})
                self.assertEqual(r.exit_code(), bit)

    def test_usage_errors_use_bit_8_only(self):
        self.assertEqual(self.run_tool(self.tmp / "absent").returncode, 8)
        self.assertEqual(self.run_tool(self.tmp, "--chain-head", "xyz").returncode, 8)

    def test_json_report_refused_inside_package(self):
        fin = self.build()
        self.assertEqual(self.run_tool(fin.root, "--json", fin.root / "r.json").returncode, 8)
        out = self.tmp / "report.json"
        proc = self.run_tool(fin.root, "--json", out)
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["integrity"]["result"], "PASS")
        self.assertEqual(report["exit_code"], proc.returncode)
        self.assertFalse(report["completeness"]["recomputed"])

    def test_verifier_does_not_modify_the_package(self):
        fin = self.build()
        def snapshot():
            return {p.relative_to(fin.root).as_posix(): (hashlib.sha256(p.read_bytes()).hexdigest(),
                                                         p.stat().st_mtime_ns)
                    for p in fin.root.rglob("*") if p.is_file()}
        before = snapshot()
        self.run_tool(fin.root, "--json", self.tmp / "r.json")
        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
