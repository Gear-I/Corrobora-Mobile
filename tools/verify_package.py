#!/usr/bin/env python3
"""Standalone verifier for Corrobora Mobile evidence packages.

Specification: docs/EVIDENCE_FORMAT.md (format version 1).
Design: docs/ARCHITECTURE.md, Section 5.7.

This file uses only the Python standard library and never imports
``corrobora_mobile``, so verification does not depend on the code that
wrote the package. It opens package files for reading only and never
writes inside the package.

It reports three separate findings:

* INTEGRITY    -- PASS, FAIL or INCOMPLETE (interrupted package);
* COMPLETENESS -- in this version NOT RECOMPUTED: the status recorded in
  the package is shown but not checked, because the raw enumeration and
  archive-listing formats are not yet specified;
* VALIDATION   -- the method validation status recorded in the manifest.
  Forensic validation is not assessed by this tool.

Exit status is a bit field:

    1  integrity is not PASS
    2  completeness is not confirmed as COMPLETE or COMPLETE_WITH_CHANGES
       (always set in this version, because completeness is not recomputed)
    4  the recorded method validation status is not VERIFIED
    8  the verifier could not run (usage error, unreadable package)

A PASS for integrity means only that the package is internally consistent
and unchanged since sealing, within the limits stated in
EVIDENCE_FORMAT.md. It never means the acquisition is complete, and
neither finding means the method is validated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERIFIER_VERSION = "1"
PACKAGE_FORMAT = "corrobora-mobile/evidence-package"
SUPPORTED_FORMAT_VERSIONS = {1}

AUDIT_LOG = "audit.jsonl"
MANIFEST = "manifest.json"
SEAL_FILE = "SEAL"
FILES_SHA256 = "hashes/files.sha256"
CHUNKS_SHA256 = "hashes/chunks.sha256"
CHUNKS_HEADER = "# path\tindex\toffset\tlength\tsha256"
FIXED_FILES = {AUDIT_LOG, MANIFEST, SEAL_FILE}

GENESIS_PREV = "0" * 64
ENTRY_TYPES = {"SESSION_START", "INTENT", "RESULT", "CHUNK", "NOTE", "SEAL"}
LINE_KEYS = {"seq", "ts", "type", "data", "prev"}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FILES_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")

EXIT_INTEGRITY, EXIT_COMPLETENESS, EXIT_VALIDATION, EXIT_ERROR = 1, 2, 4, 8
READ_BLOCK = 1024 * 1024

FORENSIC_STATEMENT = "Forensic validation is not assessed by this tool."


class UsageError(Exception):
    pass


@dataclass
class Report:
    package: str
    integrity: str = "PASS"
    audit_state: str = "UNKNOWN"
    chain_head: str | None = None
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    interrupted: dict = field(default_factory=dict)
    completeness: dict = field(default_factory=dict)
    validation: dict = field(default_factory=dict)

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def exit_code(self) -> int:
        code = 0
        if self.integrity != "PASS":
            code |= EXIT_INTEGRITY
        if self.completeness.get("status") not in ("COMPLETE", "COMPLETE_WITH_CHANGES") or \
                not self.completeness.get("recomputed"):
            code |= EXIT_COMPLETENESS
        if self.validation.get("recorded_status") != "VERIFIED":
            code |= EXIT_VALIDATION
        return code

    def to_dict(self) -> dict:
        return {
            "verifier": {"name": "verify_package.py", "version": VERIFIER_VERSION},
            "package": self.package,
            "integrity": {
                "result": self.integrity,
                "audit_log_state": self.audit_state,
                "chain_head": self.chain_head,
                "failures": self.failures,
                "notes": self.notes,
                "interrupted": self.interrupted or None,
            },
            "completeness": self.completeness,
            "validation": self.validation,
            "exit_code": self.exit_code(),
        }


# -- helpers ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(READ_BLOCK):
            h.update(block)
    return h.hexdigest()


def sha256_range(path: Path, offset: int, length: int) -> str | None:
    """SHA-256 of ``length`` bytes at ``offset``; None if the file is too short."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(offset)
        remaining = length
        while remaining:
            block = f.read(min(READ_BLOCK, remaining))
            if not block:
                return None
            h.update(block)
            remaining -= len(block)
    return h.hexdigest()


def safe_relpath(relpath: object) -> bool:
    """True for a package-relative path in the form EVIDENCE_FORMAT.md allows."""
    if not isinstance(relpath, str) or not relpath:
        return False
    return all(COMPONENT.match(c) for c in relpath.split("/"))


def resolve(root: Path, relpath: str) -> Path:
    return root.joinpath(*relpath.split("/"))


# -- audit log -----------------------------------------------------------------------------


def verify_audit(root: Path, report: Report) -> list[dict]:
    """Verify the hash chain and entry rules. Returns the parsed entries."""
    raw = (root / AUDIT_LOG).read_bytes()
    pieces = raw.split(b"\n")
    torn = pieces.pop()  # bytes after the last \n; empty if the file ends with \n
    entries: list[dict] = []
    prev = GENESIS_PREV
    open_intents: dict[int, str] = {}
    broken: list[str] = []

    for index, body in enumerate(pieces):
        line = body + b"\n"
        where = f"audit line {index}"
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            broken.append(f"{where}: not a JSON object")
            break
        if not isinstance(obj, dict) or set(obj) != LINE_KEYS:
            broken.append(f"{where}: keys must be exactly {sorted(LINE_KEYS)}")
            break
        if type(obj["seq"]) is not int or obj["seq"] != index:
            broken.append(f"{where}: seq {obj['seq']!r}, expected {index}")
            break
        if obj["prev"] != prev:
            broken.append(f"{where}: prev does not match the SHA-256 of the previous line")
            break
        if not isinstance(obj["ts"], str) or not TS.match(obj["ts"]):
            broken.append(f"{where}: invalid ts {obj['ts']!r}")
            break
        if obj["type"] not in ENTRY_TYPES or not isinstance(obj["data"], dict):
            broken.append(f"{where}: invalid type or data")
            break
        if (index == 0) != (obj["type"] == "SESSION_START"):
            broken.append(f"{where}: SESSION_START must be line 0 and only line 0")
            break
        if entries and entries[-1]["type"] == "SEAL":
            broken.append(f"{where}: entry after SEAL")
            break
        data = obj["data"]
        if obj["type"] == "INTENT":
            if not isinstance(data.get("action"), str) or not data["action"]:
                broken.append(f"{where}: INTENT without action")
                break
            open_intents[index] = data["action"]
        elif obj["type"] == "RESULT":
            target = data.get("intent_seq")
            if type(target) is not int or target not in open_intents:
                broken.append(f"{where}: RESULT does not close an open INTENT")
                break
            del open_intents[target]
        elif obj["type"] == "SEAL":
            if open_intents:
                broken.append(f"{where}: SEAL while INTENT entries are open: {sorted(open_intents)}")
                break
            if data.get("entry_count") != index + 1:
                broken.append(f"{where}: SEAL entry_count {data.get('entry_count')!r}, expected {index + 1}")
                break
            if not isinstance(data.get("manifest_sha256"), str) or not HEX64.match(data["manifest_sha256"]):
                broken.append(f"{where}: SEAL without a valid manifest_sha256")
                break
        obj["_line_sha256"] = hashlib.sha256(line).hexdigest()
        entries.append(obj)
        prev = obj["_line_sha256"]

    if broken:
        report.audit_state = "BROKEN"
        report.fail(broken[0])
        return entries
    if not entries:
        report.audit_state = "BROKEN"
        report.fail("audit log has no complete lines")
        return entries

    report.chain_head = entries[-1]["_line_sha256"]
    if entries[-1]["type"] == "SEAL":
        if torn:
            report.audit_state = "BROKEN"
            report.fail("bytes follow the SEAL line")
        else:
            report.audit_state = "SEALED"
    else:
        report.audit_state = "UNSEALED"
        report.interrupted = {
            "last_entry": {"seq": entries[-1]["seq"], "type": entries[-1]["type"]},
            "open_intents": [{"seq": s, "action": a} for s, a in sorted(open_intents.items())],
            "torn_final_line_bytes": len(torn),
        }
        if torn:
            report.notes.append(f"torn final line ({len(torn)} bytes without a newline); "
                                "reported, not repaired, not part of the chain")
    return entries


# -- sealed package --------------------------------------------------------------------


def verify_sealed(root: Path, entries: list[dict], report: Report) -> dict | None:
    seal_entry = entries[-1]["data"]
    session = entries[0]["data"]

    # SEAL file
    expected_seal = (f"chain_head {report.chain_head}\n"
                     f"manifest_sha256 {seal_entry['manifest_sha256']}\n").encode("ascii")
    seal_path = root / SEAL_FILE
    if not seal_path.is_file():
        report.fail("SEAL file missing")
    elif seal_path.read_bytes() != expected_seal:
        report.fail("SEAL file does not match the audit log's chain head and SEAL entry")

    # manifest
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        report.fail("manifest.json missing")
        return None
    if sha256_file(manifest_path) != seal_entry["manifest_sha256"]:
        report.fail("manifest.json SHA-256 does not match the SEAL entry")
    try:
        manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        report.fail("manifest.json is not valid JSON")
        return None
    if not isinstance(manifest, dict):
        report.fail("manifest.json is not a JSON object")
        return None
    if manifest.get("format") != PACKAGE_FORMAT:
        report.fail(f"unknown package format {manifest.get('format')!r}")
        return None
    if manifest.get("format_version") not in SUPPORTED_FORMAT_VERSIONS:
        report.fail(f"unsupported format_version {manifest.get('format_version')!r}")
        return None
    if manifest.get("acquisition_id") != session.get("acquisition_id"):
        report.fail("manifest acquisition_id differs from SESSION_START")
    if root.name != manifest.get("acquisition_id"):
        report.notes.append(f"package directory name {root.name!r} differs from acquisition_id")

    files = manifest.get("files")
    chunk_size = manifest.get("chunk_size")
    if not isinstance(files, list) or type(chunk_size) is not int or chunk_size <= 0:
        report.fail("manifest files or chunk_size missing or invalid")
        return manifest
    listed: dict[str, dict] = {}
    for f in files:
        if not isinstance(f, dict) or not safe_relpath(f.get("path")) or f["path"] in FIXED_FILES \
                or f["path"] in listed:
            report.fail(f"invalid or duplicate manifest file entry: {f!r}")
            continue
        listed[f["path"]] = f

    # every listed file: size and SHA-256 from disk
    disk_hash: dict[str, str] = {}
    for relpath, f in sorted(listed.items()):
        path = resolve(root, relpath)
        if not path.is_file() or path.is_symlink():
            report.fail(f"{relpath}: listed in manifest but missing")
            continue
        disk_hash[relpath] = sha256_file(path)
        if path.stat().st_size != f.get("size"):
            report.fail(f"{relpath}: size {path.stat().st_size} differs from manifest {f.get('size')!r}")
        if disk_hash[relpath] != f.get("sha256"):
            report.fail(f"{relpath}: SHA-256 differs from manifest")
        if f.get("complete") is not True:
            report.notes.append(f"{relpath}: recorded as incomplete")

    # no files on disk beyond the fixed files and the manifest list
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            report.fail(f"{rel}: symbolic link in package")
        elif path.is_file() and rel not in FIXED_FILES and rel not in listed:
            report.fail(f"{rel}: file not listed in the manifest")

    verify_files_sha256(root, listed, disk_hash, report)
    verify_chunks(root, listed, disk_hash, chunk_size, entries, report)
    verify_audit_results(entries, disk_hash, report)
    return manifest


def verify_files_sha256(root: Path, listed: dict, disk_hash: dict, report: Report) -> None:
    if FILES_SHA256 not in disk_hash:
        report.fail(f"{FILES_SHA256} not listed in the manifest or missing")
        return
    expected = {p for p, f in listed.items() if f.get("kind") != "package"}
    seen: set[str] = set()
    for n, line in enumerate(resolve(root, FILES_SHA256).read_bytes().decode("ascii", "replace")
                             .split("\n")[:-1]):
        m = FILES_LINE.match(line)
        if not m or not safe_relpath(m.group(2)) or m.group(2) in seen:
            report.fail(f"{FILES_SHA256} line {n + 1}: invalid or duplicate")
            continue
        digest, rel = m.groups()
        seen.add(rel)
        if rel not in expected:
            report.fail(f"{FILES_SHA256}: {rel} is not a listed evidence file")
        elif disk_hash.get(rel) != digest:
            report.fail(f"{FILES_SHA256}: {rel} SHA-256 differs from the file on disk")
    for rel in sorted(expected - seen):
        report.fail(f"{FILES_SHA256}: {rel} missing")


def verify_chunks(root: Path, listed: dict, disk_hash: dict, chunk_size: int, entries: list[dict],
                  report: Report) -> None:
    if CHUNKS_SHA256 not in disk_hash:
        report.fail(f"{CHUNKS_SHA256} not listed in the manifest or missing")
        return
    lines = resolve(root, CHUNKS_SHA256).read_bytes().decode("ascii", "replace").split("\n")
    if not lines or lines[0] != CHUNKS_HEADER or lines[-1] != "":
        report.fail(f"{CHUNKS_SHA256}: missing header or final newline")
        return
    rows: dict[str, list[tuple[int, int, int, str]]] = {}
    for n, line in enumerate(lines[1:-1], start=2):
        parts = line.split("\t")
        try:
            rel, index, offset, length, digest = parts
            index, offset, length = int(index), int(offset), int(length)
        except ValueError:
            report.fail(f"{CHUNKS_SHA256} line {n}: invalid")
            continue
        if not HEX64.match(digest) or rel not in listed:
            report.fail(f"{CHUNKS_SHA256} line {n}: invalid hash or unlisted file")
            continue
        rows.setdefault(rel, []).append((index, offset, length, digest))

    logged = {(e["data"].get("stream"), e["data"].get("index")): e["data"]
              for e in entries if e["type"] == "CHUNK"}
    for rel, f in sorted(listed.items()):
        chunks = rows.get(rel, [])
        if f.get("chunk_count") != len(chunks):
            report.fail(f"{rel}: {len(chunks)} chunk rows, manifest records {f.get('chunk_count')!r}")
        expected_offset = 0
        for i, (index, offset, length, digest) in enumerate(chunks):
            if index != i or offset != expected_offset or not 0 < length <= chunk_size:
                report.fail(f"{rel}: chunk {index} out of order or wrong size")
                break
            if rel in disk_hash and sha256_range(resolve(root, rel), offset, length) != digest:
                report.fail(f"{rel}: chunk {index} SHA-256 differs from the file on disk")
            log = logged.get((rel, index))
            if log is None or (log.get("offset"), log.get("length"), log.get("sha256")) != (offset, length, digest):
                report.fail(f"{rel}: chunk {index} differs from its CHUNK entry in the audit log")
            expected_offset = offset + length
        if chunks and expected_offset != f.get("size"):
            report.fail(f"{rel}: chunks cover {expected_offset} bytes of {f.get('size')!r}")
    for stream, index in sorted(k for k in logged if k[0] not in rows):
        report.fail(f"audit CHUNK entry for {stream} chunk {index} has no row in {CHUNKS_SHA256}")


def verify_audit_results(entries: list[dict], disk_hash: dict, report: Report) -> None:
    """Every RESULT that records a file's SHA-256 must match the file on disk."""
    for e in entries:
        data = e["data"]
        if e["type"] != "RESULT" or "sha256" not in data or "path" not in data:
            continue
        rel = data["path"]
        if rel == MANIFEST:
            continue  # checked against the SEAL entry
        if rel in disk_hash and disk_hash[rel] != data["sha256"]:
            report.fail(f"{rel}: SHA-256 differs from audit line {e['seq']}")


# -- interrupted package ------------------------------------------------------------------


def verify_unsealed(root: Path, entries: list[dict], report: Report) -> None:
    report.integrity = "INCOMPLETE"
    if (root / SEAL_FILE).exists():
        report.fail("SEAL file present but the audit log has no SEAL entry")
    if (root / MANIFEST).exists():
        report.notes.append("manifest.json present but not sealed; its content is not verified")
    verified, failed = 0, 0
    for e in entries:
        if e["type"] != "CHUNK":
            continue
        d = e["data"]
        rel = d.get("stream")
        if not safe_relpath(rel) or type(d.get("offset")) is not int or type(d.get("length")) is not int:
            report.fail(f"audit line {e['seq']}: invalid CHUNK entry")
            continue
        path = resolve(root, rel)
        digest = sha256_range(path, d["offset"], d["length"]) if path.is_file() else None
        if digest == d.get("sha256"):
            verified += 1
        else:
            failed += 1
            report.fail(f"{rel}: logged chunk {d.get('index')} does not match the file on disk")
    report.interrupted["chunks_verified"] = verified
    report.interrupted["chunks_failed"] = failed


# -- findings -------------------------------------------------------------------------------


def completeness_finding(root: Path, manifest: dict | None) -> dict:
    recorded = None
    if isinstance(manifest, dict) and isinstance(manifest.get("content"), dict):
        value = manifest["content"].get("completeness_status")
        recorded = value if isinstance(value, str) else None
    return {
        "recomputed": False,
        "status": None,
        "recorded_status": recorded,
        "statement": ("Completeness is NOT RECOMPUTED by this verifier version: the raw "
                      "enumeration and archive-listing formats are not yet specified. The "
                      "recorded status is shown as recorded and is not trusted."),
    }


def validation_finding(manifest: dict | None) -> dict:
    recorded = None
    if isinstance(manifest, dict) and isinstance(manifest.get("content"), dict):
        value = manifest["content"].get("method_validation_status")
        recorded = value if isinstance(value, str) else None
    return {"recorded_status": recorded, "statement": FORENSIC_STATEMENT}


def verify(root: Path, expected_chain_head: str | None = None) -> Report:
    if not root.is_dir():
        raise UsageError(f"not a directory: {root}")
    if not (root / AUDIT_LOG).is_file():
        raise UsageError(f"no {AUDIT_LOG} in {root}; not an evidence package")
    report = Report(package=str(root))
    entries = verify_audit(root, report)
    manifest = None
    if report.audit_state == "BROKEN":
        report.integrity = "FAIL"
    elif report.audit_state == "UNSEALED":
        verify_unsealed(root, entries, report)
        if report.failures:
            report.integrity = "FAIL"
    else:
        manifest = verify_sealed(root, entries, report)
        if report.failures:
            report.integrity = "FAIL"

    if expected_chain_head is not None:
        if report.chain_head != expected_chain_head:
            report.fail("chain head differs from the externally recorded value")
            report.integrity = "FAIL"
        else:
            report.notes.append("chain head matches the externally recorded value")
    elif report.audit_state == "SEALED":
        report.notes.append("chain head not compared with an external record (--chain-head); "
                            "a package regenerated in full would not be detected")

    report.completeness = completeness_finding(root, manifest)
    report.validation = validation_finding(manifest)
    return report


def render(report: Report) -> str:
    lines = [f"Package: {report.package}"]
    integ = f"INTEGRITY:     {report.integrity}  (audit log {report.audit_state}"
    integ += f", chain head {report.chain_head})" if report.chain_head else ")"
    lines.append(integ)
    for f in report.failures:
        lines.append(f"  FAIL  {f}")
    for n in report.notes:
        lines.append(f"  note  {n}")
    if report.interrupted:
        lines.append(f"  interrupted: {json.dumps(report.interrupted, sort_keys=True)}")
    c = report.completeness
    lines.append(f"COMPLETENESS:  NOT RECOMPUTED (recorded: {c['recorded_status'] or 'not recorded'})")
    lines.append(f"  {c['statement']}")
    v = report.validation
    lines.append(f"VALIDATION:    method {v['recorded_status'] or 'status not recorded'} -- {v['statement']}")
    lines.append(f"Exit code: {report.exit_code()} (1 integrity, 2 completeness, 4 validation)")
    return "\n".join(lines)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # keep exit codes 1, 2, 4 for findings
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="Verify a Corrobora Mobile evidence package (read-only).")
    parser.add_argument("package", type=Path, help="package directory (<output>/<acquisition_id>)")
    parser.add_argument("--chain-head", help="chain head recorded in your own case notes")
    parser.add_argument("--json", type=Path, help="also write the report as JSON to this file "
                                                    "(must be outside the package)")
    args = parser.parse_args(argv)
    if args.chain_head is not None and not HEX64.match(args.chain_head.lower()):
        parser.error("--chain-head must be 64 hex characters")
    root = args.package.resolve()
    if args.json is not None:
        target = args.json.resolve()
        if target == root or root in target.parents:
            parser.error("--json must not point inside the package")
    try:
        report = verify(root, args.chain_head.lower() if args.chain_head else None)
    except (UsageError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(render(report))
    if args.json is not None:
        with open(args.json, "x", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, sort_keys=True)
            f.write("\n")
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
