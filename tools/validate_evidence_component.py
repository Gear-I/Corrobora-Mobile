#!/usr/bin/env python3
"""Component validation of the evidence package writer (M1.4).

This harness checks the evidence-handling component against ground truth
produced by tools that are NOT part of Corrobora Mobile:

* Windows: ``certutil -hashfile`` and PowerShell ``Get-FileHash`` (both are
  run and must agree);
* Linux and macOS: ``sha256sum`` (or ``shasum -a 256``).

It does not validate any acquisition method, device, or OS version, and it
never changes a method's validation status (docs/ARCHITECTURE.md 0.3, 5.8).

Checks
------

V0  The input file is unchanged by the run.
V1  Bytes are stored exactly (external hash of input == external hash of
    stored copy == package's files.sha256 entry == manifest entry).
V2  Every chunk in hashes/chunks.sha256 matches the external hash of that
    byte range of the input, and the chunks cover the file exactly.
V3  Abrupt interruption (child process killed with os._exit mid-stream):
    the audit log is UNSEALED with the stream INTENT open, the partial file
    is kept, no manifest or SEAL exists, and every logged CHUNK matches the
    external hash of that byte range of the input.
V4  Tampering is detected: a one-byte change to the stored copy no longer
    matches files.sha256, and a one-byte change to audit.jsonl makes the
    log BROKEN.
V5  Every file in the finalized package is read-only and a write attempt
    is refused. INCONCLUSIVE when running as root on POSIX, where
    permissions are not enforced.
V6  Packaging the same input twice gives identical data hashes.

Usage
-----

    python tools/validate_evidence_component.py --input FILE --workdir DIR

A new run directory is created under DIR. Results are written there as
``record.md`` and ``results.json``. The exit status is 1 if any check
FAILs, otherwise 0. The input file is only ever opened for reading.
"""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from corrobora_mobile import __version__  # noqa: E402
from corrobora_mobile.audit import verify_audit_log  # noqa: E402
from corrobora_mobile.core.enums import AuditLogState  # noqa: E402
from corrobora_mobile.evidence import EvidencePackage  # noqa: E402

DATA_PATH = "data/input.bin"
READ_BLOCK = 1024 * 1024
FILE_ATTRIBUTE_READONLY = 0x1
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
PASS, FAIL, SKIPPED, INCONCLUSIVE = "PASS", "FAIL", "SKIPPED", "INCONCLUSIVE"


# -- independent ground truth ---------------------------------------------------


class ExternalHasher:
    """SHA-256 from operating-system tools, never from Corrobora Mobile."""

    def __init__(self) -> None:
        if os.name == "nt":
            self.tools = ["certutil -hashfile", "PowerShell Get-FileHash"]
        elif shutil.which("sha256sum"):
            self.tools = ["sha256sum"]
        elif shutil.which("shasum"):
            self.tools = ["shasum -a 256"]
        else:
            raise SystemExit("no external SHA-256 tool found (need sha256sum or shasum)")

    def sha256(self, path: Path) -> str:
        results = {tool: self._run(tool, path) for tool in self.tools}
        values = set(results.values())
        if len(values) != 1:
            raise RuntimeError(f"external tools disagree on {path}: {results}")
        return values.pop()

    def versions(self) -> dict[str, str]:
        out = {}
        for tool in self.tools:
            if tool == "sha256sum":
                out[tool] = _first_line(["sha256sum", "--version"])
            elif tool == "shasum -a 256":
                out[tool] = _first_line(["shasum", "--version"])
            elif tool == "PowerShell Get-FileHash":
                version = _first_line(_powershell_cmd("$PSVersionTable.PSVersion.ToString()"),
                                      env=windows_powershell_env())
                out[tool] = f"Windows PowerShell {version} ({_powershell_cmd('')[0]})"
            else:
                out[tool] = f"certutil ({_windows_exe('certutil.exe')})"
        return out

    @staticmethod
    def _run(tool: str, path: Path) -> str:
        if tool == "sha256sum":
            text = _check_output(["sha256sum", "--", str(path)])
            value = text.split()[0] if text.split() else ""
        elif tool == "shasum -a 256":
            text = _check_output(["shasum", "-a", "256", str(path)])
            value = text.split()[0] if text.split() else ""
        elif tool == "certutil -hashfile":
            text = _check_output([_windows_exe("certutil.exe"), "-hashfile", str(path), "SHA256"])
            # Line 2 holds the hash; older Windows versions separate bytes with spaces.
            lines = text.splitlines()
            value = lines[1].replace(" ", "") if len(lines) > 1 else ""
        elif tool == "PowerShell Get-FileHash":
            literal = str(path).replace("'", "''")
            text = _check_output(
                _powershell_cmd(f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{literal}').Hash"),
                env=windows_powershell_env(),
            )
            value = text
        else:
            raise ValueError(tool)
        value = value.strip().lower()
        if not SHA256_HEX.match(value):
            raise RuntimeError(f"{tool}: unexpected output for {path}: {text!r}")
        return value


def _windows_exe(*parts: str) -> str:
    """Full path under %SystemRoot%\\System32, so PATH cannot substitute another program."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return ntpath.join(root, "System32", *parts)


def _powershell_cmd(command: str) -> list[str]:
    return [_windows_exe("WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoProfile", "-NonInteractive", "-Command", command]


def windows_powershell_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for Windows PowerShell 5.1 with only its own module folders.

    When this script is started from PowerShell 7, the inherited PSModulePath
    lists PowerShell 7's module folders first. Windows PowerShell 5.1 then
    fails to load its built-in Microsoft.PowerShell.Utility module and
    reports Get-FileHash as "not recognized". Restricting PSModulePath to
    the Windows PowerShell folders also stops user-installed modules from
    replacing the built-in cmdlet.
    """
    env = dict(os.environ if base is None else base)
    system_root = env.get("SystemRoot", r"C:\Windows")
    program_files = env.get("ProgramFiles", r"C:\Program Files")
    env["PSModulePath"] = ";".join([
        ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0", "Modules"),
        ntpath.join(program_files, "WindowsPowerShell", "Modules"),
    ])
    return env


def _check_output(cmd: list[str], env: dict[str, str] | None = None) -> str:
    """Run a command; on failure, raise with its exit status and stderr."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    except OSError as exc:
        raise RuntimeError(f"cannot run {cmd[0]}: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} exited with status {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}"
        )
    return proc.stdout


def _first_line(cmd: list[str], env: dict[str, str] | None = None) -> str:
    try:
        return _check_output(cmd, env=env).splitlines()[0].strip()
    except (RuntimeError, IndexError):
        return "unknown"


def _tree_state() -> str:
    """'clean', 'modified' (uncommitted changes), or 'unknown' (not a git checkout)."""
    try:
        out = _check_output(["git", "-C", str(REPO), "status", "--porcelain"])
    except RuntimeError:
        return "unknown"
    return "modified" if out.strip() else "clean"


def external_range_sha256(hasher: ExternalHasher, source: Path, offset: int, length: int, tmp: Path) -> str:
    """Copy a byte range to a temporary file and hash it with the external tool."""
    with open(source, "rb") as src, open(tmp, "wb") as dst:
        src.seek(offset)
        remaining = length
        while remaining:
            block = src.read(min(READ_BLOCK, remaining))
            if not block:
                raise RuntimeError(f"input shorter than expected at offset {offset}")
            dst.write(block)
            remaining -= len(block)
    try:
        return hasher.sha256(tmp)
    finally:
        tmp.unlink()


# -- packaging --------------------------------------------------------------------


def package_input(source: Path, out_dir: Path, acquisition_id: str, chunk_size: int):
    pkg = EvidencePackage.create(out_dir, acquisition_id, chunk_size=chunk_size)
    with pkg.open_stream(DATA_PATH, description="validation input") as stream, open(source, "rb") as f:
        while block := f.read(READ_BLOCK):
            stream.write(block)
    return pkg.finalize({"purpose": "M1.4 component validation", "input_name": source.name})


def child_interrupt(source: Path, out_dir: Path, acquisition_id: str, chunk_size: int, chunks: int) -> None:
    """Write ``chunks`` full chunks plus half a chunk, then exit abruptly."""
    pkg = EvidencePackage.create(out_dir, acquisition_id, chunk_size=chunk_size)
    stream = pkg.open_stream(DATA_PATH, description="validation input (interrupted)")
    with open(source, "rb") as f:
        stream.write(f.read(chunk_size * chunks + chunk_size // 2))
    stream._fh.flush()
    os._exit(137)  # no cleanup, no close, no seal: simulates a crash


def read_files_sha256(root: Path) -> dict[str, str]:
    entries = {}
    for line in (root / "hashes" / "files.sha256").read_text(encoding="ascii").splitlines():
        digest, rel = line.split("  ", 1)
        entries[rel] = digest
    return entries


def read_chunks(root: Path) -> list[tuple[str, int, int, int, str]]:
    rows = []
    for line in (root / "hashes" / "chunks.sha256").read_text(encoding="ascii").splitlines()[1:]:
        path, index, offset, length, digest = line.split("\t")
        rows.append((path, int(index), int(offset), int(length), digest))
    return rows


# -- checks -----------------------------------------------------------------------


def run(source: Path, workdir: Path, chunk_size: int, interrupt_chunk_size: int) -> tuple[Path, list[dict]]:
    hasher = ExternalHasher()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = workdir / f"run-{stamp}"
    run_dir.mkdir(parents=True)
    tmp = run_dir / "range.tmp"
    results: list[dict] = []

    def record(check: str, title: str, status: str, details: str, **values) -> None:
        results.append({"check": check, "title": title, "status": status, "details": details, **values})

    source_size = source.stat().st_size
    source_sha = hasher.sha256(source)

    # V1
    try:
        fin = package_input(source, run_dir / "packages", "val-a", chunk_size)
    except Exception as exc:  # any packaging failure is a result, not a crash
        record("V1", "Bytes stored exactly", FAIL, f"packaging failed: {type(exc).__name__}: {exc}")
        for check, title in (("V2", "Chunk hashes match the input"), ("V3", "Abrupt interruption"),
                             ("V4", "Tampering is detected"), ("V5", "Files are read-only after finalization"),
                             ("V6", "Repeatable data hashes")):
            record(check, title, SKIPPED, "not run because packaging failed (V1)")
        return _finish(run_dir, hasher, source, source_sha, source_size, chunk_size,
                       interrupt_chunk_size, None, results, record)
    stored = fin.root / DATA_PATH
    stored_sha = hasher.sha256(stored)
    listed = read_files_sha256(fin.root).get(DATA_PATH)
    manifest = json.loads((fin.root / "manifest.json").read_bytes())
    in_manifest = {f["path"]: f for f in manifest["files"]}.get(DATA_PATH, {})
    ok = source_sha == stored_sha == listed == in_manifest.get("sha256") and in_manifest.get("complete") is True
    record("V1", "Bytes stored exactly", PASS if ok else FAIL,
           "external(input), external(stored), files.sha256 and manifest all agree" if ok
           else "values differ",
           external_input=source_sha, external_stored=stored_sha, files_sha256=listed,
           manifest=in_manifest.get("sha256"))

    # V2
    rows = [r for r in read_chunks(fin.root) if r[0] == DATA_PATH]
    expected_offset, bad = 0, []
    for _, index, offset, length, digest in rows:
        if offset != expected_offset:
            bad.append(f"chunk {index}: offset {offset} (expected {expected_offset})")
        elif external_range_sha256(hasher, source, offset, length, tmp) != digest:
            bad.append(f"chunk {index}: hash differs")
        expected_offset = offset + length
    if expected_offset != source_size:
        bad.append(f"chunks cover {expected_offset} bytes of {source_size}")
    record("V2", "Chunk hashes match the input", PASS if not bad else FAIL,
           f"{len(rows)} chunk(s) of up to {chunk_size} bytes checked externally" if not bad else "; ".join(bad))

    # V3
    if source_size < interrupt_chunk_size * 3:
        record("V3", "Abrupt interruption", SKIPPED,
               f"input must be at least {interrupt_chunk_size * 3} bytes")
    else:
        proc = subprocess.run(
            [sys.executable, __file__, "--child-interrupt", "--input", str(source),
             "--workdir", str(run_dir / "packages"), "--chunk-size", str(interrupt_chunk_size)],
            capture_output=True, text=True,
        )
        root = run_dir / "packages" / "val-interrupted"
        log = verify_audit_log(root / "audit.jsonl")
        chunk_entries = [
            json.loads(line)["data"] for line in (root / "audit.jsonl").read_bytes().splitlines()
            if json.loads(line)["type"] == "CHUNK"
        ]
        bad = []
        if proc.returncode != 137:
            bad.append(f"child exit status {proc.returncode} (expected 137)")
        if log.state is not AuditLogState.UNSEALED:
            bad.append(f"audit log {log.state.value} (expected UNSEALED)")
        if [o.action for o in log.open_intents] != ["capture stream"]:
            bad.append(f"open INTENTs {[o.action for o in log.open_intents]}")
        if (root / "manifest.json").exists() or (root / "SEAL").exists():
            bad.append("manifest or SEAL exists after a crash")
        partial = root / DATA_PATH
        logged_bytes = sum(c["length"] for c in chunk_entries)
        if not partial.exists() or partial.stat().st_size < logged_bytes:
            bad.append("partial file missing or shorter than the logged chunks")
        for c in chunk_entries:
            if external_range_sha256(hasher, source, c["offset"], c["length"], tmp) != c["sha256"]:
                bad.append(f"logged chunk {c['index']} does not match the input")
        record("V3", "Abrupt interruption", PASS if not bad else FAIL,
               (f"process killed after {logged_bytes} logged bytes; {len(chunk_entries)} CHUNK "
                f"entries match the input; partial file kept ({partial.stat().st_size} bytes)")
               if not bad else "; ".join(bad))

    # V4 (on a copy, never on the original package)
    tampered = run_dir / "tamper-copy"
    shutil.copytree(fin.root, tampered)
    for p in tampered.rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IRUSR | stat.S_IWUSR)
    data_copy = tampered / DATA_PATH
    bad = []
    if source_size == 0:
        bad.append("input is empty; nothing to tamper with")
    else:
        with open(data_copy, "r+b") as f:
            f.seek(source_size // 2)
            byte = f.read(1)
            f.seek(source_size // 2)
            f.write(bytes([byte[0] ^ 0x01]))
        if hasher.sha256(data_copy) == listed:
            bad.append("one-byte change to the stored copy was NOT detected")
    audit_copy = tampered / "audit.jsonl"
    raw = bytearray(audit_copy.read_bytes())
    pos = raw.index(b"validation input")
    raw[pos] ^= 0x20  # flip letter case of one byte
    audit_copy.write_bytes(bytes(raw))
    log = verify_audit_log(audit_copy, expected_chain_head=fin.chain_head)
    if log.state is not AuditLogState.BROKEN:
        bad.append(f"one-byte change to audit.jsonl gave {log.state.value} (expected BROKEN)")
    record("V4", "Tampering is detected", PASS if not bad else FAIL,
           "data change detected by external hash; audit change detected as BROKEN" if not bad
           else "; ".join(bad))

    # V5
    not_readonly, writable = [], []
    for p in sorted(fin.root.rglob("*")):
        if not p.is_file():
            continue
        st = p.stat()
        if os.name == "nt":
            readonly = bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_READONLY)
        else:
            readonly = stat.S_IMODE(st.st_mode) & 0o222 == 0
        if not readonly:
            not_readonly.append(str(p.relative_to(fin.root)))
        try:
            with open(p, "ab"):
                writable.append(str(p.relative_to(fin.root)))
        except PermissionError:
            pass
    is_root = os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0
    if not_readonly:
        status, details = FAIL, f"not marked read-only: {not_readonly}"
    elif writable and is_root:
        status, details = INCONCLUSIVE, "files are marked read-only, but running as root bypasses permissions"
    elif writable:
        status, details = FAIL, f"write was allowed: {writable}"
    else:
        status, details = PASS, "every file marked read-only and write attempts refused"
    record("V5", "Files are read-only after finalization", status, details)

    # V6
    fin_b = package_input(source, run_dir / "packages", "val-b", chunk_size)
    a, b = read_files_sha256(fin.root), read_files_sha256(fin_b.root)
    same = a == b and (fin.root / "hashes" / "chunks.sha256").read_bytes() == (
        fin_b.root / "hashes" / "chunks.sha256"
    ).read_bytes()
    record("V6", "Repeatable data hashes", PASS if same else FAIL,
           "files.sha256 and chunks.sha256 identical across two packages" if same else "hash files differ")

    return _finish(run_dir, hasher, source, source_sha, source_size, chunk_size,
                   interrupt_chunk_size, fin.chain_head, results, record)


def _finish(run_dir, hasher, source, source_sha, source_size, chunk_size, interrupt_chunk_size,
            chain_head, results, record):
    # V0 (last, so it covers the whole run)
    after = hasher.sha256(source)
    record("V0", "Input unchanged by the run", PASS if after == source_sha else FAIL,
           "external hash before and after the run agree" if after == source_sha else "INPUT CHANGED",
           before=source_sha, after=after)
    results.sort(key=lambda r: r["check"])

    environment = {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "tool_commit": _first_line(["git", "-C", str(REPO), "rev-parse", "HEAD"]),
        "tool_tree": _tree_state(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "external_tools": hasher.versions(),
        "input_name": source.name,
        "input_size": source_size,
        "input_sha256_external": source_sha,
        "chunk_size": chunk_size,
        "interrupt_chunk_size": interrupt_chunk_size,
        "chain_head_val_a": chain_head or "none (packaging failed)",
    }
    (run_dir / "results.json").write_text(
        json.dumps({"environment": environment, "results": results}, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "record.md").write_text(render_record(environment, results), encoding="utf-8")
    return run_dir, results


def render_record(env: dict, results: list[dict]) -> str:
    lines = [
        "### Component validation: evidence package writer (M1.4)",
        "",
        "Scope: evidence-handling component only. This record does not validate any",
        "acquisition method, device, or OS version, and changes no validation status.",
        "",
        "| Field | Value |",
        "|-------|-------|",
    ]
    for key in ("date_utc", "tool_version", "tool_commit", "tool_tree", "os", "machine", "python",
                "input_name", "input_size", "input_sha256_external", "chunk_size",
                "interrupt_chunk_size", "chain_head_val_a"):
        lines.append(f"| {key} | `{env[key]}` |")
    for tool, version in env["external_tools"].items():
        lines.append(f"| external tool | {tool}: `{version}` |")
    lines += ["", "| Check | Description | Result | Details |", "|-------|-------------|--------|---------|"]
    for r in results:
        lines.append(f"| {r['check']} | {r['title']} | **{r['status']}** | {r['details']} |")
    lines += ["", "Reviewed by: ______  Date: ______  Notes: ______", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, required=True, help="file to package (read-only)")
    parser.add_argument("--workdir", type=Path, required=True, help="directory for run output")
    parser.add_argument("--chunk-size", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--interrupt-chunk-size", type=int, default=1024 * 1024)
    parser.add_argument("--child-interrupt", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.child_interrupt:
        child_interrupt(args.input, args.workdir, "val-interrupted", args.chunk_size, chunks=2)
        return 1  # not reached

    if not args.input.is_file():
        parser.error(f"input is not a file: {args.input}")
    try:
        run_dir, results = run(args.input.resolve(), args.workdir.resolve(), args.chunk_size,
                               args.interrupt_chunk_size)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("No record was written. The run did not complete.", file=sys.stderr)
        return 2
    for r in results:
        print(f"{r['check']}  {r['status']:<12} {r['title']}: {r['details']}")
    print(f"\nRecord: {run_dir / 'record.md'}")
    print("Scope: component validation only; no acquisition method is validated by this run.")
    return 1 if any(r["status"] == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
