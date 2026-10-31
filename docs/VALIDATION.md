# Corrobora Mobile Validation Records

This file holds the validation records referred to in
[ARCHITECTURE.md](ARCHITECTURE.md), Section 5.8. It is the only place a
validation status change may be justified.

**Current state:** no acquisition method has been validated. Every
acquisition method is **UNVERIFIED** or **UNSUPPORTED**. The records in
Part A cover the evidence-handling components only.

---

## 1. Rules

1. **Independent ground truth.** Each check compares Corrobora Mobile's
   output with a value produced by something that is not Corrobora
   Mobile: an operating-system hashing tool, a known input, or planted
   files. A check that only re-reads Corrobora Mobile's own hashes is not
   validation.
2. **Exact environment.** Each record names the tool commit, operating
   system, Python version, external tools used, and the input (name,
   size, external SHA-256). Without these a record cannot be repeated and
   does not count.
3. **Actual results only.** Record every check as run: `PASS`, `FAIL`,
   `SKIPPED`, or `INCONCLUSIVE`, with its details. A failed or
   inconclusive run is still recorded. Records are never edited after the
   fact; a re-run gets a new record.
4. **Scope is stated.** A component record (Part A) validates a component,
   not an acquisition method. It never changes any method's validation
   status.
5. **Status changes need Part B records.** A method may be marked
   **VERIFIED** for a configuration only when a forensic-validation record
   in Part B covers that exact configuration and acquisition class
   (ARCHITECTURE.md, Section 5.8). A record from a different device,
   OS version, or build does not carry over.
6. **No evidence in the repository.** Records hold hashes, sizes, and
   names of synthetic inputs only. Never commit acquired data, device
   identifiers of personal devices, pairing records, or backups.

---

## 2. Part A: Component validation

### 2.1 Evidence package writer (M1.4)

**Procedure.** From the repository root:

```
python tools/validate_evidence_component.py --input <file> --workdir <empty folder outside the repo>
```

- Use a synthetic input file (for example random bytes) of at least
  3 MiB so the interruption check (V3) runs. Several hundred MiB
  exercises multiple 64 MiB chunks.
- The input is only opened for reading. V0 confirms it is unchanged.
- Results are written to a new `run-<UTC time>` folder in the workdir as
  `record.md` and `results.json`. The packages it creates are read-only;
  on Windows clear the attribute first with
  `attrib -r "<run folder>\*" /s /d`, then delete the folder.
- Run as an ordinary user. On Linux or macOS, running as root makes V5
  `INCONCLUSIVE` because root bypasses file permissions.
- Exit status: `1` if any check FAILs, otherwise `0`.

**Checks.**

| Check | What is shown | Ground truth |
|-------|---------------|--------------|
| V0 | The input is unchanged by the run | External hash before and after |
| V1 | Bytes are stored exactly; files.sha256 and manifest are correct | External hash of input and of stored copy |
| V2 | Every chunk hash is correct and chunks cover the file exactly | External hash of each byte range of the input |
| V3 | After an abrupt process exit, the log is UNSEALED, the stream INTENT is open, no manifest or SEAL exists, the partial file is kept, and every logged chunk hash is correct | External hash of each logged byte range of the input |
| V4 | A one-byte change to stored data, or to audit.jsonl, is detected | External hash; audit verifier with the recorded chain head |
| V5 | Every file in the finalized package is read-only and writes are refused | Operating-system file attributes and a write attempt |
| V6 | Packaging the same input twice gives identical data and chunk hashes | Comparison of two independent packages |

External tools: on Windows both `certutil -hashfile` and PowerShell
`Get-FileHash` are run and must agree; on Linux `sha256sum`; on macOS
`shasum -a 256`.

**What this does not show.** It does not validate any acquisition
method, device, transport, or OS version. It does not test power loss
or disk-full conditions (V3 simulates a process crash only), concurrent
writers, or tampering by someone who can also rewrite the externally
recorded chain head.

### 2.2 Component records

Paste the `record.md` produced by each run below, newest first, and fill
in the reviewer line. Keep `results.json` with your own lab notes.

| Date (UTC) | Component | Tool commit | OS | Python | Result | Reviewer |
|------------|-----------|-------------|----|--------|--------|----------|
| 2026-10-31 | Evidence package writer (M1.4) | `485d70f` | Windows 11 (10.0.26300) | 3.14.6 | V0–V6 PASS | Dielle De Noon |

<!-- Paste record.md contents here, one per run, newest first. -->

#### 2026-10-31: Evidence package writer (M1.4), Windows

Scope: evidence-handling component only. This record does not validate any
acquisition method, device, or OS version, and changes no validation status.

| Field | Value |
|-------|-------|
| date_utc | `2026-10-31T21:55:51+00:00` |
| tool_version | `0.1.0.dev0` |
| tool_commit | `485d70f5c3ae3afe86b215fc2f5eb571e828dfac` |
| tool_tree | `clean` |
| os | `Windows 11 (10.0.26300)` |
| machine | `AMD64` |
| python | `3.14.6` |
| input_name | `input.bin` |
| input_size | `5242880` |
| input_sha256_external | `d52e075826d65bd40edaf60afba64760c43fd221c098119679ff4972edb651fc` |
| chunk_size | `67108864` |
| interrupt_chunk_size | `1048576` |
| chain_head_val_a | `7a0c030111faa67969099730d596c3f8df80ce5d2fb9269f321dacc34356e931` |
| external tool | certutil -hashfile: `certutil (C:\WINDOWS\System32\certutil.exe)` |
| external tool | PowerShell Get-FileHash: `Windows PowerShell 5.1.26100.9549 (C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe)` |

| Check | Description | Result | Details |
|-------|-------------|--------|---------|
| V0 | Input unchanged by the run | **PASS** | external hash before and after the run agree |
| V1 | Bytes stored exactly | **PASS** | external(input), external(stored), files.sha256 and manifest all agree |
| V2 | Chunk hashes match the input | **PASS** | 1 chunk(s) of up to 67108864 bytes checked externally |
| V3 | Abrupt interruption | **PASS** | process killed after 2097152 logged bytes; 2 CHUNK entries match the input; partial file kept (2621440 bytes) |
| V4 | Tampering is detected | **PASS** | data change detected by external hash; audit change detected as BROKEN |
| V5 | Files are read-only after finalization | **PASS** | every file marked read-only and write attempts refused |
| V6 | Repeatable data hashes | **PASS** | files.sha256 and chunks.sha256 identical across two packages |

Reviewed by: Dielle De Noon  Date: 2026-10-31  Notes: Synthetic random 5 MiB input. The
input is smaller than one 64 MiB chunk, so V2 checked a single chunk; multi-chunk
coverage was exercised only by V3 (1 MiB chunks).

---

## 3. Part B: Forensic validation of acquisition methods

There are no records. Every acquisition method is **UNVERIFIED** or
**UNSUPPORTED**.

Each future record must state:

- Method name and version, and tool commit.
- Exact configuration: manufacturer, model, OS and version, build type,
  security configuration, required device state and privileges.
- Acquisition class covered (ARCHITECTURE.md, Section 0.2).
- Ground truth: what was planted or otherwise known, and how.
- Results for completeness, integrity, metadata fidelity, and
  reproducibility within the declared scope, including every failure.
- Device modifications made and whether teardown succeeded.
- Known limitations.
- Reviewer and date.

| Date (UTC) | Method | Configuration | Class | Result | Status change | Reviewer |
|------------|--------|---------------|-------|--------|---------------|----------|
| | | | | | | |
