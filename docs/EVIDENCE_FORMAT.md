# Corrobora Mobile Evidence Package Format

**Format:** `corrobora-mobile/evidence-package`, **format version 1**.

This document specifies the evidence package precisely enough to verify
one **without any Corrobora Mobile code** (ARCHITECTURE.md, Section 5.7).
`tools/verify_package.py` implements the checks in Section 9 using only
the Python standard library; Section 10 shows how to do the same checks
with standard command-line tools.

**Status of this document.** It describes what the package writer at
format version 1 produces. Parts of the package that later milestones
add (the enumeration files, the archive-entry hash list, the manifest's
acquisition-specific fields) are listed in Section 11 as not yet
specified. A verifier must not treat their absence as an integrity
failure, and must not claim to have checked them.

Key words: **must**, **must not** and **may** are used in their usual
specification sense.

---

## 1. What verification can and cannot show

- An integrity **PASS** shows that the package is internally consistent
  and that nothing covered by the hash chain, the hash lists or the
  manifest has changed since the package was sealed.
- It does **not** show that the package was not regenerated in full by
  someone with write access. Only a comparison with the chain head the
  operator recorded **outside** the package, at acquisition time, can
  show that (Section 6).
- It does **not** show that the acquisition was complete. Completeness
  is a separate finding (ARCHITECTURE.md, Section 5.2).
- It does **not** show that the acquisition method is validated. Forensic
  validation is not assessed by any verifier.

---

## 2. Layout

A package is one directory, named after the acquisition ID:

```text
<acquisition_id>/
├── audit.jsonl           hash-chained audit log (Section 4)
├── SEAL                  chain head and manifest hash (Section 6)
├── manifest.json         written at finalization (Section 7)
├── hashes/
│   ├── files.sha256      SHA-256 of each evidence file (Section 8.1)
│   └── chunks.sha256     SHA-256 of each chunk of each stream (Section 8.2)
├── identity/  plan/  enumeration/  data/  errors/
│                         evidence files written by the acquisition
└── reconciliation.json   optional; written by the acquisition
```

- The only top-level directories are `identity`, `plan`, `enumeration`,
  `data`, `errors` and `hashes`.
- The only top-level files are `audit.jsonl`, `SEAL`, `manifest.json`
  and, optionally, `reconciliation.json`.
- A sealed package must contain no file other than `audit.jsonl`,
  `SEAL`, `manifest.json` and the files listed in the manifest's `files`
  array. It must contain no symbolic links.
- After finalization the writer marks every file read-only. This is a
  best-effort host safeguard, not tamper protection, and a verifier does
  not check it.

### 2.1 Package-relative paths

Every path inside the package (in `files.sha256`, `chunks.sha256`, the
manifest and the audit log) is relative to the package directory, uses
`/` as the separator, and consists of components that each match:

```text
^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$
```

So there are no empty components, no `.` or `..`, no leading `/`, no
backslashes and no spaces. A verifier must reject any other path before
opening it. (Device paths recorded **inside** evidence files are a
separate matter: they are raw bytes and are never normalized.)

---

## 3. Hashing

- The hash function is **SHA-256**, written as 64 lowercase hexadecimal
  characters.
- Every hash is over the exact bytes of the file or byte range, with no
  newline conversion.

---

## 4. Audit log: `audit.jsonl`

### 4.1 Line format

- The file is a sequence of lines. Each line is a JSON object encoded
  as UTF-8 and terminated by exactly one `\n` (byte `0x0A`, no `\r`).
- Each object has exactly these keys:

| Key | Value |
|-----|-------|
| `seq` | integer: `0` on the first line, then increasing by 1 with no gaps |
| `ts` | UTC timestamp `YYYY-MM-DDTHH:MM:SS.ffffffZ` (always six fractional digits) |
| `type` | one of `SESSION_START`, `INTENT`, `RESULT`, `CHUNK`, `NOTE`, `SEAL` |
| `data` | JSON object (fields per type, Section 4.3) |
| `prev` | SHA-256 of the previous line (Section 4.2) |

- The writer happens to use sorted keys, compact separators and ASCII
  output. **Verification must not depend on this:** the chain is
  computed over the bytes as written, so no JSON canonicalization is ever
  needed.

### 4.2 Chain rule

- `prev` on line 0 is 64 zeros.
- `prev` on line *n* (n ≥ 1) is the SHA-256 of the **exact bytes of
  line n − 1, including its terminating `\n`**.
- The **chain head** is the SHA-256 of the exact bytes of the last
  complete line, including its `\n`.

### 4.3 Entry types

Fields marked \* are checked by the verification procedure (Section 9);
the others are recorded by the writer for the reader's information.

| Type | `data` fields written | Rules |
|------|------------------------|-------|
| `SESSION_START` | `acquisition_id`\*, `tool`, `tool_version`, `tool_commit` (or null), `retry_of` (or null), `clock_source`, `host` (object), `session_nonce` (32 hex characters) | Line 0, and only line 0. |
| `INTENT` | `action`\* (non-empty string); others vary | Written **before** the action it announces. |
| `RESULT` | `intent_seq`\*, `succeeded`, `exit_status` (or null); others vary | `intent_seq` is the `seq` of an `INTENT` that is still open; each `INTENT` is closed at most once. |
| `CHUNK` | `stream`\* (package-relative path), `index`\*, `offset`\*, `length`\*, `sha256`\* | One per completed chunk of a stream, written after the chunk is on disk. |
| `NOTE` | `message` | Informational. |
| `SEAL` | `manifest_sha256`\*, `entry_count`\* | Last line. No `INTENT` may be open. `entry_count` is the total number of lines including the `SEAL` line. |

Writer actions currently recorded:

- `INTENT` with `action` `"write file"` or `"capture stream"`, and
  `path` (package-relative);
- the matching `RESULT` with `path`, `size` and `sha256` of the file as
  written, and for streams `chunk_count` and `verified_from_disk`.

A `RESULT` that records a `path` and `sha256` must match that file on
disk, except for `manifest.json`, which is checked against the `SEAL`
entry.

### 4.4 Log states

A verifier classifies the log as exactly one of:

- **`SEALED`**: every line satisfies 4.1–4.3, the last line is `SEAL`,
  and no bytes follow it.
- **`UNSEALED`**: every complete line satisfies 4.1–4.3, and there is no
  `SEAL` line. The acquisition was interrupted. Bytes after the last
  `\n` are a **torn final line**: they are reported, never repaired, and
  are not part of the chain.
- **`BROKEN`**: anything else, for example a `prev` mismatch, a `seq`
  gap, an unparseable complete line, a line after `SEAL`, or a `RESULT`
  that closes no open `INTENT`.

**Limit of the chain.** Editing or deleting the **last** line of a log,
or truncating the log at a line boundary, cannot be detected from the
log alone, because nothing later in the log depends on those bytes. In
a sealed package the `SEAL` file and the manifest hash catch most such
changes; only the externally recorded chain head catches all of them.

---

## 5. Interrupted packages

- An interrupted package is kept, never resumed. A retry uses a new
  acquisition ID and records the old one in `retry_of`.
- It may lack `SEAL`, `manifest.json` and the hash lists. If `SEAL` is
  present while the log is `UNSEALED`, the package is inconsistent and
  fails integrity.
- Each `CHUNK` entry can still be checked against the partial stream
  file on disk. The verifier reports the open `INTENT`s, the last
  complete entry and the number of verified chunks.
- Integrity for an interrupted package is **INCOMPLETE** if every check
  that can run passes, and **FAIL** otherwise.

---

## 6. `SEAL` file

Exactly two lines, ASCII, each ending in `\n`:

```text
chain_head <64 hex>
manifest_sha256 <64 hex>
```

- `chain_head` must equal the chain head of `audit.jsonl` (Section 4.2).
- `manifest_sha256` must equal the `SEAL` entry's `manifest_sha256` and
  the SHA-256 of `manifest.json`.

The operator records the chain head shown at acquisition time in their
own case notes, outside the package. Comparing that record with the
package's chain head is the only check that detects a package
regenerated in full.

---

## 7. `manifest.json`

A JSON object, UTF-8. Its SHA-256 is recorded in the `SEAL` entry, so
any change to it is detected; its key order and whitespace do not
matter to verification.

| Field | Value |
|-------|-------|
| `format` | `"corrobora-mobile/evidence-package"` |
| `format_version` | `1` |
| `acquisition_id` | equals `SESSION_START`'s `acquisition_id` |
| `tool` | object: `name`, `version`, `commit` (or null) |
| `created_at`, `finalized_at` | UTC timestamps, as in `ts` |
| `chunk_size` | positive integer: bytes per chunk |
| `files` | array, one object per evidence file (below) |
| `content` | object: acquisition-specific fields (Section 11) |

Each `files` entry:

| Field | Value |
|-------|-------|
| `path` | package-relative path (Section 2.1) |
| `kind` | `"stream"`, `"artifact"` or `"package"` (`hashes/files.sha256` and `hashes/chunks.sha256`) |
| `size` | size in bytes |
| `sha256` | SHA-256 of the whole file |
| `complete` | `true`, or `false` for a stream that was aborted |
| `chunk_count` | number of rows for this file in `chunks.sha256` (0 for non-streams) |

`audit.jsonl`, `SEAL` and `manifest.json` are never listed in `files`.

---

## 8. Hash lists

### 8.1 `hashes/files.sha256`

- One line per evidence file whose `kind` is not `"package"`:
  `<64 hex>` + two spaces + `<package-relative path>` + `\n`.
- This is the layout `sha256sum` reads, so on Linux
  `sha256sum -c hashes/files.sha256`, run from the package directory,
  checks every evidence file.
- It is written before `chunks.sha256` and the manifest, so it does not
  list those; the manifest covers them.

### 8.2 `hashes/chunks.sha256`

- First line exactly: `# path<TAB>index<TAB>offset<TAB>length<TAB>sha256`
- Then one line per chunk, tab-separated, each ending in `\n`:
  `<path> <index> <offset> <length> <sha256>`.
- For each stream: indexes start at 0 with no gaps; the first offset is
  0 and each chunk starts where the previous one ends; every length is
  between 1 and `chunk_size`; the chunks together cover the whole file.
- Each row must equal the `CHUNK` entry in the audit log with the same
  `stream` and `index`.

---

## 9. Verification procedure

A verifier performs these checks. `tools/verify_package.py` reports
each failure separately.

**Integrity:**

1. Classify the audit log (Section 4.4). `BROKEN` → FAIL.
2. If `UNSEALED`: apply Section 5 and stop.
3. Check the `SEAL` file (Section 6).
4. Check `manifest.json`'s SHA-256 against the `SEAL` entry, its
   `format`, `format_version` and `acquisition_id`.
5. For every `files` entry: the path is valid, the file exists, and its
   size and SHA-256 match.
6. No other files and no symbolic links exist (Section 2).
7. `files.sha256` lists exactly the non-`package` files, with matching
   hashes.
8. `chunks.sha256` matches Section 8.2, every chunk hash matches the
   bytes on disk, and every chunk matches its `CHUNK` entry.
9. Every `RESULT` that records a `path` and `sha256` matches the file.
10. If the operator supplies the externally recorded chain head, it
    equals the package's chain head.

**Completeness** and **validation** are separate findings. In this
format version a verifier can only report the values recorded in
`content` (Section 11); it cannot recompute completeness.

---

## 10. Checking with standard tools (Linux)

These commands were tested with GNU coreutils on Linux. Run them from
the package directory.

```sh
# Evidence files against hashes/files.sha256
sha256sum -c hashes/files.sha256

# Hash chain: each line's prev must equal the SHA-256 of the line before
n=$(wc -l < audit.jsonl); prev=$(printf '0%.0s' $(seq 64))
for i in $(seq 1 "$n"); do
  p=$(sed -n "${i}p" audit.jsonl | grep -o '"prev":"[0-9a-f]*"' | cut -d'"' -f4)
  [ "$p" = "$prev" ] || echo "line $((i-1)): prev mismatch"
  prev=$(sed -n "${i}p" audit.jsonl | sha256sum | cut -d' ' -f1)
done
echo "chain head: $prev"      # compare with SEAL and with your case notes
cat SEAL

# Manifest hash (compare with manifest_sha256 in SEAL)
sha256sum manifest.json

# One chunk: offset 4, length 4 (from a row of hashes/chunks.sha256)
tail -c +$((4 + 1)) data/ffs.tar | head -c 4 | sha256sum
```

The `grep` in the chain loop relies on the writer's compact JSON (no
space after `:`). It is a convenience, not part of the specification.

UNVERIFIED: This claim requires additional research or testing. An
equivalent, tested procedure for Windows with PowerShell `Get-FileHash`
has not been written yet (ARCHITECTURE.md, A-17).

---

## 11. Not yet specified

These will be specified with the milestones that produce them. Until
then, a verifier must report them as not checked:

- **Manifest `content`.** By convention the writer's callers record
  `completeness_status` and `method_validation_status` there.
  `tools/verify_package.py` displays these values but does not trust or
  recompute them.
- **`reconciliation.json`.** The current reconciliation module writes
  `format: "corrobora-mobile/reconciliation"`, `format_version: 1`. Its
  full layout will be specified with the acquirer.
- **`enumeration/pre.jsonl`, `enumeration/post.jsonl`, `errors/` and
  `plan/`.** Needed to recompute completeness.
- **`hashes/entries.sha256`** (per-entry hashes read from the archive).
  Deferred. ARCHITECTURE.md Section 5.1 lists it and an earlier
  `streams.sha256`; in format version 1 `files.sha256` takes the place
  of `streams.sha256`.
