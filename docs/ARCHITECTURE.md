# Corrobora Mobile — Technical Architecture (Proposed)

**Document status:** PROPOSED — design only. Nothing described here is
implemented, tested, or validated unless explicitly marked otherwise.

**Revision:** 3 (2026-10-16). Revision 1 was merged to `main` in pull
request #3 (commit `89d028e`). A later update recording the Section 8.3
decisions (commit `24eb22c` on branch `docs/architecture`) was not part
of that merge; this revision includes those decisions. Revision 2 was
reviewed but never committed.

**Applies to repository state:** `main` at `03f9086` (README, LICENSE,
.gitignore, CodeQL workflow, Revision 1 of this document; no source code).

---

## How to Read This Document

Every technical claim in this document carries one of these labels:

| Label | Meaning |
|-------|---------|
| **[VERIFIED-SOURCE]** | Stated in a cited primary or authoritative source (see References). Not yet tested by this project. |
| **[DESIGN]** | A proposed design decision for this project. Open to change. |
| **UNVERIFIED** | "UNVERIFIED: This claim requires additional research or testing." Each one is also tracked in the register in Section 8.4. |

No acquisition method, device, or OS version is classified **VERIFIED**
for Corrobora Mobile. That status requires documented testing by this
project (Section 5.8).

Four properties of an acquisition are recorded and reported
**independently**. None implies another:

| Property | Question it answers | Defined in |
|----------|--------------------|-----------|
| **Acquisition class** | What technical scope did this acquisition cover? | Section 0.2 |
| **Completeness status** | Was everything in the declared scope captured or accounted for? | Section 5.2 |
| **Integrity status** | Is the package unchanged since it was sealed? | Section 5.6 |
| **Validation status** | Has this method been forensically validated for this configuration? | Sections 0.3 and 5.8 |

---

## 0. Terminology and Acquisition Classes

### 0.1 General Terms

| Term | Definition used by this project |
|------|--------------------------------|
| **Logical acquisition** | Data obtained through interfaces the OS exposes to an ordinary paired or authorized host, such as an iOS backup, iOS AFC media access, or Android `adb pull` without root. NIST SP 800-101r1 classifies logical extraction as Level 2 [VERIFIED-SOURCE]. |
| **Physical acquisition** | A block-level copy of storage. Out of scope for initial development. [DESIGN] |
| **Privileged access** | A state in which the acquisition host can read filesystem locations that the platform's normal security model denies to a host, such as root on Android or code execution outside the app sandbox on iOS. |
| **Data accessibility** | Whether the acquired bytes are usable (decrypted) at acquisition time. Privileged access does **not** imply accessibility (see Section 1.3). |
| **Declared scope** | The exact set of paths and mounted filesystems an acquisition intends to capture, fixed in the acquisition plan *before* any data is read. |

**Obtaining privileged access and acquiring data are separate problems,
and the architecture keeps them separate (Section 4).**

### 0.2 File-Level Acquisition Classes [DESIGN]

Every file-level acquisition is labeled with exactly one class. The label
is stored in the manifest and on every report. A class describes the
acquisition's **technical scope and capabilities**, determined from the
evidence that acquisition recorded. It is not a claim of quality, of
completeness (Section 5.2), or of validation (Section 0.3).

| Class | Definition | Required evidence for the label |
|-------|-----------|--------------------------------|
| `SELECTED_DIRECTORY` | One or more operator-chosen directories, captured **without** privileged access. | Declared path list. |
| `PRIVILEGED_SELECTED_DIRECTORY` | One or more operator-chosen directories (e.g. `/data`), captured **with** privileged access. | Declared path list, plus a record of the privileged session. |
| `PRIVILEGED_FILESYSTEM` | Every mounted filesystem in the device's mount table at acquisition time, except pseudo-filesystems excluded by a documented rule (e.g. `proc`, `sysfs`, `tmpfs`), captured with privileged access. | Captured mount table, the exclusion rule set, and an exclusion decision for each mount. |
| `FFS` | A `PRIVILEGED_FILESYSTEM` acquisition that also meets **all** of these capability criteria: (F1) every mount holding persistent user or system data is in scope, with no unexcluded mount missing; (F2) application-private data areas are in scope; (F3) file content is captured for every in-scope regular file the method could read; (F4) every **R** (required) attribute in Section 5.3.1 is captured for every in-scope entry, by the archive or the enumeration. | `PRIVILEGED_FILESYSTEM` evidence, plus the per-criterion results F1–F4 recorded in the manifest. |

Rules:

- **A `/data` TAR collection is `PRIVILEGED_SELECTED_DIRECTORY`.** It is
  never `FFS`, regardless of how many files it contains.
- The **final class** is the lower of the planned class and the highest
  class whose criteria the recorded evidence meets. A class can therefore
  only be **lowered** after the fact (for example, an acquisition planned
  as `PRIVILEGED_FILESYSTEM` that skipped a mount is relabeled
  `PRIVILEGED_SELECTED_DIRECTORY`). It can never be raised.
- The class says nothing about decryption. A `FFS`-class acquisition of
  a locked device may consist largely of ciphertext. Data accessibility is
  recorded separately in the manifest (Section 5.4).
- The class says nothing about completeness. An `FFS`-class acquisition
  can still be `PARTIAL` (Section 5.2).
- The README uses "FFS" as the project's goal. Output produced by this
  project uses the class labels above.

### 0.3 Classification Is Not Validation [DESIGN]

- **Classification** is determined per acquisition, from that
  acquisition's own evidence (plan, mount table, enumeration,
  reconciliation). It does not depend on whether the method has been
  validated.
- **Validation status** belongs to a **method on an exact configuration**
  (`VERIFIED`, `EXPERIMENTAL`, `UNVERIFIED`, `UNSUPPORTED`; Section 5.8).
  It is copied into each manifest as it stood at acquisition time, with a
  reference to the validation record, if any.
- An acquisition may therefore be `FFS`-class by method `UNVERIFIED`. The
  manifest and every report must show both, side by side, and must never
  merge them into a single label such as "validated FFS".
- A method's validation record states which classes it has been
  validated for. An acquisition whose class is higher than any class the
  method has been validated for is reported as "class not validated for
  this method".

---

## 1. System Overview and Component Responsibilities

### 1.1 Purpose

Corrobora Mobile will orchestrate device-specific, documented acquisition
methods. It will package the results as integrity-protected evidence
packages suitable for independent forensic analysis. [DESIGN]

The project does **not** assume any device or OS version can be acquired.
Support exists only where a specific method has been tested on a specific
device configuration.

### 1.2 Components

```text
            ┌──────────────────────────────────────────────┐
            │             CLI / Orchestrator                │
            └──────────────────────────────────────────────┘
                 │            │             │            │
                 ▼            ▼             ▼            ▼
          ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌───────────┐
          │Detection │ │Compatibility│ │  Access  │ │Acquisition│
          │(read-only│→│ Assessment  │→│ Providers│→│  Engines  │
          │ identify)│ │ (registry)  │ │          │ │           │
          └──────────┘ └────────────┘ └──────────┘ └───────────┘
                                                        │
                                                        ▼
          ┌──────────────┐   ┌──────────────────┐   ┌───────────┐
          │ Audit Logging│◄──│Evidence Packaging│──►│Validation │
          │ (all stages) │   │ hashing/manifest │   │& Verify   │
          └──────────────┘   └──────────────────┘   └───────────┘
```

| Component | Responsibility | Must NOT |
|-----------|---------------|----------|
| **Detection** | Read-only identification of connected devices (platform, model, OS version, build type, lock and security state where observable). Records raw responses as evidence. | Change device state, pair, unlock, root, or install anything. |
| **Compatibility** | Matches a device identity against the method registry. Returns candidate methods with their status, prerequisites, and declared risks. | Upgrade a status automatically, or infer support from a successful connection or backup. |
| **Access providers** | Establish privileged access through one documented method each. Declare every device modification before running. Tear down cleanly. | Acquire data, or hide side effects. |
| **Acquisition engines** | Copy filesystem content through an established access session into the evidence writer. Record scope, exclusions, enumeration, and errors. | Decide whether access is permitted, drop errors, or assign an acquisition class higher than the evidence supports. |
| **Evidence packaging** | Write-once evidence storage, streaming SHA-256, chunk hashes, manifests, device-modification records. | Modify acquired data after capture. |
| **Audit logging** | An append-only, hash-chained record of every operation, command, and result (Section 5.6). | Be optional or disabled. |
| **Validation** | Package verification, completeness reconciliation, reproducibility tests, comparison against reference datasets. Reports integrity, completeness, and validation as separate findings. | Treat passing unit tests as forensic validation, or let a passing hash check stand in for completeness. |
| **Reporting** (later) | Human-readable acquisition reports from the manifest and audit log. | Claim more than the manifest records. |
| **Analysis** | Out of scope. Future Chronoscope or Corrobora integration requires separate approval. | — |

### 1.3 Platform Security Facts That Constrain the Design

**iOS**

- Apple Data Protection assigns files to classes. Class A (Complete
  Protection) keys are discarded shortly after the device locks. Class C
  (Protected Until First User Authentication) keys remain in memory after
  first unlock and protect against attacks that involve a reboot. Class C
  is the default for third-party app data. [VERIFIED-SOURCE: Apple Platform
  Security]
  - **Design consequence:** an acquisition before first unlock (BFU) or
    while the device is locked can, at most, yield ciphertext for protected
    classes, even with privileged access. The manifest must record the
    device lock state as observed. Where the method cannot observe it, the
    manifest records it as unknown, not assumed.
- The standard AFC service gives a host access to the `/var/mobile/Media`
  area only. Root filesystem access over AFC required a service ("AFC2")
  that only older jailbreaks installed. [VERIFIED-SOURCE: libimobiledevice
  ifuse README]
  - **Design consequence:** AFC and iOS backups are logical acquisitions
    and are never assigned any class in Section 0.2.
- checkm8 is a bootrom vulnerability affecting A5–A11 devices. It requires
  physical access, and Apple cannot fix it without a hardware revision.
  A12 and later are not affected. [VERIFIED-SOURCE: Security Affairs; Elcomsoft]
- On the iPhone 8, iPhone 8 Plus, and iPhone X (A11), Secure Enclave
  mitigations prevent DFU-based access from unlocking the disk, even
  though the bootrom exploit still works. [VERIFIED-SOURCE: Elcomsoft, as
  a vendor statement]
- The iPhone 16 Pro Max uses the A18 Pro chip [VERIFIED-SOURCE: Apple
  support specifications], so it is outside the checkm8 range.
- UNVERIFIED: This claim requires additional research or testing. — I
  found no publicly documented, open-source FFS acquisition method for
  A18 Pro devices on iOS 26.x. Commercial tools may have undisclosed
  capabilities. That cannot be verified and is not relied on. (A-01)

**Android**

- File-based encryption (FBE) is required for devices launching with
  Android 10 and later. It was introduced in Android 7.0.
  [VERIFIED-SOURCE: AOSP FBE documentation]
- Credential Encrypted (CE) storage is the default storage location and
  is available only after the user has unlocked the device. Device
  Encrypted (DE) storage is also available in Direct Boot mode, before
  unlock. [VERIFIED-SOURCE: AOSP FBE documentation]
  - **Design consequence:** for most app data, privileged access to a
    locked, freshly rebooted device does not provide plaintext. The
    manifest must record user-unlock state.
- The `userdebug` build variant is "a user build with root access
  enabled." `user` builds have `ro.debuggable=0`; `userdebug` and `eng`
  have `ro.debuggable=1`. [VERIFIED-SOURCE: AOSP build variants]
- Android Emulator image types: **Google Play** images are
  `user/release-keys`, **Google APIs** images are `userdebug/dev-keys`,
  and AOSP images (no label) are `eng/test-keys`. [VERIFIED-SOURCE:
  Chromium Android emulator documentation]
- `adb root` on a Google Play (production) emulator image fails with
  "adbd cannot run as root in production builds". [VERIFIED-SOURCE: 8kSec]

---

## 2. Proposed Repository Structure

This builds on the structure proposed in `README.md` and adds the
`audit`, `compatibility`, and `detection` packages that CLAUDE.md
Section 10 requires to be kept separate. It also adds an isolated
`research` area for physical-device work (Section 7). [DESIGN]

The language is **Python 3.12 or later** (decided 2026-10-16; see
Section 8.3).

```text
Corrobora-Mobile/
├── docs/
│   ├── ARCHITECTURE.md            # this document
│   ├── EVIDENCE_FORMAT.md         # byte-level package and audit-log spec (5.7)
│   ├── ACQUISITION_METHODS.md     # one dossier per method (7.2)
│   ├── COMPATIBILITY.md           # generated from compatibility/ data
│   └── VALIDATION.md              # validation procedures and records
│
├── compatibility/                 # data, not code: reviewable records
│   └── methods/
│       └── android.emulator.adb_root_userdebug.json
│
├── src/corrobora_mobile/
│   ├── core/                      # shared models, errors, clock, IDs
│   ├── audit/                     # hash-chained append-only log
│   ├── evidence/                  # package writer, hashing, manifest
│   ├── detection/                 # read-only identification interface
│   ├── compatibility/             # registry loader + assessment
│   ├── access/                    # PrivilegedAccessProvider interface
│   ├── acquisition/               # FFSAcquirer interface, orchestrator,
│   │                              # enumeration + reconciliation
│   ├── validation/                # package verification, reproducibility
│   ├── platforms/
│   │   ├── android/               # Android detection/providers/acquirers
│   │   │   └── research/          # research-only providers (7.3)
│   │   └── ios/                   # iOS detection only (no providers yet)
│   │       └── research/          # research-only providers (7.3)
│   └── cli.py
│
├── tools/
│   └── verify_package.py          # standalone verifier, stdlib only (5.7)
│
└── tests/
    ├── unit/                      # no device required
    ├── integration/               # requires an Android emulator; opt-in
    └── fixtures/synthetic/        # generated test data only; no real evidence
```

Rules:

- No evidence, device images, pairing records, or personal data in the
  repository. The `.gitignore` will be extended to exclude evidence output
  directories. [DESIGN]
- Platform code lives only under `platforms/<os>/`. Generic packages must
  not import platform packages. [DESIGN]
- Code under `research/` is never loaded unless research mode is
  enabled (Section 7.3). [DESIGN]
- `tools/verify_package.py` must not import `corrobora_mobile`, so that
  verification does not depend on the code that wrote the package
  (Section 5.7). [DESIGN]

---

## 3. Device Identification and Compatibility Workflow

### 3.1 Workflow

```text
1. DETECT (read-only)
   └─ collect identity; save raw responses into the evidence package
2. ASSESS
   └─ match identity against compatibility/methods/*.json
   └─ output: list of (method, status, prerequisites, declared risks)
3. GATE
   ├─ no matching method          → stop: UNSUPPORTED (Section 6)
   ├─ status UNSUPPORTED          → stop
   ├─ status UNVERIFIED           → allowed only in research mode (7.3)
   ├─ status EXPERIMENTAL         → allowed with risk acknowledgement
   └─ status VERIFIED             → allowed with risk acknowledgement
4. ACKNOWLEDGE
   └─ operator confirms each declared device modification; recorded in audit log
5. PLAN    → declared scope and acquisition class fixed before any read
6. ACCESS  → 7. ENUMERATE (pre) → 8. ACQUIRE → 9. ENUMERATE (post)
10. RECONCILE → 11. FINALIZE (hash, manifest, seal) → 12. VERIFY
```

[DESIGN] A successful connection, pairing, or backup never changes a
compatibility status.

### 3.2 Identity Record

The identity record contains the following fields. A field the method
cannot observe is recorded as unknown, never guessed. [DESIGN]

- `platform`, `manufacturer`, `model`, `hardware_identifier`
- `os_name`, `os_version`, `os_build`, `build_type` (Android: `ro.build.type`)
- `security_patch_level` (Android)
- `lock_state`: `locked` | `unlocked` | `unknown`
- `boot_state`: `bfu` | `afu` | `unknown`
- `is_emulator`: boolean or unknown
- `raw_responses`: references to stored raw outputs

**Detection itself may modify a device:**

- **iOS:** pairing ("Trust This Computer") creates a pairing relationship
  on the device. UNVERIFIED: This claim requires additional research or
  testing. — the exact device-side records written during pairing have not
  been documented by this project (A-12). Until they are, any iOS
  detection that requires pairing is recorded as a device modification.
- **Android:** reading properties over ADB requires USB debugging to be
  enabled and the host authorized, both of which change device state.

### 3.3 Method Compatibility Record

Each method has one JSON file. It records the fields CLAUDE.md
Section 6 requires, plus the highest acquisition class the method may
claim. [DESIGN]

```json
{
  "method_id": "android.emulator.adb_root_userdebug",
  "platform": "android",
  "applies_to": {
    "manufacturer": "Android Emulator (Google)",
    "model": "AVD",
    "os_versions": ["UNVERIFIED — to be filled from testing"],
    "build_type": ["userdebug"]
  },
  "physical_device": false,
  "security_configuration": "Emulator; no hardware-backed TEE equivalence assumed",
  "required_device_state": "Booted; user unlocked (for CE storage); adb authorized",
  "required_privileges": "adbd running as root via `adb root`",
  "max_acquisition_class": "PRIVILEGED_SELECTED_DIRECTORY",
  "acquisition_scope": "/data only (M1)",
  "device_modifications": [
    "adbd restarted as root",
    "UNVERIFIED: file access-time updates caused by reading files, depending on mount options",
    "UNVERIFIED: any other side effects of the acquisition tooling"
  ],
  "known_limitations": [
    "Not a physical device",
    "Not an ordinary, unmodified, or locked device",
    "No unallocated space or deleted-data recovery",
    "TAR metadata limitations; see Section 5.3"
  ],
  "validation_status": "UNVERIFIED",
  "validation_records": []
}
```

---

## 4. Privileged-Access and Filesystem Acquisition Interfaces

The interfaces below are illustrative, not implemented. [DESIGN]

### 4.1 Separation

- A **PrivilegedAccessProvider** answers: "Can I obtain privileged
  read access on this device configuration, what will it change, and
  how do I undo it?"
- An **FFSAcquirer** answers: "Given an access session and a declared
  scope, how do I enumerate and copy that scope into the evidence writer,
  and what did I fail to copy?" The name reflects the project goal. Each
  acquirer still declares the highest class it can produce.

The same provider may serve several acquirers, for example a tar-stream
acquirer or a per-file acquirer. A new device-specific method is a new
provider plus a compatibility record. The core does not change.

### 4.2 Interfaces (sketch)

```python
class PrivilegedAccessProvider(Protocol):
    method_id: str                     # must match a compatibility record
    research_only: bool                # True → requires research mode (7.3)

    def check_preconditions(self, identity: DeviceIdentity) -> PreconditionReport:
        """Read-only. Never modifies the device."""

    def declared_modifications(self) -> list[DeviceModification]:
        """Every change this provider may make, each with a risk class
        (7.3). Shown to the operator before establish(); recorded in the
        manifest."""

    def establish(self, ctx: AcquisitionContext) -> AccessSession:
        """Obtain privileged access. Every command is logged to audit."""

    def teardown(self, session: AccessSession) -> TeardownReport:
        """Undo reversible changes; report irreversible ones."""


class FFSAcquirer(Protocol):
    acquirer_id: str
    max_class: AcquisitionClass        # highest class this acquirer may claim

    def plan(self, session: AccessSession, requested: ScopeRequest) -> AcquisitionPlan:
        """Fix the declared scope and the planned class before reading data.
        Records the mount table and the exclusion decision for each mount."""

    def enumerate(self, session: AccessSession, plan: AcquisitionPlan) -> Enumeration:
        """Independent listing of in-scope entries (path, type, size,
        mtime, inode, link count where available), produced by a mechanism
        separate from the copy mechanism. Read-only."""

    def acquire(self, session: AccessSession, plan: AcquisitionPlan,
                writer: EvidenceWriter) -> RawAcquisition:
        """Stream data to writer. Never writes to the device. Captures
        stdout, stderr, and exit status separately."""

    def reconcile(self, plan: AcquisitionPlan, pre: Enumeration,
                  raw: RawAcquisition, post: Enumeration) -> AcquisitionResult:
        """Apply the completeness criteria in Section 5.2 and assign the
        final status and class."""
```

### 4.3 Candidate Methods (research registry, initial status)

| Method | Platform / devices | Privileged access basis | Max class | Initial status |
|--------|-------------------|------------------------|-----------|----------------|
| `android.emulator.adb_root_userdebug` | Android Emulator, Google APIs images | `userdebug` build root access [VERIFIED-SOURCE] | `PRIVILEGED_SELECTED_DIRECTORY` (M1) | UNVERIFIED |
| `android.userdebug_physical` | Physical devices running userdebug/eng builds | Same build semantics [VERIFIED-SOURCE] | Not assigned | UNVERIFIED — research only |
| `android.rooted_physical` | Physical devices with an unlocked bootloader and root | UNVERIFIED: This claim requires additional research or testing. — device-specific unlocking may wipe user data (A-13) | Not assigned | UNVERIFIED — research only |
| `ios.checkm8_class` | A5–A11 only | Bootrom vulnerability [VERIFIED-SOURCE]; A11 SEP limits [VERIFIED-SOURCE, vendor] | Not assigned | UNVERIFIED — research only; no implementation planned until an authorized test device and a documented open method are identified |
| iOS A12+ / iOS 26.x | Includes iPhone 16 Pro Max | No documented open method identified | None | UNSUPPORTED |

---

## 5. Evidence Preservation, Completeness, and Validation

### 5.1 Evidence Package Layout [DESIGN]

```text
<output>/<acquisition_id>/
├── manifest.json            # finalized last; see 5.4
├── audit.jsonl              # hash-chained log (5.6)
├── SEAL                     # final chain head + manifest hash (5.6)
├── identity/                # raw detection outputs, unmodified
├── plan/
│   ├── plan.json            # declared scope and planned class
│   └── mounts.txt           # raw mount table as captured
├── enumeration/
│   ├── pre.jsonl            # independent listing before copy
│   └── post.jsonl           # independent listing after copy
├── data/
│   └── ffs.tar              # acquisition stream exactly as received
├── hashes/
│   ├── streams.sha256       # SHA-256 of each captured stream
│   ├── chunks.sha256        # SHA-256 of each fixed-size chunk (5.6)
│   └── entries.sha256       # SHA-256 per file entry, computed by reading
│                            # the tar, never by extracting it
├── reconciliation.json      # per-entry outcome (5.2)
└── errors/                  # raw stderr, per-path read errors
```

The file name `ffs.tar` names the stream, not its class. The class is
recorded only in the manifest.

Rules:

1. Acquired data is written once and never modified. Analysis works on copies.
2. SHA-256 is computed **while streaming**, before the data reaches
   disk, and again from disk at finalization. A mismatch fails the
   acquisition.
3. Evidence files are marked read-only after finalization. This is a
   best-effort host safeguard, not tamper-proofing.
4. Interrupted acquisitions are kept and marked `PARTIAL`, `FAILED`, or
   `INTERRUPTED`. They are never silently deleted (Section 5.6).
5. Following NIST SP 800-101r1, back-to-back acquisitions of a live device
   produce different whole-image hashes because the device keeps changing.
   Reproducibility is therefore assessed per file, not by whole-stream
   hash. [VERIFIED-SOURCE]

### 5.2 Completeness Criteria [DESIGN]

**A successful command exit status is never sufficient for `COMPLETE`.**
UNVERIFIED: This claim requires additional research or testing. — I could
not confirm from toybox `tar.c` alone whether an unreadable file changes
toybox `tar`'s exit status (A-05). The source shows that it prints an
error and skips the entry. Either way, the design does not rely on the
exit status.

An acquisition is `COMPLETE` only if **every** check below passes:

| # | Check | Fails → |
|---|-------|---------|
| C1 | The declared scope and planned class were recorded **before** the first data read. | `FAILED` (no valid plan) |
| C2 | The copy process exited with status 0. | `PARTIAL` or `FAILED` |
| C3 | The stderr stream contains no error lines. Any stderr content is stored and must be classified. Unclassified content counts as an error. | `PARTIAL` |
| C4 | The stream ended cleanly. The transport closed normally, the archive parses to its end-of-archive marker, and no member is truncated. | `PARTIAL` |
| C5 | The streaming hash and the at-rest hash of every stream match. | `FAILED` (`IntegrityError`) |
| C6 | Every in-scope path in the pre-acquisition enumeration has exactly one outcome: `ACQUIRED`, `EXCLUDED_BY_RULE` (with the rule ID), `UNSUPPORTED_TYPE` (e.g. socket), or `ERROR` (with the error). | `PARTIAL` |
| C7 | No in-scope entry has the outcome `ERROR`. | `PARTIAL` |
| C8 | For each `ACQUIRED` regular file, the archived size equals the enumerated size, or the difference is explained by a change between pre- and post-enumeration (C9). | `PARTIAL` |
| C9 | Entries that differ between pre- and post-enumeration are listed as `CHANGED_DURING_ACQUISITION`. They do not make the result `PARTIAL` on their own, but the result is reported as `COMPLETE_WITH_CHANGES`, and each changed entry is marked unreliable (Section 5.2.1). | (status modifier) |
| C10 | The audit log chain verifies and is sealed (Section 5.6). | `FAILED` (`IntegrityError`) |

Result statuses:

- **`COMPLETE`**: C1–C10 pass and no entry changed during acquisition.
- **`COMPLETE_WITH_CHANGES`**: C1–C8 and C10 pass. Some entries changed
  during acquisition, and every one is listed. This status means only
  that every in-scope entry was accounted for. It does **not** mean the
  changed entries are reliable (Section 5.2.1).
- **`PARTIAL`**: valid data was acquired, but one or more of C2–C4 or
  C6–C8 failed. Every failure is listed.
- **`FAILED`**: no usable data, or an integrity check (C5, C10) failed.
- **`INTERRUPTED`**: the acquisition never reached finalization. The
  verifier assigns this status from the audit log (Section 5.6).
- **`COMPLETENESS_UNVERIFIED`**: data was acquired, but no independent
  enumeration was possible, so C6–C9 could not be evaluated. This
  status can never be reported as `COMPLETE`.

#### 5.2.1 Reliability of Changed and Live-Acquired Entries [DESIGN]

Each `ACQUIRED` entry carries a `content_reliability` value, recorded in
`reconciliation.json` and summarized in the manifest:

| Value | Meaning |
|-------|---------|
| `NO_CHANGE_DETECTED` | Pre- and post-enumeration agree on every compared attribute. This is **not** a guarantee of consistency (see below). |
| `CHANGED_DURING_ACQUISITION` | Pre- and post-enumeration differ. The archived copy may reflect neither state, or a mix of both (a "torn" copy). |
| `UNKNOWN` | No post-enumeration comparison was possible for this entry. |

Rules:

- A `CHANGED_DURING_ACQUISITION` entry is **never** presented as a
  reliable or internally consistent copy. Reports must show its
  reliability flag wherever its content is shown, and analysis tools
  that consume the package must be able to read the flag.
- `NO_CHANGE_DETECTED` is limited by what enumeration compares (size,
  mtime, ctime, inode where available) and by its timestamp precision.
  A change that leaves those values unchanged, or that is reverted
  between the two enumerations, is not detected.
- **Cross-file consistency is not guaranteed for any entry.** A live
  acquisition is not a point-in-time snapshot. Related files (for
  example, a database and its journal or write-ahead log) may be
  captured at different moments, even when each one shows
  `NO_CHANGE_DETECTED`. The manifest states this for every acquisition
  of a running device.
- An acquisition whose result is `COMPLETE_WITH_CHANGES` must list the
  number of changed entries in its summary, not only in the detail files.

**Limits of enumeration:** the enumeration runs on the same live device
through the same privileged session. It can miss entries the OS hides
from it, and it races with ongoing device activity. Agreement between
enumeration and archive is necessary for `COMPLETE`. It does not prove
that every byte of user data was captured. UNVERIFIED: This claim
requires additional research or testing. — which on-device tool can
produce the enumeration (e.g. toybox `find` or `stat` output formats)
is not yet confirmed (A-06).

### 5.3 Metadata Preservation Requirements and TAR Limitations

#### 5.3.1 Requirements [DESIGN]

Each attribute is classified as one of:

- **R (required):** it must be captured, or the acquisition records a
  documented limitation for every affected entry.
- **B (best effort):** captured where the method allows; any gap is
  recorded in the manifest.

| Attribute | Level | Notes |
|-----------|-------|-------|
| Full path, as raw bytes | R | Paths may not be valid UTF-8 and must not be normalized. |
| Entry type (regular, directory, symlink, hard link, char/block device, FIFO, socket) | R | Every type must be accounted for, even if its content can't be archived. |
| Size, plus file content for regular files | R | |
| Symlink target | R | |
| Hard-link relationships | R | |
| Mode, including setuid, setgid, and sticky bits | R | |
| Numeric UID and GID | R | Never names only. |
| Modification time (mtime) | R | Full precision where the source provides it. |
| Access time (atime) and change time (ctime) | B | Reading a file can change its atime, and ctime cannot be restored. Values are taken from the pre-acquisition enumeration. |
| Birth/creation time | B | Not represented in tar. |
| SELinux label (`security.selinux`) | R on Android | |
| Other extended attributes | B | |
| POSIX ACLs | B | |
| Sparse-file layout | B | Holes must not be silently materialized as data without being recorded. |
| Device major/minor numbers | R | For device nodes. |
| Inode number and link count | B | Used for reconciliation and hard-link checks. |
| Encryption state (fscrypt policy, encrypted-name status) | B | Records whether names and content were plaintext at acquisition time. |

#### 5.3.2 What TAR Can and Cannot Carry

**Format-level facts (Python `tarfile` documentation)
[VERIFIED-SOURCE]:**

- **USTAR:** limits file size to 8 GiB and names to 256 characters at
  best.
- **PAX (POSIX.1-2001):** has "virtually no limits" and carries extended
  header records per member.
- **Reading support:** Python's `tarfile` reads all sparse variants and
  exposes pax extended headers per member (`TarInfo.pax_headers`).
- **Supported member types:** directories, regular files, hard links,
  symlinks, FIFOs, and character and block devices. **Sockets are not a
  tar member type.**

**GNU tar (reference implementation) [VERIFIED-SOURCE]:**

- `--xattrs` and `--acls` imply the pax format.
- `--selinux` adds SELinux context support.
- By default, all xattr namespaces are stored on create.

**toybox `tar` (the implementation expected on Android)
[VERIFIED-SOURCE: toybox `master` source, `toys/posix/tar.c`, read
2026-10-16]:**

| Capability | toybox `tar` behavior |
|------------|----------------------|
| SELinux labels | Only with `--selinux`. Written as a pax record with the keyword `RHT.security.selinux`. |
| Other xattrs | **Not supported.** There is no general xattr handling. |
| POSIX ACLs | **Not supported.** No ACL handling appears in the source. |
| Timestamps | **Seconds only.** Stores `st_mtime` as whole seconds. Does not write atime, ctime, or birth time. |
| Hard links | Supported (tracked by device and inode). |
| Symlinks, char/block devices, FIFOs | Supported. |
| Sockets | **Not archivable.** Reports "unknown file type" and skips the entry. |
| Sparse files | Only with `--sparse`, using `SEEK_HOLE`/`SEEK_DATA`. Without it, holes are read as zeros. |
| Long names | GNU `L`/`K` long-name records. |
| Unreadable files | Prints "can't open" and skips the entry. |

UNVERIFIED: This claim requires additional research or testing. — the
toybox version on the target emulator image may differ from `master`
(A-04). The emulator's `tar --help` output and version must be captured
as evidence and compared to this table.

#### 5.3.3 Design Consequences [DESIGN]

1. TAR alone **cannot** meet the requirements in 5.3.1. Every
   acquisition therefore pairs the archive with the independent
   enumeration (`enumeration/pre.jsonl`), which records type, size,
   mode, UID/GID, all three timestamps at the highest precision
   available, inode, link count, and SELinux label where obtainable.
2. The archive must be created with `--selinux`, plus `--sparse` once it
   has been tested (A-07). `--numeric-owner` is used on create where the
   implementation supports it.
3. Sockets are always recorded with the outcome `UNSUPPORTED_TYPE` in
   reconciliation. They are expected, not errors.
4. Missing xattrs and ACLs, and second-precision mtime, are recorded as
   **known limitations of this method**, applied to every entry in the
   acquisition.
5. **atime as a device modification:** whether reading files updates
   atime depends on the mount options (e.g. `noatime`, `relatime`). The
   mount table is captured in `plan/mounts.txt`. Possible atime updates
   are declared as a device modification unless the captured mount
   options rule them out (A-08).
6. Replacing tar with a per-file transfer, or with a purpose-built
   on-device collector that preserves more metadata, is a later research
   option. It would itself need validation (Section 8.2).

### 5.4 Manifest Contents [DESIGN]

The manifest records:

- Tool name, version, and git commit; host OS; and the versions of
  external tools (e.g. `adb`, and the on-device `tar` version and help
  output).
- Operator and case identifiers, entered by the operator.
- Start and end times (UTC), with the host clock source and its offset
  if measured.
- Device identity (3.2), `method_id`, and the provider and acquirer IDs.
- Four separate fields, never merged (see "How to Read This Document"):
  - **`acquisition_class`**: planned and final, with criteria results
    (Section 0.2, F1–F4 where applicable);
  - **`completeness_status`** (Section 5.2), with the outcome of each
    check, C1–C10, and counts per `content_reliability` value (5.2.1);
  - **`integrity`**: hashes and the chain head as recorded at sealing
    (the verifier re-checks these independently; Section 5.7);
  - **`method_validation_status`**: as it stood at acquisition time,
    with the validation record reference and the classes it covers
    (Section 0.3).
- Declared and observed device modifications, plus the operator's
  acknowledgement.
- Declared scope, the mount table, exclusion decisions, and the
  reconciliation summary (counts per outcome).
- **Data accessibility**: lock state, unlock state, and whether
  filenames or content appeared encrypted.
- **Metadata-fidelity statement**: which attributes from 5.3.1 were
  captured, by which mechanism (archive or enumeration), and which were not.
- Stream, chunk, and entry hashes.
- The validation status of the method at acquisition time.
- The statement: "This acquisition does not demonstrate capability
  against any configuration other than the one recorded here."

### 5.5 Hashing [DESIGN]

- **SHA-256** for streams, entries, and 64 MiB chunks of each stream.
  The chunk size is a design default, open to change.
- Chunk hashes are written to the audit log as each chunk completes. If
  an acquisition is interrupted, the received prefix of the stream can
  still be verified.
- Python's `hashlib` (standard library) is the only hashing dependency.

### 5.6 Audit Log Integrity [DESIGN]

#### Structure

- `audit.jsonl`: one JSON object per line, encoded as UTF-8 and
  terminated by `\n`.
- **Fields:** `seq` (starting at 0, no gaps), `ts` (UTC, RFC 3339),
  `type`, `data`, and `prev`.
- **The `prev` field:** the SHA-256 (hex) of the **exact bytes** of the
  previous line, including its `\n`. Hashing exact bytes avoids any need
  to canonicalize JSON, so anyone can recompute the chain with standard
  tools. The first entry's `prev` is 64 zeros.
- **Line 0 (`SESSION_START`):** records the acquisition ID, tool version,
  git commit, host details, and a random 128-bit session nonce.

#### Write-ahead discipline

- **Before** every action that touches the device or the evidence, an
  `INTENT` entry is written and flushed to disk (`fsync`).
- **After** the action, a `RESULT` entry is written, referencing the
  intent's `seq`, the exit status, references to the stdout and stderr
  files, and their hashes.
- During streaming, a `CHUNK` entry is written per chunk (5.5).
- An `INTENT` with no matching `RESULT` therefore shows exactly where an
  interruption happened.

#### Sealing

- At finalization, a `SEAL` entry records the manifest's SHA-256 and the
  entry count.
- The SHA-256 of the `SEAL` line (the **chain head**) is written to the
  `SEAL` file and displayed to the operator.

#### Interrupted acquisitions

The verifier classifies every log as one of:

- **`SEALED`:** the chain verifies, the log ends in `SEAL`, and the
  manifest hash matches.
- **`UNSEALED`:** the chain verifies but has no `SEAL` entry. The
  acquisition is `INTERRUPTED`. The verifier reports the last completed
  step, any open `INTENT`, and the verified chunk prefix. A torn final
  line (no trailing `\n`) is reported, never repaired.
- **`BROKEN`:** a hash mismatch, a `seq` gap, or an unparseable line
  before the end. This always results in an `IntegrityError`.

An interrupted acquisition is never resumed into the same package. A
retry creates a new acquisition ID, which references the interrupted
one.

#### What the hash chain does and does not prove

- **It does prove:** that the log was not changed after the fact without
  rewriting every later entry. Any such edit shows up as a `BROKEN` log.
- **It does not prove:** that the whole log, data included, wasn't
  regenerated by someone with write access. Protecting against that
  requires anchoring the chain head **outside** the package:
  1. **Required:** the operator records the displayed chain head in their
     own case notes, which are separate from the package.
  2. **Optional, later:** request an RFC 3161 timestamp token for the
     chain head. A token is evidence that the data existed at a
     particular time [VERIFIED-SOURCE: RFC 3161]. This requires
     network access to a Time-Stamp Authority, and the choice of
     authority and library is open (A-15).
  3. **Optional, later:** sign the chain head with an operator key. The
     Python standard library has no public-key signature support, so
     this would need a new dependency, which requires separate approval
     (A-16).

### 5.7 Independent Verification [DESIGN]

- `docs/EVIDENCE_FORMAT.md` will specify the package layout, the
  audit-log line format, the chain rule, and the hash-file formats
  precisely enough that the package can be verified **without any
  Corrobora Mobile code**.
- `tools/verify_package.py`: a single file, standard library only, that
  never imports `corrobora_mobile` and opens evidence read-only.

#### Three distinct findings

The verifier reports **three separate findings**. Each has its own
result, its own section in the output, and its own bit in the exit
code. **A passing integrity finding never implies a complete
acquisition, and neither implies a validated method.**

1. **Integrity finding** — `PASS`, `FAIL`, or `INCOMPLETE` (interrupted
   package). It checks:
   - the audit chain (`SEALED`, `UNSEALED`, or `BROKEN`);
   - the `SEAL` file against the chain head;
   - the manifest hash against the `SEAL` entry;
   - every stream and chunk hash;
   - every entry hash, by reading the tar archive.

   A `PASS` means only that the package is internally consistent and
   unchanged since sealing (subject to Section 5.6's limits).
2. **Completeness finding** — the verifier **recomputes** the
   completeness status from the raw evidence (plan, pre- and
   post-enumeration, archive listing, stderr captures) using the rules
   in Section 5.2. It does not trust `reconciliation.json`. It reports
   the recomputed status, the status the manifest recorded, and any
   disagreement between them. A disagreement is reported as a separate
   failure of the completeness finding.
3. **Validation finding** — reports the `method_validation_status`
   recorded in the manifest, the referenced validation record, and
   whether the final acquisition class is within the classes that record
   covers. The verifier **cannot** validate a method itself. It always
   states: "Forensic validation is not assessed by this tool."

Example output summary:

```text
INTEGRITY:     PASS
COMPLETENESS:  PARTIAL (recomputed; matches manifest) — 3 ERROR entries
VALIDATION:    method UNVERIFIED — forensic validation is not assessed by this tool
```

The exit code is a bit field (integrity failure = 1, completeness not
`COMPLETE`/`COMPLETE_WITH_CHANGES` = 2, method not `VERIFIED` = 4), so
scripts cannot mistake one finding for another. [DESIGN]
- **Hash files:** written in the `<sha256>  <path>` layout used by
  `sha256sum`, so stream hashes can also be checked with
  `sha256sum -c`. UNVERIFIED: This claim requires additional research or
  testing. — compatibility with the Windows equivalent
  (`Get-FileHash`) needs a documented procedure (A-17).
- **Outside review:** a third party should be able to verify a package
  from `EVIDENCE_FORMAT.md` alone. That is an explicit validation item
  for M1.

### 5.8 Validation Levels

These follow CLAUDE.md Section 8.

| Level | What it shows | Example |
|-------|--------------|---------|
| Code review / static analysis | Code quality | CodeQL, linters |
| Unit tests | Logic on synthetic data | Manifest, hash-chain, reconciliation, interrupted-log tests |
| Integration tests | Works against a controlled target | Emulator acquisition |
| Device testing | Works on a specific physical configuration | A dedicated research device |
| Forensic validation | Completeness, integrity, metadata fidelity, and reproducibility within declared scope, checked against known ground truth | Planted files of every entry type on the emulator; compare acquired versus planted |

A method may be marked **VERIFIED** for a configuration only after
forensic-validation records exist in `docs/VALIDATION.md`. Each record
names the exact configuration and the acquisition classes it covers.
Validation status never changes an acquisition's class, and an
acquisition's class never changes a method's validation status
(Section 0.3).

---

## 6. Error Handling and Unsupported-Device Behavior [DESIGN]

- **Unsupported device or configuration:** stop after read-only detection.
  Report the identity, the reason, and the status. Exit with a nonzero
  code. Never fall back to a logical method silently. Logical acquisition,
  if added later, is a separately named command that is labeled as
  logical in its output.
- **Precondition failure** (e.g. user build, device locked): stop before
  `establish()` and report which precondition failed.
- **Errors during acquisition:** record each per-path error and continue
  only where the method defines it as safe. The status follows
  Section 5.2.
- **Transport loss:** mark the result `PARTIAL`, `FAILED`, or
  `INTERRUPTED` and keep the data already received, with its chunk
  hashes.
- **Teardown failure:** report the device left in a modified state,
  prominently in the manifest and on screen.
- **Typed errors:** errors are typed (`UnsupportedDeviceError`,
  `PreconditionError`, `AccessError`, `AcquisitionError`, `IntegrityError`,
  `ResearchModeRequiredError`). An `IntegrityError` always fails the
  acquisition.
- **No blanket exception handling** may hide an error from the manifest
  or the audit log.

---

## 7. Accommodating Physical-Device Privileged-Access Research

This section defines **how** research into privileged access on physical
iOS and Android devices would be added. **It does not assert that any
such method exists** for any particular device or OS version.
Locked-device and unmodified-device acquisition remain open research
questions (Section 8.2, Q9). [DESIGN]

### 7.1 Research Lifecycle

Each candidate method moves through these stages. Each stage needs your
explicit approval.

| Stage | Entry requirement | Compatibility status |
|-------|------------------|---------------------|
| 1. Proposal | A method dossier (7.2) citing **public** documentation for the technique. | UNVERIFIED |
| 2. Feasibility | An authorized research device is identified (7.4). Read-only probes only. | UNVERIFIED |
| 3. Prototype | Provider code under `platforms/<os>/research/`. Research mode only. | UNVERIFIED |
| 4. Experimental | Documented device tests for one exact configuration. | EXPERIMENTAL |
| 5. Verified | Forensic-validation records (5.8) for that exact configuration. | VERIFIED |

A method can stop at any stage. "No viable method found" is a valid,
documented outcome.

### 7.2 Method Dossier (in `docs/ACQUISITION_METHODS.md`)

Each method's dossier records:

- **Basis:** the technique, with public sources. The dossier states where
  only vendor claims are available.
- **Applicability:** the exact devices, chips, OS versions, and build
  types the technique applies to, with sources. Anything else is
  UNVERIFIED.
- **Required device state:** BFU/AFU, locked or unlocked, boot mode.
- **Expected data accessibility:** which storage classes would be
  plaintext.
- **Risk class:** one of:
  - `NONE`
  - `STATE_CHANGE` (reversible)
  - `PERSISTENT_CHANGE`
  - `POSSIBLE_DATA_LOSS`
  - `POSSIBLE_DEVICE_DAMAGE`
- **Legal and licensing review:** of the technique and of any external
  tool it depends on.
- **Highest acquisition class** the method could claim.

### 7.3 Research Mode Controls

- **Separate code:** research providers live only under
  `platforms/<os>/research/`, and are imported only when research mode is
  enabled.
- **Required inputs:** research mode requires:
  - an explicit flag;
  - an authorization reference (device ownership or consent record ID),
    which is stored in the manifest;
  - a per-run acknowledgement of the provider's risk class.
- **Labeling:** a research-mode acquisition is labeled "RESEARCH" in the
  manifest and in reports, and can never claim a status above
  EXPERIMENTAL.
- **External tools:** a provider may wrap an external tool rather than
  reimplement a technique. Its exact version and SHA-256 are recorded,
  and its license is reviewed before use.
- **Repository policy on exploit code (open decision):** whether the
  repository may ever contain code that exploits a vulnerability, as
  opposed to wrapping a separately obtained tool, is **undecided** and
  requires your decision before any Stage 3 work (Q11 in Section 8.2).

### 7.4 Research Device Inventory

- **Inventory:** each research device is recorded in a private
  inventory, kept outside the repository. Each record holds: an
  identifier, model, chip, OS version, ownership or authorization basis,
  and whether the device holds personal data. Research devices should
  hold **no** personal data.
- **Personal devices:** a personal device (for example, the developer's
  iPhone 16 Pro Max) is never a research device. It is excluded from all
  research stages.
- **Physical-device decision:** decided 2026-10-16. There are no research
  devices for now (Section 8.3).

### 7.5 Read-Only Capability Probes

Before any access attempt, a provider may run only read-only probes, such
as reading the OS version or build type. Every probe is listed in the
dossier, together with its known device-side effects. Probe results
never change a compatibility status on their own.

---

## 8. Technical Risks, Open Questions, Decisions, and Assumptions

### 8.1 Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| The emulator is not real hardware (no equivalent TEE or Secure Element) | Emulator results don't transfer to physical devices | Emulator results are labeled emulator-only. M1 explicitly disclaims physical devices (Section 9). |
| TAR metadata limits (Section 5.3.2) | Missing xattrs, ACLs, sub-second times, and sockets | Independent enumeration; per-acquisition limitation statements |
| A live device changes during acquisition | Reconciliation discrepancies | `COMPLETE_WITH_CHANGES` status; pre- and post-enumeration |
| Reading files may update atime | Device modification | Capture the mount table; declare the modification (A-08) |
| Capturing `tar` stderr may require writing to the device | Device modification | Q3; prefer host-side capture |
| `adb root` changes device state | Must be disclosed | Declared modification; acknowledged before running |
| iOS pairing modifies the device | Detection is not read-only on iOS | iOS detection excluded from M1 |
| A local attacker regenerates an entire package | The hash chain alone does not detect this | External anchoring of the chain head (Section 5.6) |
| pymobiledevice3 is GPL-3.0 [VERIFIED-SOURCE]; this project is MIT | License compatibility for any iOS integration | Decision deferred until iOS work begins (Section 8.3). Legal review recommended before adoption. |
| No open method exists for current iOS on A12+ | The iOS FFS goal may be infeasible with public techniques | State this openly; iOS work begins with research, not code |

### 8.2 Open Questions

1. ~~Is Python the confirmed implementation language, and which minimum
   version?~~ **Resolved:** Python 3.12+ (Section 8.3).
2. ~~Which host OS is supported first?~~ **Resolved:** Windows first, with
   device-free unit tests also run on Linux in CI (Section 8.3).
3. Can `adb exec-out` carry a binary tar stream reliably, while capturing
   on-device stderr separately and without writing to the device? (A-02, A-03)
4. Which attributes does the emulator's on-device `tar` actually preserve?
   (A-04, A-07)
5. Does an unlocked, booted Google APIs emulator expose CE storage in
   plaintext to root? (A-09)
6. What are the exact device-side effects of iOS pairing? (A-12)
7. What are the licenses and terms of use for the public reference datasets?
   **Partly answered:** the Digital Corpora terms of use place the site's
   original materials under CC0 1.0 and exclude copyrighted material inside
   disk images [VERIFIED-SOURCE]. Whether CC0 covers the contributed Joshua
   Hickman images is unconfirmed. (A-14)
8. ~~What authorized physical research devices will be available?~~
   **Resolved for now:** none (Section 8.3).
9. For locked or unmodified devices: which documented, lawful,
   reproducible methods exist at all for current OS versions? This is
   open research. No feasibility is assumed.
10. Which mechanism produces the independent enumeration on Android, and
    with what timestamp precision? (A-06)
11. May the repository ever contain vulnerability-exploiting code, or only
    wrappers around separately obtained tools? (Section 7.3; decision required)
12. Which external anchoring options (RFC 3161 timestamping, signatures)
    will be adopted, and when? (A-15, A-16)

### 8.3 Decisions Recorded

| Date | Decision | Notes |
|------|----------|-------|
| 2026-10-16 | Implementation language: Python, minimum version 3.12 | Matches the existing Python `.gitignore`. |
| 2026-10-16 | Host OS: Windows first; device-free unit tests also run on Linux in CI | Emulator integration tests run on the developer's Windows machine. |
| 2026-10-16 | Physical research devices: none for now | M1 is emulator-only. |
| 2026-10-16 | GPL-3.0 dependencies (e.g. pymobiledevice3): decision deferred | Revisit when iOS work begins; legal review recommended. Not needed for M1. |

### 8.4 Register of Unverified Assumptions and Dependencies

Each entry is UNVERIFIED: This claim requires additional research or
testing. The register is the single list to close out.

| ID | Assumption or dependency | How it will be resolved |
|----|-------------------------|------------------------|
| A-01 | No public, open-source FFS method exists for A18 Pro / iOS 26.x. | Literature review; revisit periodically. |
| A-02 | `adb exec-out` transfers a binary stream unmodified on a Windows host. | M1 test: compare the host-side hash to the on-device hash of a known file. |
| A-03 | On-device stderr can be captured separately without writing to the device. | M1 test of candidate approaches; document the chosen one. |
| A-04 | The emulator's toybox `tar` matches the `master` source features in 5.3.2. | Capture `tar --help` and the toybox version; test each feature. |
| A-05 | Effect of unreadable files on toybox `tar`'s exit status. | M1 test with a deliberately unreadable planted file. |
| A-06 | An on-device enumeration tool is available (e.g. toybox `find`/`stat`), with usable output formats and timestamp precision. | M1 test; document the exact command. |
| A-07 | `tar --sparse` and `--selinux` work as described on the emulator image. | M1 test with planted sparse and labeled files. |
| A-08 | Whether reading files under `/data` updates atime (depends on mount options). | Capture the mount table; compare atime in pre- and post-enumeration. |
| A-09 | An unlocked Google APIs emulator exposes CE storage in plaintext to root. | M1 test with a planted CE-stored file. |
| A-10 | The Android emulator image actually uses FBE. | Check the emulator's encryption properties; record in identity. |
| A-11 | Python 3.12+, Android Platform-Tools, and the Android Emulator run together on the Windows host. | M1 environment setup record. |
| A-12 | The device-side effects of iOS pairing. | Literature review before any iOS detection work. |
| A-13 | Bootloader unlocking wipes user data on target Android devices. | Device-specific documentation review before any physical Android research. |
| A-14 | The license terms for Joshua Hickman's images on Digital Corpora. | Read the dataset pages; ask the maintainers if unclear. |
| A-15 | A suitable RFC 3161 Time-Stamp Authority and client library exist. | Separate proposal; not needed for M1. |
| A-16 | A signature library (new dependency) is acceptable. | Separate proposal; not needed for M1. |
| A-17 | Windows `Get-FileHash` can check the `sha256sum`-style hash files. | Write and test a procedure in `EVIDENCE_FORMAT.md`. |
| D-01 | **Dependency:** Android SDK Platform-Tools (`adb`); license not yet reviewed. | License review before M1 integration tests. |
| D-02 | **Dependency:** Android Emulator and Google APIs system image; license not yet reviewed. | License review before M1 integration tests. |
| D-03 | **Dependency:** toybox on the emulator image (part of Android, not shipped by this project). | Record the version as evidence (A-04). |
| D-04 | **Dependency:** the CodeQL workflow scans only GitHub Actions files today. Python scanning must be added with the first Python code. | Separate CI proposal alongside M1 code. |

---

## 9. First Implementation Milestone

### M1 — Privileged Android Emulator Filesystem Acquisition Proof of Concept

**What M1 demonstrates:** a complete, integrity-protected acquisition
pipeline, in which a privileged session acquires `/data` from a
`userdebug` Android Emulator image. The output is labeled
`PRIVILEGED_SELECTED_DIRECTORY`.

**What M1 does NOT demonstrate**, and must state in its documentation and
in every M1 manifest:

- It does **not** demonstrate acquisition from any **physical** device.
- It does **not** demonstrate acquisition from **ordinary, unmodified**
  devices. Privileged access in M1 exists only because `userdebug`
  builds enable root by design [VERIFIED-SOURCE]. Production devices
  run `user` builds.
- It does **not** demonstrate acquisition from **locked** devices. M1
  requires a booted, user-unlocked emulator.
- It does **not** produce an `FFS`-class acquisition. A `/data` TAR
  collection is `PRIVILEGED_SELECTED_DIRECTORY` (Section 0.2).
- It does **not** recover deleted data or unallocated space.
- It does **not** involve iOS in any way, and does not involve your
  iPhone 16 Pro Max: no connection, no pairing, no detection.

**Why this target:**

- Privileged access needs no exploit and no physical device.
- Emulator snapshots allow the same device state to be acquired
  repeatedly, which enables reproducibility testing.
- Data of every entry type can be planted as ground truth.

**Scope:**

1. `core`, `audit`, `evidence`, and `validation` packages:
   - write-ahead hash-chained audit log, with sealing;
   - streaming and chunk SHA-256 hashing;
   - manifest, and reconciliation against the C1–C10 checks.
   Covered by unit tests on synthetic data, including simulated
   interruptions and tampering.
2. `tools/verify_package.py` (standard library only) and
   `docs/EVIDENCE_FORMAT.md`.
3. `compatibility` registry with the single record
   `android.emulator.adb_root_userdebug` (status UNVERIFIED, max class
   `PRIVILEGED_SELECTED_DIRECTORY`).
4. Android read-only detection over ADB: model, OS version, build type,
   whether the target is an emulator, and encryption properties.
5. Provider: `adb root` on `userdebug` builds only. It refuses `user`
   builds with a clear `PreconditionError`.
6. Acquirer: mount-table capture, pre- and post-enumeration of `/data`,
   a `tar --selinux` stream into `data/ffs.tar`, and reconciliation.

**Acceptance criteria (M1 complete when all are met and documented):**

- **Unit tests:**
  - All unit tests pass, and the results are reported as executed.
  - They include tamper tests (a `BROKEN` log is detected) and
    interruption tests (an `UNSEALED` log is classified `INTERRUPTED`
    and its chunk prefix is verified).
- **Integration:** an acquisition from a named emulator image (exact
  system image, API level, and toybox version recorded) produces a
  package that `verify_package.py` accepts.
- **Forensic validation**, using planted ground truth covering every
  entry type in 5.3.1:
  - each entry has the correct reconciliation outcome;
  - sockets are recorded as `UNSUPPORTED_TYPE`;
  - an unreadable planted file produces `PARTIAL`, never `COMPLETE`;
  - the metadata-fidelity results are recorded for each attribute;
  - two acquisitions from the same snapshot agree per file, with any
    differences explained.
- **Refusal:** a `user` build (Google Play image) is refused before any
  device modification.
- **Independent check:** a package is verified using
  `EVIDENCE_FORMAT.md` and standard tools only, without Corrobora Mobile
  code.
- **Distinct findings:** for the planted-unreadable-file case, the
  verifier reports integrity `PASS` with completeness `PARTIAL`. If a
  sealed package's manifest is altered afterwards to claim `COMPLETE`,
  the verifier must report integrity `FAIL` **and** a completeness
  disagreement (recomputed `PARTIAL` versus recorded `COMPLETE`); the
  test checks that both findings appear.
- **Assumptions:** register entries A-02 through A-11 are resolved or
  re-recorded with test evidence.
- **Recording:** results are recorded in `docs/VALIDATION.md`. Only then
  may the emulator record move to EXPERIMENTAL or VERIFIED, **for that
  exact emulator configuration and for the `PRIVILEGED_SELECTED_DIRECTORY`
  class only**.

**Phasing:** M1 is delivered in reviewable phases (M1.1 onward), each
with its own proposal and approval.

**Explicitly out of scope for M1:** iOS acquisition of any kind,
physical devices, locked-device research, `PRIVILEGED_FILESYSTEM` and
`FFS` classes, logical or backup acquisition, RFC 3161 timestamping,
signatures, analysis, and reporting UI.

**External requirements:** Android SDK Platform-Tools (`adb`) and the
Android Emulator, installed by the operator (D-01, D-02).

---

## References

- Apple, *Apple Platform Security*, "Data Protection classes":
  https://support.apple.com/guide/security/secb010e978a/web
- Apple Support, iPhone 16 Pro Max technical specifications:
  https://support.apple.com/es-lamr/121032
- AOSP, "File-based encryption":
  https://source.android.com/docs/security/encryption/file-based
- AOSP, build variants:
  https://source.android.com/docs/setup/create/new-device
- Chromium, "Using an Android Emulator" (image build types):
  https://chromium.googlesource.com/chromium/src/+/e9b1018/docs/android_emulator.md
- 8kSec, "Rooting an Android Emulator for Mobile Security Testing":
  https://8ksec.io/rooting-an-android-emulator-for-mobile-security-testing
- libimobiledevice, ifuse README:
  https://github.com/libimobiledevice/ifuse
- pymobiledevice3 (license):
  https://github.com/doronz88/pymobiledevice3
- Security Affairs, "Checkm8" (A5–A11):
  https://securityaffairs.com/91795/hacking/checkm8-jailbreak.html
- Elcomsoft, iPadOS/tvOS/audioOS 17–18 extraction (vendor source):
  https://blog.elcomsoft.com/2025/11/exploring-ipados-tvos-and-audioos-17-and-18-devices-file-system-and-keychain-extraction/
- NIST SP 800-101 Rev. 1, *Guidelines on Mobile Device Forensics*:
  https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-101r1.pdf
- NIST CFTT Mobile Device Tool Specification (for later test design):
  https://www.nist.gov/document/cftt-md-smart-phone-tool-specification
- Digital Corpora, Android 13 image (Joshua Hickman):
  https://digitalcorpora.org/corpora/cell-phones/android-13-image/
- Digital Corpora, Terms of Use:
  https://digitalcorpora.org/terms-of-use/
- toybox `tar` source (`master`, read 2026-10-16):
  https://raw.githubusercontent.com/landley/toybox/master/toys/posix/tar.c
- Python documentation, `tarfile`:
  https://docs.python.org/3/library/tarfile.html
- GNU tar manual, "Extended File Attributes":
  https://www.gnu.org/software/tar/manual/html_node/Extended-File-Attributes.html
- RFC 3161, *Internet X.509 PKI Time-Stamp Protocol (TSP)*:
  https://www.rfc-editor.org/rfc/rfc3161
