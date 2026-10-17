# Corrobora Mobile — Technical Architecture (Proposed)

**Document status:** PROPOSED — design only. Nothing described here is
implemented, tested, or validated unless explicitly marked otherwise.

**Last reviewed:** 2026-10-16

**Applies to repository state:** `main` at `37cb5dc` (README, LICENSE,
.gitignore, CodeQL workflow; no source code).

---

## How to Read This Document

Every technical claim in this document carries one of these labels:

| Label | Meaning |
|-------|---------|
| **[VERIFIED-SOURCE]** | Stated in a cited primary or authoritative source (see References). Not yet tested by this project. |
| **[DESIGN]** | A proposed design decision for this project. Open to change. |
| **UNVERIFIED** | "UNVERIFIED: This claim requires additional research or testing." |

No acquisition method, device, or OS version is classified **VERIFIED**
for Corrobora Mobile. That status requires documented testing by this
project (see Section 5).

---

## 0. Terminology

Precise terms prevent logical acquisitions from being mistaken for FFS
acquisitions.

| Term | Definition used by this project |
|------|--------------------------------|
| **Logical acquisition** | Data obtained through interfaces the OS exposes to an ordinary paired or authorized host, such as an iOS backup, iOS AFC media access, or Android `adb pull` without root. NIST SP 800-101r1 classifies logical extraction as Level 2 [VERIFIED-SOURCE]. |
| **Full-file-system (FFS) acquisition** | A file-level copy of the device's mounted filesystem hierarchy, including system areas and application-private data, together with the filesystem metadata the method can capture. It requires **privileged access**. It is file-level, not block-level. [DESIGN] |
| **Physical acquisition** | A block-level copy of storage. Out of scope for initial development. [DESIGN] |
| **Privileged access** | A state in which the acquisition host can read filesystem locations that the platform's normal security model denies to a host, such as root on Android or code execution outside the app sandbox on iOS. |
| **Data accessibility** | Whether the acquired bytes are usable (decrypted) at acquisition time. Privileged access does **not** imply accessibility (see Section 1.3). |

**Obtaining privileged access and acquiring data are separate problems,
and the architecture keeps them separate (Section 4).**

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
| **Acquisition engines** | Copy filesystem content through an established access session into the evidence writer. Record scope, exclusions, and errors. | Decide whether access is permitted, or drop errors. |
| **Evidence packaging** | Write-once evidence storage, streaming SHA-256, manifests, device-modification records. | Modify acquired data after capture. |
| **Audit logging** | An append-only, hash-chained record of every operation, command, and result. | Be optional or disabled. |
| **Validation** | Package verification, reproducibility tests, comparison against reference datasets. | Treat passing unit tests as forensic validation. |
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
    classes, even with privileged access. The acquisition manifest must
    record the device lock state as observed. Where the method cannot
    observe it, the manifest records it as unknown, not assumed.
- The standard AFC service gives a host access to the `/var/mobile/Media`
  area only. Root filesystem access over AFC required a service ("AFC2")
  that only older jailbreaks installed. [VERIFIED-SOURCE: libimobiledevice
  ifuse README]
  - **Design consequence:** AFC and iOS backups are logical acquisitions
    and must never be labeled FFS.
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
  capabilities. That cannot be verified and is not relied on.

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
Section 10 requires to be kept separate. [DESIGN]

The language is **Python 3.12 or later** (decided 2026-10-16; see
Section 7.3).

```text
Corrobora-Mobile/
├── docs/
│   ├── ARCHITECTURE.md            # this document
│   ├── ACQUISITION_METHODS.md     # one entry per method (Section 3.3 schema)
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
│   ├── acquisition/               # FFSAcquirer interface + orchestrator
│   ├── validation/                # package verification, reproducibility
│   ├── platforms/
│   │   ├── android/               # Android detection/providers/acquirers
│   │   └── ios/                   # iOS detection only (no providers yet)
│   └── cli.py
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
   ├─ status UNVERIFIED           → allowed only with --research flag
   ├─ status EXPERIMENTAL         → allowed with risk acknowledgement
   └─ status VERIFIED             → allowed with risk acknowledgement
4. ACKNOWLEDGE
   └─ operator confirms each declared device modification; recorded in audit log
5. ACCESS → 6. ACQUIRE → 7. FINALIZE (hash, manifest) → 8. VERIFY
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
  been documented by this project. Until they are, any iOS detection
  that requires pairing is recorded as a device modification.
- **Android:** reading properties over ADB requires USB debugging to be
  enabled and the host authorized, both of which change device state.

### 3.3 Method Compatibility Record

Each method has one JSON file. It records the fields CLAUDE.md
Section 6 requires. [DESIGN]

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
  "security_configuration": "Emulator; no hardware-backed TEE equivalence assumed",
  "required_device_state": "Booted; user unlocked (for CE storage); adb authorized",
  "required_privileges": "adbd running as root via `adb root`",
  "acquisition_scope": "File-level copy of selected mounted filesystems; see scope list",
  "device_modifications": [
    "adbd restarted as root",
    "UNVERIFIED: any other side effects of the acquisition tooling"
  ],
  "known_limitations": [
    "Not a physical device",
    "No unallocated space or deleted-data recovery",
    "Metadata fidelity depends on the on-device tar implementation (UNVERIFIED)"
  ],
  "validation_status": "UNVERIFIED",
  "validation_records": []
}
```

---

## 4. Privileged-Access and FFS Acquisition Interfaces

The interfaces below are illustrative, not implemented. [DESIGN]

### 4.1 Separation

- A **PrivilegedAccessProvider** answers: "Can I obtain privileged
  read access on this device configuration, what will it change, and
  how do I undo it?"
- An **FFSAcquirer** answers: "Given an access session, how do I copy
  the declared scope into the evidence writer, and what did I fail to copy?"

The same provider may serve several acquirers, for example a tar-stream
acquirer or a per-file acquirer. A new device-specific method is a new
provider plus a compatibility record. The core does not change.

### 4.2 Interfaces (sketch)

```python
class PrivilegedAccessProvider(Protocol):
    method_id: str                     # must match a compatibility record

    def check_preconditions(self, identity: DeviceIdentity) -> PreconditionReport:
        """Read-only. Never modifies the device."""

    def declared_modifications(self) -> list[DeviceModification]:
        """Every change this provider may make. Shown to the operator
        before establish(); recorded in the manifest."""

    def establish(self, ctx: AcquisitionContext) -> AccessSession:
        """Obtain privileged access. Every command is logged to audit."""

    def teardown(self, session: AccessSession) -> TeardownReport:
        """Undo reversible changes; report irreversible ones."""


class FFSAcquirer(Protocol):
    acquirer_id: str

    def plan(self, session: AccessSession) -> AcquisitionPlan:
        """Declare scope: included paths, excluded paths and why
        (e.g. /proc, /sys, /dev pseudo-filesystems)."""

    def acquire(self, session: AccessSession, plan: AcquisitionPlan,
                writer: EvidenceWriter) -> AcquisitionResult:
        """Stream data to writer. Never writes to the device. Returns
        per-path errors; never suppresses them."""
```

`AcquisitionResult.status` is one of:

- `COMPLETE`: every planned path was read without error.
- `PARTIAL`: there are errors, and every one is listed.
- `FAILED`: nothing usable was acquired.

The result never says "success" without listing the scope. [DESIGN]

### 4.3 Candidate Methods (research registry, initial status)

| Method | Platform / devices | Privileged access basis | Initial status |
|--------|-------------------|------------------------|----------------|
| `android.emulator.adb_root_userdebug` | Android Emulator, Google APIs images | `userdebug` build root access [VERIFIED-SOURCE] | UNVERIFIED |
| `android.userdebug_physical` | Physical devices running userdebug/eng builds | Same build semantics [VERIFIED-SOURCE] | UNVERIFIED |
| `android.rooted_physical` | Physical devices with an unlocked bootloader and root | UNVERIFIED: This claim requires additional research or testing. — device-specific unlocking may wipe user data | UNVERIFIED |
| `ios.checkm8_class` | A5–A11 only | Bootrom vulnerability [VERIFIED-SOURCE]; A11 SEP limits [VERIFIED-SOURCE, vendor] | UNVERIFIED — research only; no implementation planned until an authorized test device and a documented open method are identified |
| iOS A12+ / iOS 26.x | Includes iPhone 16 Pro Max | No documented open method identified | UNSUPPORTED |

Locked-device and unmodified-device acquisition are long-term
research questions (Section 7). They are not features of this architecture.
The architecture makes them addable as providers. It does not make them
possible.

---

## 5. Evidence Preservation and Validation Requirements

### 5.1 Evidence Package Layout [DESIGN]

```text
<output>/<acquisition_id>/
├── manifest.json            # finalized last; see 5.2
├── audit.jsonl              # hash-chained log (5.3)
├── identity/                # raw detection outputs, unmodified
├── data/
│   └── ffs.tar              # acquisition stream exactly as received
├── hashes/
│   ├── streams.sha256       # SHA-256 of each captured stream
│   └── entries.sha256       # SHA-256 per file entry, computed by reading
│                            # the tar, never by extracting it over itself
└── errors/                  # stderr captures, per-path read errors
```

Rules:

1. Acquired data is written once and never modified. Analysis works on copies.
2. SHA-256 is computed **while streaming**, before the data reaches
   disk, and again from disk at finalization. A mismatch fails the
   acquisition.
3. Evidence files are marked read-only after finalization. This is a
   best-effort host safeguard, not tamper-proofing.
4. Interrupted acquisitions are kept and marked `PARTIAL` or `FAILED`.
   They are never silently deleted.
5. Following NIST SP 800-101r1, back-to-back acquisitions of a live device
   produce different whole-image hashes because the device keeps changing.
   Reproducibility is therefore assessed per file, not by whole-stream
   hash. [VERIFIED-SOURCE]

### 5.2 Manifest Contents [DESIGN]

The manifest records:

- Tool name, version, and git commit; host OS; and the versions of
  external tools (e.g. `adb`).
- Operator and case identifiers, entered by the operator.
- Start and end times (UTC) and the clock source.
- Device identity (3.2), `method_id`, and the provider and acquirer IDs.
- Declared and observed device modifications, plus the operator's
  acknowledgement.
- Planned scope, actual scope, exclusions, and errors.
- Stream and entry hashes, and the result status.
- A metadata-fidelity statement: which attributes were captured (e.g. mode,
  owner, mtime) and which were not (e.g. creation time, extended
  attributes, SELinux labels). This is UNVERIFIED until tested per method.
- The validation status of the method at acquisition time.

### 5.3 Audit Log [DESIGN]

- JSON Lines format. Each entry contains: a timestamp, the stage, the
  action, the exact command or API call, its exit status, a reference to
  stdout and stderr, and the SHA-256 of the previous entry.
- A hash chain makes changes evident. It does not prevent them. The final
  chain hash is recorded in the manifest.
- Logging cannot be disabled.

### 5.4 Validation Levels

These follow CLAUDE.md Section 8.

| Level | What it shows | Example |
|-------|--------------|---------|
| Code review / static analysis | Code quality | CodeQL, linters |
| Unit tests | Logic on synthetic data | Manifest and hash-chain tests |
| Integration tests | Works against a controlled target | Emulator acquisition |
| Device testing | Works on a specific physical configuration | A dedicated research device |
| Forensic validation | Completeness, integrity, and reproducibility within declared scope, checked against known ground truth | Seeded known files on the emulator; compare acquired versus planted |

A method may be marked **VERIFIED** for a configuration only after
forensic-validation records exist in `docs/VALIDATION.md`.

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
  only where the method defines it as safe. The final status is
  `PARTIAL`, never `COMPLETE`.
- **Transport loss:** mark the result `PARTIAL` or `FAILED` and keep the
  data already received, with its hashes.
- **Teardown failure:** report the device left in a modified state,
  prominently in the manifest and on screen.
- **Typed errors:** errors are typed (`UnsupportedDeviceError`,
  `PreconditionError`, `AccessError`, `AcquisitionError`, `IntegrityError`).
  An `IntegrityError` always fails the acquisition.
- **No blanket exception handling** may hide an error from the manifest
  or the audit log.

---

## 7. Technical Risks and Unresolved Research Questions

### 7.1 Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| The emulator is not real hardware (no equivalent TEE or Secure Element) | Emulator results don't transfer to physical devices | Emulator results are labeled as emulator-only and never counted as physical-device support |
| On-device `tar` metadata fidelity is unknown | Missing timestamps, xattrs, or SELinux labels | Measure in the M1 forensic validation; record the result in the manifest |
| Capturing `tar` stderr may require writing to the device | Device modification | Research question 3; prefer host-side capture |
| `adb root` changes device state | Must be disclosed | Declared modification; acknowledged before running |
| iOS pairing modifies the device | Detection is not read-only on iOS | iOS detection is excluded from M1 |
| pymobiledevice3 is GPL-3.0 [VERIFIED-SOURCE]; this project is MIT | License compatibility for any iOS integration | Decision deferred until iOS work begins (Section 7.3). Legal review recommended before adoption. |
| No open method exists for current iOS on A12+ | The iOS FFS goal may be infeasible with public techniques | State this openly; iOS work begins with research, not code |

### 7.2 Unresolved Questions

1. ~~Is Python the confirmed implementation language, and which minimum
   version?~~ **Resolved:** Python 3.12+ (Section 7.3).
2. ~~Which host OS is supported first?~~ **Resolved:** Windows first, with
   device-free unit tests also run on Linux in CI (Section 7.3).
   UNVERIFIED: This claim requires additional research or testing. —
   behavior parity across hosts has not been tested.
3. Can `adb exec-out` carry a binary tar stream reliably, while
   capturing on-device stderr separately and without writing to the device?
   UNVERIFIED: This claim requires additional research or testing.
4. Which attributes does the emulator's on-device `tar` preserve (mode,
   owner, mtime, xattrs, SELinux contexts, hard links, sparse files)?
   UNVERIFIED: This claim requires additional research or testing.
5. Does an unlocked, booted Google APIs emulator expose CE storage in
   plaintext to root? This is expected from the AOSP FBE documentation, but
   UNVERIFIED: This claim requires additional research or testing.
6. What are the exact device-side effects of iOS pairing?
7. What are the licenses and terms of use for the public reference datasets
   (Digital Corpora / Joshua Hickman images)? **Partly answered:** the
   Digital Corpora terms of use place the site's original materials under
   CC0 1.0 and exclude copyrighted material inside disk images
   [VERIFIED-SOURCE]. The terms base CC0 on the materials being produced
   by US government staff. UNVERIFIED: This claim requires additional
   research or testing. — whether CC0 covers the contributed Joshua
   Hickman images has not been confirmed.
8. ~~What authorized physical research devices will be available?~~
   **Resolved for now:** none. M1 is emulator-only; physical devices will
   be decided later (Section 7.3).
9. For locked or unmodified devices: which documented, lawful,
   reproducible methods exist at all for current OS versions? This is
   open research. No feasibility is assumed.

### 7.3 Decisions Recorded

| Date | Decision | Notes |
|------|----------|-------|
| 2026-10-16 | Implementation language: Python, minimum version 3.12 | Matches the existing Python `.gitignore`. |
| 2026-10-16 | Host OS: Windows first; device-free unit tests also run on Linux in CI | Emulator integration tests run on the developer's Windows machine. |
| 2026-10-16 | Physical research devices: none for now | M1 is emulator-only. |
| 2026-10-16 | GPL-3.0 dependencies (e.g. pymobiledevice3): decision deferred | Revisit when iOS work begins; legal review recommended. Not needed for M1. |

---

## 8. Recommended First Implementation Milestone

### M1 — Android Emulator FFS Reference Acquisition

**Goal:** one complete, end-to-end FFS pipeline on a target that is
safe, free, reproducible, and disposable. It exercises every component
in Section 1.2.

**Why this target:**

- Google APIs emulator images are `userdebug` builds, where root access is
  enabled by design [VERIFIED-SOURCE]. Privileged access needs no exploit
  and no physical device.
- Emulator snapshots allow the same device state to be acquired repeatedly,
  which enables reproducibility testing.
- Data can be planted on the emulator as ground truth for forensic validation.
- **It does not involve your iPhone 16 Pro Max in any way**: no connection,
  no pairing, no detection.

**Scope:**

1. `core`, `audit`, `evidence`, and `validation` packages: manifest,
   streaming SHA-256, hash-chained audit log, package verifier. Covered by
   unit tests on synthetic data.
2. `compatibility` registry with the single record
   `android.emulator.adb_root_userdebug` (status UNVERIFIED).
3. Android read-only detection over ADB: model, OS version, build type,
   and whether the target is an emulator.
4. Provider: `adb root` on `userdebug` builds only. It refuses `user`
   builds with a clear `PreconditionError`.
5. Acquirer: a tar stream of the declared scope (initially `/data`, with
   other mounted filesystems as a later extension) into `data/ffs.tar`,
   with streaming hashes.
6. `verify` command: recompute and compare all hashes, and check the audit
   chain.

**Acceptance criteria (M1 complete when all are met and documented):**

- Unit tests pass, and the results are reported as executed.
- An integration acquisition from a named emulator image (exact system
  image and API level recorded) produces a package that `verify` accepts.
- Forensic validation: planted files are present with matching SHA-256.
  The metadata-fidelity results are recorded. Two acquisitions from the
  same snapshot agree per file, with any differences explained.
- A `user` build (Google Play image) is refused before any device
  modification.
- Results are recorded in `docs/VALIDATION.md`. Only then may the
  emulator record move to EXPERIMENTAL or VERIFIED **for that exact
  emulator configuration**.

**Explicitly out of scope for M1:** iOS acquisition of any kind, physical
devices, locked-device research, logical or backup acquisition, analysis,
and reporting UI.

**External requirement:** Android SDK Platform-Tools (`adb`) and the
Android Emulator, installed by the operator. UNVERIFIED: This claim
requires additional research or testing. — their license terms have not
yet been reviewed by this project.

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
