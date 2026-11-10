# Corrobora Mobile Acquisition Method Dossiers

One dossier per candidate acquisition method, as required by
[ARCHITECTURE.md](ARCHITECTURE.md), Section 7.2. A dossier records what is
known about a method **before** it is relied on. It does not claim that the
method works.

Lifecycle stages (Section 7.1): 1 Proposal, 2 Feasibility, 3 Prototype,
4 Experimental, 5 Verified. Each stage needs the project owner's explicit
approval.

| Method ID | Stage | Status | Highest class |
|-----------|-------|--------|---------------|
| `android.emulator.adb_root_userdebug` | 3 Prototype (provider and one-folder acquirer implemented; acquirer not yet run on the emulator) | UNVERIFIED | `PRIVILEGED_SELECTED_DIRECTORY` |
| `android.physical.shell_shared_storage` | 1 Proposal | UNVERIFIED | `SELECTED_DIRECTORY` |
| `android.physical.magisk_su` | 1 Proposal | UNVERIFIED | `PRIVILEGED_SELECTED_DIRECTORY` |

No physical research device exists yet (Section 7.4, decision 2026-11-09).
The physical-device dossiers therefore stop at Stage 1.

Claims marked **[OBSERVED]** were seen on the developer's Android 17
emulators on the date given; they are evidence for that configuration
only. Claims marked **[SOURCE]** are from the cited public document.
Everything else is UNVERIFIED: This claim requires additional research or
testing.

---

## 1. `android.emulator.adb_root_userdebug`

**Basis.** On a `userdebug` build, `adb root` restarts `adbd` with root
privileges; on a `user` build it is refused.
[OBSERVED 2026-11-09: `userdebug` image gave `uid=0(root)`, context
`u:r:su:s0`; `user` image printed "adbd cannot run as root in production
builds" and **still exited 0**.]

**Applicability.** Android Emulator, Google APIs system images, build type
`userdebug`, x86_64. Observed on Android 17 (SDK 37), build fingerprint
`google/sdk_gphone64_x86_64/emu64xa:17/CE2A.260420.051.A3/16571990:userdebug/dev-keys`.
Other API levels and images: UNVERIFIED.

**Required device state.** Booted, user unlocked (credential-encrypted
storage available), `adb` authorized. The unlock check reads
`sys.user.0.ce_available` (observed `true` on an unlocked emulator) plus
operator attestation; its meaning on a locked device is UNVERIFIED (A-18).

**Expected data accessibility.** `/data` with file-based encryption
[OBSERVED: `ro.crypto.state=encrypted`, `ro.crypto.type=file`]. Whether
credential-encrypted storage is plaintext to root while unlocked: A-09.

**Transport (observed 2026-11-09).**
- `adb exec-out` delivers the `tar` stream byte-for-byte (host and device
  SHA-256 matched; two runs identical). It **does not return the remote
  exit status** (always 0) and **mixes stderr into the data**.
- `adb shell` and `adb shell -T` return the exit status and keep stderr
  separate, but **alter binary output** (605,184 bytes became 608,692).
- Decision 2026-11-09: stream with `exec-out`; write `tar`'s stderr and exit
  status to sidecar files under `/data/local/tmp/<acquisition_id>/`, read
  them back, then delete them. The sidecar folder is excluded from scope by
  a recorded rule.

**Device tools (observed).** toybox 0.8.13-android: `tar` with `--selinux`,
`--sparse`, `--numeric-owner`, `-T`/`--null`; `stat -c` with `%C`
(SELinux context); `find -printf` lacks `%y`. Observation 3 (2026-11-09):
`find -printf` writes NUL separators and handles any file name, but its
`%T@` drops leading zeros of the fraction; `stat`'s full-form times have
nine fractional digits and `%Z` is the change time; `tar --sparse` made no
difference to the output (A-07). The sidecar route was tested end to end:
the archive matched the device-side hash and the exit status read back.

**Mounts (observed).** `/data` is ext4 mounted `noatime`, so reading does
not update access times on this emulator (A-08). `/data/user/0` is the same
filesystem mounted again inside `/data`; without an exclusion rule its
contents would be listed and archived twice.

**Risk class.** `STATE_CHANGE` (reversible): `adbd` restarted as root and
back; `service.adb.root` left at `0` (observed); sidecar files written to
and deleted from `/data/local/tmp`, which changes that folder's
modification and change times (recorded before and after each run).

**Legal and licensing review.** Android SDK Platform-Tools and the Android
Emulator licenses: not yet reviewed (D-01, D-02). The emulator is the
developer's own test environment; no personal data.

**Highest class.** `PRIVILEGED_SELECTED_DIRECTORY` (`/data` only). The M1.11
acquirer takes one folder under `/data` with no other mount point inside it.

---

## 2. `android.physical.shell_shared_storage` (route A)

**Basis.** With USB debugging enabled and the host's RSA key accepted on
the device, `adb` can run commands as the non-root `shell` user, which can
read shared storage (`/sdcard`). [SOURCE: Android Debug Bridge
documentation: USB debugging must be enabled in Developer options; on
Android 4.2.2 and later the device asks the user to accept an RSA key, and
only an unlocked device can confirm it.]

**Applicability.** Ordinary Android phones with USB debugging available.
No specific device is identified yet.

**Required device state.** Booted and unlocked (to enable Developer
options and accept the RSA key).

**Expected data accessibility.** Shared storage only (for example photos,
downloads, documents) and whatever the `shell` user may read. **Not** app
private data under `/data/data`. Scoped-storage restrictions on what
`shell` can read: UNVERIFIED.

**Transport.** Intended: the same `tar`-over-`exec-out` stream as method 1,
run as `shell` rather than root. That avoids `adb pull`, which writes each
file to the host under its device name. Whether `shell` can write the
sidecar files to `/data/local/tmp` on a physical phone: UNVERIFIED.

**Risk class.** `STATE_CHANGE`: enabling Developer options and USB
debugging and storing the host's key on the device are device changes and
must be logged.

**Legal and licensing review.** As method 1 for `adb`. Each acquisition
needs authorization for that device.

**Highest class.** `SELECTED_DIRECTORY`. Never FFS.

---

## 3. `android.physical.magisk_su` (route B)

**Basis.** Root on a physical phone through Magisk, then the same
`tar`-over-`exec-out` acquisition as method 1, with privileges obtained
through `su` instead of `adb root`. [SOURCE: Magisk installation guide:
"Your device's bootloader has to be unlocked"; the boot or init_boot image
is patched by the Magisk app on the same device and flashed with
`fastboot`.] [SOURCE: Android Open Source Project, "Lock and unlock the
bootloader": unlocking requires the user to enable **OEM unlocking** in
Developer options, and the device should perform a **factory data reset**
when unlocked.]

**Applicability.** Phones whose bootloader can be unlocked. Community
sources report that Google Pixels sold unlocked generally can be, and
carrier-locked ones generally cannot (UNVERIFIED; check OEM unlocking is
available before acquiring a device). No device identified yet.

**Required device state.** Bootloader unlocked, Magisk installed, booted
and user unlocked, `su` access granted to the `adb` shell.

**Expected data accessibility.** As method 1, on a physical device's
`/data` with its own file-based encryption. Not established for any device.

**Risk class.** `POSSIBLE_DATA_LOSS`: unlocking the bootloader performs a
factory data reset [SOURCE]. Magisk's guide also warns that restoring
stock boot partitions incorrectly can make a device unbootable. Rooting is
a `PERSISTENT_CHANGE`.
**This method can only ever be applied to a dedicated test phone prepared
in advance; it can never be applied to a device holding evidence, because
preparing it erases the device.**

**Known differences from method 1.** `su` prompts on the device and
timeouts; root detection via `su` rather than `adb root`; Magisk version and
configuration must be recorded. A new provider is required.

**Legal and licensing review.** Magisk's license: not yet reviewed.
Magisk would be used as a separately installed tool, not bundled.

**Highest class.** `PRIVILEGED_SELECTED_DIRECTORY`.

---

## Sources

- Android Open Source Project, "Lock and unlock the bootloader",
  https://source.android.com/docs/core/architecture/bootloader/locking_unlocking
  (page last updated 2026-10-09, read 2026-11-09).
- Magisk, "Installation", https://topjohnwu.github.io/Magisk/install.html
  (read 2026-11-09).
- Android Developers, "Android Debug Bridge (adb)",
  https://developer.android.com/tools/adb (read 2026-11-09).
- Developer's observation logs of 2026-11-09 (kept outside the repository).
