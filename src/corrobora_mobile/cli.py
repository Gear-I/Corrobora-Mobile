"""The ``corrobora-mobile`` command (docs/ARCHITECTURE.md, Section 2).

A thin front end over existing code; it adds no device capability.

    corrobora-mobile --version
    corrobora-mobile devices                       list adb devices (read-only)
    corrobora-mobile detect [--serial S] [--save DIR]
    corrobora-mobile provider-check --serial S --output DIR [--research ...]
    corrobora-mobile acquire --path /data/FOLDER --output DIR [--research ...]
    corrobora-mobile verify PACKAGE [--chain-head HEX] [--json FILE]

``devices`` and ``detect`` are read-only. ``provider-check`` and ``acquire``
CHANGE DEVICE STATE (adbd is restarted as root, then non-root; ``acquire``
also creates and deletes a folder in /data/local/tmp); see their --help.
``verify`` runs the standalone verifier (tools/verify_package.py) in a
separate Python process, so verification still does not depend on this
package's code.

adb is found in this order: --adb, then ``adb_path`` from --config, then
``adb`` on PATH, then the Android SDK's default Windows location
(%LOCALAPPDATA%\\Android\\Sdk\\platform-tools\\adb.exe).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from corrobora_mobile import __version__
from corrobora_mobile.config import load_config
from corrobora_mobile.core.errors import CorroboraError

USAGE = """usage: corrobora-mobile [--config FILE] [--adb PATH] COMMAND [options]

Commands:
  devices          list connected adb devices with build type and model (read-only)
  detect           device identity, compatibility assessment and gate decision (read-only)
  provider-check   establish and release adb root on a userdebug device (CHANGES DEVICE STATE)
  acquire          acquire one folder under /data from a userdebug emulator (CHANGES DEVICE STATE)
  verify           verify an evidence package with the standalone verifier

Options:
  --config FILE    corrobora.toml with adb_path / output_dir
  --adb PATH       path to adb
  --version        show the version
  -h, --help       show this help; COMMAND --help shows a command's options

Pre-alpha research software. No acquisition method is validated.
"""

COMMANDS = ("devices", "detect", "provider-check", "acquire", "verify")


def default_adb_candidates() -> list[str]:
    candidates = []
    on_path = shutil.which("adb")
    if on_path:
        candidates.append(on_path)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(str(Path(local, "Android", "Sdk", "platform-tools", "adb.exe")))
    return candidates


def resolve_adb(explicit: str | None, config_path: str | None) -> str:
    if explicit:
        return explicit
    if config_path:
        return load_config(Path(config_path)).adb_path
    for candidate in default_adb_candidates():
        if Path(candidate).is_file():
            return candidate
    return "adb"


def verifier_path() -> Path:
    """tools/verify_package.py in a source checkout of the repository."""
    return Path(__file__).resolve().parents[2] / "tools" / "verify_package.py"


def _devices(adb_path: str, argv: list[str]) -> int:
    from corrobora_mobile.platforms.android.adb import Adb, parse_devices

    if argv and argv[0] in ("-h", "--help"):
        print("usage: corrobora-mobile devices\n\nList adb devices with build type and model. "
              "Read-only: runs only `adb devices` and `getprop`.")
        return 0
    adb = Adb(adb_path)
    record = adb.devices()
    devices = parse_devices(record.stdout)
    if not devices:
        print("No devices. Start an emulator (or connect a device with USB debugging authorized).")
        return 0
    print(f"{'SERIAL':<22}{'STATE':<14}{'BUILD TYPE':<12}MODEL")
    for serial, state in devices:
        build = model = "-"
        if state == "device":
            build = adb.getprop(serial, "ro.build.type").stdout.decode(errors="replace").strip() or "?"
            model = adb.getprop(serial, "ro.product.model").stdout.decode(errors="replace").strip() or "?"
        print(f"{serial:<22}{state:<14}{build:<12}{model}")
    print("\nSerials are connection details, not identifiers; they can change between runs.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    adb_explicit = config_path = None
    while args and args[0].startswith("-"):
        opt = args.pop(0)
        if opt in ("-h", "--help"):
            print(USAGE)
            return 0
        if opt == "--version":
            print(f"corrobora-mobile {__version__}")
            return 0
        if opt in ("--adb", "--config") and args:
            if opt == "--adb":
                adb_explicit = args.pop(0)
            else:
                config_path = args.pop(0)
            continue
        print(f"corrobora-mobile: unknown or incomplete option {opt}\n\n{USAGE}", file=sys.stderr)
        return 2
    if not args or args[0] not in COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    command, rest = args[0], args[1:]

    if command == "verify":
        tool = verifier_path()
        if not tool.is_file():
            print(f"error: standalone verifier not found at {tool} (needs a source checkout)",
                  file=sys.stderr)
            return 8
        return subprocess.run([sys.executable, str(tool), *rest], check=False).returncode

    try:
        adb_path = resolve_adb(adb_explicit, config_path)
    except CorroboraError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if command == "devices":
        try:
            return _devices(adb_path, rest)
        except CorroboraError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if "--adb" not in rest:
        rest = ["--adb", adb_path, *rest]
    if command == "detect":
        from corrobora_mobile.platforms.android import detection
        return detection.main(rest)
    if command == "acquire":
        from corrobora_mobile.platforms.android import acquirer
        return acquirer.main(rest)
    from corrobora_mobile.platforms.android.providers import adb_root
    return adb_root.main(rest)


if __name__ == "__main__":
    sys.exit(main())
