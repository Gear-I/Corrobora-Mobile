"""What the GUI shows, computed without any window code (M1.12).

Every function here calls the same code as the command line, so the GUI
cannot reach a different decision:

* ``devices``  -> ``detection.list_devices``   (as ``corrobora-mobile devices``)
* ``detect``   -> ``detection.detect`` and ``detection.summarize_methods``
                  (as ``corrobora-mobile detect``)
* ``verify``   -> the standalone verifier ``tools/verify_package.py``, run as
                  a separate Python process (as ``corrobora-mobile verify``)

All three are read-only. Nothing in the GUI package can change a device:
it never imports the adb-root provider or the acquirer, and ``Adb`` is
used only through the two read-only detection functions above (enforced by
tests/unit/test_gui_model.py).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from corrobora_mobile.platforms.android.adb import Adb
from corrobora_mobile.platforms.android.detection import (
    DeviceRow,
    MethodSummary,
    detect as _detect,
    list_devices,
    summarize_methods,
)

READ_ONLY_NOTICE = ("Read-only: this window lists, detects and verifies. It never changes a device. "
                    "Pre-alpha research software; no acquisition method is validated.")
VERIFIER_BITS = ((1, "integrity"), (2, "completeness"), (4, "validation"))

AdbFactory = Callable[[str], Adb]


def devices(adb_path: str, *, adb_factory: AdbFactory = Adb) -> list[DeviceRow]:
    return list_devices(adb_factory(adb_path))


@dataclass(frozen=True, slots=True)
class DetectionView:
    serial: str
    identity: dict[str, Any]
    notes: tuple[str, ...]
    methods: tuple[MethodSummary, ...]

    def lines(self) -> list[str]:
        """Plain-text report, matching the wording of ``corrobora-mobile detect``."""
        out = [f"Device (adb serial {self.serial}; serials are not identifiers):"]
        out += [f"  {k}: {v}" for k, v in self.identity.items()]
        out += [f"  note: {n}" for n in self.notes]
        if not self.methods:
            out += ["", "No compatibility record for this platform: UNSUPPORTED."]
        for s in self.methods:
            a = s.assessment
            out += ["", f"Method {a.method_id}: status {a.validation_status.value}, "
                        f"match {a.matches.value}"]
            out += [f"  - {line}" for line in s.details]
            for mode, d in (("normal mode", s.gate_normal),
                            ("research mode requested", s.gate_research)):
                out.append(f"  gate ({mode}): {'ALLOWED' if d.allowed else 'REFUSED'} -- {d.reason}")
        out += ["", "Detection is read-only. It does not validate any method."]
        return out


def detect(adb_path: str, serial: str | None, *, adb_factory: AdbFactory = Adb,
           registry: Any = None) -> DetectionView:
    result = _detect(adb_factory(adb_path), serial)
    identity = {k: v for k, v in result.identity.to_dict().items() if k != "raw_responses"}
    return DetectionView(serial=result.serial, identity=identity, notes=tuple(result.notes),
                         methods=tuple(summarize_methods(result.identity, registry)))


@dataclass(frozen=True, slots=True)
class VerifyView:
    exit_code: int
    text: str
    report: dict[str, Any] | None = None
    error: str | None = None
    flags: tuple[str, ...] = field(default=())

    @property
    def integrity(self) -> str:
        if self.report is None:
            return "NOT RUN"
        integrity = self.report.get("integrity")
        result = integrity.get("result") if isinstance(integrity, dict) else None
        return result if isinstance(result, str) else "UNKNOWN"


def verifier_path() -> Path:
    from corrobora_mobile.cli import verifier_path as cli_verifier_path
    return cli_verifier_path()


def verify(package: Path, chain_head: str | None = None, *,
           python: str = sys.executable, tool: Path | None = None) -> VerifyView:
    """Run the standalone verifier in its own process; read its JSON report."""
    tool = tool or verifier_path()
    if not tool.is_file():
        return VerifyView(exit_code=8, text="", error=f"standalone verifier not found at {tool} "
                                                       "(needs a source checkout)")
    with tempfile.TemporaryDirectory(prefix="cm-verify-") as tmp:
        report_file = Path(tmp) / "report.json"
        argv = [python, str(tool), str(package), "--json", str(report_file)]
        if chain_head:
            argv += ["--chain-head", chain_head.strip()]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        report = None
        if report_file.is_file():
            report = json.loads(report_file.read_text(encoding="utf-8"))
    could_not_run = proc.returncode == 8 or report is None
    flags = () if could_not_run else tuple(
        name for bit, name in VERIFIER_BITS if proc.returncode & bit)
    error = None
    if could_not_run:
        error = proc.stderr.strip() or f"verifier exited with status {proc.returncode}"
    return VerifyView(exit_code=proc.returncode, text=proc.stdout, report=report, error=error,
                      flags=flags)
