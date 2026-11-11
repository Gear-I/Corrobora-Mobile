"""The Corrobora Mobile window (M1.12): read-only first version, tkinter.

Three tabs, each a thin front end over ``gui.model``:

* Devices -- ``adb devices`` with build type and model.
* Detect  -- identity, compatibility assessment and gate decision.
* Verify  -- the standalone verifier on an evidence package.

Device and verifier calls run on one background thread so the window
stays responsive; results are handed back to the Tk thread with
``after``. Only one task runs at a time and the buttons are disabled
while it runs.

Start it with ``corrobora-mobile gui`` (or ``python -m corrobora_mobile.gui``).
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from importlib import resources
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any, Callable

from corrobora_mobile import __version__
from corrobora_mobile.core.errors import CorroboraError
from corrobora_mobile.gui import model
from corrobora_mobile.platforms.android.adb import Adb

POLL_MS = 100
TITLE = f"Corrobora Mobile {__version__} (pre-alpha)"
#: Made from docs/Logo_Icon/Corrobora_Mobile_logo.png; see assets/README.md.
HEADER_LOGO = "logo-96.png"
ICON_SIZES = ("logo-64.png", "logo-32.png", "logo-16.png")


def load_image(name: str) -> tk.PhotoImage | None:
    """Load a packaged image; None if it is missing or Tk cannot read it.

    The window works without its images, so a missing logo is not an error.
    """
    try:
        with resources.as_file(resources.files("corrobora_mobile.gui") / "assets" / name) as path:
            return tk.PhotoImage(file=str(path))
    except (OSError, tk.TclError):
        return None


class App:
    def __init__(self, window: tk.Tk, *, adb_path: str = "adb",
                 adb_factory: model.AdbFactory = Adb,
                 verify_fn: Callable[..., model.VerifyView] = model.verify) -> None:
        self.window = window
        self._adb_factory = adb_factory
        self._verify_fn = verify_fn
        self._results: queue.Queue[tuple[Callable[[Any], None], Any]] = queue.Queue()
        self._busy = False
        self._buttons: list[ttk.Button] = []

        window.title(TITLE)
        window.geometry("900x600")
        window.minsize(640, 420)

        # Keep references: Tk shows nothing if a PhotoImage is garbage-collected.
        self.icons = [img for img in map(load_image, ICON_SIZES) if img is not None]
        if self.icons:
            window.iconphoto(True, *self.icons)
        self.logo = load_image(HEADER_LOGO)

        header = ttk.Frame(window, padding=(10, 8))
        header.pack(fill="x")
        if self.logo is not None:
            ttk.Label(header, image=self.logo).pack(side="left", padx=(0, 12))
        top = ttk.Frame(header)
        top.pack(side="left", fill="x", expand=True)
        ttk.Label(top, text=model.READ_ONLY_NOTICE, wraplength=740, foreground="#8a4b00").pack(
            anchor="w")
        row = ttk.Frame(top)
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="adb:").pack(side="left")
        self.adb_path = tk.StringVar(value=adb_path)
        ttk.Entry(row, textvariable=self.adb_path).pack(side="left", fill="x", expand=True, padx=6)
        self._button(row, "Browse...", self._browse_adb).pack(side="left")

        self.tabs = ttk.Notebook(window)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self._build_devices()
        self._build_detect()
        self._build_verify()

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(window, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(8, 2)).pack(fill="x", side="bottom")
        self._after_id: str | None = window.after(POLL_MS, self._poll)
        window.bind("<Destroy>", self._on_destroy, add="+")

    # -- layout ------------------------------------------------------------------------

    def _button(self, parent: tk.Widget, text: str, command: Callable[[], None]) -> ttk.Button:
        b = ttk.Button(parent, text=text, command=command)
        self._buttons.append(b)
        return b

    def _text(self, parent: tk.Widget) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(6, 0))
        text = tk.Text(frame, wrap="word", height=10, font=("Consolas", 10), state="disabled")
        bar = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    def _build_devices(self) -> None:
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="Devices")
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self._button(bar, "Refresh", self.refresh_devices).pack(side="left")
        ttk.Label(bar, text="Double-click a device to detect it. Serials can change between runs; "
                            "they are not identifiers.").pack(side="left", padx=10)
        cols = ("serial", "state", "build_type", "model")
        self.device_table = ttk.Treeview(tab, columns=cols, show="headings", height=8)
        for col, label, width in zip(cols, ("Serial", "State", "Build type", "Model"),
                                     (200, 120, 110, 300)):
            self.device_table.heading(col, text=label)
            self.device_table.column(col, width=width, anchor="w")
        self.device_table.pack(fill="both", expand=True, pady=(6, 0))
        self.device_table.bind("<Double-1>", self._detect_selected)

    def _build_detect(self) -> None:
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="Detect")
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Label(bar, text="Serial:").pack(side="left")
        self.serial = tk.StringVar()
        self.serial_box = ttk.Combobox(bar, textvariable=self.serial, width=28)
        self.serial_box.pack(side="left", padx=6)
        self._button(bar, "Detect", self.run_detect).pack(side="left")
        self.detect_text = self._text(tab)

    def _build_verify(self) -> None:
        tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(tab, text="Verify")
        grid = ttk.Frame(tab)
        grid.pack(fill="x")
        ttk.Label(grid, text="Package folder:").grid(row=0, column=0, sticky="w")
        self.package = tk.StringVar()
        ttk.Entry(grid, textvariable=self.package).grid(row=0, column=1, sticky="ew", padx=6)
        self._button(grid, "Browse...", self._browse_package).grid(row=0, column=2)
        ttk.Label(grid, text="Chain head (from your notes):").grid(row=1, column=0, sticky="w",
                                                                     pady=(6, 0))
        self.chain_head = tk.StringVar()
        ttk.Entry(grid, textvariable=self.chain_head).grid(row=1, column=1, sticky="ew", padx=6,
                                                            pady=(6, 0))
        self._button(grid, "Verify", self.run_verify).grid(row=1, column=2, pady=(6, 0))
        grid.columnconfigure(1, weight=1)
        self.verdict = tk.StringVar(value="")
        self.verdict_label = ttk.Label(tab, textvariable=self.verdict, font=("Segoe UI", 11, "bold"))
        self.verdict_label.pack(anchor="w", pady=(8, 0))
        self.caveat = tk.StringVar(value="")
        ttk.Label(tab, textvariable=self.caveat).pack(anchor="w")
        self.verify_text = self._text(tab)

    # -- actions -----------------------------------------------------------------------

    # Tk variables are read here, on the Tk thread, never inside the background work.

    def refresh_devices(self) -> None:
        adb_path, make = self.adb_path.get(), self._adb_factory
        self._run("Listing devices...", lambda: model.devices(adb_path, adb_factory=make),
                  self._show_devices)

    def run_detect(self) -> None:
        adb_path, make = self.adb_path.get(), self._adb_factory
        serial = self.serial.get().strip() or None
        self._run("Detecting (read-only)...",
                  lambda: model.detect(adb_path, serial, adb_factory=make),
                  self._show_detection)

    def run_verify(self) -> None:
        folder = self.package.get().strip()
        if not folder:
            self.status.set("Choose a package folder first.")
            return
        head = self.chain_head.get().strip() or None
        verify = self._verify_fn
        self._run("Verifying...", lambda: verify(Path(folder), head), self._show_verify)

    def _detect_selected(self, _event: Any = None) -> None:
        selection = self.device_table.selection()
        if selection:
            self.serial.set(self.device_table.item(selection[0], "values")[0])
            self.tabs.select(1)
            self.run_detect()

    def _browse_adb(self) -> None:
        path = filedialog.askopenfilename(title="Find adb", filetypes=[("adb", "adb*"), ("All", "*")])
        if path:
            self.adb_path.set(path)

    def _browse_package(self) -> None:
        path = filedialog.askdirectory(title="Choose an evidence package folder", mustexist=True)
        if path:
            self.package.set(path)

    # -- results -----------------------------------------------------------------------

    def _show_devices(self, rows: list[Any]) -> None:
        self.device_table.delete(*self.device_table.get_children())
        for r in rows:
            self.device_table.insert("", "end", values=(r.serial, r.state, r.build_type, r.model))
        ready = [r.serial for r in rows if r.state == "device"]
        self.serial_box.configure(values=ready)
        if len(ready) == 1 and not self.serial.get():
            self.serial.set(ready[0])
        self.status.set(f"{len(rows)} device(s)." if rows else
                        "No devices. Start an emulator, or connect a device with USB debugging "
                        "authorized.")

    def _show_detection(self, view: model.DetectionView) -> None:
        self._set_text(self.detect_text, "\n".join(view.lines()))
        self.serial.set(view.serial)
        self.status.set(f"Detected {view.serial} (read-only).")

    def _show_verify(self, view: model.VerifyView) -> None:
        self.caveat.set("")
        if view.error:
            self.verdict.set("COULD NOT VERIFY")
            self.verdict_label.configure(foreground="#a00000")
            self._set_text(self.verify_text, view.error + ("\n\n" + view.text if view.text else ""))
            self.status.set("Verifier could not run.")
            return
        ok = view.integrity == "PASS"
        self.verdict.set(f"INTEGRITY {view.integrity}"
                         + ("" if ok else "  -- do not rely on this package"))
        self.caveat.set("Completeness is not recomputed by this verifier version, and integrity "
                        "does not mean the acquisition method is validated.")
        self.verdict_label.configure(foreground="#006400" if ok else "#a00000")
        self._set_text(self.verify_text, view.text)
        self.status.set(f"Verifier exit code {view.exit_code}.")

    def _show_error(self, exc: BaseException) -> None:
        self.status.set(f"Error: {exc}")

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # -- background work ---------------------------------------------------------------

    def _run(self, message: str, work: Callable[[], Any], done: Callable[[Any], None]) -> None:
        if self._busy:
            return
        self._busy = True
        for b in self._buttons:
            b.state(["disabled"])
        self.status.set(message)

        def worker() -> None:
            try:
                result: tuple[Callable[[Any], None], Any] = (done, work())
            except (CorroboraError, OSError, ValueError) as exc:
                result = (self._show_error, exc)
            except Exception as exc:  # report anything else instead of failing silently
                result = (self._show_error, RuntimeError(f"unexpected {type(exc).__name__}: {exc}"))
            self._results.put(result)

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                handler, value = self._results.get_nowait()
                try:
                    handler(value)
                finally:
                    self._busy = False
                    for b in self._buttons:
                        b.state(["!disabled"])
        except queue.Empty:
            pass
        self._after_id = self.window.after(POLL_MS, self._poll)

    def _on_destroy(self, event: Any) -> None:
        if event.widget is self.window and self._after_id is not None:
            self.window.after_cancel(self._after_id)
            self._after_id = None

    @property
    def busy(self) -> bool:
        return self._busy


def main(adb_path: str = "adb") -> int:
    window = tk.Tk()
    App(window, adb_path=adb_path)
    window.mainloop()
    return 0
