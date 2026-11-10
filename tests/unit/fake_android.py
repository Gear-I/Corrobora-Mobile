"""A simulated userdebug emulator with a small filesystem, for acquirer tests.

It answers only the commands the acquirer is allowed to send, and follows
what toybox 0.8.13 did on 2026-11-09: ``find -printf`` with NUL separators,
name-free ``stat`` lines, ``tar`` skipping sockets with "unknown file type
'140000'" and exiting 1, and ``adb exec-out`` returning exit status 0 while
the real status goes to the sidecar file.
"""

from __future__ import annotations

import io
import re
import tarfile
import time

from tests.unit.test_adb_root_provider import FakeEmulator

SIDE_RE = re.compile(r" 2>(\S+)\.err; echo \$\? >(\S+)\.exit$")
T0 = 1794271831_952000766


def full_time(ns: int) -> str:
    secs, frac = divmod(ns, 1_000_000_000)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(secs)) + f".{frac:09d} +0000"


class Node:
    def __init__(self, path: bytes, kind: str, *, content: bytes = b"", target: bytes = b"",
                 inode: int, mode: int = 0o660, uid: int = 1000, gid: int = 1000,
                 label: str = "u:object_r:system_data_file:s0", mtime_ns: int = T0):
        self.path, self.kind, self.content, self.target = path, kind, content, target
        self.inode, self.mode, self.uid, self.gid, self.label = inode, mode, uid, gid, label
        self.mtime_ns = self.ctime_ns = self.atime_ns = mtime_ns

    @property
    def size(self) -> int:
        return {"f": len(self.content), "d": 4096, "l": len(self.target)}.get(self.kind, 0)


def sample_tree(root: bytes = b"/data/system/users") -> list[Node]:
    return [
        Node(root, "d", inode=100, mode=0o775),
        Node(root + b"/0", "d", inode=101, mode=0o700),
        Node(root + b"/0/settings.xml", "f", content=b"<settings/>", inode=102),
        Node(root + b"/0/new\nline", "f", content=b"nl", inode=103),
        Node(root + b"/0/bad\xffname", "f", content=b"bad", inode=104),
        Node(root + b"/0/link", "l", target=b"settings.xml", inode=105, mode=0o777),
        Node(root + b"/0/hard", "f", content=b"<settings/>", inode=102),  # hard link to 102
        Node(root + b"/0/fifo", "p", inode=106),
        Node(root + b"/userlist.xml", "f", content=b"<users/>" * 100, inode=107),
    ]


class FakeAndroid(FakeEmulator):
    def __init__(self, nodes=None, *, mounts=None, build_type="userdebug", **kw):
        super().__init__(build_type, **kw)
        self.nodes: list[Node] = nodes if nodes is not None else sample_tree()
        self.mounts = mounts or (b"/dev/block/dm-6 /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0\n"
                                 b"/dev/block/dm-6 /data/user/0 ext4 rw,seclabel,noatime 0 0\n")
        self.files: dict[str, bytes] = {}   # sidecar files
        self.dirs: set[str] = set()
        self.texts: list[str] = []           # every shell / exec-out command text
        self.before_tar = None               # callable(fake) run before the archive is made
        self.after_tar = None                # callable(fake) run after the archive is made
        self.extra_tar_stderr: list[str] = []
        self.stat_drop_last = False
        self.mkdir_fails = False
        self.stream_raises = None
        self.stream_cut_at = None           # send only this many bytes, then adb exits 1

    # -- filesystem views -------------------------------------------------------------

    def _under(self, root: bytes) -> list[Node]:
        return [n for n in self.nodes if n.path == root or n.path.startswith(root + b"/")]

    def _links(self, node: Node) -> int:
        return sum(1 for n in self.nodes if n.inode == node.inode)

    def _find(self, root: bytes) -> bytes:
        out = b""
        for n in self._under(root):
            perm = "%o" % n.mode
            fields = [(n.kind if n.kind != "f" else "-").encode() + b"rw-rw----", perm.encode(),
                      str(n.uid).encode(), str(n.gid).encode(), str(n.size).encode(),
                      str(n.inode).encode(), n.label.encode(),
                      n.target if n.kind == "l" else b"", n.path]
            out += b"".join(f + b"\0" for f in fields)
        return out

    def _stat(self, root: bytes) -> bytes:
        nodes = self._under(root)
        if self.stat_drop_last:
            nodes = nodes[:-1]
        lines = []
        for n in nodes:
            parts = [str(n.inode), str(self._links(n))]
            for ns in (n.mtime_ns, n.ctime_ns, n.atime_ns):
                parts += [str(ns // 1_000_000_000), full_time(ns)]
            lines.append("|".join(parts))
        return ("\n".join(lines) + "\n").encode() if lines else b""

    def _tar(self, root: bytes) -> tuple[bytes, list[str], int]:
        parent = root.rsplit(b"/", 1)[0]
        buf = io.BytesIO()
        errors: list[str] = []
        first_by_inode: dict[int, bytes] = {}
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT,
                          encoding="utf-8", errors="surrogateescape") as tf:
            for n in self._under(root):
                if n.kind == "s":
                    errors.append("tar: unknown file type '140000'")
                    continue
                name = n.path[len(parent) + 1:].decode("utf-8", "surrogateescape")
                info = tarfile.TarInfo(name)
                info.mode, info.uid, info.gid = n.mode, n.uid, n.gid
                info.mtime = n.mtime_ns // 1_000_000_000
                info.pax_headers = {"RHT.security.selinux": n.label}
                data = None
                if n.kind == "d":
                    info.type = tarfile.DIRTYPE
                elif n.kind == "l":
                    info.type, info.linkname = tarfile.SYMTYPE, n.target.decode("utf-8", "surrogateescape")
                elif n.kind == "p":
                    info.type = tarfile.FIFOTYPE
                elif n.kind == "f" and n.inode in first_by_inode:
                    info.type = tarfile.LNKTYPE
                    info.linkname = first_by_inode[n.inode][len(parent) + 1:].decode(
                        "utf-8", "surrogateescape")
                else:
                    first_by_inode[n.inode] = n.path
                    info.size, data = len(n.content), io.BytesIO(n.content)
                tf.addfile(info, data)
        errors += self.extra_tar_stderr
        if errors:
            errors.append("tar: had errors")
        return buf.getvalue(), errors, 1 if errors else 0

    # -- adb ---------------------------------------------------------------------------

    def __call__(self, argv, timeout):
        args = argv[1:]
        if len(args) == 4 and args[2] in ("shell", "exec-out") and args[3] not in ("id",) \
                and not args[3].startswith("getprop"):
            self.calls.append(args)
            return self._command(args[2], args[3])
        return super().__call__(argv, timeout)

    def _side(self, text: str, err: str, code: int) -> None:
        m = SIDE_RE.search(text)
        assert m, text
        side_dir = m.group(1).rsplit("/", 1)[0]
        assert side_dir in self.dirs, f"sidecar folder missing: {side_dir}"
        self.files[m.group(1) + ".err"] = err.encode()
        self.files[m.group(2) + ".exit"] = f"{code}\n".encode()

    def _command(self, how: str, text: str):
        self.texts.append(text)
        root_m = re.search(r"'(/data/[^']+)'", text)
        if text == "cat /proc/mounts":
            return 0, self.mounts, b""
        if text == "toybox --version":
            return 0, b"toybox 0.8.13-android\r\n", b""
        if text.startswith("stat -c '%Y|%y|%Z|%z' /data/local/tmp"):
            return 0, f"{T0 // 10**9}|{full_time(T0)}|{T0 // 10**9}|{full_time(T0)}\r\n".encode(), b""
        if text.startswith("mkdir /data/local/tmp/"):
            path = text.split(" ", 1)[1]
            if self.mkdir_fails or path in self.dirs:
                return 1, f"mkdir: '{path}': File exists\r\n".encode(), b""
            self.dirs.add(path)
            return 0, b"", b""
        if text.startswith("rm -r /data/local/tmp/"):
            path = text.split(" ")[2]
            self.dirs.discard(path)
            self.files = {k: v for k, v in self.files.items() if not k.startswith(path + "/")}
            return 0, b"", b""
        if text.startswith("cat /data/local/tmp/"):
            path = text.split(" ", 1)[1]
            if path in self.files:
                return 0, self.files[path], b""
            return 0, f"cat: {path}: No such file or directory\n".encode(), b""  # exec-out merges
        if text.startswith("find '") and "-printf" in text:
            self._side(text, "", 0)
            return 0, self._find(root_m.group(1).encode()), b""
        if text.startswith("find '") and "-exec stat" in text:
            self._side(text, "", 0)
            return 0, self._stat(root_m.group(1).encode()), b""
        raise AssertionError(f"unexpected device command ({how}): {text}")

    def stream(self, argv, sink):
        text = argv[-1]
        self.texts.append(text)
        self.calls.append(argv[1:])
        assert argv[3] == "exec-out" and text.startswith("tar -c --selinux --numeric-owner -f - -C"), argv
        parent, base = re.search(r"-C '([^']+)' '([^']+)'", text).groups()
        if self.before_tar:
            self.before_tar(self)
        data, errors, code = self._tar(f"{parent}/{base}".encode())
        if self.stream_cut_at is not None:
            sink(data[:self.stream_cut_at])
            self._side(text, "", 0)
            return 1, b"error: device offline\n"
        for i in range(0, len(data), 4096):
            if self.stream_raises is not None and i >= 4096:
                raise self.stream_raises
            sink(data[i:i + 4096])
        self._side(text, "".join(e + "\n" for e in errors), code)
        if self.after_tar:
            self.after_tar(self)
        return 0, b""


def node(fake: FakeAndroid, suffix: bytes) -> Node:
    (found,) = [n for n in fake.nodes if n.path.endswith(suffix)]
    return found

