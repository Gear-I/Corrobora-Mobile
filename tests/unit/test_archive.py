import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.acquisition.archive import read_archive
from corrobora_mobile.core.enums import EntryType


def make_tar(members, *, end=True):
    """members: (name bytes, type, data). Written as PAX with SELinux labels."""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8",
                      errors="surrogateescape")
    for name, kind, data in members:
        info = tarfile.TarInfo(name.decode("utf-8", "surrogateescape"))
        info.type = kind
        info.pax_headers = {"RHT.security.selinux": "u:object_r:system_data_file:s0"}
        if kind == tarfile.SYMTYPE or kind == tarfile.LNKTYPE:
            info.linkname = data.decode()
            data = None
        if data is not None:
            info.size = len(data)
        tf.addfile(info, io.BytesIO(data) if data is not None else None)
    if end:
        tf.close()
        return buf.getvalue()
    tf.fileobj = None  # do not write the end marker
    return buf.getvalue()


MEMBERS = [
    (b"users", tarfile.DIRTYPE, None),
    (b"users/a.xml", tarfile.REGTYPE, b"hello"),
    (b"users/new\nline", tarfile.REGTYPE, b"nl"),
    (b"users/bad\xffname", tarfile.REGTYPE, b"bad"),
    (b"users/link", tarfile.SYMTYPE, b"a.xml"),
    (b"users/hard", tarfile.LNKTYPE, b"users/a.xml"),
    (b"users/fifo", tarfile.FIFOTYPE, None),
]


class ArchiveTests(unittest.TestCase):
    def read(self, data, base=b"/data/system"):
        path = Path(tempfile.mkdtemp()) / "a.tar"
        path.write_bytes(data)
        return read_archive(path, base=base)

    def test_complete_archive(self):
        listing = self.read(make_tar(MEMBERS))
        self.assertTrue(listing.parsed_to_end)
        got = {m.path: (m.entry_type, m.size) for m in listing.members}
        self.assertEqual(got, {
            b"/data/system/users": (EntryType.DIRECTORY, None),
            b"/data/system/users/a.xml": (EntryType.REGULAR, 5),
            b"/data/system/users/new\nline": (EntryType.REGULAR, 2),
            b"/data/system/users/bad\xffname": (EntryType.REGULAR, 3),
            b"/data/system/users/link": (EntryType.SYMLINK, None),
            b"/data/system/users/hard": (EntryType.HARDLINK, None),
            b"/data/system/users/fifo": (EntryType.FIFO, None),
        })
        self.assertEqual(listing.selinux_labelled, 7)
        self.assertEqual(listing.notes, ())

    def test_toybox_style_end_marker_exactly_two_blocks(self):
        data = make_tar(MEMBERS)
        body = data.rstrip(b"\0")
        body += b"\0" * (-len(body) % 512)
        self.assertTrue(self.read(body + b"\0" * 1024).parsed_to_end)
        self.assertFalse(self.read(body + b"\0" * 512).parsed_to_end)  # only one zero block

    def test_missing_end_marker(self):
        listing = self.read(make_tar(MEMBERS, end=False))
        self.assertFalse(listing.parsed_to_end)
        self.assertEqual(len(listing.members), 7)

    def test_data_after_the_end_marker(self):
        listing = self.read(make_tar(MEMBERS) + b"tar: had errors\n")
        self.assertFalse(listing.parsed_to_end)

    def test_truncated_member(self):
        data = make_tar([(b"users", tarfile.DIRTYPE, None),
                         (b"users/big", tarfile.REGTYPE, b"x" * 5000)])
        listing = self.read(data[:5000])   # inside big's content
        self.assertFalse(listing.parsed_to_end)
        self.assertEqual(listing.truncated_members, (b"/data/system/users/big",))
        listing = self.read(data[:3000])   # inside big's header: users is whole
        self.assertFalse(listing.parsed_to_end)
        self.assertEqual(listing.truncated_members, ())

    def test_not_a_tar(self):
        listing = self.read(b"error: device offline\n" + b"x" * 600)
        self.assertFalse(listing.parsed_to_end)
        self.assertEqual(listing.members, ())

    def test_invalid_and_duplicate_names(self):
        listing = self.read(make_tar([(b"users/../../etc/x", tarfile.REGTYPE, b"x"),
                                      (b"users/a", tarfile.REGTYPE, b"1"),
                                      (b"users/a", tarfile.REGTYPE, b"2")]))
        self.assertEqual(listing.invalid_member_names, (b"users/../../etc/x",))
        self.assertEqual(listing.duplicate_members, (b"/data/system/users/a",))
        self.assertEqual([m.path for m in listing.members], [b"/data/system/users/a"])


if __name__ == "__main__":
    unittest.main()
