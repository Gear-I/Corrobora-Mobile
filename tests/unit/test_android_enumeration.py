"""Enumeration parsing, based on what toybox 0.8.13 printed on 2026-11-09.

Pass 1 samples are the observed bytes for planted test files in
/data/local/tmp/cm-obs3 on the developer's userdebug Android 17 emulator
(observation 3; no personal data), minus the %T@ field that run also
printed. Pass 2 lines are CONSTRUCTED in the observed stat format; only the
directory's times and the format itself were observed.
"""

import json
import unittest

from corrobora_mobile.core.enums import EntryType
from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.platforms.android.enumeration import merge, parse_find, parse_stat

D = b"/data/local/tmp/cm-obs3"
L = b"u:object_r:shell_data_file:s0"

# pass 1 for four entries, as observed (except that the observed run also printed %T@)
OBSERVED_FIND = (
    b"drwxrwxrwx\x00777\x000\x000\x004096\x0065545\x00" + L + b"\x00\x00" + D + b"\x00"
    b"-rw-rw-rw-\x00666\x000\x000\x002\x0065549\x00" + L + b"\x00\x00" + D + b"/new\nline\x00"
    b"-rw-rw-rw-\x00666\x000\x000\x003\x0065550\x00" + L + b"\x00\x00" + D + b"/bad\xffname\x00"
    b"lrwxrwxrwx\x00777\x000\x000\x005\x0065551\x00" + L + b"\x00plain\x00" + D + b"/link\x00"
)
# pass 2 lines in the same order (constructed; see the module docstring)
OBSERVED_STAT = (
    b"65545|3|1794271832|2026-11-09 19:50:32.424000778 -0500|1794271832|2026-11-09 19:50:32.424000778 -0500|1794271831|2026-11-09 19:50:31.916000765 -0500\n"
    b"65549|1|1794271832|2026-11-09 19:50:32.044000768 -0500|1794271832|2026-11-09 19:50:32.044000768 -0500|1794271832|2026-11-09 19:50:32.044000768 -0500\n"
    b"65550|1|1794271832|2026-11-09 19:50:32.092000769 -0500|1794271832|2026-11-09 19:50:32.092000769 -0500|1794271832|2026-11-09 19:50:32.092000769 -0500\n"
    b"65551|1|1794271832|2026-11-09 19:50:32.168000771 -0500|1794271832|2026-11-09 19:50:32.168000771 -0500|1794271832|2026-11-09 19:50:32.168000771 -0500\n"
)


class FindTests(unittest.TestCase):
    def test_observed_output(self):
        records = parse_find(OBSERVED_FIND)
        self.assertEqual([r.path for r in records],
                         [D, D + b"/new\nline", D + b"/bad\xffname", D + b"/link"])
        self.assertEqual([r.entry_type for r in records],
                         [EntryType.DIRECTORY, EntryType.REGULAR, EntryType.REGULAR, EntryType.SYMLINK])
        self.assertEqual(records[0].mode, 0o777)
        self.assertEqual(records[1].size, 2)
        self.assertEqual(records[3].symlink_target, b"plain")
        self.assertIsNone(records[1].symlink_target)
        self.assertEqual(records[0].selinux_label, L.decode())

    def test_every_type_character(self):
        for char, kind in (("-", EntryType.REGULAR), ("d", EntryType.DIRECTORY),
                           ("l", EntryType.SYMLINK), ("p", EntryType.FIFO),
                           ("s", EntryType.SOCKET), ("c", EntryType.CHAR_DEVICE),
                           ("b", EntryType.BLOCK_DEVICE), ("D", EntryType.UNKNOWN)):
            data = char.encode() + b"rw-------\x00600\x000\x000\x000\x001\x00?\x00\x00/data/x\x00"
            with self.subTest(char=char):
                (record,) = parse_find(data)
                self.assertIs(record.entry_type, kind)
                self.assertIsNone(record.selinux_label)  # "?" means no label

    def test_malformed_output_is_rejected(self):
        for bad in (OBSERVED_FIND[:-1],                       # no final NUL
                    OBSERVED_FIND + b"x\x00",                 # field count not a multiple of 9
                    OBSERVED_FIND.replace(b"\x00666\x00", b"\x00rw\x00", 1),
                    OBSERVED_FIND.replace(b"\x0065549\x00", b"\x00-\x00", 1),
                    b"find: '/data/x': Permission denied\n"):
            with self.subTest(bad=bad[:40]), self.assertRaises(ModelValidationError):
                parse_find(bad)
        self.assertEqual(parse_find(b""), [])


class StatTests(unittest.TestCase):
    def test_observed_output_keeps_leading_zero_nanoseconds(self):
        records = parse_stat(OBSERVED_STAT)
        # find's %T@ printed this mtime as 1794271832.44000768 (leading zero lost)
        self.assertEqual(records[1].mtime_ns, 1794271832_044000768)
        self.assertEqual(records[0].atime_ns, 1794271831_916000765)
        self.assertEqual(records[0].link_count, 3)
        self.assertEqual({r.second_precision_fields for r in records}, {0})

    def test_short_or_missing_fraction_falls_back_to_seconds(self):
        line = b"7|1|100|1970-01-01 00:01:40.44 +0000|100|1970-01-01 00:01:40 +0000|100|1970-01-01 00:01:40.000000001 +0000\n"
        (r,) = parse_stat(line)
        self.assertEqual(r.mtime_ns, 100_000_000_000)   # 2 digits: not trusted
        self.assertEqual(r.ctime_ns, 100_000_000_000)
        self.assertEqual(r.atime_ns, 100_000_000_001)
        self.assertEqual(r.second_precision_fields, 2)

    def test_negative_seconds(self):
        (r,) = parse_stat(b"7|1|-1|1969-12-31 23:59:59.500000000 +0000|0|1970-01-01 00:00:00.000000000 +0000|0|1970-01-01 00:00:00.000000000 +0000\n")
        self.assertEqual(r.mtime_ns, -500_000_000)

    def test_malformed(self):
        for bad in (b"1|2|3\n", b"x|1|1|2026-01-01 00:00:00.000000000 +0000|1|a|1|b\n",
                    b"1|1|1|yesterday|1|2026-01-01 00:00:00 +0000|1|2026-01-01 00:00:00 +0000\n",
                    "1|1|1|2026-01-01 00:00:00 +0000|1|2026-01-01 00:00:00 +0000|1|é\n".encode()):
            with self.subTest(bad=bad), self.assertRaises((ModelValidationError, UnicodeDecodeError)):
                parse_stat(bad)


class MergeTests(unittest.TestCase):
    def test_merged_entries(self):
        e = merge(parse_find(OBSERVED_FIND), parse_stat(OBSERVED_STAT))
        self.assertTrue(e.stat_pass_used)
        self.assertEqual(e.entries[1].mtime_ns, 1794271832_044000768)
        self.assertEqual(e.entries[0].link_count, 3)
        self.assertEqual(e.symlink_targets, {D + b"/link": b"plain"})
        lines = e.to_jsonl(label="pre").decode().splitlines()
        self.assertEqual(json.loads(lines[0])["entry_count"], 4)
        self.assertEqual(json.loads(lines[4])["symlink_target"]["display"], "plain")

    def test_count_mismatch_drops_pass_2(self):
        stats = parse_stat(OBSERVED_STAT)[:-1]
        e = merge(parse_find(OBSERVED_FIND), stats)
        self.assertFalse(e.stat_pass_used)
        self.assertTrue(all(x.mtime_ns is None and x.link_count is None for x in e.entries))
        self.assertIn("3 lines for 4 entries", e.notes[0])

    def test_inode_mismatch_drops_pass_2(self):
        stats = parse_stat(OBSERVED_STAT.replace(b"65550|", b"99999|"))
        e = merge(parse_find(OBSERVED_FIND), stats)
        self.assertFalse(e.stat_pass_used)
        self.assertIn("first at entry 2", e.notes[0])

    def test_pass_2_unavailable(self):
        e = merge(parse_find(OBSERVED_FIND), None, stat_unavailable_reason="exit status 1")
        self.assertFalse(e.stat_pass_used)
        self.assertIn("exit status 1", e.notes[0])

    def test_duplicate_path_is_rejected(self):
        twice = parse_find(OBSERVED_FIND)
        with self.assertRaises(ModelValidationError):
            merge(twice + twice[:1], None)


if __name__ == "__main__":
    unittest.main()
