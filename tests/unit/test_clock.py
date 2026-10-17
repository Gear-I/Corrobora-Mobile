import unittest
from datetime import datetime, timedelta, timezone

from corrobora_mobile.core.clock import (
    FixedClock,
    SystemClock,
    format_rfc3339,
    ns_to_utc,
    parse_rfc3339,
)
from corrobora_mobile.core.errors import ModelValidationError


class ClockTests(unittest.TestCase):
    def test_format_utc(self):
        instant = datetime(2026, 10, 16, 21, 5, 9, 123456, tzinfo=timezone.utc)
        self.assertEqual(format_rfc3339(instant), "2026-10-16T21:05:09.123456Z")

    def test_format_converts_offset_to_utc(self):
        instant = datetime(2026, 10, 16, 17, 0, 0, tzinfo=timezone(timedelta(hours=-4)))
        self.assertEqual(format_rfc3339(instant), "2026-10-16T21:00:00.000000Z")

    def test_naive_datetime_rejected(self):
        with self.assertRaises(ModelValidationError):
            format_rfc3339(datetime(2026, 10, 16, 21, 0, 0))

    def test_fixed_clock_rejects_naive(self):
        with self.assertRaises(ModelValidationError):
            FixedClock(datetime(2026, 10, 16))

    def test_fixed_clock_returns_instant(self):
        instant = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(FixedClock(instant).now(), instant)

    def test_four_digit_year_before_1000(self):
        # strftime("%Y") does not zero-pad on all platforms.
        self.assertEqual(
            format_rfc3339(datetime(999, 1, 2, tzinfo=timezone.utc)), "0999-01-02T00:00:00.000000Z"
        )
        self.assertEqual(
            format_rfc3339(datetime(1, 1, 1, tzinfo=timezone.utc)), "0001-01-01T00:00:00.000000Z"
        )

    def test_parse_round_trip(self):
        for instant in (
            datetime(2026, 10, 16, 21, 5, 9, 123456, tzinfo=timezone.utc),
            datetime(1, 1, 1, tzinfo=timezone.utc),
            datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
        ):
            with self.subTest(instant=instant):
                self.assertEqual(parse_rfc3339(format_rfc3339(instant)), instant)

    def test_parse_rejects_non_canonical(self):
        for bad in (
            "2026-10-16T21:05:09Z",            # no fraction
            "2026-10-16T21:05:09.123Z",        # short fraction
            "2026-10-16T21:05:09.123456z",     # lowercase z
            "2026-10-16T21:05:09.123456+00:00",  # offset
            "2026-10-16 21:05:09.123456Z",     # space separator
            "2026-02-30T00:00:00.000000Z",     # impossible date
            "2026-10-16T24:00:00.000000Z",     # hour 24
            "\u0662026-10-16T21:05:09.123456Z",  # non-ASCII digit
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    parse_rfc3339(bad)

    def test_ns_to_utc_handles_pre_epoch(self):
        self.assertEqual(ns_to_utc(0), datetime(1970, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(
            ns_to_utc(-1), datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
        )

    def test_ns_to_utc_rejects_bool(self):
        with self.assertRaises(ModelValidationError):
            ns_to_utc(True)

    def test_ns_to_utc_out_of_range(self):
        with self.assertRaises(ModelValidationError):
            ns_to_utc(10**30)

    def test_clocks_declare_source(self):
        self.assertTrue(SystemClock.source)
        self.assertTrue(FixedClock.source)

    def test_system_clock_is_aware_utc(self):
        now = SystemClock().now()
        self.assertIsNotNone(now.tzinfo)
        self.assertEqual(now.utcoffset(), timedelta(0))


if __name__ == "__main__":
    unittest.main()
