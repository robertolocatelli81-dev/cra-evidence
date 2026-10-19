# SPDX-License-Identifier: AGPL-3.0-or-later
"""Art. 14: the obligation arises on awareness of ACTIVE EXPLOITATION (Commission guidance C(2026) 5252 annex §217,
non-binding; Art. 71(2) the norm), from 11 September 2026 under BOTH readings of the day — 00:00 UTC and 00:00
Europe/Brussels (2026-09-10T22:00Z, CEST) — with "depends on the time-zone reading" between them (Roberto's decision,
18/10/2026). The Brussels rule of the module is checked against the IANA zone (zoneinfo) day by day."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence import applicability as A  # noqa: E402
from cra_evidence import cli  # noqa: E402
from cra_evidence.vuln import VulnerabilityRecord  # noqa: E402

try:
    from zoneinfo import ZoneInfo
    BXL = ZoneInfo("Europe/Brussels")
except Exception:   # noqa: BLE001 — no zoneinfo module or no tz database on this host
    BXL = None

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


class BrusselsRule(unittest.TestCase):
    @unittest.skipIf(BXL is None, "no IANA time-zone database here")
    def test_midnight_and_offsets_equal_the_iana_zone_2000_2040(self):
        d, n = datetime(2000, 1, 1), 0
        while d.year <= 2040:
            want = datetime(d.year, d.month, d.day, tzinfo=BXL).astimezone(timezone.utc)
            self.assertEqual(A.day_start(d.year, d.month, d.day, "europe_brussels"), want, d)
            for h in (0, 1, 2, 3, 12, 23):   # around each transition (01:00 UTC) and elsewhere in the day
                t = datetime(d.year, d.month, d.day, h, 30, tzinfo=timezone.utc)
                self.assertEqual(A.brussels_offset(t), t.astimezone(BXL).utcoffset(), t)
            d += timedelta(days=1); n += 1
        self.assertEqual(n, 14976)
        for y in range(2000, 2041):   # the transition instants themselves (01:00:00 UTC) and one second before
            for m in (3, 10):
                t = A._last_sunday(y, m).replace(hour=1)
                for u in (t - timedelta(seconds=1), t):
                    self.assertEqual(A.brussels_offset(u), u.astimezone(BXL).utcoffset(), u)
        self.assertEqual(A.day_start(2026, 9, 11, "europe_brussels").isoformat(), "2026-09-10T22:00:00+00:00")
        self.assertEqual(A.day_start(2027, 12, 11, "europe_brussels").isoformat(), "2027-12-10T23:00:00+00:00")

    @unittest.skipIf(BXL is None, "no IANA time-zone database here")
    def test_positive_control_a_wrong_rule_is_seen(self):
        wrong = sum(1 for m in range(1, 13) for dd in (1, 15)
                    if datetime(2026, m, dd, tzinfo=timezone.utc) - timedelta(hours=1)
                    != datetime(2026, m, dd, tzinfo=BXL).astimezone(timezone.utc))
        self.assertGreater(wrong, 0, "a fixed +1 h rule must differ from the zone in summer")


class Obligation(unittest.TestCase):
    def test_the_three_cases_of_217(self):
        r = A.art14_obligation("2026-09-01T10:00:00Z", vulnerability_awareness_utc="2026-08-01T00:00:00Z")
        self.assertEqual((r["outcome"], r["obligation"]), ("no_obligation", False))   # exploitation known before: not retroactive
        r = A.art14_obligation("2026-09-15T10:00:00Z", vulnerability_awareness_utc="2026-08-01T00:00:00Z")
        self.assertEqual((r["outcome"], r["obligation"]), ("obligation", True))       # vulnerability before, exploitation after
        self.assertEqual(r["vulnerability_awareness_utc"], "2026-08-01T00:00:00+00:00")
        self.assertIn("non-binding", r["interpretation"]); self.assertIn("§217", r["interpretation"]); self.assertIn("71(2)", r["norm"])

    def test_boundaries_under_both_readings(self):
        for at, out in (("2026-09-10T21:59:59Z", "no_obligation"), ("2026-09-10T22:00:00Z", "depends_on_time_zone_reading"),
                        ("2026-09-10T23:59:59Z", "depends_on_time_zone_reading"), ("2026-09-11T00:00:00Z", "obligation"),
                        ("2026-09-11T00:30:00+02:00", "depends_on_time_zone_reading")):
            r = A.art14_obligation(at)
            self.assertEqual(r["outcome"], out, at)
        r = A.art14_obligation("2026-09-10T23:00:00Z")
        self.assertIsNone(r["obligation"])
        self.assertEqual(r["readings"], {"utc": {"obligation_from_utc": "2026-09-11T00:00:00+00:00", "obligation": False},
                                         "europe_brussels": {"obligation_from_utc": "2026-09-10T22:00:00+00:00", "obligation": True}})

    def test_steward_and_incident(self):
        self.assertEqual(A.art14_obligation("2027-06-01T00:00:00Z", "open_source_steward")["outcome"], "no_obligation")
        self.assertEqual(A.art14_obligation("2027-12-10T23:00:00Z", "open_source_steward")["outcome"], "depends_on_time_zone_reading")
        r = A.art14_obligation("2026-09-12T00:00:00Z", stream="incident")
        self.assertEqual((r["outcome"], r["trigger"]), ("obligation", "awareness of the severe incident"))
        self.assertIn("this tool's reading, not the guidance's", r["interpretation"]); self.assertIn("§211", r["interpretation"])

    def test_refusals(self):
        with self.assertRaises(ValueError):   # the vulnerability cannot become known after its exploitation
            A.art14_obligation("2026-09-15T00:00:00Z", vulnerability_awareness_utc="2026-09-16T00:00:00Z")
        with self.assertRaises(ValueError):
            A.art14_obligation("2026-09-15T00:00:00Z", stream="incident", vulnerability_awareness_utc="2026-09-01T00:00:00Z")
        with self.assertRaises(ValueError):
            A.art14_obligation("2026-09-15T00:00:00")   # a naive local time is not a legal instant


class Record(unittest.TestCase):
    def test_overdue_follows_the_obligation(self):
        o = VulnerabilityRecord("p", "CVE-2026-1", True, "2026-09-01T00:00:00Z").overdue(NOW)
        self.assertEqual((o["reporting_applicable"], o["any_overdue"], o["art14_obligation"]["outcome"]), (False, False, "no_obligation"))
        o = VulnerabilityRecord("p", "CVE-2026-1", True, "2026-10-01T00:00:00Z").overdue(NOW)
        self.assertEqual((o["reporting_applicable"], o["any_overdue"]), (True, True))
        o = VulnerabilityRecord("p", "CVE-2026-1", True, "2026-09-10T23:00:00Z").overdue(NOW)
        self.assertIsNone(o["reporting_applicable"]); self.assertTrue(o["any_overdue"])
        self.assertEqual(o["time_zone_reading"], {"outcome": "depends_on_time_zone_reading",
                                                  "utc": {"reporting_applicable": False, "any_overdue": False},
                                                  "europe_brussels": {"reporting_applicable": True, "any_overdue": True}})
        o = VulnerabilityRecord("p", "CVE-2026-1", False, "2026-10-01T00:00:00Z").overdue(NOW)
        self.assertEqual((o["reporting_applicable"], o["art14_obligation"]), (False, None))

    def test_cra_vuln_exit_for_an_exploitation_known_before_the_start(self):
        d = tempfile.mkdtemp(prefix="cra-a14-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}; env["PYTHONPATH"] = ROOT
        base = [sys.executable, "-B", "-m", "cra_evidence.cli", "vuln", "--ledger", os.path.join(d, "l.jsonl"), "--product", "p",
                "--version", "1", "--exploited"]
        p = subprocess.run(base + ["--id", "CVE-2026-2", "--aware", "2026-09-01T00:00:00Z"], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stdout[-400:])   # 0.5.1: exit 1, "overdue" from 2 September
        self.assertEqual(json.loads(p.stdout)["overdue"]["art14_obligation"]["outcome"], "no_obligation")
        p = subprocess.run(base + ["--id", "CVE-2026-3", "--aware", "2026-09-20T00:00:00Z"], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 1, "positive control: an exploitation known after the start is overdue")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class ObligationsCLI(unittest.TestCase):
    def test_exploitation_aware(self):
        rc, out, _ = _run(["obligations", "--exploitation-aware", "2026-09-10T23:30:00Z", "--vulnerability-aware", "2026-08-01T00:00:00Z"])
        self.assertEqual(rc, 0); r = json.loads(out)
        self.assertEqual(r["art14_obligation"]["outcome"], "depends_on_time_zone_reading"); self.assertNotIn("reporting", r)

    def test_support_period_below_under_one_reading_exits_1(self):
        rc, out, _ = _run(["obligations", "--placed-on-market", "2028-01-15T00:00:00Z", "--support-period-end", "2033-01-15T23:30:00Z"])
        self.assertEqual(rc, 1); self.assertEqual(json.loads(out)["support_period"]["status"], "depends_on_time_zone_reading")
        rc, out, _ = _run(["obligations", "--placed-on-market", "2028-01-15T00:00:00Z", "--support-period-end", "2033-01-16T00:00:00Z"])
        self.assertEqual(rc, 0)

    def test_usage(self):
        for argv in (["obligations", "--vulnerability-aware", "2026-08-01T00:00:00Z", "--at", "2027-01-01T00:00:00Z"],
                     ["obligations", "--exploitation-aware", "2026-09-15T00:00:00Z", "--vulnerability-aware", "2026-09-16T00:00:00Z"],
                     ["obligations", "--exploitation-aware", "2026-09-15T00:00:00"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--placed-on-market", "2028-01-01T00:00:00Z", "--substantially-modified", "2027-01-01T00:00:00Z"]):
            rc, out, err = _run(argv)
            self.assertEqual(rc, 2, argv); self.assertEqual(out, "", argv); self.assertIn("usage", err, argv)


if __name__ == "__main__":
    unittest.main()
