"""17/10/2026 (Athena), reviewed 19/10/2026 (Noûs): which CRA obligations are in force for whom, and the horizons counted
in years (Art. 13(8), 13(9), 13(13), 14(8), 24(3), 69(2)-(3), 71(2); sources in `cra_evidence/applicability.py` and
`spec/LEGAL_BASIS.md`). Every boundary is tested on both sides of the instant, under both readings of the day (00:00 UTC
and 00:00 Europe/Brussels), so a date moved by one second, one hour or one day turns a test red. Review changes: the day
is no longer read in UTC alone (Roberto's decision of 18/10/2026), and the year horizons follow Reg. 1182/71 Art. 3."""
import contextlib, io, json, os, subprocess, sys, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence import applicability as A
from cra_evidence import cli


class Reporting(unittest.TestCase):
    def test_manufacturer_from_11_september_2026_both_readings(self):
        self.assertEqual(A.reporting_in_force("manufacturer", "2026-09-10T21:59:59Z")["outcome"], "not_in_force")
        self.assertTrue(A.reporting_in_force("manufacturer", "2026-09-11T00:00:00Z")["in_force"])
        # 01:00 in Rome on 11/09 is 23:00 UTC on 10/09: in force at Brussels midnight, not yet at UTC midnight — both said
        r = A.reporting_in_force("manufacturer", "2026-09-11T01:00:00+02:00")
        self.assertIsNone(r["in_force"]); self.assertEqual(r["outcome"], "depends_on_time_zone_reading")
        self.assertEqual({k: v["in_force"] for k, v in r["readings"].items()}, {"utc": False, "europe_brussels": True})
        self.assertEqual(r["readings"]["europe_brussels"]["applies_from_utc"], "2026-09-10T22:00:00+00:00")
        self.assertIsNone(r["scope_condition"]); self.assertIn("69(3)", r["basis"]); self.assertIn("1182/71", r["start_rule"])

    def test_steward_from_11_december_2027_with_its_scope_condition(self):
        for stream in A.STREAMS:
            self.assertFalse(A.reporting_in_force("open_source_steward", "2027-12-10T22:59:59Z", stream)["in_force"])   # CET: 23:00Z
            self.assertEqual(A.reporting_in_force("open_source_steward", "2027-12-10T23:00:00Z", stream)["outcome"], "depends_on_time_zone_reading")
            r = A.reporting_in_force("open_source_steward", "2027-12-11T00:00:00Z", stream)
            self.assertTrue(r["in_force"]); self.assertIn("24(3)", r["scope_condition"]); self.assertFalse(r["scope_condition_checked"])
        # the manufacturer's obligation is in force on a day the steward's is not
        self.assertTrue(A.reporting_in_force("manufacturer", "2027-01-01T00:00:00Z")["in_force"])
        self.assertFalse(A.reporting_in_force("open_source_steward", "2027-01-01T00:00:00Z")["in_force"])
        self.assertNotEqual(A.reporting_in_force("open_source_steward", "2028-01-01T00:00:00Z", "vulnerability")["scope_condition"],
                            A.reporting_in_force("open_source_steward", "2028-01-01T00:00:00Z", "incident")["scope_condition"])

    def test_refusals(self):
        with self.assertRaises(ValueError):
            A.reporting_in_force("importer", "2027-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            A.reporting_in_force("manufacturer", "2027-01-01T00:00:00Z", "voluntary")
        with self.assertRaises(ValueError):   # a naive local time is not a legal instant (vuln.parse_utc)
            A.reporting_in_force("manufacturer", "2027-01-01T00:00:00")


class LegacyScope(unittest.TestCase):
    def test_art_69(self):
        r = A.legacy_product_scope("2025-01-01T00:00:00Z")
        self.assertFalse(r["requirements_apply"]); self.assertTrue(r["art14_applies"])
        self.assertEqual(r["art14_applies_from_utc"], {"utc": "2026-09-11T00:00:00+00:00", "europe_brussels": "2026-09-10T22:00:00+00:00"})
        # a substantial modification counts only from 11 December 2027
        self.assertFalse(A.legacy_product_scope("2025-01-01T00:00:00Z", "2027-12-10T22:59:59Z")["requirements_apply"])
        self.assertTrue(A.legacy_product_scope("2025-01-01T00:00:00Z", "2027-12-11T00:00:00Z")["requirements_apply"])
        self.assertFalse(A.legacy_product_scope("2027-12-10T22:59:59Z")["requirements_apply"])
        self.assertEqual(A.legacy_product_scope("2027-12-10T23:59:59Z")["outcome"], "depends_on_time_zone_reading")
        self.assertTrue(A.legacy_product_scope("2027-12-11T00:00:00Z")["requirements_apply"])
        self.assertFalse(r["in_scope_checked"]); self.assertFalse(r["substantial_checked"])

    def test_modification_before_placing_is_refused(self):
        with self.assertRaises(ValueError):
            A.legacy_product_scope("2028-01-01T00:00:00Z", "2027-12-31T00:00:00Z")


class SupportPeriod(unittest.TestCase):
    def test_five_years_under_1182_71_and_both_readings(self):
        # the day of placing is excluded and the period ends at the expiry of 15/01/2033: 00:00 of 16/01 (UTC), 23:00Z (CET)
        self.assertEqual(A.support_period("2028-01-15T00:00:00Z", "2033-01-16T00:00:00Z")["status"], "meets_minimum")
        r = A.support_period("2028-01-15T00:00:00Z", "2033-01-15T23:30:00Z")
        self.assertEqual(r["status"], "depends_on_time_zone_reading")
        self.assertEqual({k: v["status"] for k, v in r["readings"].items()}, {"utc": "below_minimum", "europe_brussels": "meets_minimum"})
        r = A.support_period("2028-01-15T00:00:00Z", "2033-01-15T22:59:59Z")
        self.assertEqual(r["status"], "below_minimum")
        self.assertEqual({k: v["minimum_end_utc"] for k, v in r["readings"].items()},
                         {"utc": "2033-01-16T00:00:00+00:00", "europe_brussels": "2033-01-15T23:00:00+00:00"})

    def test_shorter_with_a_declared_reason_is_recorded_not_assessed(self):
        r = A.support_period("2028-01-15T00:00:00Z", "2030-01-15T00:00:00Z", "single-season event app, expected use 2 years")
        self.assertEqual(r["status"], "shorter_declared"); self.assertFalse(r["reason_assessed"])
        self.assertEqual(A.support_period("2028-01-15T00:00:00Z", "2030-01-15T00:00:00Z", "   ")["status"], "below_minimum")
        with self.assertRaises(ValueError):   # nothing to justify
            A.support_period("2028-01-15T00:00:00Z", "2035-01-15T00:00:00Z", "a reason")
        with self.assertRaises(ValueError):
            A.support_period("2028-01-15T00:00:00Z", "2028-01-15T00:00:00Z")

    def test_29_february(self):
        r = A.support_period("2028-02-29T12:00:00Z", "2040-01-01T00:00:00Z")   # 28/02/2033 is the last day (1182/71 Art. 3(2)(c))
        self.assertEqual({k: v["minimum_end_utc"] for k, v in r["readings"].items()},
                         {"utc": "2033-03-01T00:00:00+00:00", "europe_brussels": "2033-02-28T23:00:00+00:00"})
        self.assertEqual(A.add_years(A.parse_utc("2028-02-29T00:00:00Z"), 4).isoformat(), "2032-02-29T00:00:00+00:00")


class Horizons(unittest.TestCase):
    def test_retention_ten_years_or_support_period_whichever_longer(self):
        r = A.retention_until("2028-01-01T00:00:00Z")
        self.assertEqual(r["latest_until_utc"], "2038-01-02T00:00:00+00:00")
        self.assertEqual({k: (v["until_utc"], v["governed_by"]) for k, v in r["readings"].items()},
                         {"utc": ("2038-01-02T00:00:00+00:00", "ten_years"), "europe_brussels": ("2038-01-01T23:00:00+00:00", "ten_years")})
        r = A.retention_until("2028-01-01T00:00:00Z", "2040-01-01T00:00:00Z")
        self.assertEqual((r["latest_until_utc"], r["readings"]["utc"]["governed_by"]), ("2040-01-01T00:00:00+00:00", "support_period"))
        self.assertEqual(A.retention_until("2028-01-01T00:00:00Z", "2035-01-01T00:00:00Z")["readings"]["utc"]["governed_by"], "ten_years")

    def test_same_ten_years_as_the_pack(self):
        from cra_evidence.locker import RETENTION_YEARS
        self.assertEqual(A.RETENTION_YEARS, RETENTION_YEARS)

    def test_update_availability(self):
        r = A.update_available_until("2030-06-30T08:00:00Z")
        self.assertEqual({k: v["until_utc"] for k, v in r["readings"].items()},
                         {"utc": "2040-07-01T00:00:00+00:00", "europe_brussels": "2040-06-30T22:00:00+00:00"})
        r = A.update_available_until("2030-06-30T08:00:00Z", "2045-01-01T00:00:00Z")
        self.assertEqual((r["latest_until_utc"], r["readings"]["europe_brussels"]["governed_by"]), ("2045-01-01T00:00:00+00:00", "support_period"))

    def test_user_information_has_no_computed_deadline(self):
        r = A.user_information("2026-10-01T08:00:00Z")
        self.assertEqual(r["status"], "not_recorded"); self.assertIsNone(r["deadline_utc"])
        r = A.user_information("2026-10-01T08:00:00Z", "2026-10-02T09:00:00+02:00")
        self.assertEqual((r["status"], r["users_informed_utc"]), ("recorded", "2026-10-02T07:00:00+00:00"))
        with self.assertRaises(ValueError):
            A.user_information("2026-10-01T08:00:00Z", "2026-10-01T07:59:59Z")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class ObligationsCLI(unittest.TestCase):
    def test_outcome_and_exit_codes(self):
        rc, out, _ = _run(["obligations", "--at", "2026-10-17T00:00:00Z", "--placed-on-market", "2025-03-01T00:00:00Z",
                           "--support-period-end", "2031-03-01T00:00:00Z", "--update-issued", "2026-10-01T00:00:00Z"])
        self.assertEqual(rc, 0); r = json.loads(out)
        self.assertTrue(r["reporting"]["in_force"]); self.assertFalse(r["legacy_scope"]["requirements_apply"])
        self.assertEqual(r["support_period"]["status"], "meets_minimum")
        self.assertEqual(r["retention"]["latest_until_utc"], "2035-03-02T00:00:00+00:00")
        self.assertEqual(r["update_availability"]["latest_until_utc"], "2036-10-02T00:00:00+00:00")
        # below the minimum with no declared reason: a finding, exit 1, the outcome still printed
        rc, out, _ = _run(["obligations", "--at", "2028-01-01T00:00:00Z", "--placed-on-market", "2028-01-01T00:00:00Z",
                           "--support-period-end", "2030-01-01T00:00:00Z"])
        self.assertEqual(rc, 1); self.assertEqual(json.loads(out)["support_period"]["status"], "below_minimum")
        rc, out, _ = _run(["obligations", "--at", "2028-01-01T00:00:00Z", "--placed-on-market", "2028-01-01T00:00:00Z",
                           "--support-period-end", "2030-01-01T00:00:00Z", "--shorter-use-reason", "expected use 2 years"])
        self.assertEqual(rc, 0); self.assertEqual(json.loads(out)["support_period"]["status"], "shorter_declared")

    def test_usage_errors_exit_2_and_print_nothing(self):
        for argv in (["obligations"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--shorter-use-reason", "x"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--substantially-modified", "2028-01-01T00:00:00Z"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--support-period-end", "2032-01-01T00:00:00Z"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--placed-on-market", "2027-01-01T00:00:00Z", "--shorter-use-reason", "x"],
                     ["obligations", "--at", "2027-01-01T00:00:00Z", "--role", "importer"]):
            rc, out, err = _run(argv)
            self.assertEqual(rc, 2, argv); self.assertEqual(out, "", argv); self.assertIn("usage", err, argv)

    def test_a_real_process(self):
        p = subprocess.run([sys.executable, "-m", "cra_evidence.cli", "obligations", "--role", "open_source_steward",
                            "--stream", "incident", "--at", "2027-12-11T00:00:00Z"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)["reporting"]
        self.assertTrue(r["in_force"]); self.assertIn("network and information systems", r["scope_condition"])


if __name__ == "__main__":
    unittest.main()
