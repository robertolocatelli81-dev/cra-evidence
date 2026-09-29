"""ENISA CRA SRP glossary, page dated 25/09/2026 (read 29/09/2026): one row added, v26a. Each measurement below is
made against the two vendored snapshots (15/09 and 29/09); the bench proves it can fail (positive controls)."""
import json, os, re, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from cra_evidence.srp_notice import COMMON_FIELDS, INCIDENT_FIELDS, VULN_FIELDS, SRPNotice, schema

OLD = os.path.join(ROOT, "spec", "sources", "enisa_srp_glossary_20260915.json")
NEW = os.path.join(ROOT, "spec", "sources", "enisa_srp_glossary_20260929.json")
ROW = re.compile(r"[vi]?\d+[a-z]?\.")          # a row number may carry a letter suffix ("v26a.")
NARROW = re.compile(r"[vi]?\d+\.")             # the pattern used until 0.3.3
CODE = {"Required": "R", "Optional": "O", "N/A": "-", "By default copied from previous step, or updated": "C",
        "Required if such information available": "A"}
AW = "2026-09-01T00:00:00Z"
EW = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
      "product_name": "p", "product_version": "1", "awareness_datetime_utc": AW}
N72 = {**EW, "general_information": "g"}


def _load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _numbered(snap, pattern=ROW):
    return [r for r in snap["rows"] if len(r) >= 10 and pattern.match(r[0])]


def check_schema_against(snap):
    """The derivation used by tests/test_council_r2.py: the module's per-stage codes must equal the snapshot's, row by row."""
    rows = _numbered(snap)
    ours = list(COMMON_FIELDS.values()) + list(VULN_FIELDS.values()) + list(INCIDENT_FIELDS.values())
    assert len(rows) == len(ours), (len(rows), len(ours))
    for r, spec in zip(rows, ours):
        assert spec["stages"] == {"early_warning": CODE[r[7]], "notification": CODE[r[8]], "final_report": CODE[r[9]]}, r[1]
        assert spec["glossary_row"] + "." == r[0], (spec["glossary_row"], r[0])


class TestGlossary20260925(unittest.TestCase):
    def test_difference_15_09_to_25_09_is_exactly_one_inserted_row(self):
        old, new = _load(OLD), _load(NEW)
        self.assertEqual(old["header"], new["header"])
        self.assertEqual(len(old["rows"]), 44); self.assertEqual(len(new["rows"]), 45)
        added = [r for r in new["rows"] if r and r[0] == "v26a."]
        self.assertEqual(len(added), 1)
        self.assertEqual([r for r in new["rows"] if r not in added], old["rows"])     # same 44 rows, same content, same order
        i = new["rows"].index(added[0]); self.assertEqual(new["rows"][i - 1][0], "v26."); self.assertEqual(new["rows"][i + 1][0], "v27.")
        v26a = added[0]
        self.assertEqual(v26a[1], "Date and time when the Actively Exploited Vulnerability occurred (UTC time)")
        self.assertEqual(v26a[2], "AEV"); self.assertEqual(v26a[6], "Date and time")
        self.assertEqual(v26a[7:10], ["Optional", "Required", "By default copied from previous step, or updated"])
        self.assertEqual(len(_numbered(new)), 40); self.assertEqual(len(_numbered(old)), 39)
        by_scope = {s: len([r for r in _numbered(new) if r[2] == s]) for s in ("Both", "AEV", "SI")}
        self.assertEqual(by_scope, {"Both": 18, "AEV": 13, "SI": 9})

    def test_schema_derived_from_the_25_09_snapshot(self):
        check_schema_against(_load(NEW))
        self.assertEqual(VULN_FIELDS["vulnerability_occurred_datetime_utc"]["stages"], {"early_warning": "O", "notification": "R", "final_report": "C"})
        self.assertEqual(list(VULN_FIELDS).index("vulnerability_occurred_datetime_utc"), list(VULN_FIELDS).index("awareness_datetime_utc") + 1)
        self.assertEqual(len(schema("vulnerability")), 31); self.assertEqual(len(schema("incident")), 27)

    def test_positive_control_the_15_09_snapshot_fails_the_derivation(self):
        with self.assertRaises(AssertionError):
            check_schema_against(_load(OLD))

    def test_positive_control_the_narrow_pattern_would_have_missed_v26a(self):
        # measured: with the pattern used until 0.3.3, the 25/09 snapshot still yields 39 rows — a count check alone
        # would have stayed green without the new field; the wide pattern sees 40
        self.assertEqual(len(_numbered(_load(NEW), NARROW)), 39)
        self.assertEqual(len(_numbered(_load(NEW), ROW)), 40)


class TestV26aInNotices(unittest.TestCase):
    def test_72h_notification_without_v26a_is_incomplete(self):
        self.assertTrue(SRPNotice("vulnerability", "early_warning", dict(EW)).complete())          # optional at 24 h
        n = SRPNotice("vulnerability", "notification", dict(N72))
        self.assertEqual(n.missing(), ["vulnerability_occurred_datetime_utc"]); self.assertFalse(n.complete())
        ok = SRPNotice("vulnerability", "notification", {**N72, "vulnerability_occurred_datetime_utc": "2026-08-24T09:15:00Z"})
        self.assertTrue(ok.complete(), ok.missing())
        self.assertTrue(ok.payload()["glossary_source"].startswith("ENISA CRA SRP Glossary (40 fields"))

    def test_final_report_carries_v26a_or_reports_it_missing(self):
        fr_fields = {**N72, "corrective_available_date": "2026-09-02T09:15:00Z", "security_update_details": "u", "severity_description": "sev",
                     "impact_description": "imp", "corrective_measures_taken": "c", "user_measures": "um"}
        self.assertIn("vulnerability_occurred_datetime_utc", SRPNotice("vulnerability", "final_report", dict(fr_fields)).missing())
        carried = SRPNotice("vulnerability", "final_report", dict(fr_fields),
                            previous_fields={**N72, "vulnerability_occurred_datetime_utc": "2026-08-24T09:15:00Z"})
        self.assertNotIn("vulnerability_occurred_datetime_utc", carried.missing())
        self.assertEqual(carried.fields["vulnerability_occurred_datetime_utc"], "2026-08-24T09:15:00Z")

    def test_v26a_must_be_an_instant_and_is_not_in_the_incident_stream(self):
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "notification", {**N72, "vulnerability_occurred_datetime_utc": "yesterday"})
        with self.assertRaises(ValueError):                      # naive instant refused, as every other datetime here
            SRPNotice("vulnerability", "notification", {**N72, "vulnerability_occurred_datetime_utc": "2026-08-24T09:15:00"})
        with self.assertRaises(ValueError):
            SRPNotice("incident", "notification", {**N72, "notification_type": "Incident", "vulnerability_occurred_datetime_utc": "2026-08-24T09:15:00Z"})

    def test_cli_notice_exit_code_and_template(self):
        from cra_evidence.cli import main
        d = tempfile.mkdtemp()
        try:
            led = os.path.join(d, "l.jsonl"); drop = os.path.join(d, "drop")
            f_missing = os.path.join(d, "n72.json"); f_ok = os.path.join(d, "n72ok.json")
            with open(f_missing, "w", encoding="utf-8") as f:
                json.dump(N72, f)
            with open(f_ok, "w", encoding="utf-8") as f:
                json.dump({**N72, "vulnerability_occurred_datetime_utc": "2026-08-24T09:15:00Z"}, f)
            base = ["notice", "--ledger", led, "--product", "p", "--version", "1", "--stage", "notification", "--drop", drop]
            self.assertEqual(main(base + ["--fields", f_missing]), 1)
            self.assertEqual(main(base + ["--fields", f_ok]), 0)
            import io, contextlib
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["schema", "--stream", "vulnerability", "--template", "notification"])
            self.assertIn("vulnerability_occurred_datetime_utc", json.loads(out.getvalue()))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
