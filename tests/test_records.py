import json, os, shutil, sys, tempfile, unittest
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.sbom import SBOMComponent, SBOMRecord, sbom_from_cyclonedx, sbom_from_installed
from cra_evidence.vuln import VulnerabilityRecord
from cra_evidence.srp_notice import SRPNotice, DryRunDrop, schema

AW = "2026-09-12T08:00:00Z"   # explicit instants only: never `now()` in a test


class TestSBOM(unittest.TestCase):
    def test_cyclonedx_min_and_dedup_and_hash_deterministic(self):
        c = [SBOMComponent("a", "1.0", purl="pkg:pypi/a@1.0"), SBOMComponent("a", "1.0", purl="pkg:pypi/a@1.0"), SBOMComponent("b", "2", sha256="ab" * 32)]
        r = SBOMRecord("prod", "1", c, record_id="rid", generated_utc="2026-09-15T00:00:00+00:00")
        cdx = r.to_cyclonedx_min()
        self.assertEqual(cdx["bomFormat"], "CycloneDX"); self.assertEqual(len(cdx["components"]), 2)
        self.assertEqual(cdx["components"][1]["hashes"][0]["content"], "ab" * 32)
        self.assertEqual(r.canonical_hash(), SBOMRecord("prod", "1", c, record_id="rid", generated_utc="2026-09-15T00:00:00+00:00").canonical_hash())

    def test_installed_floor_is_honest(self):
        r = sbom_from_installed("p", "1", ["json", "this-package-does-not-exist-xyz"])
        names = {c.name.lower(): c.version for c in r.components}
        self.assertEqual(names["this-package-does-not-exist-xyz"], "NOT-INSTALLED")

    def test_ingest_cyclonedx_robust(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.json")
        json.dump({"bomFormat": "CycloneDX", "metadata": {"tools": {"components": [{"name": "syft"}]}},
                   "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1", "hashes": [{"alg": "SHA-256", "content": "cd" * 32}],
                                   "licenses": [{"license": {"id": "MIT"}}]}, "garbage", {"version": "no-name"}]}, open(p, "w"))
        r = sbom_from_cyclonedx(p, "prod", "1"); self.assertEqual(len(r.components), 1); self.assertEqual(r.depth, "external:cyclonedx:syft")
        self.assertEqual(r.components[0].license, "MIT")
        json.dump({"components": "not-a-list"}, open(p, "w"))
        with self.assertRaises(ValueError):
            sbom_from_cyclonedx(p, "prod", "1")
        shutil.rmtree(d, ignore_errors=True)


class TestVuln(unittest.TestCase):
    def test_deadlines_and_final_report_anchored_to_fix(self):
        v = VulnerabilityRecord("p", "CVE-2026-0001", True, AW)
        d = v.deadlines()
        self.assertEqual(d["early_warning_due_utc"], "2026-09-13T08:00:00+00:00"); self.assertEqual(d["notification_due_utc"], "2026-09-15T08:00:00+00:00")
        self.assertIsNone(d["final_report_due_utc"])                        # no fix yet → undetermined, not awareness+14d
        v2 = VulnerabilityRecord("p", "CVE-2026-0001", True, AW, corrective_available_utc="2026-09-14T00:00:00Z")
        self.assertEqual(v2.deadlines()["final_report_due_utc"], "2026-09-28T00:00:00+00:00")

    def test_overdue_both_directions_and_only_if_exploited(self):
        v = VulnerabilityRecord("p", "CVE-2026-0001", True, AW)
        t = datetime(2026, 9, 13, 9, 0, tzinfo=timezone.utc)
        self.assertTrue(v.overdue(t)["early_warning_overdue"]); self.assertFalse(v.overdue(t)["notification_overdue"])
        self.assertFalse(v.overdue(datetime(2026, 9, 12, 9, 0, tzinfo=timezone.utc))["early_warning_overdue"])
        sent = VulnerabilityRecord("p", "CVE-2026-0001", True, AW, status="early_warning_sent")
        self.assertFalse(sent.overdue(t)["early_warning_overdue"])
        ne = VulnerabilityRecord("p", "CVE-2026-0002", False, AW)
        o = ne.overdue(datetime(2027, 1, 1, tzinfo=timezone.utc)); self.assertFalse(o["reporting_applicable"]); self.assertFalse(o["early_warning_overdue"])

    def test_guards(self):
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "", True, AW)
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "x", True, (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "x", True, AW, corrective_available_utc="2026-09-01T00:00:00Z")


class TestSRPNotice(unittest.TestCase):
    BASE = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "ACME", "member_states_available": ["IT"],
            "product_name": "P", "product_version": "1", "awareness_datetime_utc": AW}

    def test_schema_counts_match_glossary(self):
        self.assertEqual(len(schema("vulnerability")), 18 + 12); self.assertEqual(len(schema("incident")), 18 + 9)

    def test_required_by_stage_from_glossary(self):
        ew = SRPNotice("vulnerability", "early_warning", dict(self.BASE)); self.assertTrue(ew.complete(), ew.missing())
        n72 = SRPNotice("vulnerability", "notification", dict(self.BASE))
        self.assertEqual(set(n72.missing()), {"general_information", "particular_exceptional_circumstances", "pec_delay_reason"})
        fr = SRPNotice("vulnerability", "final_report", dict(self.BASE))
        self.assertIn("corrective_available_date", fr.missing()); self.assertIn("severity_description", fr.missing())
        self.assertIn("corrective_measures_taken", fr.missing()); self.assertNotIn("attack_vector", fr.missing())
        self.assertNotIn("malicious_actor", ew.missing())      # required-if-available is never "missing"
        inc = SRPNotice("incident", "early_warning", {**self.BASE, "notification_type": "Incident"})
        self.assertEqual(inc.missing(), ["suspected_malicious"])

    def test_deadlines_and_payload_and_guards(self):
        n = SRPNotice("vulnerability", "early_warning", dict(self.BASE)); self.assertEqual(n.deadline_utc(), "2026-09-13T08:00:00+00:00")
        fr = SRPNotice("vulnerability", "final_report", {**self.BASE, "corrective_available_date": "2026-09-20T00:00:00Z"})
        self.assertEqual(fr.deadline_utc(), "2026-10-04T00:00:00+00:00")
        self.assertIsNone(SRPNotice("vulnerability", "final_report", dict(self.BASE)).deadline_utc())
        inc = SRPNotice("incident", "final_report", {**self.BASE, "notification_type": "Incident"})
        self.assertEqual(inc.deadline_utc(), "2026-10-15T08:00:00+00:00")   # awareness + 72 h + 30 days
        pl = n.payload(); self.assertIn("NOT submitted", pl["submission"]); self.assertEqual(pl["notice_sha3"], n.canonical_hash())
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "early_warning", {**self.BASE, "product_type": "Huge"})
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "early_warning", {**self.BASE, "title": "x" * 256})
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "early_warning", {**self.BASE, "not_a_field": 1})
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "early_warning", {**self.BASE, "awareness_datetime_utc": "2099-01-01T00:00:00Z"})

    def test_dry_run_never_sends(self):
        import socket
        d = tempfile.mkdtemp()
        real = socket.socket.connect
        def boom(*a, **k):
            raise AssertionError("network call during dry run")
        socket.socket.connect = boom
        try:
            r = DryRunDrop(d).prepare(SRPNotice("vulnerability", "early_warning", dict(self.BASE)))
        finally:
            socket.socket.connect = real
        self.assertEqual(r["status"], "prepared_not_sent"); self.assertTrue(os.path.exists(os.path.join(d, r["drop_file"])))
        self.assertNotIn(os.sep, r["drop_file"])            # a NAME, never a path (no directory layout leaks into the ledger)
        self.assertEqual(len(r["drop_sha3"]), 64)
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
