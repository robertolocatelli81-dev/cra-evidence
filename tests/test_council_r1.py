"""Findings of the pre-publication council (15/09/2026, Haiku 4.5 + Gemini 3.1 Pro; Fable/Opus/Sonnet in round 2).
Each test was RED on the code as reviewed and is GREEN after the fix named in the test."""
import json, os, shutil, sys, tempfile, unittest, uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.canonical import canonical_bytes, floatfree
from cra_evidence.ledger import Ledger
from cra_evidence.locker import CRAEvidenceLocker
from cra_evidence.vuln import VulnerabilityRecord
from cra_evidence.srp_notice import SRPNotice, DryRunDrop
from cra_evidence.sbom import SBOMComponent, SBOMRecord
from cra_evidence.longterm import LongTermEvidence, Signer, register_algorithm, HASHES
from cra_evidence.verify_pack import verify_pack
from cra_evidence import feeds

try:
    from cra_evidence.signing import keygen
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False


class TestCouncilR1(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    # Gemini A.3 — {"1": "a", 1: "b"} silently collapsed in floatfree / TypeError in json.dumps
    def test_non_string_keys_refused_not_collapsed(self):
        with self.assertRaises(TypeError):
            floatfree({"1": "a", 1: "b"})
        with self.assertRaises(TypeError):
            canonical_bytes({1: "b"})

    # Gemini A.2 — a JSON line that is a list/str crashed verify() with AttributeError instead of a FAIL verdict
    def test_non_dict_line_is_a_verdict_not_a_crash(self):
        p = os.path.join(self.d, "l.jsonl")
        Ledger(p).append({"k": 1})
        with open(p, "a") as f:
            f.write('["not", "a", "dict"]\n')
        v = Ledger(p).verify()
        self.assertFalse(v["chain_ok"]); self.assertTrue(any("not an object" in x for x in v["failures"]))

    # Haiku A.2 — keygen O_TRUNC destroyed an existing key
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_keygen_refuses_to_overwrite(self):
        k = os.path.join(self.d, "a.key"); keygen(k)
        with self.assertRaises(FileExistsError):
            keygen(k)

    # Haiku A.3 — a pack over an empty ledger "proved" nothing but was produced
    def test_pack_refused_on_empty_ledger(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        with self.assertRaises(ValueError):
            lk.evidence_pack(os.path.join(self.d, "p.json"))

    # Gemini A.1 — ledger_file "../../x" resolved outside the pack directory; Haiku A.5 — anchoring not reported
    def test_ledger_file_confined_to_pack_dir_and_anchored_flag(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, "2026-09-01T00:00:00Z"))
        pack_path = os.path.join(self.d, "p.json"); lk.evidence_pack(pack_path)
        r = verify_pack(pack_path); self.assertTrue(r["ok"]); self.assertTrue(r["anchored"])
        pk = json.load(open(pack_path)); pk["ledger_file"] = "../../../../" + pk["ledger_file"]
        json.dump(pk, open(pack_path, "w"))          # pack_sha3 now stale too → must be FAIL, never a path walk
        r = verify_pack(pack_path); self.assertFalse(r["ok"])
        self.assertTrue(all(".." not in (l.get("detail") or "") for l in r["layers"]))

    # Gemini A.5 — hash hard-coded in the seal chain: every record now names its hash and verify uses it
    def test_seal_records_name_their_hash_and_a_deprecated_hash_is_flagged(self):
        register_algorithm("test-plain", gen=lambda: ("sk", "pk"), sign=lambda sk, m: m.hex(), verify=lambda pub, sig, m: sig == m.hex())
        lte = LongTermEvidence("ab" * 32)
        rec = lte.seal(Signer("test-plain"), t=1.0)
        self.assertEqual(rec["hash"], "sha3-256"); self.assertIn("sha3-256", HASHES)
        from cra_evidence.longterm import AlgorithmPolicy
        self.assertTrue(lte.verify(now=2.0, policy=AlgorithmPolicy())["ok"])
        self.assertFalse(lte.verify(now=2.0, policy=AlgorithmPolicy({"sha3-256": 1.5}))["ok"])   # hash retired → not ok
        lte.records[0]["hash"] = "sha3-256-unknown"
        self.assertFalse(lte.verify(now=2.0, policy=AlgorithmPolicy())["ok"])

    # Gemini B.1 — incident final_report rejected because awareness is "-" at that stage in the ENISA schema
    def test_incident_final_report_without_awareness_is_valid(self):
        n = SRPNotice("incident", "final_report", {"notification_type": "Incident", "title": "t", "summary": "s",
                                                    "manufacturer_name": "m", "member_states_available": ["IT"],
                                                    "product_name": "p", "product_version": "1", "suspected_malicious": "No",
                                                    "mitigation_measures": "x", "severity_description": "x", "impact_description": "x",
                                                    "threat_type_root_cause": "x"})
        self.assertIsNone(n.deadline_utc())     # undetermined without the awareness instant, never invented
        with self.assertRaises(ValueError):     # but awareness stays REQUIRED where the schema says R
            SRPNotice("incident", "early_warning", {"title": "t"})

    # Gemini B.4 / Haiku — notice_id / record_id are file-name material: must be UUIDs, never paths
    def test_ids_must_be_uuids(self):
        base = {"notification_type": "Vulnerability", "awareness_datetime_utc": "2026-09-01T00:00:00Z"}
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "early_warning", dict(base), notice_id="../../etc/cron.d/evil")
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "CVE-1", False, "2026-09-01T00:00:00Z", record_id="../x")

    # Gemini B.2 — severe incident could not be modelled in the vulnerability clock (README promised it)
    def test_incident_clock_one_month_after_notification(self):
        r = VulnerabilityRecord("p", "INC-1", True, "2026-09-01T00:00:00Z", kind="incident")
        self.assertIsNone(r.deadlines()["final_report_due_utc"])   # Art. 14(4)(c): anchored to the SUBMISSION, unknown until recorded
        r = VulnerabilityRecord("p", "INC-1", True, "2026-09-01T00:00:00Z", kind="incident", notification_sent_utc="2026-09-02T10:00:00Z")
        d = r.deadlines()
        self.assertEqual(d["final_report_due_utc"], "2026-10-02T10:00:00+00:00")   # one CALENDAR month after the submission
        self.assertIn("one calendar month", d["final_report_basis"])
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "x", True, "2026-09-01T00:00:00Z", kind="rumour")

    # Gemini B.3 — OSV pagination token ignored → truncated results reported as complete; batches now chunked
    def test_osv_pagination_followed_and_chunked(self):
        calls = []
        def fake_post(url, body, timeout):
            calls.append((url, body))
            if url.endswith("querybatch"):
                return {"results": [{"vulns": [{"id": f"V{i}"}], "next_page_token": "tok" if i == 0 else None}
                                    for i in range(len(body["queries"]))]}
            return {"vulns": [{"id": "V0-page2"}]}      # /v1/query with page_token
        old = feeds._post_json; feeds._post_json = fake_post
        try:
            comps = [{"name": f"p{i}", "version": "1", "ecosystem": "PyPI"} for i in range(1200)]
            r = feeds.osv_query_batch(comps)
        finally:
            feeds._post_json = old
        self.assertIsNone(r["error"]); self.assertEqual(len(r["results"]), 1200)
        self.assertEqual(sum(1 for u, _ in calls if u.endswith("querybatch")), 2)     # 1000 + 200
        self.assertIn("V0-page2", r["results"][0])

    # Haiku B.8 — component order followed dependency traversal: same environment, different SBOM bytes
    def test_sbom_components_deterministically_ordered(self):
        a = SBOMComponent("zeta", "1"); b = SBOMComponent("alpha", "2")
        s1 = SBOMRecord("p", "1", [a, b]); s2 = SBOMRecord("p", "1", [b, a], record_id=s1.record_id, generated_utc=s1.generated_utc)
        self.assertEqual(s1.canonical_hash(), s2.canonical_hash())

    # Gemini B.5 — "extra==" / "extra  ==" markers slipped into the SBOM as runtime deps
    def test_extra_marker_regex(self):
        from cra_evidence.sbom import _is_extra_requirement
        self.assertTrue(_is_extra_requirement("pytest; extra == 'test'"))
        self.assertTrue(_is_extra_requirement("pytest ; extra=='test'"))
        self.assertFalse(_is_extra_requirement("cryptography>=41"))

    # Haiku B.7 — an EUVD payload of unknown shape produced count 0 with error None
    def test_euvd_unknown_shape_is_an_error(self):
        old = feeds._get_json; feeds._get_json = lambda url, timeout: {"unexpected": {"deep": 1}}
        try:
            r = feeds.euvd_kev_ids()
        finally:
            feeds._get_json = old
        self.assertIsNotNone(r["error"]); self.assertEqual(r["count"], 0)

    # Gemini A.6 — standard VEX/CSAF documents can be embedded (content-bound) in the vulnerability record
    def test_vex_attachment_is_content_bound(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        vex = {"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "not_affected"}}]}
        e = lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, "2026-09-01T00:00:00Z"),
                                    attachments=[{"format": "cyclonedx-vex", "document": vex}])
        self.assertEqual(e["data"]["attachments"][0]["format"], "cyclonedx-vex")
        self.assertEqual(len(e["data"]["attachments"][0]["document_sha3"]), 64)
        with self.assertRaises(ValueError):
            lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2", False, "2026-09-01T00:00:00Z"),
                                    attachments=[{"format": "unknown-thing", "document": {}}])


if __name__ == "__main__":
    unittest.main(verbosity=1)
