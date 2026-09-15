"""Third council round (15/09/2026, five minds on the twice-corrected code). RED before each fix, GREEN after."""
import json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.canonical import canonical_bytes
from cra_evidence.ledger import Ledger
from cra_evidence.locker import CRAEvidenceLocker
from cra_evidence.longterm import AlgorithmPolicy, LongTermEvidence, Signer, register_algorithm
from cra_evidence.sbom import SBOMComponent, SBOMRecord, is_spdx_id, sbom_from_installed
from cra_evidence.srp_notice import SRPNotice
from cra_evidence.verify_pack import verify_pack
from cra_evidence.vuln import VulnerabilityRecord
from cra_evidence import feeds

try:
    from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False

AW = "2026-09-01T00:00:00Z"
BASE = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
        "product_name": "p", "product_version": "1", "awareness_datetime_utc": AW, "cve_id": "CVE-2026-1"}
register_algorithm("test-plain3", gen=lambda: ("sk", "pk"), sign=lambda sk, m: m.hex(), verify=lambda pub, sig, m: sig == m.hex())


class TestCouncilR3(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    # Fable/Opus/Gemini/Sonnet A1 — the outer seal's own fields are signed: any mutation breaks it
    def test_outer_seal_fields_are_signed(self):
        lte = LongTermEvidence("ab" * 32); lte.seal(Signer("test-plain3"), t=1.0)
        self.assertTrue(lte.verify(now=2.0, policy=AlgorithmPolicy())["ok"])
        for k, v in (("t", "0.5"), ("ts_source", "rfc3161"), ("ephemeral_key", False), ("token_sha3", "00" * 32), ("pub", "other")):
            bad = LongTermEvidence.from_dict(json.loads(json.dumps(lte.to_dict()))); bad.records[-1][k] = v
            self.assertFalse(bad.verify(now=2.0, policy=AlgorithmPolicy())["ok"], k)

    # A: hash policy enforced on intermediate records and in renewal_due; malformed records are verdicts
    def test_hash_policy_everywhere_and_malformed_records(self):
        lte = LongTermEvidence("ab" * 32); lte.seal(Signer("test-plain3"), t=1.0, hash_alg="sha2-512"); lte.seal(Signer("test-plain3"), t=5.0)
        pol = AlgorithmPolicy({"sha2-512": 3.0})
        v = lte.verify(now=6.0, policy=pol, timestamp_trust_fn=lambda r: True)
        self.assertFalse(v["ok"]); self.assertTrue(any("hash already broken" in r for r in v["reasons"]))
        one = LongTermEvidence("ab" * 32); one.seal(Signer("test-plain3"), t=1.0, hash_alg="sha2-512")
        self.assertTrue(one.renewal_due(now=2.9, policy=AlgorithmPolicy({"sha2-512": 3.0, "test-plain3": 100.0}), margin=0.5)["due"])
        bad = LongTermEvidence("ab" * 32, records=[{"alg": "test-plain3", "pub": "pk", "sig": "00", "t": "abc"}])
        self.assertFalse(bad.verify(now=2.0)["ok"])
        self.assertFalse(LongTermEvidence("ab" * 32, records=[{"alg": "x"}]).verify(now=2.0)["ok"])

    # A2 — surrogate keys refused like values; A4 — duplicate keys refused on read
    def test_surrogate_keys_and_duplicate_keys(self):
        with self.assertRaises(TypeError):
            canonical_bytes({"\ud800": 1})
        p = os.path.join(self.d, "l.jsonl"); Ledger(p).append({"k": 1})
        line = open(p).read().rstrip("\n"); dup = line[:-1] + ',"data":{"k":"evil"}}'
        open(p, "w").write(dup + "\n")
        v = Ledger(p).verify(); self.assertFalse(v["chain_ok"]); self.assertTrue(any("duplicate key" in f for f in v["failures"]))

    # A3 — fingerprint recomputed
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_fingerprint_is_recomputed(self):
        k = os.path.join(self.d, "k.key"); keygen(k); key = load_key(k)
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1"); lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); lk.evidence_pack(pack); sign_pack(pack, key, "acme")
        side = json.load(open(sidecar_path(pack))); side["fingerprint"] = "0123456789abcdef"; json.dump(side, open(sidecar_path(pack), "w"))
        self.assertEqual(verify_pack(pack)["authenticity"], "FAIL")

    # B1 — a required ledger that is missing is a FAIL, not a skip
    def test_required_ledger_missing_is_fail(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1"); lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); lk.evidence_pack(pack)
        os.remove(os.path.join(self.d, "l.jsonl"))
        self.assertFalse(verify_pack(pack, log_pubkey_hex="00" * 32)["ok"])
        self.assertFalse(verify_pack(pack, ledger_path=os.path.join(self.d, "nowhere.jsonl"))["ok"])
        r = verify_pack(pack); self.assertEqual(r["authenticity"], "FAIL")   # unsigned + no ledger = nothing to trust

    # B3/B4 — binding: latest record wins, ids stripped, product must match, absent awareness refused when bound
    def test_binding_latest_record_strip_and_product(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        lk.record_vulnerability(VulnerabilityRecord("p", " CVE-2026-1 ", True, "2026-08-01T00:00:00Z"))   # superseded
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2026-1", True, AW))                       # current
        e = lk.record_notice(SRPNotice("vulnerability", "early_warning", dict(BASE))); self.assertEqual(len(e["data"]["bound_vuln_records"]), 1)
        with self.assertRaises(ValueError):
            lk.record_notice(SRPNotice("vulnerability", "final_report", {**BASE, "awareness_datetime_utc": None}))
        with self.assertRaises(ValueError):
            lk.record_vulnerability(VulnerabilityRecord("OTHER", "CVE-9", False, AW))

    # B5/B6 — seal only anchored digests by default; pack appears only once anchored
    def test_seal_requires_anchor_and_pack_is_atomic(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1"); lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        with self.assertRaises(ValueError):
            lk.seal_longterm("ab" * 32)
        pack = os.path.join(self.d, "p.json"); pk = lk.evidence_pack(pack)
        lk.seal_longterm(pk["pack_sha3"], t=1_800_000_000.0)
        with self.assertRaises(ValueError):
            lk.seal_longterm("zz" * 32, external_digest=True)
        lk.ledger.append = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        with self.assertRaises(OSError):
            lk.evidence_pack(os.path.join(self.d, "p2.json"))
        self.assertFalse(os.path.exists(os.path.join(self.d, "p2.json"))); self.assertFalse(os.path.exists(os.path.join(self.d, "p2.json.tmp")))

    # C1 — incident final report in the notice is never invented (test_records covers the None); C4 — carried fields
    def test_carried_fields_from_previous_payload(self):
        alone = SRPNotice("vulnerability", "notification", {"awareness_datetime_utc": AW, "general_information": "x"})
        self.assertIn("title", alone.missing()); self.assertFalse(alone.complete())
        prev = dict(BASE)
        n = SRPNotice("vulnerability", "notification", {"general_information": "x"}, previous_fields=prev)
        self.assertEqual(n.fields["title"], "t"); self.assertEqual(n.fields["awareness_datetime_utc"], AW); self.assertTrue(n.complete(), n.missing())
        self.assertEqual(n.deadline_utc(), "2026-09-04T00:00:00+00:00")

    # C2 — aliases resolved per id (querybatch is condensed); positive control demands a CVE alias
    def test_osv_aliases_resolved_and_control(self):
        calls = []
        def fake_post(url, body, timeout):
            return {"results": [{"vulns": [{"id": "GHSA-1"}]} for _ in body["queries"]]}
        def fake_get(url, timeout):
            calls.append(url); return {"id": "GHSA-1", "aliases": ["CVE-2020-25659"]}
        oldp, oldg = feeds._post_json, feeds._get_json; feeds._post_json, feeds._get_json = fake_post, fake_get
        try:
            r = feeds.osv_query_batch([{"name": "a", "version": "1"}, {"name": "b", "version": "2"}])
            n_after_batch = len(calls)
            pc = feeds.osv_positive_control()
        finally:
            feeds._post_json, feeds._get_json = oldp, oldg
        self.assertIn("CVE-2020-25659", r["results"][0]); self.assertEqual(n_after_batch, 1)   # cached across components
        self.assertTrue(pc["ok"])
        feeds._get_json = lambda url, timeout: {"id": "GHSA-1", "aliases": []}; feeds._post_json = fake_post
        try:
            self.assertFalse(feeds.osv_positive_control()["ok"])   # ids but no CVE alias → the control does not pass
        finally:
            feeds._post_json, feeds._get_json = oldp, oldg

    # C3 — free-text licences go to name, SPDX ids to id
    def test_licence_id_vs_name(self):
        self.assertTrue(is_spdx_id("MIT")); self.assertFalse(is_spdx_id("Apache Software License"))
        doc = SBOMRecord("p", "1", [SBOMComponent("a", "1", license="Apache Software License"), SBOMComponent("b", "1", license="MIT")]).to_cyclonedx_min()
        lic = {c["name"]: c["licenses"][0]["license"] for c in doc["components"]}
        self.assertEqual(lic["a"], {"name": "Apache Software License"}); self.assertEqual(lic["b"], {"id": "MIT"})

    # C5 — the floor is not met by NOT-INSTALLED phantoms
    def test_floor_ignores_phantom_components(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        e = lk.record_sbom(sbom_from_installed("p", "1", ["package-that-does-not-exist-xyz"]))
        self.assertFalse(e["data"]["sbom_floor_met"]); self.assertEqual(e["data"]["resolved_components"], 0)

    # C6 — EUVD aliases joined by newlines
    def test_euvd_newline_aliases(self):
        old = feeds._get_json
        feeds._get_json = lambda url, timeout: {"items": [{"id": "EUVD-1", "aliases": "CVE-2021-44228\nCVE-2026-9"}]}
        try:
            r = feeds.euvd_kev_ids()
        finally:
            feeds._get_json = old
        self.assertIsNone(r["error"]); self.assertIn("CVE-2026-9", r["ids"])

    # Opus/Sonnet C — a feed-confirmed exploitation sets the clock; C8 — schema template feeds `cra notice`
    def test_cli_feed_confirmation_sets_exploited_and_template(self):
        from cra_evidence.cli import main
        oldk = feeds.cisa_kev_ids
        feeds.cisa_kev_ids = lambda timeout=60: {"ids": {"CVE-2021-44228"}, "count": 1, "error": None}
        led = os.path.join(self.d, "l.jsonl")
        try:
            rc = main(["vuln", "--ledger", led, "--product", "p", "--version", "1", "--id", "CVE-2021-44228", "--aware", "2026-01-01T00:00:00Z", "--source", "cisa_kev"])
        finally:
            feeds.cisa_kev_ids = oldk
        self.assertEqual(rc, 1)   # exploited (forced) and overdue → 1
        d = [json.loads(l)["data"] for l in open(led)][-1]; self.assertTrue(d["actively_exploited"])
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["schema", "--stream", "vulnerability", "--template", "early_warning"])
        t = json.loads(buf.getvalue()); self.assertIn("title", t); self.assertNotIn("attack_vector", t)


if __name__ == "__main__":
    unittest.main(verbosity=1)
