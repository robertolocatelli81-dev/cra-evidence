"""Second council round (15/09/2026, all five minds: Fable 5.1, Opus 4.8, Sonnet 5, Haiku 4.5, Gemini 3.1 Pro).
Each test was RED on the reviewed code and is GREEN after the named fix; sources re-read for the legal points:
Reg. (EU) 2024/2847 Art. 13(13) and Art. 14(4)(c) (EUR-Lex), ENISA SRP glossary (snapshot in spec/sources)."""
import json, os, re, shutil, sys, tempfile, unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from cra_evidence import ledger as ledger_mod
from cra_evidence.canonical import canonical_bytes, floatfree
from cra_evidence.ledger import Ledger
from cra_evidence.locker import CRAEvidenceLocker
from cra_evidence.longterm import AlgorithmPolicy, LongTermEvidence, Signer, register_algorithm
from cra_evidence.sbom import SBOMComponent, SBOMRecord, components_for_osv, pypi_purl
from cra_evidence.srp_notice import COMMON_FIELDS, INCIDENT_FIELDS, VULN_FIELDS, SRPNotice
from cra_evidence.verify_pack import verify_pack
from cra_evidence.vuln import VulnerabilityRecord, add_months, parse_utc
from cra_evidence import feeds

try:
    from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False

AW = "2026-09-01T00:00:00Z"
BASE = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
        "product_name": "p", "product_version": "1", "awareness_datetime_utc": AW, "cve_id": "CVE-2026-1"}


class TestCouncilR2(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    # Opus B10 — the per-stage rules are DERIVED from the vendored ENISA snapshot, not asserted
    def test_srp_schema_matches_the_vendored_enisa_snapshot(self):
        snap = json.load(open(os.path.join(ROOT, "spec", "sources", "enisa_srp_glossary_20260915.json")))
        rows = [r for r in snap["rows"] if len(r) >= 10 and re.match(r"[vi]?\d+\.", r[0])]
        self.assertEqual(len(rows), 39)
        code = {"Required": "R", "Optional": "O", "N/A": "-", "By default copied from previous step, or updated": "C",
                "Required if such information available": "A"}
        ours = list(COMMON_FIELDS.values()) + list(VULN_FIELDS.values()) + list(INCIDENT_FIELDS.values())
        for r, spec in zip(rows, ours):
            self.assertEqual(spec["stages"], {"early_warning": code[r[7]], "notification": code[r[8]], "final_report": code[r[9]]}, r[1])
        self.assertEqual(VULN_FIELDS["particular_exceptional_circumstances"]["stages"]["notification"], "O")   # not R
        with self.assertRaises(ValueError):   # enum-list now validated (three Art. 16(2) circumstances)
            SRPNotice("vulnerability", "notification", {**BASE, "pec_delay_reason": ["pippo"]})
        SRPNotice("vulnerability", "notification", {**BASE, "pec_delay_reason": ["imminent_high_risk"]})

    # Fable A3 — sidecar signer_id / signed_utc were not covered by the signature
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_sidecar_identity_is_signed(self):
        k = os.path.join(self.d, "k.key"); keygen(k); key = load_key(k)
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); lk.evidence_pack(pack); sign_pack(pack, key, "acme-ci")
        self.assertEqual(verify_pack(pack)["authenticity"], "signed")
        side = json.load(open(sidecar_path(pack))); side["signer_id"] = "TUV Notified Body"; json.dump(side, open(sidecar_path(pack), "w"))
        r = verify_pack(pack); self.assertEqual(r["authenticity"], "FAIL")

    # Fable A2 / Opus A4 — seal chain renewable, key pinned (the log key), identity declared
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_seal_renewal_chain_with_pinned_key(self):
        k = os.path.join(self.d, "k.key"); keygen(k); key = load_key(k)
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        first = lk.seal_longterm("ab" * 32, t=1_800_000_000.0, external_digest=True)
        second = lk.seal_longterm("ab" * 32, t=1_900_000_000.0, previous=first, external_digest=True)
        lte = LongTermEvidence.from_dict(second); self.assertEqual(len(lte.records), 2)
        self.assertFalse(lte.records[0]["ephemeral_key"]); self.assertEqual(lte.records[0]["pub"], key[1])
        v = lte.verify(now=1_950_000_000.0, timestamp_trust_fn=lambda r: True, trusted_pubs={key[1]})
        self.assertTrue(v["ok"], v)
        self.assertFalse(lte.verify(now=1_950_000_000.0, timestamp_trust_fn=lambda r: True, trusted_pubs={"00" * 32})["ok"])
        self.assertFalse(lte.verify(now=1_950_000_000.0)["ok"])          # renewal on UNVERIFIED times is not ok
        with self.assertRaises(ValueError):
            lk.seal_longterm("cd" * 32, previous=first, external_digest=True)   # previous seal over another digest
        with self.assertRaises(ValueError):                                     # label without token
            lk.seal_longterm("ab" * 32, ts_source="rfc3161", external_digest=True)

    # Sonnet A5 — default policy is NIST IR 8547, never "valid forever"
    def test_default_policy_is_time_bounded(self):
        register_algorithm("test-plain2", gen=lambda: ("sk", "pk"), sign=lambda sk, m: m.hex(), verify=lambda pub, sig, m: sig == m.hex())
        lte = LongTermEvidence("ab" * 32); lte.seal(Signer("test-plain2"), t=1.0)
        v = lte.verify(now=2.0)
        self.assertIn("NOT bounded", v["policy_note"])
        self.assertTrue(AlgorithmPolicy.nist_ir_8547().broken_after["ed25519"] > 2_000_000_000)

    # Fable A6 / Opus A2 / Sonnet A3 — no lock → refuse to append (fail-closed), unless declared
    def test_append_without_lock_is_refused(self):
        p = os.path.join(self.d, "l.jsonl"); old = ledger_mod._lock; ledger_mod._lock = lambda f: False
        try:
            with self.assertRaises(RuntimeError):
                Ledger(p).append({"k": 1})
            Ledger(p, allow_unlocked=True).append({"k": 1})
        finally:
            ledger_mod._lock = old

    # Fable A5 — hostile input is a verdict, never a crash
    def test_hostile_inputs_are_verdicts(self):
        p = os.path.join(self.d, "l.jsonl"); Ledger(p).append({"k": 1})
        with open(p, "a") as f:
            f.write('{"idx": 1, "ts": "x", "prev_hash": "y", "data": {"x": NaN}, "self_hash": "z"}\n')
        self.assertFalse(Ledger(p).verify()["chain_ok"])
        pack = os.path.join(self.d, "p.json"); open(pack, "w").write("[]")
        r = verify_pack(pack); self.assertFalse(r["ok"]); self.assertEqual(r["authenticity"], "FAIL")
        with self.assertRaises(TypeError):
            floatfree({"cvss": float("nan")})
        with self.assertRaises(TypeError):
            canonical_bytes({"n": 2 ** 63})
        with self.assertRaises(TypeError):
            canonical_bytes({"s": "\ud800"})

    # Fable A1 / Sonnet A2 — a pack over a broken chain is refused; and a shipped pack's own snapshot is checked
    def test_pack_refused_on_broken_chain_and_self_snapshot_checked(self):
        p = os.path.join(self.d, "l.jsonl"); lk = CRAEvidenceLocker(p, "p", "1")
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        lines = open(p).read().splitlines(); e = json.loads(lines[0]); e["data"]["kind"] = "cra_vulnX"
        open(p, "w").write(json.dumps(e) + "\n")
        with self.assertRaises(ValueError):
            lk.evidence_pack(os.path.join(self.d, "p.json"))
        # a pack whose own verification snapshot says chain_ok:false must FAIL even without the ledger
        lk2 = CRAEvidenceLocker(os.path.join(self.d, "l2.jsonl"), "p", "1"); lk2.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p2.json"); pk = lk2.evidence_pack(pack)
        pk["verification"]["chain_ok"] = False; pk.pop("pack_sha3"); pk["pack_sha3"] = __import__("cra_evidence.canonical", fromlist=["sha3_hex"]).sha3_hex(pk)
        alone = os.path.join(self.d, "alone", "p2.json"); os.makedirs(os.path.dirname(alone)); json.dump(pk, open(alone, "w"))
        r = verify_pack(alone); self.assertFalse(r["ok"]); self.assertIn("pack-self-verification", [l["layer"] for l in r["layers"] if l["status"] == "FAIL"])

    # Fable A7 — declared ledger state is checked against the ledger
    def test_pack_ledger_state_is_checked(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1"); lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); pk = lk.evidence_pack(pack); self.assertTrue(verify_pack(pack)["ok"])
        from cra_evidence.canonical import sha3_hex
        pk["ledger_entries"] = 999999; pk.pop("pack_sha3"); pk["pack_sha3"] = sha3_hex(pk); json.dump(pk, open(pack, "w"))
        r = verify_pack(pack)     # anchor no longer matches this digest either: FAIL, and the state layer names it
        self.assertFalse(r["ok"])

    # Fable A4 — a truncated tail AFTER the anchor is seen through the signed tip when the log key is trusted
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_truncated_tail_seen_through_signed_tip(self):
        k = os.path.join(self.d, "k.key"); keygen(k); key = load_key(k)
        p = os.path.join(self.d, "l.jsonl"); lk = CRAEvidenceLocker(p, "p", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); lk.evidence_pack(pack)
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2", True, AW))     # the inconvenient record after the anchor
        self.assertTrue(verify_pack(pack, log_pubkey_hex=key[1])["ok"])
        lines = open(p).read().splitlines(); open(p, "w").write("\n".join(lines[:-1]) + "\n")
        self.assertTrue(verify_pack(pack)["ok"])                                  # without the key: undetectable, and SKIP says so
        self.assertIn("SKIP", [l["status"] for l in verify_pack(pack)["layers"] if l["layer"] == "signed-tip"])
        r = verify_pack(pack, log_pubkey_hex=key[1]); self.assertFalse(r["ok"])
        self.assertIn("signed-tip", [l["layer"] for l in r["layers"] if l["status"] == "FAIL"])

    # Fable A9 — a trust store demanded and no signature → FAIL; explicit ledger path honoured
    def test_trust_store_requires_a_signature(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1"); lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW))
        pack = os.path.join(self.d, "p.json"); lk.evidence_pack(pack)
        self.assertTrue(verify_pack(pack)["ok"]); self.assertFalse(verify_pack(pack, trust_store={"x": "00" * 32})["ok"])
        moved = os.path.join(self.d, "elsewhere", "p.json"); os.makedirs(os.path.dirname(moved)); shutil.copy(pack, moved)
        self.assertFalse(verify_pack(moved)["anchored"]); self.assertTrue(verify_pack(moved, ledger_path=os.path.join(self.d, "l.jsonl"))["anchored"])

    # Sonnet B2 — the notice cannot carry a different awareness than the vulnerability record it refers to
    def test_notice_awareness_bound_to_vuln_record(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2026-1", True, AW))
        with self.assertRaises(ValueError):
            lk.record_notice(SRPNotice("vulnerability", "early_warning", {**BASE, "awareness_datetime_utc": "2026-09-14T00:00:00Z"}))
        e = lk.record_notice(SRPNotice("vulnerability", "early_warning", dict(BASE)))
        self.assertEqual(len(e["data"]["bound_vuln_records"]), 1)
        lk.record_notice(SRPNotice("vulnerability", "early_warning", {**BASE, "awareness_datetime_utc": "2026-09-14T00:00:00Z"}),
                         divergence_reason="awareness corrected after forensic review; see ticket 42")

    # Fable B5 / Opus B5 — calendar month, anchored to the submission; Fable B7 — naive instants refused
    def test_calendar_month_and_strict_timezone(self):
        self.assertEqual(add_months(parse_utc("2026-01-31T10:00:00Z"), 1).isoformat(), "2026-02-28T10:00:00+00:00")
        self.assertEqual(add_months(parse_utc("2028-01-31T10:00:00Z"), 1).isoformat(), "2028-02-29T10:00:00+00:00")
        with self.assertRaises(ValueError):
            parse_utc("2026-09-12T10:00:00")
        self.assertEqual(parse_utc("2026-09-12T10:00:00+0200").isoformat(), "2026-09-12T08:00:00+00:00")
        with self.assertRaises(ValueError):
            VulnerabilityRecord("p", "x", True, AW, status="aare")

    # Fable B3 / Opus B3 — the CycloneDX export validates against the official 1.6 schema (root is strict)
    def test_cyclonedx_export_is_schema_valid(self):
        try:
            import jsonschema
            from referencing import Registry, Resource
        except ImportError:
            self.skipTest("jsonschema not installed")
        sd = os.path.join(ROOT, "spec", "schemas")
        bom = json.load(open(os.path.join(sd, "bom-1.6.schema.json")))
        reg = Registry().with_resources([(name, Resource.from_contents(json.load(open(os.path.join(sd, name)))))
                                         for name in ("spdx.schema.json", "jsf-0.82.schema.json")])
        doc = SBOMRecord("p", "1", [SBOMComponent("a", "1", purl=pypi_purl("A_b.c", "1"), license="MIT", sha256="ab" * 32)]).to_cyclonedx_min()
        jsonschema.Draft7Validator(bom, registry=reg).validate(doc)
        self.assertEqual(doc["components"][0]["purl"], "pkg:pypi/a-b-c@1")
        self.assertNotIn("sbom_sha3", doc); self.assertTrue(any(p["name"] == "cra-evidence:sbom_sha3" for p in doc["metadata"]["properties"]))

    # Fable B2 / Opus B4 — OSV results aligned with the INPUT list, aliases included; ecosystems mapped from purls
    def test_osv_alignment_aliases_and_ecosystem_mapping(self):
        def fake_post(url, body, timeout):
            return {"results": [{"vulns": [{"id": "GHSA-x", "aliases": ["CVE-2020-25659"]}]} for _ in body["queries"]]}
        old = feeds._post_json; feeds._post_json = fake_post
        try:
            r = feeds.osv_query_batch([{"name": "a", "version": "NOT-INSTALLED"}, {"name": "b", "version": "1.0"}])
        finally:
            feeds._post_json = old
        self.assertIsNone(r["results"][0]); self.assertIn("CVE-2020-25659", r["results"][1]); self.assertIn("b@1.0", r["by_component"])
        rec = SBOMRecord("p", "1", [SBOMComponent("left-pad", "1", purl="pkg:npm/left-pad@1"), SBOMComponent("x", "1", purl="pkg:deb/x@1")])
        eco = {c["name"]: c["ecosystem"] for c in components_for_osv(rec)}
        self.assertEqual(eco["left-pad"], "npm"); self.assertEqual(eco["x"], "")

    # Sonnet B3 / B5 — KEV/EUVD positive control, case-insensitive signal
    def test_kev_positive_control_and_case(self):
        old = feeds._get_json; feeds._get_json = lambda url, timeout: {"catalogVersion": "x", "vulnerabilities": [{"cveID": "CVE-1"}]}
        try:
            self.assertIsNotNone(feeds.cisa_kev_ids()["error"])
            feeds._get_json = lambda url, timeout: {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "cve-1"}]}
            k = feeds.cisa_kev_ids(); self.assertIsNone(k["error"])
        finally:
            feeds._get_json = old
        s = feeds.exploitation_signal(["cve-2021-44228"], k, None); self.assertIn("cve-2021-44228", s["actively_exploited"])

    # found while testing r2: the record's `kind` field shadowed the ledger kind "cra_vuln" → binding silently skipped
    def test_vuln_record_kind_not_shadowed(self):
        lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        e = lk.record_vulnerability(VulnerabilityRecord("p", "CVE-1", False, AW, kind="incident"))
        self.assertEqual(e["data"]["kind"], "cra_vuln"); self.assertEqual(e["data"]["event_kind"], "incident")
        self.assertEqual(lk.verify()["records_checked"], 1)

    # Fable B6 — exit codes: overdue → 1
    def test_cli_vuln_exit_code_on_overdue(self):
        from cra_evidence.cli import main
        led = os.path.join(self.d, "l.jsonl")
        rc = main(["vuln", "--ledger", led, "--product", "p", "--version", "1", "--id", "CVE-1", "--aware", "2026-01-01T00:00:00Z", "--exploited"])
        self.assertEqual(rc, 1)
        rc = main(["vuln", "--ledger", led, "--product", "p", "--version", "1", "--id", "CVE-1", "--aware", "2026-01-01T00:00:00Z", "--exploited",
                   "--ew-sent", "2026-01-01T10:00:00Z", "--notified", "2026-01-02T00:00:00Z", "--final-sent", "2026-01-20T00:00:00Z", "--fix-available", "2026-01-10T00:00:00Z"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
