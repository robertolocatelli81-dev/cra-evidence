import importlib.util, json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import CRAEvidenceLocker, SBOMComponent, SBOMRecord, SRPNotice, DryRunDrop, VulnerabilityRecord, verify_pack
from cra_evidence.longterm import AlgorithmPolicy, LongTermEvidence, Signer
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
AW = "2026-09-12T08:00:00Z"


class TestLockerPack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.led = os.path.join(self.d, "cra.ledger.jsonl"); self.pack = os.path.join(self.d, "cra_pack.json")
        self.lk = CRAEvidenceLocker(self.led, "prod", "1.0")
        self.lk.record_sbom(SBOMRecord("prod", "1.0", [SBOMComponent("a", "1")]))
        self.lk.record_vulnerability(VulnerabilityRecord("prod", "CVE-2026-1", True, AW))
        n = SRPNotice("vulnerability", "early_warning", {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m",
                                                          "member_states_available": ["IT"], "product_name": "prod", "product_version": "1.0", "awareness_datetime_utc": AW})
        self.lk.record_notice(n, DryRunDrop(os.path.join(self.d, "drop")).prepare(n))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_pack_anchored_and_verifies_offline(self):
        pk = self.lk.evidence_pack(self.pack)
        self.assertTrue(pk["verification"]["chain_ok"]); self.assertIn("NOT a conformity assessment", pk["honest_scope"])
        r = verify_pack(self.pack); self.assertTrue(r["ok"], r); self.assertEqual(r["authenticity"], "anchored")

    def test_positive_controls_every_tamper_fails(self):
        self.lk.evidence_pack(self.pack)
        # (a) pack field changed
        p = json.load(open(self.pack)); p["product_version"] = "9"; json.dump(p, open(self.pack, "w"))
        self.assertFalse(verify_pack(self.pack)["ok"])
        # (b) ledger record content changed with stale record_sha3 (content-binding)
        self.lk.evidence_pack(self.pack)
        lines = open(self.led).read().split("\n"); e = json.loads(lines[0]); e["data"]["component_count"] = 99
        e["self_hash"] = __import__("cra_evidence.ledger", fromlist=["entry_hash"]).entry_hash(e)   # re-chained coherently…
        lines[0] = json.dumps(e, sort_keys=True, separators=(",", ":")); open(self.led, "w").write("\n".join(lines))
        r = verify_pack(self.pack); self.assertFalse(r["ok"])                         # …still caught (chain or binding)
        # (c) pack not anchored: a pack from another ledger
        other = CRAEvidenceLocker(os.path.join(self.d, "o.ledger.jsonl"), "prod", "1.0"); other.record_sbom(SBOMRecord("prod", "1.0", [SBOMComponent("z", "1")]))
        other.evidence_pack(os.path.join(self.d, "o.json"))
        shutil.copy(os.path.join(self.d, "o.json"), self.pack)
        r = verify_pack(self.pack, ledger_path=self.led); self.assertFalse(r["ok"]); self.assertTrue(any("not anchored" in l["detail"] or "FAIL" == l["status"] for l in r["layers"]))

    def test_empty_sbom_does_not_meet_floor(self):
        e = self.lk.record_sbom(SBOMRecord("prod", "1.0", [])); self.assertFalse(e["data"]["sbom_floor_met"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography absent")
    def test_signed_trusted_and_seal(self):
        from cra_evidence.signing import keygen, load_key, sign_pack
        k = os.path.join(self.d, "k"); pk = keygen(k)["public_key_hex"]
        self.lk.evidence_pack(self.pack); sign_pack(self.pack, load_key(k), "acme-ci")
        self.assertEqual(verify_pack(self.pack)["authenticity"], "signed")
        self.assertEqual(verify_pack(self.pack, trust_store={"acme-ci": pk})["authenticity"], "trusted-signed")
        r = verify_pack(self.pack, trust_store={"acme-ci": "00" * 32}); self.assertFalse(r["ok"])   # wrong key pinned → FAIL
        p = json.load(open(self.pack)); p["retention_years"] = 1; p["pack_sha3"] = __import__("cra_evidence.canonical", fromlist=["sha3_hex"]).sha3_hex({k2: v for k2, v in p.items() if k2 != "pack_sha3"})
        json.dump(p, open(self.pack, "w")); self.assertFalse(verify_pack(self.pack)["ok"])          # re-hashed after signing → FAIL
        # long-term seal: valid now, renewal due before the algorithm breaks, tamper detected
        lte = LongTermEvidence("ab" * 32); lte.seal(Signer("ed25519"), t=1_800_000_000.0)
        pol = AlgorithmPolicy({"ed25519": 2_000_000_000.0})
        self.assertTrue(lte.verify(1_900_000_000.0, pol)["ok"]); self.assertTrue(lte.renewal_due(1_990_000_000.0, pol, 20_000_000.0)["due"])
        self.assertFalse(lte.verify(2_100_000_000.0, pol)["ok"])                                    # outer algorithm broken now
        lte.records[0]["rehash"] = "x"; self.assertFalse(lte.verify(1_900_000_000.0, pol)["ok"])
        d = self.lk.seal_longterm("ab" * 32, t=1_800_000_000.0, external_digest=True); self.assertEqual(d["format"], "CRA-LTA-1"); self.assertTrue(self.lk.verify()["chain_ok"])
        with self.assertRaises(ValueError):
            self.lk.seal_longterm("cd" * 32, t=1_800_000_000.0)      # not anchored here → refused by default

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography absent")
    def test_tip_written_and_checked(self):
        from cra_evidence.signing import keygen, load_key, verify_tip
        k = os.path.join(self.d, "k"); pk = keygen(k)["public_key_hex"]
        led = os.path.join(self.d, "t.ledger.jsonl"); lk = CRAEvidenceLocker(led, "prod", "1.0", tip_key=load_key(k))
        for i in range(3):
            lk.record_vulnerability(VulnerabilityRecord("prod", f"CVE-2026-{i}", False, AW))
        tip = json.load(open(led + ".tip.json")); es = list(lk.ledger.entries())
        self.assertTrue(verify_tip(tip, pk, 3, es[0]["self_hash"], es[2]["self_hash"])["ok"])
        self.assertEqual(verify_tip(tip, pk, 2, es[0]["self_hash"], es[1]["self_hash"])["error"], "tail_truncated")




class TestSignedFixtureEveryConfig(unittest.TestCase):
    """a genuinely signed pack (vendored) — with cryptography: trusted-signed; without: FAIL that says NOT checkable, never 'invalid'"""
    FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "signed_pack")

    def _run(self):
        from cra_evidence.verify_pack import verify_pack
        trust = json.load(open(os.path.join(self.FX, "trust.json")))
        return verify_pack(os.path.join(self.FX, "p.json"), trust_store=trust, log_pubkey_hex=trust["fixture-ci"])

    def test_verdict_matches_the_backend_available(self):
        r = self._run()
        sig = next(l for l in r["layers"] if l["layer"] == "producer-signature")
        tip = next(l for l in r["layers"] if l["layer"] == "signed-tip")
        try:
            import cryptography  # noqa: F401
            self.assertEqual(r["authenticity"], "trusted-signed", r["layers"])
            self.assertEqual((sig["status"], tip["status"]), ("PASS", "PASS"))
        except ImportError:
            self.assertFalse(r["ok"])
            self.assertIn("NOT checkable", sig["detail"]); self.assertNotIn("invalid", sig["detail"])
            self.assertIn("tip_unchecked", tip["detail"]); self.assertNotIn("invalid", tip["detail"])

    def test_without_backend_the_reason_is_true(self):
        import sys
        saved = {k: v for k, v in sys.modules.items() if k == "cryptography" or k.startswith("cryptography.")}
        for k in saved:
            sys.modules[k] = None                       # simulate the "none" configuration in any interpreter
        sys.modules["cryptography"] = None
        try:
            r = self._run()
        finally:
            for k in list(sys.modules):
                if k == "cryptography" or k.startswith("cryptography."):
                    del sys.modules[k]
            sys.modules.update(saved)
        self.assertFalse(r["ok"])
        sig = next(l for l in r["layers"] if l["layer"] == "producer-signature")
        self.assertIn("NOT checkable", sig["detail"]); self.assertNotIn("invalid", sig["detail"])


if __name__ == "__main__":
    unittest.main()
