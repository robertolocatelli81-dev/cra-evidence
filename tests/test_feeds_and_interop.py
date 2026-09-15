import importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import feeds


class TestFeedsOffline(unittest.TestCase):
    def test_degrade_is_explicit(self):
        real = feeds._post_json
        feeds._post_json = lambda *a, **k: (_ for _ in ()).throw(OSError("no network"))
        try:
            r = feeds.osv_query_batch([{"name": "x", "version": "1"}]); self.assertIsNotNone(r["error"]); self.assertEqual(r["results"], [])
            self.assertFalse(feeds.osv_positive_control()["ok"])
        finally:
            feeds._post_json = real
        s = feeds.exploitation_signal(["CVE-1"], {"ids": {"CVE-1"}, "error": None}, {"ids": set(), "error": "x"})
        self.assertEqual(s["actively_exploited"], {"CVE-1": ["cisa_kev"]}); self.assertFalse(s["sources_loaded"]["enisa_euvd"])

    @unittest.skipUnless(os.environ.get("CRA_LIVE_FEEDS") == "1", "set CRA_LIVE_FEEDS=1 for the live positive control")
    def test_live_positive_control(self):
        self.assertTrue(feeds.osv_positive_control()["ok"])
        self.assertGreater(feeds.cisa_kev_ids()["count"], 1000)


@unittest.skipUnless(importlib.util.find_spec("verifier") is not None, "cryptovalid-opencore not installed")
class TestInteropCryptovalid(unittest.TestCase):
    """A ledger written here must verify with the INDEPENDENT cryptovalid reference (pip install the wheel)."""
    def test_cryptovalid_verifies_our_ledger_and_tip(self):
        import verifier
        from cra_evidence import CRAEvidenceLocker, SBOMComponent, SBOMRecord
        d = tempfile.mkdtemp(); led = os.path.join(d, "l.jsonl")
        key = None
        if importlib.util.find_spec("cryptography"):
            from cra_evidence.signing import keygen, load_key
            keygen(os.path.join(d, "k")); key = load_key(os.path.join(d, "k"))
        lk = CRAEvidenceLocker(led, "p", "1", tip_key=key)
        for i in range(5):
            lk.record_sbom(SBOMRecord("p", "1", [SBOMComponent(f"c{i}", "1")]))
        r = verifier.verify_ledger(led); self.assertEqual(r["verdict"], "PASS", r.get("parse_errors"))
        if key is not None and hasattr(verifier, "verify_ledger") and "trusted_pubkey_hex" in verifier.verify_ledger.__code__.co_varnames:
            r2 = verifier.verify_ledger(led, trusted_pubkey_hex=key[1], require_tip=True); self.assertEqual(r2["verdict"], "PASS", r2.get("parse_errors"))
            lines = open(led).read().split("\n"); open(led, "w").write("\n".join(lines[:-2]) + "\n")
            self.assertEqual(verifier.verify_ledger(led, trusted_pubkey_hex=key[1])["verdict"], "FAIL")   # truncation seen via the tip
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
