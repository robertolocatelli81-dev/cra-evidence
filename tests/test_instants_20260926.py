"""26/09/2026: signed_utc (and the ledger tip's ts) were checked by a regular expression only, so a signature dated
2026-02-30, 25:61:61 or month 13 verified PASS in all four verifiers (measured). An instant must exist."""
import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import signing as S

PACK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "self_evidence", "cra_pack.json")


class Instants(unittest.TestCase):
    def test_instant_rule(self):
        for s in ("2026-09-26T10:00:00Z", "2024-02-29T23:59:59.123+05:30", "0001-01-01T00:00:00-23:59"):
            self.assertTrue(S.is_instant(s), s)
        for s in ("2026-02-30T10:00:00Z", "2025-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z",
                  "2026-09-26T24:00:00Z", "2026-09-26T10:60:00Z", "2026-09-26T10:00:60Z", "2026-09-26T10:00:00+24:00",
                  "2026-09-26T10:00:00+05:60", "2026-09-00T10:00:00Z", "2026-9-26T10:00:00Z", 5, None):
            self.assertFalse(S.is_instant(s), s)

    def test_a_signature_dated_on_a_day_that_does_not_exist_fails(self):
        with tempfile.TemporaryDirectory() as d:
            S.keygen(os.path.join(d, "k.json")); key = S.load_key(os.path.join(d, "k.json"))
            p = os.path.join(d, "p.json"); shutil.copy(PACK, p)
            S.sign_pack(p, key, "test-signer")
            side = json.load(open(S.sidecar_path(p))); side["signed_utc"] = "2026-02-30T10:00:00+00:00"
            side["signature_hex"] = key[0].sign(S.signed_payload(side)).hex()
            json.dump(side, open(S.sidecar_path(p), "w"))
            self.assertEqual(S.verify_pack_signature(p)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
