# SPDX-License-Identifier: AGPL-3.0-or-later
"""0.6.0 review (19/10/2026): (1) a product placed before 11 December 2027 and not substantially modified from that date
is not subject to Art. 13 (Art. 69(2)) — its support period is never a finding; (2) the basis text of a product placed
between the two readings of 11 December 2027; (3) without `cryptography`, a tip or a sidecar that is malformed is judged
(`tip_invalid`, `sidecar_malformed`), only the signature itself is `instrument_failure`. Every test here fails on f2b3062."""
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
AP = importlib.import_module("cra_evidence.applicability")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def cli(args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "CRA_VERIFY_INJECT_FAULT")}
    env["PYTHONPATH"] = ROOT
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-B", "-m", "cra_evidence.cli"] + args, capture_output=True, text=True, env=env)


class TestObligationsLegacyScope(unittest.TestCase):
    def test_legacy_product_short_support_is_not_a_finding(self):
        p = cli(["obligations", "--placed-on-market", "2025-03-01T00:00:00Z", "--support-period-end", "2027-03-01T00:00:00Z"])
        self.assertEqual(p.returncode, 0, p.stdout[-400:])
        r = json.loads(p.stdout)
        self.assertEqual(r["legacy_scope"]["outcome"], "requirements_do_not_apply")
        self.assertEqual(r["support_period"]["status"], "below_minimum")        # computed, still shown
        self.assertIs(r["support_period"]["requirements_apply"], False)
        self.assertIs(r["retention"]["requirements_apply"], False)

    def test_new_product_short_support_is_a_finding(self):   # positive control: the same period on a product placed in 2028
        p = cli(["obligations", "--placed-on-market", "2028-03-01T00:00:00Z", "--support-period-end", "2030-03-01T00:00:00Z"])
        self.assertEqual(p.returncode, 1, p.stdout[-400:])
        self.assertIs(json.loads(p.stdout)["support_period"]["requirements_apply"], True)

    def test_legacy_product_substantially_modified_is_a_finding(self):
        p = cli(["obligations", "--placed-on-market", "2025-03-01T00:00:00Z", "--substantially-modified", "2028-01-01T00:00:00Z",
                 "--support-period-end", "2027-03-01T00:00:00Z"])
        self.assertEqual(p.returncode, 1, p.stdout[-400:])

    def test_placed_between_readings_below_minimum_only_under_brussels_reading(self):
        # placed 23:30Z on 10/12/2027: requirements apply under Brussels only; a short period is a finding there (exit 1)
        p = cli(["obligations", "--placed-on-market", "2027-12-10T23:30:00Z", "--support-period-end", "2029-01-01T00:00:00Z"])
        self.assertEqual(p.returncode, 1, p.stdout[-400:])
        self.assertIsNone(json.loads(p.stdout)["support_period"]["requirements_apply"])

    def test_update_without_placing_says_not_known(self):
        p = cli(["obligations", "--update-issued", "2026-10-01T00:00:00Z"])
        self.assertEqual(p.returncode, 0)
        self.assertIsNone(json.loads(p.stdout)["update_availability"]["requirements_apply"])

    def test_basis_of_a_product_placed_between_the_readings_and_modified(self):
        r = AP.legacy_product_scope("2027-12-10T23:30:00Z", "2028-01-05T00:00:00Z")
        self.assertEqual(r["outcome"], "requirements_apply")
        self.assertIn("10 December under the UTC reading", r["basis"])
        r = AP.legacy_product_scope("2027-12-11T00:00:00Z")
        self.assertEqual(r["basis"], "placed on the market from 11 December 2027: the Regulation applies (Art. 71(2))")


@unittest.skipUnless(HAVE_CRYPTO, "the bases are signed: needs cryptography")
class TestNoCryptoJudgesWhatNeedsNoLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import states_bench
        cls.work = tempfile.mkdtemp(prefix="cra-review-")
        cls.bases = states_bench.build_bases(cls.work)
        cls.block = os.path.join(cls.work, "block"); os.makedirs(os.path.join(cls.block, "cryptography"))
        with open(os.path.join(cls.block, "cryptography", "__init__.py"), "w") as f:
            f.write("raise ImportError('blocked by the test')\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def copy(self):
        d = tempfile.mkdtemp(prefix="c", dir=self.work)
        shutil.rmtree(d); shutil.copytree(self.bases["full"]["dir"], d)
        return d, os.path.join(d, "cra_pack.json")

    def nocrypto(self, args):
        return cli(args, {"PYTHONPATH": self.block + os.pathsep + ROOT})

    def test_garbage_tip_is_tip_invalid_exit_1(self):
        d, pack = self.copy()
        os.remove(pack + ".sig.json")
        with open(os.path.join(d, "cra.ledger.jsonl.tip.json"), "w") as f:
            f.write("{}")
        p = self.nocrypto(["verify", pack, "--log-pubkey", self.bases["full"]["log"]])
        self.assertEqual(p.returncode, 1, p.stdout[-500:])
        r = json.loads(p.stdout)
        self.assertTrue(r["assessed"])
        self.assertEqual(r["states"]["signed_tip"], {"state": "contradicted", "reasons": ["tip_invalid"]})

    def test_well_formed_tip_stays_instrument_failure_exit_77(self):   # control: the declared case is untouched
        d, pack = self.copy()
        os.remove(pack + ".sig.json")
        p = self.nocrypto(["verify", pack, "--log-pubkey", self.bases["full"]["log"]])
        self.assertEqual(p.returncode, 77, p.stdout[-500:])

    def test_sidecar_without_signature_is_sidecar_malformed_exit_1(self):
        d, pack = self.copy()
        sp = pack + ".sig.json"
        with open(sp, encoding="utf-8") as f:
            s = json.load(f)
        del s["signature_hex"]
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(s, f)
        p = self.nocrypto(["verify", pack])
        self.assertEqual(p.returncode, 1, p.stdout[-500:])
        r = json.loads(p.stdout)
        self.assertEqual(r["states"]["producer_signature"], {"state": "contradicted", "reasons": ["sidecar_malformed"]})

    def test_well_formed_sidecar_stays_instrument_failure_exit_77(self):
        d, pack = self.copy()
        os.remove(os.path.join(d, "cra.ledger.jsonl.tip.json"))
        p = self.nocrypto(["verify", pack])
        self.assertEqual(p.returncode, 77, p.stdout[-500:])
        self.assertEqual(json.loads(p.stdout)["states"]["producer_signature"]["reasons"], ["instrument_failure"])


if __name__ == "__main__":
    unittest.main()
