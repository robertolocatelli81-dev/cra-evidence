# SPDX-License-Identifier: AGPL-3.0-or-later
"""0.6.0 receipt (spec/RECEIPT.md): admission, refusal_class, states (cra-evidence/states-1), policy — one test per rule,
then the generative bench (verifiers/states_bench.py) and one sabotage that must turn it red. Every test here fails on
0.5.1 (the fields do not exist there; the tip case exits 1 there)."""
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
VP = importlib.import_module("cra_evidence.verify_pack")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def cli(args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", VP.FAULT_ENV)}
    env["PYTHONPATH"] = ROOT
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-B", "-m", "cra_evidence.cli"] + args, capture_output=True, text=True, env=env)


@unittest.skipUnless(HAVE_CRYPTO, "the bases are signed: needs cryptography")
class TestStates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import states_bench
        cls.work = tempfile.mkdtemp(prefix="cra-states-")
        cls.bases = states_bench.build_bases(cls.work)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def copy(self, name):
        d = tempfile.mkdtemp(prefix="c", dir=self.work)
        shutil.rmtree(d); shutil.copytree(self.bases[name]["dir"], d)
        return d, os.path.join(d, "cra_pack.json")

    def trust(self, name):
        b = self.bases[name]
        return {b["signer"]: b["pub"]}

    def edit_pack(self, pack, **kv):
        with open(pack, encoding="utf-8") as f:
            p = json.load(f)
        for k, v in kv.items():
            if v is KeyError:
                del p[k]
            else:
                p[k] = v
        with open(pack, "w", encoding="utf-8") as f:
            json.dump(p, f)

    def test_intact_full_pack_every_subject_verified(self):
        d, pack = self.copy("full")
        r = VP.verify_pack(pack, trust_store=self.trust("full"), log_pubkey_hex=self.bases["full"]["log"], require_sources=True)
        self.assertTrue(r["ok"])
        self.assertEqual((r["admission"], r["refusal_class"], r["states_vocabulary"]), ("admitted", None, "cra-evidence/states-1"))
        self.assertEqual({s: o["state"] for s, o in r["states"].items()}, {s: "verified" for s in VP.SUBJECTS})
        self.assertEqual(r["policy"], {"met": True, "unmet": []})

    def test_no_trust_store_is_self_asserted_and_a_wrong_one_key_unresolved(self):
        d, pack = self.copy("full")
        r = VP.verify_pack(pack)
        self.assertTrue(r["ok"]); self.assertEqual(r["authenticity"], "signed")
        self.assertEqual(r["states"]["producer_signature"], {"state": "not_evaluated", "reasons": ["self_asserted"]})
        self.assertEqual(r["states"]["signed_tip"], {"state": "not_evaluated", "reasons": ["key_not_given"]})
        r = VP.verify_pack(pack, trust_store={self.bases["full"]["signer"]: "ab" * 32})
        self.assertFalse(r["ok"])
        self.assertEqual(r["states"]["producer_signature"], {"state": "not_evaluated", "reasons": ["key_unresolved"]})
        self.assertEqual(r["policy"], {"met": False, "unmet": ["trusted_signer"]})
        self.assertNotIn("contradicted", {o["state"] for o in r["states"].values()})

    def test_refusal_classes_and_their_order(self):
        cases = [({"kind": "other/1"}, "format_unsupported"), ({"x_unknown": 1}, "unknown_member"),
                 ({"kind": "other/1", "x_unknown": 1}, "format_unsupported"), ({"honest_scope": KeyError}, "malformed"),
                 ({"x_unknown": 1, "honest_scope": 3}, "unknown_member"), ({"ledger_file": "../l"}, "malformed")]
        for kv, cls in cases:
            d, pack = self.copy("full")
            self.edit_pack(pack, **kv)
            r = VP.verify_pack(pack, trust_store=self.trust("full"))
            self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["policy"], r["ok"]), ("refused", cls, None, None, False), kv)
        d, pack = self.copy("full")
        open(pack, "w").write("{\"a\": 1, \"a\": 2}")
        r = VP.verify_pack(pack)
        self.assertEqual((r["admission"], r["refusal_class"]), ("refused", "malformed"))
        p = cli(["verify", pack]); self.assertEqual(p.returncode, 1); self.assertEqual(json.loads(p.stdout)["refusal_class"], "malformed")

    def test_verifier_exception_is_not_evaluated_exit_77(self):
        d, pack = self.copy("full")
        p = cli(["verify", pack], {VP.FAULT_ENV: "1"})
        self.assertEqual(p.returncode, 77)
        r = json.loads(p.stdout)
        self.assertEqual((r["admission"], r["refusal_class"], r["states"], r["policy"], r["assessed"]), ("not_evaluated", None, None, None, False))

    def test_tip_unchecked_without_cryptography_is_instrument_failure_exit_77(self):
        """Declared not-additive change (spec/RECEIPT.md §6): 0.5.1 exited 1 here (a FAIL layer judged against the pack)."""
        d, pack = self.copy("full")
        os.remove(pack + ".sig.json")   # unsigned: the tip is the only check that needs cryptography
        block = os.path.join(d, "block"); os.makedirs(os.path.join(block, "cryptography"))
        open(os.path.join(block, "cryptography", "__init__.py"), "w").write("raise ImportError('blocked by the test')\n")
        p = cli(["verify", pack, "--log-pubkey", self.bases["full"]["log"]], {"PYTHONPATH": block + os.pathsep + ROOT})
        self.assertEqual(p.returncode, 77, p.stdout[-500:])
        r = json.loads(p.stdout)
        self.assertFalse(r["ok"]); self.assertFalse(r["assessed"])
        self.assertEqual(r["states"]["signed_tip"]["reasons"], ["instrument_failure"])
        self.assertEqual(r["states"]["ledger_anchor"]["state"], "verified")
        p = cli(["verify", pack, "--log-pubkey", self.bases["full"]["log"]])
        self.assertEqual(p.returncode, 0, "positive control: with cryptography the same pack verifies")

    def test_required_ledger_absent_tip_absent_sources_hash_only(self):
        d, pack = self.copy("full")
        os.remove(os.path.join(d, "cra.ledger.jsonl.tip.json"))
        src = os.path.join(d, "cra.ledger.jsonl.sources"); [os.remove(os.path.join(src, n)) for n in os.listdir(src)]
        r = VP.verify_pack(pack, trust_store=self.trust("full"), log_pubkey_hex=self.bases["full"]["log"], require_sources=True)
        self.assertFalse(r["ok"])
        self.assertEqual(r["policy"]["unmet"], ["tip_required", "sources_required"])
        self.assertEqual(r["states"]["source_documents"], {"state": "not_evaluated", "reasons": ["hash_only"]})
        os.remove(os.path.join(d, "cra.ledger.jsonl"))
        r = VP.verify_pack(pack, trust_store=self.trust("full"), log_pubkey_hex=self.bases["full"]["log"])
        self.assertEqual(r["policy"]["unmet"], ["ledger_required"])
        self.assertEqual(r["states"]["ledger_anchor"]["reasons"], ["not_present"])
        self.assertEqual(r["states"]["signed_tip"]["reasons"], ["ledger_not_verified"])

    def test_unsigned_unanchored_is_authenticity_basis(self):
        d, pack = self.copy("unsigned")
        os.remove(os.path.join(d, "cra.ledger.jsonl"))
        r = VP.verify_pack(pack)
        self.assertFalse(r["ok"]); self.assertTrue(r["assessed"])
        self.assertEqual(r["policy"], {"met": False, "unmet": ["authenticity_basis"]})
        self.assertNotIn("contradicted", {o["state"] for o in r["states"].values()})

    def test_contradictions_are_named(self):
        d, pack = self.copy("full")
        with open(pack + ".sig.json", encoding="utf-8") as f:
            s = json.load(f)
        s["signature_hex"] = ("0" if s["signature_hex"][0] != "0" else "1") + s["signature_hex"][1:]
        with open(pack + ".sig.json", "w", encoding="utf-8") as f:
            json.dump(s, f)
        with open(os.path.join(d, "cra.ledger.jsonl"), "ab") as f:
            f.write(b"")
        src = os.path.join(d, "cra.ledger.jsonl.sources"); open(os.path.join(src, os.listdir(src)[0]), "ab").write(b" ")
        r = VP.verify_pack(pack, trust_store=self.trust("full"))
        self.assertEqual(r["states"]["producer_signature"], {"state": "contradicted", "reasons": ["signature_invalid"]})
        self.assertEqual(r["states"]["source_documents"], {"state": "contradicted", "reasons": ["source_mismatch"]})
        self.assertTrue(r["assessed"])

    def test_precedence_contradicted_over_not_evaluated(self):
        f = VP._fold([("not_evaluated", "instrument_failure"), ("contradicted", "x"), ("verified", None), ("not_evaluated", "y")])
        self.assertEqual(f, {"state": "contradicted", "reasons": ["instrument_failure", "x", "y"]})
        self.assertEqual(VP._fold([]), {"state": "not_evaluated", "reasons": ["not_present"]})
        self.assertEqual(VP._fold([("verified", None)] * 2)["state"], "verified")


@unittest.skipUnless(HAVE_CRYPTO, "the bench builds signed bases: needs cryptography")
class TestStatesBench(unittest.TestCase):
    def bench(self, *extra):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "verifiers", "states_bench.py"), "--quick", "--no-js"] + list(extra),
                              capture_output=True, text=True, env=env, timeout=900)

    def test_bench_green_and_a_sabotage_red(self):
        p = self.bench()
        self.assertEqual(p.returncode, 0, p.stdout[-1500:] + p.stderr[-1500:])
        self.assertIn('"violations": 0', p.stdout)
        q = self.bench("--sabotage", "refused_with_states")
        self.assertEqual(q.returncode, 1, "the bench must be able to fail")
        self.assertIn("C1 refused with states/policy", q.stdout)


if __name__ == "__main__":
    unittest.main()
