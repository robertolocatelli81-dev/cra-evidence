# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cells of spec/RECEIPT.md §2 that survived a mutant (NEMESIS 19/10/2026): a stored source path that is not a regular
file is `source_mismatch` (contradicted), never `unreadable`; a declared fingerprint that is not the key's is
`signature_invalid`, never `sidecar_malformed` (the fingerprint is outside the signed payload: only its branch sees it)."""
import importlib
import json
import os
import shutil
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


@unittest.skipUnless(HAVE_CRYPTO, "the bases are signed: needs cryptography")
class TestStatesCells(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import states_bench
        cls.work = tempfile.mkdtemp(prefix="cra-states-n-")
        cls.bases = states_bench.build_bases(cls.work)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def copy(self):
        d = tempfile.mkdtemp(prefix="c", dir=self.work)
        shutil.rmtree(d); shutil.copytree(self.bases["full"]["dir"], d)
        return d, os.path.join(d, "cra_pack.json")

    def test_stored_source_that_is_a_directory_is_source_mismatch(self):
        d, pack = self.copy()
        src = os.path.join(d, "cra.ledger.jsonl.sources"); name = os.listdir(src)[0]
        os.remove(os.path.join(src, name)); os.mkdir(os.path.join(src, name))
        r = VP.verify_pack(pack, trust_store={self.bases["full"]["signer"]: self.bases["full"]["pub"]})
        self.assertFalse(r["ok"])
        self.assertEqual(r["states"]["source_documents"]["state"], "contradicted")
        self.assertEqual(r["states"]["source_documents"]["reasons"], ["source_mismatch"])

    def test_declared_fingerprint_not_the_keys_is_signature_invalid(self):
        d, pack = self.copy()
        with open(pack + ".sig.json", encoding="utf-8") as f:
            s = json.load(f)
        s["fingerprint"] = "0" * 16
        with open(pack + ".sig.json", "w", encoding="utf-8") as f:
            json.dump(s, f)
        r = VP.verify_pack(pack, trust_store={self.bases["full"]["signer"]: self.bases["full"]["pub"]})
        self.assertFalse(r["ok"])
        self.assertEqual(r["states"]["producer_signature"], {"state": "contradicted", "reasons": ["signature_invalid"]})

    def test_required_sources_all_stored_one_mismatching_is_not_sources_required(self):
        # policy sources_required is a document recorded by hash ONLY (spec/RECEIPT.md §3), not any source FAIL
        d, pack = self.copy()
        src = os.path.join(d, "cra.ledger.jsonl.sources")
        with open(os.path.join(src, os.listdir(src)[0]), "ab") as f:
            f.write(b" ")
        b = self.bases["full"]
        r = VP.verify_pack(pack, trust_store={b["signer"]: b["pub"]}, log_pubkey_hex=b["log"], require_sources=True)
        self.assertEqual(r["states"]["source_documents"], {"state": "contradicted", "reasons": ["source_mismatch"]})
        self.assertNotIn("sources_required", r["policy"]["unmet"])

    def test_tip_that_is_a_directory_is_tip_invalid(self):
        d, pack = self.copy()
        tip = os.path.join(d, "cra.ledger.jsonl.tip.json"); os.remove(tip); os.mkdir(tip)
        b = self.bases["full"]
        r = VP.verify_pack(pack, trust_store={b["signer"]: b["pub"]}, log_pubkey_hex=b["log"])
        self.assertFalse(r["ok"])
        self.assertEqual(r["states"]["signed_tip"], {"state": "contradicted", "reasons": ["tip_invalid"]})


if __name__ == "__main__":
    unittest.main()
