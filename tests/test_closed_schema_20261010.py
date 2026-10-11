# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Closed schema (2026-10-10): a key nobody defined — in the signature sidecar, at the pack's top level, at a ledger entry's
top level — is a named FAIL, never a silent pass. Each case is built from examples/self_evidence in a temporary directory
(removed at the end); the intact copy is the positive control (trusted-signed)."""
import copy
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
VP = importlib.import_module("cra_evidence.verify_pack")
C = importlib.import_module("cra_evidence.canonical")
L = importlib.import_module("cra_evidence.ledger")
EX = os.path.join(ROOT, "examples", "self_evidence")


class TestClosedSchema(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cra-closed-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        for n in ("cra_pack.json", "cra_pack.json.sig.json", "cra.ledger.jsonl", "trust.json"):
            shutil.copy(os.path.join(EX, n), os.path.join(self.d, n))
        shutil.copytree(os.path.join(EX, "cra.ledger.jsonl.sources"), os.path.join(self.d, "cra.ledger.jsonl.sources"))
        self.pack = os.path.join(self.d, "cra_pack.json"); self.sig = self.pack + ".sig.json"; self.led = os.path.join(self.d, "cra.ledger.jsonl")
        with open(os.path.join(self.d, "trust.json"), encoding="utf-8") as f:
            self.trust = json.load(f)

    def verify(self, led=None):
        return VP.verify_pack(self.pack, led or self.led, trust_store=self.trust)

    def layers(self, r):
        return {x["layer"]: x for x in r["layers"]}

    def test_intact_is_trusted_signed(self):
        r = self.verify()
        try:
            import cryptography  # noqa: F401
        except ImportError:   # the no-dependency CI job: the signature cannot be checked, a named FAIL by design (11/10/2026 review)
            self.assertFalse(r["ok"]); self.assertIn("cryptography not installed", self.layers(r)["producer-signature"]["detail"])
        else:
            self.assertTrue(r["ok"]); self.assertEqual(r["authenticity"], "trusted-signed")
        self.assertEqual(self.layers(r)["pack-schema"]["status"], "PASS"); self.assertNotIn("ledger-schema", self.layers(r))

    def test_unknown_sidecar_field_is_named_fail(self):
        with open(self.sig, encoding="utf-8") as f:
            side = json.load(f)
        side["x_unknown_2026"] = "x"
        with open(self.sig, "w", encoding="utf-8") as f:
            json.dump(side, f)
        r = self.verify()
        self.assertFalse(r["ok"]); self.assertEqual(r["authenticity"], "FAIL")
        self.assertIn("x_unknown_2026", self.layers(r)["producer-signature"]["detail"])

    def test_unknown_pack_top_level_key_is_named_fail(self):
        with open(self.pack, encoding="utf-8") as f:
            pack = json.load(f)
        pack["x_unknown_2026"] = "x"; pack["pack_sha3"] = C.sha3_hex({k: v for k, v in pack.items() if k != "pack_sha3"})
        with open(self.pack, "w", encoding="utf-8") as f:
            json.dump(pack, f)
        r = self.verify()
        self.assertFalse(r["ok"]); ps = self.layers(r)["pack-schema"]
        self.assertEqual(ps["status"], "FAIL"); self.assertIn("x_unknown_2026", ps["detail"])

    def test_unknown_ledger_entry_key_is_named_fail(self):
        with open(self.led, encoding="utf-8") as f:
            es = [json.loads(ln) for ln in f if ln.strip()]
        es[1]["x_unknown_2026"] = "x"
        prev = "0" * 64
        with open(self.led, "w", encoding="utf-8") as f:
            for e in es:
                e = dict(e); e["prev_hash"] = prev; e.pop("self_hash", None); e["self_hash"] = L.entry_hash(e); prev = e["self_hash"]
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        r = self.verify()
        self.assertFalse(r["ok"]); ls = self.layers(r)["ledger-schema"]
        self.assertEqual(ls["status"], "FAIL"); self.assertIn("x_unknown_2026", ls["detail"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
