# SPDX-License-Identifier: AGPL-3.0-or-later
"""CI wrapper of verifiers/closed_schema_mutants.py (closed schema of 2026-10-10; generative + differential across the verifiers
available here: Python and Node always, Go and Rust when their toolchains are present).

Two tests: the quick bench is GREEN on this tree; and the bench CAN go red — pointed at a copy of the Node verifier whose sidecar
rule is switched off it must count silent passes (a positive control of the bench, not of a verifier)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "verifiers", "closed_schema_mutants.py")
JS = os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs")


try:
    import cryptography  # noqa: F401 — the bench signs its sources (keygen, sign_pack)
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


@unittest.skipUnless(HAVE_CRYPTO, "the bench builds signed lockers: needs cryptography (the job without it ran 2 errors, 11/10/2026)")
class TestClosedSchemaMutants(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cra-mutants-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _run(self, *extra):
        out = os.path.join(self.d, "out.json")
        r = subprocess.run([sys.executable, BENCH, "--quick", "--seed", "20261011", "--out", out, *extra], capture_output=True, text=True, timeout=1800, cwd=ROOT)
        with open(out, encoding="utf-8") as f:
            return r.returncode, json.load(f), r.stdout[-2000:] + r.stderr[-800:]

    def test_quick_bench_is_green_on_every_verifier_available(self):
        rc, s, tail = self._run()
        self.assertEqual(rc, 0, tail)
        self.assertEqual(s["disagreements"], 0, tail)
        self.assertFalse(any(s["out_of_class"].values()), s["out_of_class"])
        self.assertFalse(any(s["unnamed_foreign_key"].values()), s["unnamed_foreign_key"])
        self.assertIn("python", s["verifiers"]); self.assertIn("js", s["verifiers"])
        self.assertGreaterEqual(sum(c["n"] for k, c in s["per_class"].items() if "unknown" in k and "in_data" not in k), 25)

    def test_bench_can_fail_lax_js_copy_counts_silent_passes(self):
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        lax = src.replace("if (unknownSide.length) return", "if (false) return", 1)
        self.assertNotEqual(lax, src, "the sidecar rule to switch off was not found: the control is void")
        # the name must END with "cra-verify.mjs": the verifier runs main() only then (a copy named otherwise prints nothing)
        lax_path = os.path.join(ROOT, "verifiers", "js", "lax_control_tmp_cra-verify.mjs")
        with open(lax_path, "w", encoding="utf-8") as f:
            f.write(lax)
        self.addCleanup(lambda: os.path.exists(lax_path) and os.remove(lax_path))
        rc, s, tail = self._run("--only", "python,js", "--js", lax_path)
        self.assertEqual(rc, 1, tail)
        self.assertGreater(s["silent_pass_on_expected_fail"]["js"], 0, s)
        self.assertEqual(s["silent_pass_on_expected_fail"]["python"], 0, s)

    def test_bench_lists_match_the_reference_lists(self):
        import importlib
        sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "verifiers"))
        V = importlib.import_module("cra_evidence.verify_pack")   # the MODULE (the package exports a function of the same name)
        S = importlib.import_module("cra_evidence.signing")
        import closed_schema_mutants as B   # noqa: E402
        self.assertEqual(set(B.PACK_KEYS), set(V.PACK_KEYS)); self.assertEqual(set(B.ENTRY_KEYS), set(V.ENTRY_KEYS))
        self.assertEqual(set(B.SIDECAR_KEYS), set(S.SIDECAR_KEYS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
