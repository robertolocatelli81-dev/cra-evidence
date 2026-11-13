# SPDX-License-Identifier: AGPL-3.0-or-later
"""art14-filing v0.2: cases the line mutants of the review found untested (13/11/2026). Each test fails on a
mutant that the earlier tests let live:
- the CVE year is exactly four digits (mutant `{4}` -> `{2,4}` in ID_FORMS["cve"]);
- build_statement refuses a case reference for v0.1, an object with other keys, and surrogates at both ends of the
  range (mutants: the case-reference block skipped, `or` -> `and`, `<=` -> `<`);
- the receipt of a statement with an undefined TypeURI keeps the v0.1 TypeURI, and a non-string TypeURI does not crash
  (mutant `and` -> `or` in _type_read)."""
import base64, importlib.util, json, os, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from omega_cra_evol import art14_attest as A  # noqa: E402
from gen_art14_vectors import TEST_KEY_STRING, envelope, test_key  # noqa: E402

VD = os.path.join(ROOT, "spec", "art14-filing", "v0.2", "vectors")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None


def _read(p):
    with open(p) as f:
        return json.load(f)


def _payload(name):
    return json.loads(base64.b64decode(_read(os.path.join(VD, name))["payload"]))


def _check(st):
    return A.check_statement(json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


class CVEYear(unittest.TestCase):
    def test_year_is_four_digits(self):
        base = _payload("valid_cve_euvd_without_drop.intoto.json")
        for sid, ok in (("CVE-2024-3094", True), ("CVE-24-3094", False), ("CVE-202-3094", False),
                        ("CVE-20245-3094", False), ("CVE--3094", False)):
            st = json.loads(json.dumps(base))
            st["predicate"]["vulnerabilityIds"][0]["id"] = sid
            got, errs, _ = _check(st)
            with self.subTest(sid):
                self.assertEqual(got is not None, ok, errs)
                if not ok:
                    self.assertEqual([e["code"] for e in errs], ["predicate_identifier"])


class ProducerCaseReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.drop = os.path.join(VD, "drop_no_ids.json")
        cls.ledger = os.path.join(VD, "ledger.jsonl")

    def build(self, **kw):
        return A.build_statement(self.drop, self.ledger, **kw)

    def test_control_the_valid_reference_is_written(self):
        st = json.loads(self.build(predicate="v0.2", case_reference={"issuer": "Example CSIRT", "id": "C-1"}))
        self.assertEqual(st["predicate"]["caseReference"], {"issuer": "Example CSIRT", "id": "C-1"})

    def test_refused(self):
        for name, kw in (
                ("v0.1 with a case reference", {"predicate": "v0.1", "case_reference": {"issuer": "a", "id": "b"}}),
                ("an extra key", {"predicate": "v0.2", "case_reference": {"issuer": "a", "id": "b", "url": "c"}}),
                ("a missing key", {"predicate": "v0.2", "case_reference": {"issuer": "a"}}),
                ("not a dict", {"predicate": "v0.2", "case_reference": ["a", "b"]}),
                ("surrogate U+D800", {"predicate": "v0.2", "case_reference": {"issuer": "a\ud800", "id": "b"}}),
                ("surrogate U+DFFF", {"predicate": "v0.2", "case_reference": {"issuer": "a", "id": "\udfffb"}}),
                ("predicate v0.3", {"predicate": "v0.3"})):
            with self.subTest(name):
                with self.assertRaises(A.AttestRefused):
                    self.build(**kw)


@unittest.skipUnless(HAVE_CRYPTO, "the envelope is signed: cryptography needed")
class ReceiptTypeURI(unittest.TestCase):
    def verify(self, st):
        k = test_key(TEST_KEY_STRING)
        ts = _read(os.path.join(VD, "trust_store.json"))
        pl = json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(envelope(pl, k), f)
        try:
            return A.verify_envelope(f.name, ts)
        finally:
            os.unlink(f.name)

    def test_undefined_type_keeps_the_v01_type(self):
        base = _payload("valid_no_identifiers_without_drop.intoto.json")
        for t in (A.TYPE_URI_V02.replace("v0.2", "v0.3"), ["x"], {"a": 1}, 7, None):
            st = dict(base, predicateType=t)
            with self.subTest(t=t):
                r = self.verify(st)
                self.assertFalse(r["verified"])
                self.assertEqual(r["predicate_type"], A.TYPE_URI)
                self.assertIn("predicate_type", [x["code"] for x in r["reasons"]])
        self.assertEqual(self.verify(base)["predicate_type"], A.TYPE_URI_V02)      # control: a defined type is shown


if __name__ == "__main__":
    unittest.main()
