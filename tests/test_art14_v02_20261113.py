# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — art14-filing v0.2 (spec/art14-filing/v0.2/README.md), written before the code that implements it.

- every vector of spec/art14-filing/v0.2/vectors gives its expected verdict, exact set of reason codes and receipt
  values, through the library and through `cra verify-attestation`; the vectors are what the generator writes;
- two statements of the same product and stage, without the notice, are told apart by their receipts (spec §1);
- a v0.1 statement keeps the receipt of cra-evidence 0.8.0 byte for byte (receipts of 0.8.0 on the v0.1 vectors,
  vendored in tests/fixtures/art14_v01_receipts_080/);
- `cra attest` writes v0.2 by default, with the identifiers of the notice, and the same bytes as the vectors (built
  without the v0.2 producer); `--predicate v0.1` writes what 0.8.0 wrote; `--case-reference` is checked;
- generative: an unknown key in every new object, every wrong JSON type on every new leaf, and random identifier and
  reference strings against an oracle written without regular expressions."""
import contextlib, importlib.util, io, json, os, random, shutil, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V2 = os.path.join(ROOT, "spec", "art14-filing", "v0.2", "vectors")
V1 = os.path.join(ROOT, "spec", "art14-filing", "v0.1", "vectors")
R080 = os.path.join(ROOT, "tests", "fixtures", "art14_v01_receipts_080")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
TYPE_V01 = "https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.1"
TYPE_V02 = "https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.2"


def manifest(d=V2):
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)


def run(v, d=V2):
    from cra_evidence.art14_attest import verify_envelope
    from cra_evidence.ledger import load_trust_store
    with open(os.path.join(d, v["trust_store"]), encoding="utf-8") as f:
        ts = load_trust_store(f.read())
    return verify_envelope(os.path.join(d, v["envelope"]), ts, v["drop"] and os.path.join(d, v["drop"]),
                           v["ledger"] and os.path.join(d, v["ledger"]))


def cli(*argv):
    from cra_evidence.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


def argv_of(v, d):
    a = ["verify-attestation", os.path.join(d, v["envelope"]), "--trust-store", os.path.join(d, v["trust_store"])]
    if v["drop"]:
        a += ["--drop", os.path.join(d, v["drop"])]
    if v["ledger"]:
        a += ["--ledger", os.path.join(d, v["ledger"])]
    return a


def payload_of(env_path):
    from cra_evidence.art14_attest import b64decode
    with open(env_path, encoding="utf-8") as f:
        return b64decode(json.load(f)["payload"])


@unittest.skipUnless(HAVE_CRYPTO, "the vectors are signed: cryptography needed to check them")
class TestV02Vectors(unittest.TestCase):
    def test_every_vector_gives_its_expected_verdict_and_receipt(self):
        m = manifest()
        self.assertEqual(m["predicate_type"], TYPE_V02)
        self.assertGreaterEqual(len(m["vectors"]), 50)
        for v in m["vectors"]:
            with self.subTest(vector=v["name"]):
                r = run(v)
                codes = [x["code"] for x in r["reasons"]]
                e = v["expect"]
                self.assertEqual(r["verified"], e["verified"], r["reasons"])
                self.assertEqual(sorted(set(codes)), sorted(set(e["codes"])), r["reasons"])
                if r["verified"]:
                    self.assertEqual(codes, [])
                    for k in ("drop", "ledger"):
                        self.assertEqual(r[k], e.get(k, "PASS"))
                if e.get("no_v02_keys"):
                    self.assertNotIn("vulnerability_ids", r)
                    self.assertNotIn("case_reference", r)
                    self.assertEqual(r["predicate_type"], TYPE_V01)
                if "vulnerability_ids_result" in e:
                    self.assertEqual(r["predicate_type"], TYPE_V02)
                    self.assertEqual(r["vulnerability_ids"]["result"], e["vulnerability_ids_result"])
                if "vulnerability_ids_declared" in e:
                    self.assertEqual(r["vulnerability_ids"]["declared"], e["vulnerability_ids_declared"])
                if "vulnerability_ids_notice" in e:
                    self.assertEqual(r["vulnerability_ids"]["notice"], e["vulnerability_ids_notice"])
                if "case_reference_result" in e:
                    self.assertEqual(r["case_reference"]["result"], e["case_reference_result"])
                if e["verified"] and "vulnerability_ids_result" in e and v["drop"] is None:
                    self.assertIsNone(r["vulnerability_ids"]["notice"])
                if "vulnerability_ids" in e["codes"]:      # the reason says which identifiers differ
                    det = " ".join(x["detail"] for x in r["reasons"] if x["code"] == "vulnerability_ids")
                    self.assertIn("only in the statement", det)
                    self.assertIn("only in the notice", det)

    def test_cli_exit_codes(self):
        for v in manifest()["vectors"]:
            with self.subTest(vector=v["name"]):
                rc, out, err = cli(*argv_of(v, V2))
                self.assertEqual(rc, v["expect"]["exit"], out[-600:])
                self.assertEqual(json.loads(out)["verified"], v["expect"]["verified"])

    def test_vectors_are_the_generator_output(self):
        import gen_art14_v02_vectors
        d = tempfile.mkdtemp()
        try:
            out = os.path.join(d, "vectors")
            gen_art14_v02_vectors.generate(out)
            self.assertEqual(sorted(os.listdir(out)), sorted(os.listdir(V2)))
            for n in os.listdir(out):
                with open(os.path.join(out, n), "rb") as a, open(os.path.join(V2, n), "rb") as b:
                    self.assertEqual(a.read(), b.read(), n)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_every_new_rule_has_a_vector(self):
        codes = {c for v in manifest()["vectors"] for c in v["expect"]["codes"]}
        self.assertTrue({"vulnerability_ids", "predicate_identifier", "predicate_rule", "predicate_enum", "predicate_type_error",
                         "predicate_unknown_key", "predicate_missing_key", "duplicate_key", "predicate_type"} <= codes)
        n_ok = sum(1 for v in manifest()["vectors"] if v["expect"]["verified"])
        self.assertGreaterEqual(n_ok, 6)
        self.assertGreaterEqual(len(manifest()["vectors"]) - n_ok, 11)

    def test_the_identifiers_are_the_real_ones_of_the_spec(self):
        with open(os.path.join(ROOT, "spec", "art14-filing", "v0.2", "README.md"), encoding="utf-8") as f:
            spec = f.read()
        for name in ("drop_cve_euvd.json", "drop_cve_only.json", "drop_previous.json"):
            with open(os.path.join(V2, name), encoding="utf-8") as f:
                p = json.load(f)
            for k in ("cve_id", "euvd_id"):
                for blk in (p["fields"], p["previous_fields"] or {}):
                    if k in blk:
                        self.assertIn(blk[k], spec, f"{name} {k}: not a record listed in spec v0.2 §8")

    def test_two_statements_same_product_and_stage_told_apart_without_the_notice(self):
        vs = {v["name"]: v for v in manifest()["vectors"]}
        a, b = run(vs["valid_cve_euvd_without_drop"]), run(vs["valid_cve_only_without_drop"])
        self.assertTrue(a["verified"] and b["verified"])
        pa, pb = (json.loads(payload_of(os.path.join(V2, vs[n]["envelope"])))["predicate"]
                  for n in ("valid_cve_euvd_without_drop", "valid_cve_only_without_drop"))
        self.assertEqual((pa["product"], pa["stage"]), (pb["product"], pb["stage"]))
        self.assertNotEqual(a["vulnerability_ids"]["declared"], b["vulnerability_ids"]["declared"])


@unittest.skipUnless(HAVE_CRYPTO, "the vectors are signed: cryptography needed to check them")
class TestV01ReceiptsUnchanged(unittest.TestCase):
    def test_receipts_of_the_v01_vectors_are_those_of_080_byte_for_byte(self):
        names = sorted(n[:-5] for n in os.listdir(R080) if n.endswith(".json"))
        self.assertEqual(len(names), 51)     # the 52 vectors of 0.8.0 but predicate_type_wrong (its TypeURI is now defined)
        vs = {v["name"]: v for v in manifest(V1)["vectors"]}
        cwd = os.getcwd()
        try:
            os.chdir(V1)     # the receipts of 0.8.0 were taken with paths relative to the vector folder
            for n in names:
                with self.subTest(vector=n):
                    v = vs[n]
                    argv = [x if not x.startswith(V1 + os.sep) else os.path.relpath(x, V1) for x in argv_of(v, V1)]
                    rc, out, err = cli(*argv)
                    with open(os.path.join(R080, n + ".json"), encoding="utf-8") as f:
                        want = json.load(f)
                    self.assertEqual(rc, want["exit"])
                    self.assertEqual(out, want["stdout"])
        finally:
            os.chdir(cwd)

    def test_predicate_type_wrong_now_uses_an_undefined_version(self):
        v = next(x for x in manifest(V1)["vectors"] if x["name"] == "predicate_type_wrong")
        st = json.loads(payload_of(os.path.join(V1, v["envelope"])))
        self.assertNotIn(st["predicateType"], (TYPE_V01, TYPE_V02))
        self.assertEqual([x["code"] for x in run(v, V1)["reasons"]], ["predicate_type"])


@unittest.skipUnless(HAVE_CRYPTO, "cra attest signs: cryptography needed")
class TestAttestV02(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        shutil.copytree(V2, os.path.join(self.d, "v"))
        self.v = os.path.join(self.d, "v")
        from gen_art14_vectors import TEST_KEY_STRING
        import hashlib
        self.key = os.path.join(self.d, "k.seed")
        with open(self.key, "w", encoding="utf-8") as f:
            f.write(hashlib.sha256(TEST_KEY_STRING.encode()).digest().hex())

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def attest(self, drop, *extra):
        out = os.path.join(self.d, "o.intoto.json")
        if os.path.exists(out):
            os.remove(out)
        rc, o, e = cli("attest", os.path.join(self.v, drop), "--ledger", os.path.join(self.v, "ledger.jsonl"),
                       "--key", self.key, "--signer-id", "test-signer", "--out", out, *extra)
        return rc, json.loads(o) if o.strip() else None, out

    def predicate(self, out):
        return json.loads(payload_of(out))

    def test_default_is_v02_with_the_notice_identifiers(self):
        for drop, want in (("drop_cve_euvd.json", [{"scheme": "cve", "id": "CVE-2024-3094"}, {"scheme": "euvd", "id": "EUVD-2024-31700"}]),
                           ("drop_previous.json", [{"scheme": "cve", "id": "CVE-2024-21762"}, {"scheme": "euvd", "id": "EUVD-2024-19376"}]),
                           ("drop_cve_only.json", [{"scheme": "cve", "id": "CVE-2021-44228"}]),
                           ("drop_no_ids.json", None)):
            with self.subTest(drop=drop):
                rc, r, out = self.attest(drop)
                self.assertEqual(rc, 0, r)
                st = self.predicate(out)
                self.assertEqual(st["predicateType"], TYPE_V02)
                self.assertEqual(st["predicate"].get("vulnerabilityIds"), want)
                self.assertNotIn("caseReference", st["predicate"])
                rc, o, _ = cli("verify-attestation", out, "--trust-store", os.path.join(self.v, "trust_store.json"),
                               "--drop", os.path.join(self.v, drop), "--ledger", os.path.join(self.v, "ledger.jsonl"))
                self.assertEqual(rc, 0, o)
                self.assertEqual(json.loads(o)["vulnerability_ids"]["result"], "matched")

    def test_producer_gives_the_bytes_of_the_vectors(self):
        """the vectors were built from v0.1 statements by hand; the producer must give the same payload"""
        from datetime import datetime, timezone
        from cra_evidence.art14_attest import build_statement
        at = datetime(2026, 11, 13, 7, 5, 0, tzinfo=timezone.utc)
        vs = {v["name"]: v for v in manifest()["vectors"]}
        for name, drop, case in (("valid_cve_euvd_matched", "drop_cve_euvd.json", None),
                                 ("valid_no_identifiers", "drop_no_ids.json", None),
                                 ("valid_identifiers_from_previous_fields", "drop_previous.json", None),
                                 ("valid_identifiers_and_case_reference", "drop_cve_euvd.json",
                                  {"issuer": "CSIRT Italia (synthetic case)", "id": "CASE-2026-000123"})):
            with self.subTest(vector=name):
                got = build_statement(os.path.join(self.v, drop), os.path.join(self.v, "ledger.jsonl"), attested_at=at,
                                      predicate="v0.2", case_reference=case)
                self.assertEqual(got, payload_of(os.path.join(V2, vs[name]["envelope"])))

    def test_predicate_v01_writes_what_080_wrote(self):
        from datetime import datetime, timezone
        from cra_evidence.art14_attest import build_statement
        at = datetime(2026, 11, 13, 6, 5, 0, tzinfo=timezone.utc)
        vs = {v["name"]: v for v in manifest(V1)["vectors"]}
        for p in (None, "v0.1"):      # the library default stays v0.1 (callers of 0.8.0 unchanged)
            kw = {} if p is None else {"predicate": p}
            got = build_statement(os.path.join(V1, "drop_native_early_warning.json"), os.path.join(V1, "ledger.jsonl"),
                                  attested_at=at, **kw)
            self.assertEqual(got, payload_of(os.path.join(V1, vs["valid_native_early_warning"]["envelope"])))
        rc, r, out = self.attest("drop_cve_euvd.json", "--predicate", "v0.1")
        self.assertEqual(rc, 0, r)
        st = self.predicate(out)
        self.assertEqual(st["predicateType"], TYPE_V01)
        self.assertNotIn("vulnerabilityIds", st["predicate"])

    def test_notice_identifier_out_of_form_refused_nothing_written(self):
        rc, r, out = self.attest("drop_lower_case.json")
        self.assertEqual(rc, 1)
        self.assertFalse(r["attested"])
        self.assertIn("cve-2024-3094", r["reasons"][0])
        self.assertFalse(os.path.exists(out))
        rc, r, out = self.attest("drop_lower_case.json", "--predicate", "v0.1")      # v0.1 does not read identifiers
        self.assertEqual(rc, 0, r)

    def test_case_reference(self):
        rc, r, out = self.attest("drop_no_ids.json", "--case-reference", "CSIRT Italia (synthetic case)", "CASE-2026-000123")
        self.assertEqual(rc, 0, r)
        self.assertEqual(self.predicate(out)["predicate"]["caseReference"],
                         {"issuer": "CSIRT Italia (synthetic case)", "id": "CASE-2026-000123"})
        for bad in (["", "x"], ["x", ""], ["x\u0007", "y"], ["x ", "y"], ["x", "y" * 256], ["x", "\u0085"]):
            with self.subTest(case=bad):
                rc, r, out = self.attest("drop_no_ids.json", "--case-reference", *bad)
                self.assertEqual(rc, 1, r)
                self.assertFalse(os.path.exists(out))
        rc, r, out = self.attest("drop_no_ids.json", "--predicate", "v0.1", "--case-reference", "a", "b")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(out))


def _is_cve(s):
    """oracle without regular expressions: CVE-, 4 ASCII digits, -, 4 to 19 ASCII digits"""
    p = s.split("-")
    return (len(p) == 3 and p[0] == "CVE" and len(p[1]) == 4 and all(c in "0123456789" for c in p[1])
            and 4 <= len(p[2]) <= 19 and all(c in "0123456789" for c in p[2]))


def _is_euvd(s):
    p = s.split("-")
    return (len(p) == 3 and p[0] == "EUVD" and len(p[1]) == 4 and all(c in "0123456789" for c in p[1])
            and 1 <= len(p[2]) <= 19 and all(c in "0123456789" for c in p[2]))


def _is_ref(s):
    return (1 <= len(s) <= 255 and not any(ord(c) <= 0x1f or 0x7f <= ord(c) <= 0x9f for c in s)
            and s[0] != " " and s[-1] != " ")


class TestGenerative(unittest.TestCase):
    """check_statement on payloads (no signature needed): every mutation of the new fields is refused with a reason"""

    @classmethod
    def setUpClass(cls):
        vs = {v["name"]: v for v in manifest()["vectors"]}
        cls.base = json.loads(payload_of(os.path.join(V2, vs["valid_identifiers_and_case_reference"]["envelope"])))

    def check(self, st):
        from cra_evidence.art14_attest import check_statement
        payload = json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ok, reasons, _ = check_statement(payload)
        return ok is not None, [r["code"] for r in reasons]

    def test_base_accepted(self):
        self.assertEqual(self.check(self.base), (True, []))

    def test_unknown_key_in_every_new_object(self):
        objs = [("vulnerabilityIds", 0), ("vulnerabilityIds", 1), ("caseReference",)]
        for path in objs:
            for k in ("x", "", "ID", "scheme ", "issuer\u0000", "__proto__", "\U0001F600"):
                with self.subTest(path=path, key=k):
                    st = json.loads(json.dumps(self.base))
                    o = st["predicate"]
                    for p in path:
                        o = o[p]
                    o[k] = "CVE-2024-3094"
                    self.assertEqual(self.check(st), (False, ["predicate_unknown_key"]))

    def test_every_wrong_type_on_every_new_leaf(self):
        wrong = [None, True, 0, 1, -1, 2 ** 53 - 1, [], ["CVE-2024-3094"], {}, {"id": "x"}]
        leaves = [("vulnerabilityIds",), ("vulnerabilityIds", 0), ("vulnerabilityIds", 0, "scheme"), ("vulnerabilityIds", 0, "id"),
                  ("vulnerabilityIds", 1, "scheme"), ("vulnerabilityIds", 1, "id"), ("caseReference",),
                  ("caseReference", "issuer"), ("caseReference", "id")]
        n = 0
        for path in leaves:
            for w in wrong:
                st = json.loads(json.dumps(self.base))
                o = st["predicate"]
                for p in path[:-1]:
                    o = o[p]
                o[path[-1]] = w
                ok, codes = self.check(st)
                with self.subTest(path=path, value=w):
                    self.assertFalse(ok)
                    self.assertTrue(codes)
                    self.assertTrue(set(codes) <= {"predicate_type_error", "predicate_rule", "predicate_missing_key",
                                                   "predicate_unknown_key"}, codes)
                n += 1
        self.assertEqual(n, 90)

    def test_random_identifier_strings_against_the_oracle(self):
        rng = random.Random(20261113)
        alphabet = list("CVEUDcveud-0123456789 ") + ["\n", "３", "٣", "\u0000", "é"]
        seen = {"cve": [0, 0], "euvd": [0, 0]}
        for i in range(6000):
            scheme = rng.choice(["cve", "euvd"])
            if rng.random() < 0.5:     # near the form: a valid shape with one edit
                s = ("CVE-" if scheme == "cve" else "EUVD-") + "".join(rng.choice("0123456789") for _ in range(4)) + "-" + \
                    "".join(rng.choice("0123456789") for _ in range(rng.randint(0, 21)))
                if rng.random() < 0.5:
                    j = rng.randrange(len(s) + 1)
                    s = s[:j] + rng.choice(alphabet) + s[j + 1:]
            else:
                s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
            want = _is_cve(s) if scheme == "cve" else _is_euvd(s)
            st = json.loads(json.dumps(self.base))
            st["predicate"]["vulnerabilityIds"] = [{"scheme": scheme, "id": s}]
            ok, codes = self.check(st)
            with self.subTest(i=i, scheme=scheme, s=s):
                self.assertEqual(ok, want, codes)
                if not ok:
                    self.assertEqual(codes, ["predicate_identifier"])
            seen[scheme][want] += 1
        for scheme in seen:      # both sides of the oracle are exercised
            self.assertGreater(seen[scheme][0], 300)
            self.assertGreater(seen[scheme][1], 300)

    def test_random_reference_strings_against_the_oracle(self):
        rng = random.Random(1113)
        alphabet = [chr(c) for c in range(0, 0xa0)] + list("èß€") + ["\U0001F600", " ", " "]
        seen = [0, 0]
        for i in range(4000):
            n = rng.choice([0, 1, 2, 5, 30, 254, 255, 256, 300])
            s = "".join(rng.choice(alphabet) if rng.random() < 0.08 else rng.choice("abcXYZ-019 ") for _ in range(n))
            field = rng.choice(["issuer", "id"])
            st = json.loads(json.dumps(self.base))
            st["predicate"]["caseReference"][field] = s
            ok, codes = self.check(st)
            want = _is_ref(s)
            with self.subTest(i=i, s=s[:40]):
                self.assertEqual(ok, want, codes)
                if not ok:
                    self.assertEqual(codes, ["predicate_identifier"])
            seen[want] += 1
        self.assertGreater(seen[0], 300)
        self.assertGreater(seen[1], 300)

    def test_list_shapes(self):
        c1, c2 = {"scheme": "cve", "id": "CVE-2024-3094"}, {"scheme": "cve", "id": "CVE-2021-44228"}
        e1, e2 = {"scheme": "euvd", "id": "EUVD-2024-31700"}, {"scheme": "euvd", "id": "EUVD-2021-34768"}
        for ids, want in (([c1], True), ([e1], True), ([c1, e1], True), ([], False), ([e1, c1], False), ([c1, c1], False),
                          ([c1, c2], False), ([e1, e2], False), ([c1, e1, e2], False), ([c1, e1, c1], False),
                          ([c1, e1] * 8 + [c1], False)):
            with self.subTest(ids=ids):
                st = json.loads(json.dumps(self.base))
                st["predicate"]["vulnerabilityIds"] = ids
                ok, codes = self.check(st)
                self.assertEqual(ok, want, codes)
                if not ok:
                    self.assertEqual(codes, ["predicate_rule"])

    def test_v01_type_with_any_new_key_refused(self):
        for k in ("vulnerabilityIds", "caseReference"):
            st = json.loads(json.dumps(self.base))
            st["predicateType"] = TYPE_V01
            other = "caseReference" if k == "vulnerabilityIds" else "vulnerabilityIds"
            del st["predicate"][other]
            self.assertEqual(self.check(st), (False, ["predicate_unknown_key"]))


class TestStatementPayloadIsJCS(unittest.TestCase):
    """spec v0.2 §6: the payloads `cra attest` writes are the RFC 8785 serialisation of the statement (every member name
    is ASCII). Measured on every envelope of the v0.1 and v0.2 vectors; positive control: a payload with a key beyond
    the BMP is not."""

    def test_every_vector_payload(self):
        from test_canonical_vs_jcs_20261113 import jcs
        n = 0
        for d in (V1, V2):
            for v in manifest(d)["vectors"]:
                try:
                    p = payload_of(os.path.join(d, v["envelope"]))
                    st = json.loads(p, object_pairs_hook=_no_duplicates, parse_float=_no_float)
                except (ValueError, KeyError):
                    continue     # refused vectors: an envelope that does not decode, a duplicate key, a float
                with self.subTest(vector=v["name"]):
                    self.assertTrue(all(ord(c) <= 0x7e for c in _member_names(st)))
                    self.assertEqual(p, jcs(st))
                    n += 1
        self.assertGreaterEqual(n, 90)

    def test_positive_control_key_beyond_the_bmp(self):
        from test_canonical_vs_jcs_20261113 import jcs
        st = {"\U00010000": 1, "": 2}
        p = json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertNotEqual(p, jcs(st))


def _member_names(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from k
            yield from _member_names(v)
    elif isinstance(x, list):
        for v in x:
            yield from _member_names(v)


def _no_duplicates(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_float(x):
    raise ValueError("float")


if __name__ == "__main__":
    unittest.main()
