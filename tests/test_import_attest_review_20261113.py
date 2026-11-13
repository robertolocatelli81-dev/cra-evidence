# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — review of 0.8.0 before its release. Each test failed on the reviewed commit (9000fca):

- import: a date id ("aware_at", "occurred_at", "measure_available_at") inside snapshot.srp_fields was a second pair
  for one notice field — kept silently instead of refused (a valid date) or a traceback (a non-date); a date whose UTC
  instant falls outside years 1-9999 was an OverflowError traceback; "GR, EL" (one Member State, two codes) was
  accepted; an unreadable --report, a next_due.due that is not an instant and a `values` that is not an object are
  refusals the tests did not pin (three surviving mutants);
- import: a ledger append failing midway left the drop files of the notices not recorded and a traceback;
- verify-attestation: a signature without keyid, or with an empty one (DSSE envelope.md: the same), was never tried
  with any key; an awareAt whose deadline falls after year 9999, or an instant before year 1000, was a traceback; a
  lone surrogate in the payload was accepted."""
import base64, contextlib, copy, glob, hashlib, importlib.util, io, json, os, shutil, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "sbomify_4ef6128")
V = os.path.join(ROOT, "spec", "art14-filing", "v0.1", "vectors")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
REP = os.path.join(FIX, "report_s1AfwOnAgUPN.json")
FILINGS = sorted(glob.glob(os.path.join(FIX, "filing_s1AfwOnAgUPN_*.json")))
EW = os.path.join(FIX, "filing_s1AfwOnAgUPN_early_warning_1.json")


def cli(*argv):
    from cra_evidence.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


def files(d):
    return sorted(os.path.relpath(os.path.join(r, f), d) for r, _, fs in os.walk(d) for f in fs)


class TestImportReview(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def _write(self, name, obj):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        return p

    def _import(self, report, filing_paths):
        return cli("import", "sbomify", "--ledger", os.path.join(self.d, "l.jsonl"), "--product", "p", "--version", "1",
                   "--report", report, *sum((["--filing", x] for x in filing_paths), []), "--drop-dir",
                   os.path.join(self.d, "drop"), "--source-version", "4ef6128")

    def _refused(self, report, filing_paths, needle):
        rc, out, err = self._import(report, filing_paths)
        self.assertEqual(rc, 1, (out, err))
        self.assertNotIn("Traceback", err)
        r = json.loads(out)
        self.assertIs(r["imported"], False)
        self.assertIn(needle, " ".join(r["reasons"]))
        self.assertFalse(os.path.exists(os.path.join(self.d, "l.jsonl")))
        self.assertEqual([x for x in files(self.d) if not x.endswith(".json") or x.startswith(("drop/", "l.jsonl"))], [])

    def test_date_id_inside_srp_fields_refused(self):
        for k, v in (("aware_at", "2026-11-01T00:00:00Z"), ("occurred_at", "garbage"), ("measure_available_at", "2026-11-11T16:00:00Z")):
            with self.subTest(k=k):
                f = json.load(open(EW, encoding="utf-8"))
                f["snapshot"]["srp_fields"][k] = v
                self._refused(REP, [self._write(f"f_{k}.json", f)], "is a date of the snapshot")

    def test_instant_outside_years_1_9999_refused(self):
        for v in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(v=v):
                f = json.load(open(EW, encoding="utf-8"))
                f["snapshot"]["occurred_at"] = v
                self._refused(REP, [self._write("f.json", f)], "no UTC instant between years 1 and 9999")

    def test_offset_before_year_1000_normalised_with_four_digits(self):
        from cra_evidence.sbomify_import import _utc
        norms = []
        self.assertEqual(_utc("occurred_at", "0999-06-01T00:30:00+01:00", norms), "0999-05-31T23:30:00Z")

    def test_gr_and_el_are_one_member_state(self):
        f = json.load(open(EW, encoding="utf-8"))
        f["snapshot"]["srp_fields"]["member_states"] = "GR, EL"
        self._refused(REP, [self._write("f.json", f)], "GR and EL are one")

    def test_unreadable_report_refused(self):
        self._refused(os.path.join(self.d, "absent.json"), [EW], "unreadable")

    def test_next_due_due_not_an_instant_refused(self):
        r = json.load(open(REP, encoding="utf-8"))
        r["next_due"] = {"stage": "final_report", "label": "x", "due": "2026-13-01T00:00:00Z", "overdue": False}
        self._refused(self._write("r.json", r), [EW], "next_due.due")

    def test_values_not_an_object_refused(self):
        r = json.load(open(REP, encoding="utf-8"))
        r["values"] = []
        self._refused(self._write("r.json", r), [EW], "values: not a JSON object")

    def test_ledger_failure_midway_names_what_was_recorded(self):
        from cra_evidence.locker import CRAEvidenceLocker
        orig = CRAEvidenceLocker.record_notice
        calls = {"n": 0}

        def failing(self_, *a, **k):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(28, "No space left on device")
            return orig(self_, *a, **k)
        with mock.patch.object(CRAEvidenceLocker, "record_notice", failing):
            rc, out, err = self._import(REP, FILINGS)
        self.assertEqual(rc, 74, (out, err))
        self.assertNotIn("Traceback", err)
        r = json.loads(out)
        self.assertEqual(r["imported"], "partial")
        self.assertEqual(len(r["recorded"]), 2)
        self.assertEqual(len(r["not_recorded_filings"]), len(FILINGS) - 2)
        with open(os.path.join(self.d, "l.jsonl"), encoding="utf-8") as f:
            self.assertEqual(sum(1 for _ in f), 3)            # the event and two notices: append-only, they stay
        notices = [x for x in os.listdir(os.path.join(self.d, "drop")) if not x.startswith("sbomify_")]
        self.assertEqual(sorted(notices), sorted(x["drop_file"] for x in r["recorded"]))
        # the filings not recorded import alone, under the event already recorded
        left = [p for p in FILINGS if json.load(open(p, encoding="utf-8"))["id"] in r["not_recorded_filings"]]
        rc, out, err = self._import(REP, left)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("already_recorded", json.loads(out)["event"])
        for x in sorted(os.listdir(os.path.join(self.d, "drop"))):
            if not x.startswith("sbomify_"):
                rc, out, err = cli("check-notice", os.path.join(self.d, "drop", x), "--ledger", os.path.join(self.d, "l.jsonl"))
                self.assertEqual(rc, 0, (x, out))


@unittest.skipUnless(HAVE_CRYPTO, "signatures: cryptography needed")
class TestAttestationReview(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        m = json.load(open(os.path.join(V, "manifest.json"), encoding="utf-8"))
        self.sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(m["test_keys"]["test-signer"]["seed_string"].encode()).digest())
        env = json.load(open(os.path.join(V, "valid_early_warning.intoto.json"), encoding="utf-8"))
        self.payload = base64.b64decode(env["payload"])
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        with open(os.path.join(V, "trust_store.json"), encoding="utf-8") as f:
            from cra_evidence.ledger import load_trust_store
            self.ts = load_trust_store(f.read())

    def _env(self, payload, keyid="test-signer", sk=None):
        from cra_evidence.art14_attest import PAYLOAD_TYPE, pae
        s = {"sig": base64.b64encode((sk or self.sk).sign(pae(PAYLOAD_TYPE, payload))).decode()}
        if keyid is not None:
            s["keyid"] = keyid
        p = os.path.join(self.d, "e.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"payload": base64.b64encode(payload).decode(), "payloadType": PAYLOAD_TYPE, "signatures": [s]}, f)
        return p

    def _verify(self, env, drop=True):
        from cra_evidence.art14_attest import verify_envelope
        return verify_envelope(env, self.ts, os.path.join(V, "drop_early_warning.json") if drop else None,
                               os.path.join(V, "ledger.jsonl") if drop else None)

    def test_signature_without_keyid_tried_with_every_trusted_key(self):
        for kid in (None, ""):
            with self.subTest(keyid=kid):
                r = self._verify(self._env(self.payload, keyid=kid))
                self.assertTrue(r["verified"], r["reasons"])
                self.assertEqual(r["trusted_by"], ["test-signer"])

    def test_signature_without_keyid_by_an_untrusted_key_not_trusted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        r = self._verify(self._env(self.payload, keyid="", sk=Ed25519PrivateKey.generate()))
        self.assertFalse(r["verified"])
        self.assertEqual(sorted({x["code"] for x in r["reasons"]}), ["not_trusted", "signature_failed"])

    def test_unknown_keyid_still_not_tried(self):
        r = self._verify(self._env(self.payload, keyid="someone-else"))
        self.assertFalse(r["trusted"])
        self.assertEqual([x["code"] for x in r["signatures_not_verified"]], ["unknown_keyid"])

    def _mut(self, f):
        st = json.loads(self.payload)
        f(st)
        return json.dumps(st, sort_keys=True, separators=(",", ":")).encode()

    def test_instants_at_the_edges_refused_not_crashed(self):
        # a deadline after year 9999: refused with a reason (was an OverflowError traceback)
        r = self._verify(self._env(self._mut(lambda st: st["predicate"].update(awareAt="9999-12-31T23:00:00Z",
                                                                               deadlineAt="9999-12-31T23:00:00Z"))), drop=False)
        self.assertFalse(r["verified"])
        self.assertEqual([x["code"] for x in r["reasons"]], ["predicate_timestamp"])
        # year 1: the deadline is computed and compared (was "1-01-02T…", a ValueError traceback)
        r = self._verify(self._env(self._mut(lambda st: st["predicate"].update(awareAt="0001-01-01T00:00:00Z",
                                                                               deadlineAt="0001-01-02T00:00:00Z"))), drop=False)
        self.assertEqual(r["reasons"], [])
        r = self._verify(self._env(self._mut(lambda st: st["predicate"].update(awareAt="0001-01-01T00:00:00Z",
                                                                               deadlineAt="0001-01-03T00:00:00Z"))), drop=False)
        self.assertEqual([x["code"] for x in r["reasons"]], ["deadline"])

    def test_year_before_1000_formatted_with_four_digits(self):
        from datetime import datetime, timezone
        from cra_evidence.art14_attest import z
        self.assertEqual(z(datetime(999, 1, 2, tzinfo=timezone.utc)), "0999-01-02T00:00:00Z")

    def test_lone_surrogate_in_payload_refused(self):
        r = self._verify(self._env(self._mut(lambda st: st["predicate"]["product"].update(id="\ud800"))), drop=False)
        self.assertFalse(r["verified"])
        self.assertEqual([x["code"] for x in r["reasons"]], ["payload_json"])

    # ── tests for the mutants of art14_attest.py that survived the suite of 9000fca ──
    def test_receipt_of_refusals_before_the_signatures(self):
        p = os.path.join(self.d, "m.json")
        with open(p, "w") as f:
            f.write("[]")
        r = self._verify(p)
        self.assertIs(r["trusted"], False)
        self.assertIs(r["verified"], False)

    def test_signature_entries_malformed_or_badly_encoded(self):
        from cra_evidence.art14_attest import verify_envelope
        env = json.load(open(self._env(self.payload), encoding="utf-8"))
        for extra, code, result in (("x", "envelope_malformed", "malformed"), ({"keyid": "test-signer", "sig": 5}, "envelope_malformed", "malformed"),
                                    ({"keyid": "test-signer", "sig": "@@"}, "base64", "bad_encoding")):
            with self.subTest(extra=extra):
                e = copy.deepcopy(env)
                e["signatures"].append(extra)
                p = os.path.join(self.d, "x.json")
                with open(p, "w") as f:
                    json.dump(e, f)
                r = verify_envelope(p, self.ts)
                self.assertFalse(r["verified"])
                self.assertIn(code, [x["code"] for x in r["reasons"]])
                self.assertEqual(r["signatures"][1]["result"], result)

    def test_statement_rules_checked_without_drop_and_ledger(self):
        cases = (("noticeRules", lambda st: st["predicate"].update(noticeRules="srp-notice/1"), "predicate_rule"),
                 ("source.tool", lambda st: st["predicate"]["source"].update(tool="other-tool"), "predicate_enum"),
                 ("subject []", lambda st: st.update(subject=[]), "subject"))
        for name, f, code in cases:
            with self.subTest(name=name):
                r = self._verify(self._env(self._mut(f)), drop=False)
                self.assertFalse(r["verified"])
                self.assertIn(code, [x["code"] for x in r["reasons"]])

    def test_a_refused_subject_stops_before_the_predicate(self):
        def f(st):
            st["subject"] = []
            st["predicate"]["noticeRules"] = "srp-notice/1"
        r = self._verify(self._env(self._mut(f)), drop=False)
        self.assertEqual([x["code"] for x in r["reasons"]], ["subject"])

    def test_complete_at_intermediate_must_be_null(self):
        env = json.load(open(os.path.join(V, "valid_intermediate.intoto.json"), encoding="utf-8"))
        st = json.loads(base64.b64decode(env["payload"]))
        st["predicate"]["complete"] = True
        r = self._verify(self._env(json.dumps(st, sort_keys=True, separators=(",", ":")).encode()), drop=False)
        self.assertFalse(r["verified"])
        self.assertIn("complete must be null", " ".join(x["detail"] for x in r["reasons"]))

    def test_producer_refuses_what_its_verifier_refuses(self):
        import cra_evidence.art14_attest as A
        with mock.patch.object(A, "check_statement", return_value=(None, [{"code": "x", "detail": "y"}], [])):
            with self.assertRaises(A.AttestRefused):
                A.build_statement(os.path.join(V, "drop_native_early_warning.json"), os.path.join(V, "ledger.jsonl"))

    def test_record_written_before_0_8_0_product_not_evaluated(self):
        from cra_evidence.locker import CRAEvidenceLocker
        orig = CRAEvidenceLocker._append

        def old_format(self_, entry):
            entry = dict(entry)
            if entry.get("kind") == "cra_srp_notice":
                entry.pop("product_id", None)
                entry.pop("product_version", None)
            return orig(self_, entry)
        led, drop = os.path.join(self.d, "l.jsonl"), os.path.join(self.d, "drop")
        fields = os.path.join(self.d, "f.json")
        with open(fields, "w") as f:
            json.dump({"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m",
                       "member_states_available": ["IT"], "product_name": "p", "product_version": "1",
                       "awareness_datetime_utc": "2026-11-12T08:00:00Z"}, f)
        with mock.patch.object(CRAEvidenceLocker, "_append", old_format):
            rc, out, err = cli("notice", "--ledger", led, "--product", "p", "--version", "1", "--stage", "early_warning",
                               "--fields", fields, "--drop", drop)
        self.assertEqual(rc, 0, (out, err))
        d = os.path.join(drop, os.listdir(drop)[0])
        key = os.path.join(self.d, "k")
        with open(key, "w") as f:
            f.write(hashlib.sha256(json.load(open(os.path.join(V, "manifest.json")))["test_keys"]["test-signer"]["seed_string"].encode()).hexdigest())
        from cra_evidence.art14_attest import build_statement, sign_envelope
        from cra_evidence.signing import load_key
        env = sign_envelope(build_statement(d, led, "p", "1"), load_key(key), "test-signer")
        p = os.path.join(self.d, "e.json")
        with open(p, "w") as f:
            json.dump(env, f)
        from cra_evidence.art14_attest import verify_envelope
        r = verify_envelope(p, self.ts, d, led)
        self.assertTrue(r["verified"], r["reasons"])
        self.assertTrue(r["product"].startswith("not_evaluated (the ledger record does not carry the product"), r["product"])


if __name__ == "__main__":
    unittest.main()
