# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — `cra import sbomify` closed by construction, `cra check-notice` on cra-srp/3, `cra attest` refusals.
Negative cases are mutations of the real sbomify responses (tests/fixtures/sbomify_4ef6128/) made here:

- generative: an unknown key added to EVERY object of the report and of a filing (top level, listings, next_due, values,
  snapshot, srp_fields); a wrong JSON type put on EVERY leaf; a duplicate key in EVERY object (raw text) — each refused;
- bad dates (no offset, impossible day, 7 fractional digits, before 2026-10-21), unknown product_type, bad Member State
  codes, PEC free text, unknown stage, a filing its report does not list (or lists differently), an incident with a
  vulnerability field, an awareness instant that the event does not carry (rule 8) — each refused;
- every refusal writes nothing: no ledger line, no drop file, no stored source (a refusal on the LAST filing too);
- a date with another offset is converted and listed; a PEC option text becomes its code;
- check-notice: every imported drop verifies with and without the ledger; altered source/filing blocks, an altered kept
  document and a changed mapping are each refused; rule 9 refusals (csirt_note, other glossary);
- attest: refused on a cra-srp/2 drop and on a drop the ledger does not bind; verify-attestation exit 2 on a bad trust
  store."""
import contextlib, copy, glob, hashlib, importlib.util, io, json, os, shutil, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "sbomify_4ef6128")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
REP_V = os.path.join(FIX, "report_s1AfwOnAgUPN.json")
REP_I = os.path.join(FIX, "report_BA1rXunidkQE.json")
F = lambda n: os.path.join(FIX, f"filing_{n}.json")   # noqa: E731
V_FILINGS = [F("s1AfwOnAgUPN_" + s) for s in ("early_warning_1", "notification_1", "intermediate_1", "intermediate_2",
                                               "final_report_1", "users_informed_1")]
I_FILINGS = [F("BA1rXunidkQE_early_warning_1"), F("BA1rXunidkQE_notification_1")]
COMMIT = "4ef61281e69d693e3560185bf81ec5474179ea98"


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def objects(o, path=()):
    """every (path, dict) of a JSON value"""
    if isinstance(o, dict):
        yield path, o
        for k, v in o.items():
            yield from objects(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from objects(v, path + (i,))


def leaves(o, path=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from leaves(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, path + (i,))
    else:
        yield path, o


def at(o, path):
    for p in path:
        o = o[p]
    return o


def ser_dup(o, target, path=()):
    """JSON text of o whose object at `target` carries its first key twice"""
    if isinstance(o, dict):
        items = list(o.items())
        if path == target and items:
            items = [items[0]] + items
        return "{" + ",".join(json.dumps(k) + ":" + ser_dup(v, target, path + (k,)) for k, v in items) + "}"
    if isinstance(o, list):
        return "[" + ",".join(ser_dup(v, target, path + (i,)) for i, v in enumerate(o)) + "]"
    return json.dumps(o)


class _Tmp:
    """Mixin, not a TestCase: the CI check wants every TestCase class to have run."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.n = 0

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, obj=None, raw=None):
        self.n += 1
        p = os.path.join(self.d, f"in_{self.n}.json")
        with open(p, "wb") as f:
            f.write(raw if raw is not None else json.dumps(obj).encode())
        return p

    def cli(self, *argv):
        from cra_evidence.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def imp(self, report, filings, tag="x"):
        led, drop = os.path.join(self.d, tag + ".jsonl"), os.path.join(self.d, "drop_" + tag)
        argv = ["import", "sbomify", "--report", report, "--ledger", led, "--product", "p", "--version", "1", "--drop-dir", drop,
                "--source-version", COMMIT]
        for f in filings:
            argv += ["--filing", f]
        rc, out, err = self.cli(*argv)
        return rc, out, err, led, drop

    def refused(self, report, filings, tag="x"):
        """exit 1, a JSON refusal, and nothing written: no ledger, no drop file, no stored source"""
        rc, out, err, led, drop = self.imp(report, filings, tag)
        self.assertEqual(rc, 1, out + err)
        r = json.loads(out)
        self.assertFalse(r["imported"])
        self.assertFalse(os.path.exists(led), "a refused import wrote the ledger")
        self.assertFalse(os.path.exists(led + ".sources") and os.listdir(led + ".sources"))
        self.assertFalse(os.path.isdir(drop) and os.listdir(drop), "a refused import left files in the drop folder")
        return r["reasons"][0]


class TestGenerativeClosed(_Tmp, unittest.TestCase):
    def test_unknown_key_in_every_object_is_refused(self):
        rep, fil = load(REP_V), load(V_FILINGS[1])
        n = 0
        for which, doc in (("report", rep), ("filing", fil)):
            for path, _ in list(objects(doc)):
                m = copy.deepcopy(doc)
                at(m, path)["zz_unknown"] = "x"
                with self.subTest(doc=which, path=path):
                    rp = self.write(m) if which == "report" else REP_V
                    fp = self.write(m) if which == "filing" else V_FILINGS[1]
                    self.refused(rp, [fp], tag=f"u{n}")
                    n += 1
        self.assertGreater(n, 10)

    def test_wrong_type_on_every_leaf_is_refused(self):
        rep, fil = load(REP_V), load(V_FILINGS[4])
        n = 0
        for which, doc in (("report", rep), ("filing", fil)):
            for path, v in list(leaves(doc)):
                for bad in (123, True, [], {}, [v]):
                    if type(bad) is type(v) and not isinstance(v, (list, dict)):
                        continue                       # next_due.overdue is a boolean
                    m = copy.deepcopy(doc)
                    parent = at(m, path[:-1])
                    parent[path[-1]] = bad
                    with self.subTest(doc=which, path=path, bad=bad):
                        rp = self.write(m) if which == "report" else REP_V
                        fp = self.write(m) if which == "filing" else V_FILINGS[4]
                        self.refused(rp, [fp], tag=f"t{n}")
                        n += 1
        self.assertGreater(n, 100)

    def test_duplicate_key_in_every_object_is_refused(self):
        rep, fil = load(REP_I), load(I_FILINGS[1])
        n = 0
        for which, doc in (("report", rep), ("filing", fil)):
            for path, o in list(objects(doc)):
                if not o:
                    continue
                raw = ser_dup(doc, path).encode()
                with self.subTest(doc=which, path=path):
                    rp = self.write(raw=raw) if which == "report" else REP_I
                    fp = self.write(raw=raw) if which == "filing" else I_FILINGS[1]
                    self.assertIn("duplicate key", self.refused(rp, [fp], tag=f"d{n}"))
                    n += 1
        self.assertGreater(n, 5)


class TestRefusals(_Tmp, unittest.TestCase):
    def mutate_filing(self, path, value, src=None, listing=False):
        """a filing (and, with listing=True, its report listing) with one value changed"""
        src = src or V_FILINGS[1]
        f = load(src)
        at(f, path[:-1])[path[-1]] = value
        rep = load(REP_V if "s1Af" in src else REP_I)
        if listing:
            for x in rep["filings"]:
                if x["id"] == f["id"]:
                    x[path[-1]] = value
        return (self.write(rep) if listing else (REP_V if "s1Af" in src else REP_I)), self.write(f)

    def test_bad_dates(self):
        for path, value, listing in ((("snapshot", "aware_at"), "2026-11-09T07:30:00", False),
                                     (("snapshot", "occurred_at"), "2026-02-30T22:15:00+00:00", False),
                                     (("snapshot", "aware_at"), "2026-11-09T07:30:00.1234567+00:00", False),
                                     (("filed_at",), "2026-11-11T09:00:00", True),
                                     (("filed_at",), "2026-10-20T23:59:59Z", True),
                                     (("snapshot", "aware_at"), "09/11/2026", False)):
            with self.subTest(path=path, value=value):
                rp, fp = self.mutate_filing(path, value, listing=listing)
                self.refused(rp, [fp])

    def test_before_the_glossary_16_is_refused_and_the_boundary_is_accepted(self):
        def moved(filed_at):     # the incident aware at 2026-11-12, moved back consistently so that only filed_at decides
            rep, f = load(REP_I), load(I_FILINGS[0])
            rep["aware_at"] = "2026-10-20T06:00:00Z"; f["snapshot"]["aware_at"] = "2026-10-20T06:00:00+00:00"
            f["snapshot"]["occurred_at"] = "2026-10-20T02:40:00+00:00"; rep["occurred_at"] = "2026-10-20T02:40:00Z"
            for x in rep["filings"]:
                x["filed_at"] = filed_at
            f["filed_at"] = filed_at
            return self.write(rep), self.write(f)
        rp, fp = moved("2026-10-20T23:59:59Z")
        self.assertIn("before 2026-10-21T00:00:00Z", self.refused(rp, [fp]))
        rp, fp = moved("2026-10-21T00:00:00Z")
        rc, out, err, *_ = self.imp(rp, [fp], tag="b")
        self.assertEqual(rc, 0, out + err)

    def test_values_that_do_not_convert(self):
        for sid, value in (("member_states", "AT, AT"), ("member_states", "AT, DE, AT"), ("product_type", "Medium"), ("product_type", "important"), ("member_states", "AT, XX"),
                           ("member_states", "AT,,DE"), ("member_states", "UK"), ("member_states", "at"),
                           ("member_states", ""), ("end_of_support", "Maybe")):
            with self.subTest(sid=sid, value=value):
                rp, fp = self.mutate_filing(("snapshot", "srp_fields", sid), value)
                if value == "":
                    rc, out, err, *_ = self.imp(rp, [fp], tag="e")   # empty = not a pair: imported, listed, not invented
                    self.assertEqual(rc, 0, out)
                    self.assertIn(sid, json.loads(out)["notices"][0]["empty_at_source"])
                else:
                    self.refused(rp, [fp])

    def test_pec_free_text_refused_readings_and_options(self):
        rp, fp = self.mutate_filing(("snapshot", "srp_fields", "pec"), "Yes, the CSIRT asked us to wait")
        self.assertIn("never guessed", self.refused(rp, [fp]))
        rp, fp = self.mutate_filing(("snapshot", "srp_fields", "pec"), "none")   # not exactly one of the readings
        self.refused(rp, [fp])
        from cra_evidence.srp_notice import PEC_OPTIONS
        rp, fp = self.mutate_filing(("snapshot", "srp_fields", "pec"), PEC_OPTIONS["imminent_high_risk"])
        rc, out, err, led, drop = self.imp(rp, [fp], tag="pec")
        self.assertEqual(rc, 0, out + err)
        n = json.loads(out)["notices"][0]
        self.assertIn({"sbomify_id": "pec", "from": PEC_OPTIONS["imminent_high_risk"], "to": ["imminent_high_risk"],
                       "conversion": "pec_option"}, n["normalisations"])
        d = load(os.path.join(drop, n["drop_file"]))
        self.assertEqual(d["fields"]["particular_exceptional_circumstances"], ["imminent_high_risk"])
        for reading in ("N/A", "No", "None", "Not applicable"):
            rp, fp = self.mutate_filing(("snapshot", "srp_fields", "pec"), reading)
            rc, out, err, *_ = self.imp(rp, [fp], tag="r" + reading.replace("/", ""))
            self.assertEqual(rc, 0, out + err)
            self.assertEqual(json.loads(out)["notices"][0]["readings"][0]["value"], reading)

    def test_unknown_stage(self):
        rp, fp = self.mutate_filing(("stage",), "draft", listing=True)
        self.refused(rp, [fp])
        rp, fp = self.mutate_filing(("stage",), "intermediate")   # the listing says notification
        self.assertIn("differs from its listing", self.refused(rp, [fp]))

    def test_report_filing_mismatch(self):
        self.assertIn("not listed", self.refused(REP_V, [I_FILINGS[0]]))
        rp, fp = self.mutate_filing(("srp_reference",), "SRP-OTHER")
        self.assertIn("differs from its listing", self.refused(rp, [fp]))
        self.assertIn("given twice", self.refused(REP_V, [V_FILINGS[0], V_FILINGS[0]]))

    def test_incident_with_vulnerability_fields(self):
        rp, fp = self.mutate_filing(("snapshot", "srp_fields", "cve_id"), "CVE-2099-0001", src=I_FILINGS[1])
        self.assertIn("unmapped", self.refused(rp, [fp]))
        rp, fp = self.mutate_filing(("snapshot", "measure_available_at"), "2026-11-12T06:00:00+00:00", src=I_FILINGS[1])
        self.assertIn("unmapped", self.refused(rp, [fp]))
        rep = load(REP_I); rep["values"]["cve_id"] = "CVE-2099-0001"
        self.assertIn("unmapped", self.refused(self.write(rep), I_FILINGS))

    def test_unknown_or_other_kind_key_with_an_empty_value_is_refused(self):
        for src, sid in ((V_FILINGS[1], "zz_unknown"), (I_FILINGS[1], "cve_id"), (V_FILINGS[1], "root_cause")):
            for empty in (None, ""):
                with self.subTest(sid=sid, empty=empty):
                    rp, fp = self.mutate_filing(("snapshot", "srp_fields", sid), empty, src=src)
                    self.assertIn("unmapped", self.refused(rp, [fp]))

    def test_awareness_the_event_does_not_carry(self):
        rp, fp = self.mutate_filing(("snapshot", "aware_at"), "2026-11-09T08:30:00+00:00")
        self.assertIn("binding", self.refused(rp, [fp]))

    def test_refusal_on_the_last_filing_writes_nothing(self):
        f = load(V_FILINGS[5]); f["snapshot"]["srp_fields"]["member_states"] = "AT, ZZ"
        self.refused(REP_V, V_FILINGS[:5] + [self.write(f)])

    def test_reimport_refused_and_nothing_added(self):
        rc, out, err, led, drop = self.imp(REP_I, I_FILINGS, tag="re")
        self.assertEqual(rc, 0, out + err)
        with open(led, "rb") as f:
            before = f.read()
        files = sorted(os.listdir(drop))
        rc, out, err, *_ = self.imp(REP_I, I_FILINGS[:1], tag="re")
        self.assertEqual(rc, 1); self.assertIn("already imported", out)
        with open(led, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(sorted(os.listdir(drop)), files)

    def test_other_offset_converted_and_listed(self):
        rep, f = load(REP_I), load(I_FILINGS[1])
        f["snapshot"]["aware_at"] = "2026-11-12T08:00:00+02:00"      # the same instant as 06:00Z
        rc, out, err, led, drop = self.imp(REP_I, [self.write(f)], tag="off")
        self.assertEqual(rc, 0, out + err)
        n = json.loads(out)["notices"][0]
        self.assertIn({"sbomify_id": "aware_at", "from": "2026-11-12T08:00:00+02:00", "to": "2026-11-12T06:00:00Z",
                       "conversion": "utc_offset"}, n["normalisations"])
        self.assertEqual(load(os.path.join(drop, n["drop_file"]))["previous_fields"]["awareness_datetime_utc"], "2026-11-12T06:00:00Z")

    def test_event_recorded_once_per_report(self):
        rc, out, err, led, drop = self.imp(REP_V, V_FILINGS[:2], tag="once")
        self.assertEqual(rc, 0, out + err)
        rc, out, err, *_ = self.imp(REP_V, V_FILINGS[2:], tag="once")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("already_recorded", json.loads(out)["event"])
        from cra_evidence.ledger import Ledger
        kinds = [e["data"]["kind"] for e in Ledger(led).entries()]
        self.assertEqual(kinds.count("cra_vuln"), 1); self.assertEqual(kinds.count("cra_srp_notice"), 6)


class TestWriteFailureLeavesNothing(_Tmp, unittest.TestCase):
    def test_a_drop_file_that_cannot_be_written_undoes_the_import(self):
        from cra_evidence.outputs import OutputNotWritten
        from cra_evidence.srp_notice import DryRunDrop
        real, calls = DryRunDrop.prepare, []

        def flaky(self_, notice):
            calls.append(1)
            if len(calls) == 2:
                raise OutputNotWritten("simulated full disk")
            return real(self_, notice)
        with mock.patch.object(DryRunDrop, "prepare", flaky):
            rc, out, err, led, drop = self.imp(REP_I, I_FILINGS, tag="w")
        self.assertEqual(rc, 74, out + err)
        self.assertFalse(os.path.exists(led))
        self.assertEqual(os.listdir(led + ".sources"), [])
        self.assertEqual(os.listdir(drop), [])


class TestCheckNoticeV3(_Tmp, unittest.TestCase):
    def imported(self):
        rc, out, err, led, drop = self.imp(REP_V, V_FILINGS, tag="cn")
        self.assertEqual(rc, 0, out + err)
        return led, [os.path.join(drop, n["drop_file"]) for n in json.loads(out)["notices"]]

    def check(self, drop, led=None):
        from cra_evidence.notice_check import check_notice
        return check_notice(drop, led)

    def test_every_imported_drop_verifies(self):
        led, drops = self.imported()
        rc, out, err, led2, drops2 = self.imp(REP_I, I_FILINGS, tag="cn2")
        drops += [os.path.join(drops2, n["drop_file"]) for n in json.loads(out)["notices"]]
        self.assertEqual(len(drops), 8)
        for d in drops:
            with self.subTest(drop=os.path.basename(d)):
                self.assertTrue(self.check(d)["verified"])
                r = self.check(d, led if "drop_cn" + os.sep in d else led2)
                self.assertTrue(r["verified"], r["reasons"])
                self.assertIn("re-derived from the kept source document: identical", r["notes"])
                rc, out, _ = self.cli("check-notice", d)
                self.assertEqual(rc, 0)

    def rewrite(self, path, fn, rehash=True):
        from cra_evidence.srp_notice import SourcedSRPNotice
        p = load(path)
        fn(p)
        if rehash:
            n = SourcedSRPNotice(stream=p["stream"], stage=p["stage"], fields=dict(p["fields"]), previous_fields=p["previous_fields"],
                                 glossary_version=p["glossary_version"], notice_id=p["notice_id"], generated_utc=p["generated_utc"],
                                 source=p["source"], filing=p["filing"])
            p["notice_sha3"] = n.canonical_hash()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(p, f)

    def test_altered_blocks_are_refused(self):
        led, drops = self.imported()
        fr = drops[4]
        cases = [("reading changed, hash not recomputed", lambda p: p["source"]["readings"][0].update(value="N/A"), False, False),
                 ("unknown key in source", lambda p: p["source"].update(extra=1), False, False),
                 ("unknown key in a later_stage entry", lambda p: p["source"]["readings"][0].update(extra=1), False, False),
                 ("declared_by other than the tool", lambda p: p["filing"].update(declared_by="cra-evidence"), False, False),
                 ("conversion not in the list", lambda p: p["source"]["normalisations"][0].update(conversion="guess"), False, False),
                 ("filing without the source's reference, rehashed", lambda p: p["filing"].update(srp_reference="X"), True, True),
                 ("readings dropped, rehashed", lambda p: p["source"].update(readings=[]), True, True)]
        for name, fn, rehash, needs_ledger in cases:
            with self.subTest(case=name):
                tmp = os.path.join(self.d, "alt.json")
                shutil.copyfile(fr, tmp)
                self.rewrite(tmp, fn, rehash)
                r = self.check(tmp, led if needs_ledger else None)
                self.assertFalse(r["verified"], name)

    def test_unknown_key_rebuilt_is_refused_by_the_checker(self):
        led, drops = self.imported()
        p = load(drops[0]); p["source"]["extra"] = 1
        tmp = os.path.join(self.d, "u.json")
        with open(tmp, "w") as f:
            json.dump(p, f)
        r = self.check(tmp)
        self.assertFalse(r["verified"]); self.assertIn("unknown keys", " ".join(r["reasons"]))
        p = load(drops[0]); p["surprise"] = 1
        with open(tmp, "w") as f:
            json.dump(p, f)
        self.assertIn("unknown top-level keys", " ".join(self.check(tmp)["reasons"]))

    def test_kept_document_altered_or_mapping_changed(self):
        led, drops = self.imported()
        d = drops[1]
        sha = load(d)["source"]["document_sha256"]
        kept = os.path.join(led + ".sources", sha + ".json")
        with open(kept, "rb") as f:
            raw = f.read()
        with open(kept, "wb") as f:
            f.write(raw.replace(b"Adjacent network", b"Adjacent  network"))
        self.assertIn("does not hash", " ".join(self.check(d, led)["reasons"]))
        with open(kept, "wb") as f:
            f.write(raw)
        self.assertTrue(self.check(d, led)["verified"])
        from cra_evidence import sbomify_import as si
        table = dict(si.MAPPING); table[("both", "attack_vector")] = "component_name"   # a mapping that places it elsewhere
        with mock.patch.object(si, "MAPPING", table):
            r = self.check(d, led)
        self.assertFalse(r["verified"]); self.assertIn("re-derived", " ".join(r["reasons"]))

    def test_rule9(self):
        from cra_evidence.srp_notice import SRPNotice
        n = SRPNotice("vulnerability", "intermediate", {"attack_vector": "x", "cve_id": "CVE-2099-0001"})
        self.assertIsNone(n.complete()); self.assertEqual(n.missing(), []); self.assertIsNone(n.deadline_utc())
        self.assertEqual(n.payload()["schema"], "cra-srp/2")
        for bad, why in ((lambda: SRPNotice("vulnerability", "users_informed", {"csirt_note": "x"}), "CSIRT"),
                         (lambda: SRPNotice("vulnerability", "intermediate", {"no_such": "x"}), "not in the SRP schema"),
                         (lambda: SRPNotice("vulnerability", "intermediate", {"title": 1}), "JSON type"),
                         (lambda: SRPNotice("vulnerability", "intermediate", {"title": "t"}, previous_fields={"title": 1}), "JSON type"),
                         (lambda: SRPNotice("incident", "intermediate", {"cve_id": "x"}), "not in the SRP schema"),
                         (lambda: SRPNotice("vulnerability", "intermediate", {"title": "t"}, glossary_version="enisa_srp_glossary_20260929"),
                          "srp-notice/2 only"),
                         (lambda: SRPNotice("vulnerability", "draft", {}), "unknown stream/stage")):
            with self.subTest(why=why):
                with self.assertRaises(ValueError) as cm:
                    bad()
                self.assertIn(why, str(cm.exception))

    def test_notice_cli_keeps_its_three_stages(self):
        rc, out, err = self.cli("notice", "--ledger", os.path.join(self.d, "l"), "--product", "p", "--version", "1",
                                "--stage", "intermediate", "--fields", self.write({}), "--drop", self.d)
        self.assertEqual(rc, 2)


class TestAttestRefusals(_Tmp, unittest.TestCase):
    def test_attest_refuses_a_cra_srp_2_drop_and_an_unbound_drop(self):
        from cra_evidence.art14_attest import AttestRefused, build_statement
        legacy = os.path.join(ROOT, "tests", "fixtures", "srp_legacy_nemesis", "vulnerability_early_warning_8d0a9c38-4596-4396-993e-3629d585eb50.json")
        with self.assertRaises(AttestRefused) as cm:
            build_statement(legacy, os.path.join(self.d, "none.jsonl"), "p", "1")
        self.assertIn("cra-srp/2 or cra-srp/3", str(cm.exception))
        rc, out, err, led, drop = self.imp(REP_I, I_FILINGS[:1], tag="a")
        d = glob.glob(os.path.join(drop, "incident_*.json"))[0]
        other = os.path.join(self.d, "other.jsonl")
        self.imp(REP_V, V_FILINGS[:1], tag="other")
        with self.assertRaises(AttestRefused):
            build_statement(d, other, "p", "1")          # this ledger does not record the drop
        st = json.loads(build_statement(d, led, "p", "1"))
        self.assertEqual(st["predicate"]["ledger"]["entryIndex"], 1)
        self.assertIsNotNone(st["predicate"]["deadlineAt"])

    def test_rule9_keeps_the_future_awareness_refusal(self):
        from cra_evidence.srp_notice import SRPNotice
        for stage in ("intermediate", "users_informed"):
            with self.assertRaises(ValueError) as cm:
                SRPNotice("vulnerability", stage, {"awareness_datetime_utc": "2099-01-01T00:00:00Z"})
            self.assertIn("future", str(cm.exception))

    def native(self):
        led = os.path.join(self.d, "n.jsonl")
        ew = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
              "product_name": "p", "product_version": "1", "awareness_datetime_utc": "2026-11-01T08:00:00Z", "cve_id": "CVE-2026-0002"}
        rc, out, err = self.cli("notice", "--ledger", led, "--product", "prod", "--version", "9", "--stage", "early_warning",
                                "--fields", self.write(ew), "--drop", os.path.join(self.d, "nd"))
        self.assertEqual(rc, 0, out + err)
        return led, os.path.join(self.d, "nd", json.loads(out)["drop_file"])

    def test_native_statement(self):
        from cra_evidence import __version__
        from cra_evidence.art14_attest import AttestRefused, build_statement
        led, d = self.native()
        with open(d, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        st = json.loads(build_statement(d, led))
        pr = st["predicate"]
        self.assertEqual(pr["source"], {"tool": "cra-evidence", "toolVersion": __version__, "documentSha256": sha, "absentAtSource": []})
        self.assertIsNone(pr["filing"]); self.assertEqual(pr["product"], {"id": "prod", "version": "9"})
        self.assertTrue(pr["complete"]); self.assertEqual(st["subject"][0]["digest"]["sha256"], sha)
        st = json.loads(build_statement(d, led, filing={"srp_reference": "", "filed_at": "2026-11-01T21:00:00+01:00", "filed_by": ""}))
        self.assertEqual(st["predicate"]["filing"], {"declaredBy": "cra-evidence", "srpReference": "", "filedAt": "2026-11-01T20:00:00Z", "filedBy": ""})
        for kw, why in (({"product_id": "other"}, "differs from the product"), ({"product_version": "8"}, "differs from the product"),
                        ({"filing": {"srp_reference": "x", "filed_at": "2026-11-01T21:00:00", "filed_by": ""}}, "--filed-at"),
                        ({"filing": {"srp_reference": "x", "filed_at": "", "filed_by": ""}}, "--filed-at")):
            with self.subTest(kw=kw):
                with self.assertRaises(AttestRefused) as cm:
                    build_statement(d, led, **kw)
                self.assertIn(why, str(cm.exception))
        rc, out, err, led3, drop3 = self.imp(REP_I, I_FILINGS[:1], tag="f3")
        d3 = glob.glob(os.path.join(drop3, "incident_*.json"))[0]
        with self.assertRaises(AttestRefused) as cm:
            build_statement(d3, led3, filing={"srp_reference": "", "filed_at": "2026-11-12T13:00:00Z", "filed_by": ""})
        self.assertIn("cra-srp/3", str(cm.exception))
        rc, out, err = self.cli("attest", d, "--ledger", led, "--key", "k", "--signer-id", "a", "--out", os.path.join(self.d, "o"),
                                "--srp-reference", "SRP-1")
        self.assertEqual(rc, 2)

    def test_product_not_evaluated_only_when_the_record_lacks_it(self):
        from cra_evidence.art14_attest import AttestRefused, build_statement, check_statement
        from cra_evidence.canonical import sha3_hex
        from cra_evidence.ledger import Ledger
        led, d = self.native()
        old = os.path.join(self.d, "old.jsonl")              # the same records as cra-evidence 0.7.1 wrote them: no product
        for e in Ledger(led).entries():
            data = {k: v for k, v in e["data"].items() if k not in ("product_id", "product_version", "record_sha3")}
            data["record_sha3"] = sha3_hex(data)
            Ledger(old).append(data, ts=e["ts"])
        with self.assertRaises(AttestRefused) as cm:
            build_statement(d, old)
        self.assertIn("does not carry the product", str(cm.exception))
        st = json.loads(build_statement(d, old, "declared-product", "7"))
        self.assertEqual(st["predicate"]["product"], {"id": "declared-product", "version": "7"})
        if HAVE_CRYPTO:
            key = os.path.join(self.d, "k")
            rc, out, _ = self.cli("keygen", key)
            ts = self.write({"a": json.loads(out)["public_key_hex"]})
            for ledger, product, want, rc_want in ((old, ["--product", "declared-product", "--version", "7"], "not_evaluated", 0),
                                                   (led, [], "PASS", 0)):
                env = os.path.join(self.d, "e.json")
                rc, out, err = self.cli("attest", d, "--ledger", ledger, "--key", key, "--signer-id", "a", "--out", env, *product)
                self.assertEqual(rc, 0, out + err)
                rc, out, err = self.cli("verify-attestation", env, "--trust-store", ts, "--drop", d, "--ledger", ledger)
                r = json.loads(out)
                self.assertEqual(rc, rc_want, out); self.assertTrue(r["product"].startswith(want), r["product"])
            # a statement whose ledger entry is not the one given: rule 3 refuses it, the product is not judged on it
            rc, out, err = self.cli("attest", d, "--ledger", old, "--key", key, "--signer-id", "a", "--out", env, "--product", "x", "--version", "7")
            rc, out, err = self.cli("verify-attestation", env, "--trust-store", ts, "--drop", d, "--ledger", led)
            r = json.loads(out)
            self.assertEqual(rc, 1); self.assertIn("rule3", [x["code"] for x in r["reasons"]])
            self.assertTrue(r["product"].startswith("not_evaluated (the ledger entry"), r["product"])

    def test_verify_attestation_usage(self):
        v = os.path.join(ROOT, "spec", "art14-filing", "v0.1", "vectors")
        rc, out, err = self.cli("verify-attestation", os.path.join(v, "valid_early_warning.intoto.json"),
                                "--trust-store", self.write(raw=b'{"a":"b","a":"c"}'))
        self.assertEqual(rc, 2)
        rc, out, err = self.cli("verify-attestation", os.path.join(v, "valid_early_warning.intoto.json"))
        self.assertEqual(rc, 2)

    @unittest.skipUnless(HAVE_CRYPTO, "signing needs cryptography")
    def test_attest_then_verify_round_trip_and_tamper(self):
        rc, out, err, led, drop = self.imp(REP_V, V_FILINGS, tag="rt")
        key = os.path.join(self.d, "k")
        rc, out, _ = self.cli("keygen", key)
        ts = self.write({"acme": json.loads(out)["public_key_hex"]})
        for d in sorted(glob.glob(os.path.join(drop, "vulnerability_*.json"))):
            env = d + ".intoto.json"
            rc, out, err = self.cli("attest", d, "--ledger", led, "--product", "p", "--version", "1", "--key", key,
                                    "--signer-id", "acme", "--out", env)
            self.assertEqual(rc, 0, out + err)
            rc, out, err = self.cli("verify-attestation", env, "--trust-store", ts, "--drop", d, "--ledger", led)
            self.assertEqual(rc, 0, out)
            r = json.loads(out)
            self.assertEqual((r["drop"], r["ledger"]), ("PASS", "PASS"))
            rc, out, err = self.cli("verify-attestation", env, "--trust-store", ts)
            self.assertEqual(rc, 0); self.assertEqual(json.loads(out)["ledger"], "not_evaluated")
            with open(d, "rb") as f:
                raw = f.read()
            with open(d, "wb") as f:
                f.write(raw + b" ")                       # one byte more: not the subject any more
            rc, out, err = self.cli("verify-attestation", env, "--trust-store", ts, "--drop", d)
            self.assertEqual(rc, 1); self.assertIn("subject_digest", out)


if __name__ == "__main__":
    unittest.main()
