# SPDX-License-Identifier: AGPL-3.0-or-later
"""ENISA CRA SRP glossary "Version 1.6. Last update: 21 October 2026", read 12/11/2026 (spec/SRP_FIELDS.md): the tables
derived from every vendored snapshot, the notice rules srp-notice/2 tried over the whole field x stage x type space, the
notices recorded under the earlier glossaries still checked under theirs. Each bench is shown able to fail (positive
controls). The extractor and the drift check: tests/test_srp_glossary_drift.py."""
import contextlib, copy, io, json, os, re, shutil, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from omega_cra_evol.cli import main                                                   # noqa: E402
from omega_cra_evol.locker import EvidenceLocker                                   # noqa: E402
from omega_cra_evol.notice_check import check_notice                                  # noqa: E402
from omega_cra_evol.srp_notice import (CURRENT_GLOSSARY, GLOSSARIES, LEGACY_SOURCES, STAGES, SRPNotice,  # noqa: E402
                                     schema, template)
from omega_cra_evol.vuln import VulnerabilityRecord                                   # noqa: E402
import gen_srp_fields                                                               # noqa: E402

SRC = os.path.join(ROOT, "spec", "sources")
LEGACY = os.path.join(ROOT, "tests", "fixtures", "srp_legacy_060")
G16, G0929, G0915 = "enisa_srp_glossary_20261112", "enisa_srp_glossary_20260929", "enisa_srp_glossary_20260915"
ROW = re.compile(r"[vi]?\d+[a-z]?\.")
# every glossary cell text met so far -> (code, condition). A text not listed is not guessed: the derivation fails.
CELL = {"Required": ("R", None), "Mandatory": ("R", None), "Optional": ("O", None), "N/A": ("-", None),
        "By default copied from previous step, or updated": ("C", None), "By default copied from previous step": ("C", None),
        "Required if such information available": ("A", None),
        "Optional(after completion of v17)": ("O", "user_measures"), "Optional (after completion of v17)": ("O", "user_measures"),
        "Optional upon PEC activation": ("O", "particular_exceptional_circumstances"),
        "Optional under PEC activation": ("O", "particular_exceptional_circumstances")}
AW = "2026-11-01T08:00:00Z"
EW_V = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
        "product_name": "p", "product_version": "1", "awareness_datetime_utc": AW, "cve_id": "CVE-2026-0001"}
EW_I = {**{k: v for k, v in EW_V.items() if k != "cve_id"}, "notification_type": "Incident", "suspected_malicious": "Unknown"}
N72_V = {"general_information": "g"}
N72_I = {"incident_nature": "n", "initial_assessment": "a"}
FR_V = {"corrective_measures_taken": "c", "user_measures": "u", "corrective_available_date": "2026-11-05T00:00:00Z",
        "security_update_details": "d", "severity_description": "sev", "impact_description": "imp"}
FR_I = {"corrective_measures_taken": "c", "user_measures": "u", "mitigation_measures": "m", "severity_description": "sev",
        "impact_description": "imp", "threat_type_root_cause": "r"}
MINIMAL = {("vulnerability", "early_warning"): EW_V, ("vulnerability", "notification"): N72_V, ("vulnerability", "final_report"): FR_V,
           ("incident", "early_warning"): EW_I, ("incident", "notification"): N72_I, ("incident", "final_report"): FR_I}
PREVIOUS = {("vulnerability", "early_warning"): None, ("vulnerability", "notification"): EW_V, ("vulnerability", "final_report"): N72_V,
            ("incident", "early_warning"): None, ("incident", "notification"): EW_I, ("incident", "final_report"): N72_I}


def _load(name):
    with open(os.path.join(SRC, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def derive(snapshot, version):
    """The module's tables for `version` must be the snapshot's, row by row: number, order, scope, stage codes,
    conditions, and (srp-notice/2) the maximum lengths the glossary states and the i31 format."""
    rows = [r for r in snapshot["rows"] if len(r) >= 10 and ROW.match(r[0])]
    ours = [(scope, k, s) for scope, t in GLOSSARIES[version]["groups"] for k, s in t.items()]
    assert len(rows) == len(ours), (len(rows), len(ours))
    for r, (scope, k, s) in zip(rows, ours):
        assert s["glossary_row"] + "." == r[0], (s["glossary_row"], r[0])
        assert scope == r[2], (k, scope, r[2])
        codes = {st: CELL[r[7 + i]] for i, st in enumerate(STAGES)}           # KeyError on an unknown cell text
        assert s["stages"] == {st: c for st, (c, _) in codes.items()}, (k, s["stages"], r[7:10])
        assert s.get("when", {}) == {st: w for st, (_, w) in codes.items() if w}, (k, s.get("when"))
        if GLOSSARIES[version]["rules"] == "srp-notice/2":
            m = re.search(r"max\.\s*(\d+)", r[4])
            if r[6] != "System-generated / read-only" and r[6] != "Select one configured category":
                assert (int(m.group(1)) if m else None) == s.get("max"), (k, m and m.group(1), s.get("max"))
            if r[6] == "Free text":
                assert s["format"] == "text", k
    return len(rows)


class TestDerivation(unittest.TestCase):
    def test_every_version_is_derived_from_its_snapshot(self):
        self.assertEqual(derive(_load(G16), G16), 43)
        self.assertEqual(derive(_load(G0929), G0929), 40)
        self.assertEqual(derive(_load(G0915), G0915), 39)
        self.assertEqual(len(schema("vulnerability")), 34); self.assertEqual(len(schema("incident")), 30)
        self.assertEqual(CURRENT_GLOSSARY, G16)

    def test_positive_controls(self):
        with self.assertRaises(AssertionError):                    # the old snapshot against the new tables
            derive(_load(G0929), G16)
        with self.assertRaises(AssertionError):                    # the 1.4 page (01/10/2026) has no row 7a
            derive(_load("enisa_srp_glossary_20261010"), G16)
        snap = _load(G16)
        for r in snap["rows"]:
            if r and r[0] == "i38.":
                r[8] = "Required"                                  # i38 as it was before 21/10/2026
        with self.assertRaises(AssertionError):
            derive(snap, G16)
        snap = _load(G16)
        snap["rows"][2][8] = "Copied"                              # a cell text never seen
        with self.assertRaises(KeyError):
            derive(snap, G16)

    def test_measured_changes_since_29_09(self):
        old = {r[0]: r for r in _load(G0929)["rows"] if len(r) >= 10}
        new = {r[0]: r for r in _load(G16)["rows"] if len(r) >= 10}
        self.assertEqual(sorted(set(new) - set(old)), ["40.", "41.", "7a."]); self.assertEqual(set(old) - set(new), set())
        renamed = sorted(k for k in old if old[k][1] != new[k][1])
        self.assertEqual(renamed, ["1.", "11.", "5.", "i37.", "v24.", "v25.", "v26.", "v28."])   # + v26a's id spacing: none in the extract
        copied_to_na = {st: sorted(k for k in old if old[k][7 + i].startswith("By default copied") and new[k][7 + i] == "N/A")
                        for i, st in ((1, "72h"), (2, "FR"))}
        self.assertEqual(len(copied_to_na["72h"]), 17); self.assertEqual(len(copied_to_na["FR"]), 25)
        self.assertEqual((old["i38."][8], new["i38."][8]), ("Required", "Optional"))


class TestSnapshotAndDocument(unittest.TestCase):
    def test_spec_tables_are_the_generated_ones(self):
        with open(os.path.join(ROOT, "spec", "SRP_FIELDS.md"), encoding="utf-8") as f:
            doc = f.read()
        self.assertEqual(gen_srp_fields.render(doc), doc)
        self.assertIn('"glossary_version": "enisa_srp_glossary_20261112"', doc)
        broken = doc.replace("| v21 | `general_information` | O | R | - |", "| v21 | `general_information` | O | O | - |")
        self.assertNotEqual(broken, doc); self.assertNotEqual(gen_srp_fields.render(broken), broken)   # positive control


class TestRulesV2(unittest.TestCase):
    def build(self, stream, stage, fields, previous="default", **kw):
        prev = PREVIOUS[(stream, stage)] if previous == "default" else previous
        return SRPNotice(stream, stage, copy.deepcopy(fields), previous_fields=copy.deepcopy(prev), **kw)

    def test_minimal_payloads_are_complete(self):
        for (stream, stage), f in MINIMAL.items():
            n = self.build(stream, stage, f)
            self.assertTrue(n.complete(), (stream, stage, n.missing()))
            self.assertEqual(n.glossary_version, G16); self.assertEqual(n.payload()["glossary_version"], G16)

    def test_every_na_field_present_is_refused_and_absent_is_accepted(self):
        n = 0
        for (stream, stage), f in MINIMAL.items():
            for k, spec in schema(stream).items():
                if spec["stages"][stage] != "-":
                    continue
                value = ["IT"] if spec["format"] in ("list", "enum-list") else (spec["enum"][0] if spec.get("enum") else
                                                                                ("2026-10-01T00:00:00Z" if spec["format"] == "datetime-utc" else "x"))
                if spec["format"] == "enum-list":
                    value = [spec["enum"][0]]
                with self.assertRaisesRegex(ValueError, "not a field of stage", msg=(stream, stage, k)):
                    self.build(stream, stage, {**f, k: value})
                for empty in (None, "") if spec["format"] not in ("list", "enum-list") else (None, []):
                    self.build(stream, stage, {**f, k: empty})     # absent = accepted
                n += 1
        self.assertEqual(n, 86)                                    # = the N/A cells of the snapshot over both streams (counted apart)

    def test_every_required_field_missing_is_reported_and_never_complete(self):
        n = 0
        for (stream, stage), f in MINIMAL.items():
            for k in list(f):
                spec = schema(stream)[k]
                if spec["stages"][stage] != "R" or k == "awareness_datetime_utc":
                    continue
                g = {x: v for x, v in f.items() if x != k}
                nt = self.build(stream, stage, g)
                self.assertEqual(nt.missing(), [k]); self.assertFalse(nt.complete()); self.assertFalse(nt.payload()["complete"])
                n += 1
            if schema(stream)["awareness_datetime_utc"]["stages"][stage] == "R":
                with self.assertRaisesRegex(ValueError, "required"):
                    self.build(stream, stage, {x: v for x, v in f.items() if x != "awareness_datetime_utc"})
        self.assertEqual(n, 30)                                    # = 32 Required/Mandatory cells minus the 2 awareness ones

    def test_unknown_keys_at_every_level(self):
        junk = ["x", "End of support indicator", "End of the support indicator", "Notification type (Vulnerability/Incident)",
                "end_of_support_indicator", "v26a .", "TITLE", "title ", "csirt note", "", " ", "glossary_version"]
        for (stream, stage), f in MINIMAL.items():
            other = "incident" if stream == "vulnerability" else "vulnerability"
            foreign = sorted(set(schema(other)) - set(schema(stream)))
            for k in junk + foreign:
                with self.assertRaisesRegex(ValueError, "not in the SRP schema", msg=(stream, stage, k)):
                    self.build(stream, stage, {**f, k: "x"})
                with self.assertRaisesRegex(ValueError, "not in the SRP schema", msg=(stream, stage, k)):
                    self.build(stream, stage, f, previous={**(PREVIOUS[(stream, stage)] or {}), k: "x"})

    def test_wrong_json_types_are_refused_for_every_field(self):
        wrong_text = [0, 1.5, True, {"a": "b"}, ["x"], [["x"]]]
        wrong_list = ["IT", 3, {"IT": True}, [1], [["IT"]], [None], [{"x": "y"}]]
        n = 0
        for (stream, stage), f in MINIMAL.items():
            for k, spec in schema(stream).items():
                if spec["stages"][stage] == "-" or spec.get("entered_by"):
                    continue
                for bad in (wrong_list if spec["format"] in ("list", "enum-list") else wrong_text):
                    with self.assertRaises(ValueError, msg=(stream, stage, k, bad)):
                        self.build(stream, stage, {**f, k: bad})
                    n += 1
        self.assertGreater(n, 500)

    def test_previous_fields_types_are_checked(self):
        for k, bad in (("title", 5), ("member_states_available", "IT"), ("summary", {"a": "b"}), ("awareness_datetime_utc", 1.5)):
            with self.assertRaisesRegex(ValueError, "previous_fields", msg=k):
                self.build("vulnerability", "notification", N72_V, previous={**EW_V, k: bad})
        with self.assertRaises(ValueError):
            self.build("vulnerability", "notification", N72_V, previous={**EW_V, "awareness_datetime_utc": "2026-11-01T08:00:00"})   # naive
        SRPNotice("vulnerability", "notification", {**EW_V, "general_information": "g"}, previous_fields={**EW_V, "title": 5},
                  glossary_version=G0929)          # srp-notice/1 is frozen: the type rule is not applied there

    def test_conditions(self):
        for stage, f in (("early_warning", EW_V), ("notification", N72_V)):
            with self.assertRaisesRegex(ValueError, "only when user_measures"):
                self.build("vulnerability", stage, {**f, "corrective_available_date": "2026-11-02T00:00:00Z"})
            self.build("vulnerability", stage, {**f, "corrective_available_date": "2026-11-02T00:00:00Z", "user_measures": "u"})
        self.build("vulnerability", "notification", {**N72_V, "corrective_available_date": "2026-11-02T00:00:00Z"},
                   previous={**EW_V, "user_measures": "u"})              # v17 completed at the early warning
        for k, v in (("pec_delay_reason", ["imminent_high_risk"]), ("further_information_cdac", "x")):
            with self.assertRaisesRegex(ValueError, "only when particular_exceptional_circumstances"):
                self.build("vulnerability", "notification", {**N72_V, k: v})
            with self.assertRaisesRegex(ValueError, "only when particular_exceptional_circumstances"):
                self.build("vulnerability", "notification", {**N72_V, k: v, "particular_exceptional_circumstances": []})
            self.build("vulnerability", "notification", {**N72_V, k: v, "particular_exceptional_circumstances": ["imminent_high_risk"]})
        with self.assertRaisesRegex(ValueError, "only when particular_exceptional_circumstances"):   # v28 counts in this payload only
            self.build("vulnerability", "notification", {**N72_V, "pec_delay_reason": ["imminent_high_risk"]},
                       previous={**EW_V, "particular_exceptional_circumstances": ["imminent_high_risk"]})
        with self.assertRaisesRegex(ValueError, "not a field of stage"):     # v28 at the early warning
            self.build("vulnerability", "early_warning", {**EW_V, "particular_exceptional_circumstances": ["imminent_high_risk"]})

    def test_csirt_note_refused_ar_note_accepted_at_every_stage(self):
        for (stream, stage), f in MINIMAL.items():
            with self.assertRaisesRegex(ValueError, "entered by the designated CSIRT"):
                self.build(stream, stage, {**f, "csirt_note": "x"})
            self.assertEqual(self.build(stream, stage, {**f, "ar_note": "note"}).fields["ar_note"], "note")
            self.assertNotIn("csirt_note", template(stream, stage)); self.assertIn("ar_note", template(stream, stage))

    def test_copy_forward_only_where_the_glossary_copies(self):
        ew = {**EW_V, "vulnerability_occurred_datetime_utc": "2026-10-30T00:00:00Z", "product_type": "Default"}
        n = self.build("vulnerability", "notification", N72_V, previous=ew)
        self.assertEqual(sorted(n.fields), ["general_information", "vulnerability_occurred_datetime_utc"])
        self.assertEqual(n.deadline_utc(), "2026-11-04T08:00:00+00:00")          # awareness from the early warning
        self.assertIsNone(self.build("vulnerability", "notification", N72_V, previous=None).deadline_utc())
        ni = self.build("incident", "notification", N72_I)
        self.assertEqual(sorted(ni.fields), ["incident_nature", "initial_assessment", "suspected_malicious"])
        self.assertEqual(ni.missing(), [])                                          # i38 optional at 72 h since 21/10/2026
        self.assertEqual(self.build("incident", "notification", N72_I, previous=None).missing(), ["suspected_malicious"])
        old = SRPNotice("incident", "notification", {**EW_I, **N72_I}, glossary_version=G0929)
        self.assertIn("incident_datetime_utc", old.missing())                     # positive control: R at 72 h before

    def test_i31_is_free_text_now_and_an_enum_before(self):
        self.build("incident", "early_warning", {**EW_I, "suspected_malicious": "Yes - credential stuffing seen in the logs"})
        with self.assertRaises(ValueError):
            self.build("incident", "early_warning", {**EW_I, "suspected_malicious": "x" * 256})
        with self.assertRaises(ValueError):
            SRPNotice("incident", "early_warning", {**EW_I, "suspected_malicious": "Yes - credential stuffing"}, glossary_version=G0929)

    def test_unknown_glossary_version_refused(self):
        for v in ("enisa_srp_glossary_20261010", "1.6", "", None, 3):
            with self.assertRaises(ValueError):
                SRPNotice("vulnerability", "early_warning", dict(EW_V), glossary_version=v)

    def test_record_binds_awareness_through_the_previous_stage(self):
        d = tempfile.mkdtemp()
        try:
            lk = EvidenceLocker(os.path.join(d, "l.jsonl"), "p", "1")
            lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2026-0001", True, AW))
            e = lk.record_notice(self.build("vulnerability", "notification", N72_V))
            self.assertEqual(len(e["data"]["bound_vuln_records"]), 1); self.assertEqual(e["data"]["glossary_version"], G16)
            with self.assertRaisesRegex(ValueError, "differs from the recorded awareness"):
                lk.record_notice(self.build("vulnerability", "notification", N72_V, previous={**EW_V, "awareness_datetime_utc": "2026-10-31T00:00:00Z"}))
        finally:
            shutil.rmtree(d, ignore_errors=True)


def _cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(list(args))
    return rc, out.getvalue()


class TestCheckNotice(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, name, obj, raw=None):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(raw if raw is not None else json.dumps(obj))
        return p

    def notice(self, stage, fields, previous=None, extra=()):
        led, drop = os.path.join(self.d, "l.jsonl"), os.path.join(self.d, "drop")
        args = ["notice", "--ledger", led, "--product", "p", "--version", "1", "--stage", stage, "--drop", drop,
                "--fields", self.write(stage + ".json", fields)] + (["--previous", self.write(stage + "_prev.json", previous)] if previous else []) + list(extra)
        rc, out = _cli(*args)
        return rc, (os.path.join(drop, json.loads(out)["drop_file"]) if rc in (0, 1) and out else None), led

    def test_new_notices_round_trip_and_tampering_is_seen(self):
        rc, ew, led = self.notice("early_warning", EW_V)
        self.assertEqual(rc, 0)
        rc, n72, _ = self.notice("notification", N72_V, previous=EW_V)
        self.assertEqual(rc, 0)
        for p in (ew, n72):
            r = check_notice(p, led)
            self.assertTrue(r["verified"], r); self.assertEqual(r["glossary_version_from"], "recorded"); self.assertEqual(r["notice_sha3"], "recomputed")
            self.assertTrue(check_notice(p)["verified"])
            self.assertEqual(_cli("check-notice", p, "--ledger", led)[0], 0)
        with open(n72, encoding="utf-8") as f:
            pay = json.load(f)
        self.assertEqual(pay["schema"], "cra-srp/2"); self.assertEqual(pay["glossary_version"], G16); self.assertEqual(pay["previous_fields"], EW_V)
        for mutate in (lambda q: q["fields"].update(general_information="other"), lambda q: q.update(glossary_version=G0929),
                       lambda q: q.update(extra=1), lambda q: q.pop("previous_fields"), lambda q: q.update(complete=False),
                       lambda q: q["fields"].update(title="t"), lambda q: q.update(previous_fields=None),
                       lambda q: q.update(glossary_source=LEGACY_SOURCES and GLOSSARIES[G0929]["source"])):
            q = copy.deepcopy(pay); mutate(q)
            p = self.write("t.json", q)
            self.assertFalse(check_notice(p)["verified"], q); self.assertFalse(check_notice(p, led)["verified"])
            self.assertEqual(_cli("check-notice", p)[0], 1)
        self.assertFalse(check_notice(self.write("dup.json", None, raw='{"schema": "cra-srp/2", "schema": "cra-srp/1"}'))["verified"])
        self.assertFalse(check_notice(self.write("arr.json", None, raw="[]"))["verified"])

    def test_ledger_record_glossary_version_must_match(self):
        rc, ew, led = self.notice("early_warning", EW_V)
        self.assertTrue(check_notice(ew, led)["verified"])
        rec = [json.loads(x)["data"] for x in open(led, encoding="utf-8") if '"cra_srp_notice"' in x][0]
        led2 = os.path.join(self.d, "l2.jsonl")
        lk = EvidenceLocker(led2, "p", "1")
        body = {k: v for k, v in rec.items() if k != "record_sha3"}
        lk._append({**body, "glossary_version": G0929})
        r = check_notice(ew, led2)
        self.assertFalse(r["verified"]); self.assertTrue(any("glossary_version" in x for x in r["reasons"]), r)
        lk2 = EvidenceLocker(os.path.join(self.d, "l3.jsonl"), "p", "1"); lk2._append(dict(body))   # control: same record
        self.assertTrue(check_notice(ew, os.path.join(self.d, "l3.jsonl"))["verified"])

    def test_refusals_write_nothing_and_exit_1(self):
        drop = os.path.join(self.d, "drop")
        for bad in ({**N72_V, "title": "t"}, {**N72_V, "csirt_note": "x"}, {**N72_V, "x": 1}, {**N72_V, "general_information": 4}):
            rc, _, _ = self.notice("notification", bad, previous=EW_V)
            self.assertEqual(rc, 1)
        p = self.write("dup.json", None, raw='{"general_information": "a", "general_information": "b"}')
        rc, _ = _cli("notice", "--ledger", os.path.join(self.d, "l.jsonl"), "--product", "p", "--version", "1", "--stage", "notification",
                     "--fields", p, "--drop", drop)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(drop) and os.listdir(drop)); self.assertFalse(os.path.exists(os.path.join(self.d, "l.jsonl")))
        rc, _, _ = self.notice("notification", {}, previous=EW_V)     # missing required: written, incomplete, exit 1
        self.assertEqual(rc, 1); self.assertEqual(len(os.listdir(drop)), 1)

    def test_old_notices_still_verify_under_their_glossary(self):
        ex = os.path.join(ROOT, "examples", "self_evidence")
        exd = os.path.join(ex, "drop", "vulnerability_early_warning_61110a92-bc09-4e8f-837e-3b0ab18b3cc9.json")
        r = check_notice(exd, os.path.join(ex, "cra.ledger.jsonl"))
        self.assertTrue(r["verified"], r); self.assertEqual((r["glossary_version"], r["notice_sha3"]), (G0929, "recomputed"))
        # written by cra-evidence 0.6.0 (origin/master f18097e) on 12/11/2026: an early warning and a 72 h notification built
        # with --previous (its notice_sha3 covered previous_fields, which 0.6.0 did not write: only the ledger binds it)
        led = os.path.join(LEGACY, "cra.ledger.jsonl")
        files = sorted(os.path.join(LEGACY, "drop", f) for f in os.listdir(os.path.join(LEGACY, "drop")))
        ew, n72 = [f for f in files if "_early_warning_" in f][0], [f for f in files if "_notification_" in f][0]
        self.assertTrue(check_notice(ew)["verified"]); self.assertTrue(check_notice(ew, led)["verified"])
        alone = check_notice(n72)
        self.assertFalse(alone["verified"]); self.assertEqual(alone["notice_sha3"], "differs")
        bound = check_notice(n72, led)
        self.assertTrue(bound["verified"], bound); self.assertEqual(bound["notice_sha3"], "bound_by_ledger")
        self.assertEqual(bound["glossary_version"], G0929)
        # under the glossary of today the same 72 h payload would be refused (awareness and title are N/A at 72 h)
        with open(n72, encoding="utf-8") as f:
            legacy = json.load(f)
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "notification", dict(legacy["fields"]))
        # a legacy file altered by one byte of a field is not verified, with or without the ledger
        legacy["fields"]["general_information"] += "!"
        p = self.write("alt.json", legacy)
        self.assertFalse(check_notice(p)["verified"]); self.assertFalse(check_notice(p, led)["verified"])
        with open(ew, encoding="utf-8") as f:
            pristine = json.load(f)
        self.assertTrue(check_notice(self.write("ok.json", pristine))["verified"])            # control: the copy verifies
        for src in ("ENISA CRA SRP Glossary (41 fields), read 2026-10-01", GLOSSARIES[G16]["source"], None, 7):
            r = check_notice(self.write("src.json", {**pristine, "glossary_source": src}))
            self.assertFalse(r["verified"], src); self.assertIsNone(r["glossary_version"])

    def test_a_15_09_notice_is_read_as_such(self):
        n = SRPNotice("vulnerability", "notification", {**EW_V, "general_information": "g"}, glossary_version=G0915,
                      generated_utc="2026-09-16T00:00:00+00:00")
        object.__setattr__(n, "_unversioned", True)
        pay = n.payload()
        for k in ("glossary_version", "previous_fields"):
            pay.pop(k)
        pay.update(schema="cra-srp/1", glossary_source="ENISA CRA SRP Glossary (39 fields), read 2026-09-15")
        r = check_notice(self.write("o.json", pay))
        self.assertTrue(r["verified"], r); self.assertEqual(r["glossary_version"], G0915); self.assertTrue(pay["complete"])
        self.assertFalse(SRPNotice("vulnerability", "notification", {**EW_V, "general_information": "g"}, glossary_version=G0929).complete())


if __name__ == "__main__":
    unittest.main()
