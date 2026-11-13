# SPDX-License-Identifier: AGPL-3.0-or-later
"""Review of 12/11/2026 (glossary 1.6 change): the paths the first tests left open, each test failing on the code before
the fix or on a mutant of it — srp-notice/1 kept frozen (an N/A field and non-string values accepted in a notice written by
0.6.0), a 0.3.x drop file, the ledger's negative answers, the submission statement, an unknown glossary_version, the hash
covering glossary_version, a refused binding leaving no file, a new notice only under the current glossary, values the
canonical profile refuses, JSON equality, the drift check's version line / notes / local errors, and the fetch retry."""
import contextlib, copy, http.server, io, json, os, shutil, subprocess, sys, tempfile, threading, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from omega_cra_evol.canonical import sha3_hex                                          # noqa: E402
from omega_cra_evol.cli import main                                                    # noqa: E402
from omega_cra_evol.notice_check import check_notice                                   # noqa: E402
from omega_cra_evol.srp_notice import CURRENT_GLOSSARY, SRPNotice, template            # noqa: E402
import srp_glossary                                                                  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "srp_legacy_nemesis")
V060_NA = os.path.join(FIX, "vulnerability_early_warning_d3d6c417-0af7-4c84-8909-64cff5311284.json")   # cra-evidence 0.6.0
V033 = os.path.join(FIX, "vulnerability_early_warning_8d0a9c38-4596-4396-993e-3629d585eb50.json")      # cra-evidence 0.3.3
EW = {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m", "member_states_available": ["IT"],
      "product_name": "p", "product_version": "1.0", "awareness_datetime_utc": "2026-11-01T08:00:00Z", "cve_id": "CVE-2026-0002"}
G0929 = "enisa_srp_glossary_20260929"


def _rehash(p):
    body = {k: p[k] for k in ("stream", "stage", "fields", "generated_utc", "notice_id", "previous_fields", "glossary_version")}
    p["notice_sha3"] = sha3_hex(body)
    return p


class _Tmp:
    """Mixin, not a TestCase: the CI check wants every TestCase class to have run."""
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, name, obj, raw=None):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(raw if raw is not None else json.dumps(obj).encode())
        return p

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()


class TestLegacyFrozen(_Tmp, unittest.TestCase):
    def test_060_notice_with_na_field_and_integers_still_verifies(self):
        with open(V060_NA, encoding="utf-8") as f:
            p = json.load(f)
        self.assertIn("attack_vector", p["fields"]); self.assertIsInstance(p["fields"]["component_name"], int)   # N/A at EW, not a string
        r = check_notice(V060_NA)
        self.assertTrue(r["verified"], r); self.assertEqual((r["glossary_version"], r["rules"]), (G0929, "srp-notice/1"))

    def test_033_notice_is_read_under_the_glossary_of_15_09(self):
        r = check_notice(V033)
        self.assertTrue(r["verified"], r); self.assertEqual(r["glossary_version"], "enisa_srp_glossary_20260915")


class TestCheckNoticeRefusals(_Tmp, unittest.TestCase):
    def drop(self):
        return SRPNotice("vulnerability", "notification", {"general_information": "g"}, previous_fields=dict(EW)).payload()

    def test_valid_control(self):
        self.assertTrue(check_notice(self.write("ok.json", self.drop()))["verified"])

    def test_submission_statement_altered(self):
        p = self.drop(); p["submission"] = p["submission"] + " "
        self.assertFalse(check_notice(self.write("s.json", p))["verified"])

    def test_unknown_or_non_string_glossary_version_is_a_reason_not_a_crash(self):
        for v in ("enisa_srp_glossary_20990101", ["x"], 3):
            p = self.drop(); p["glossary_version"] = v
            r = check_notice(self.write("g.json", p))
            self.assertFalse(r["verified"]); self.assertIn("glossary_version", r["reasons"][0])

    def test_glossary_source_must_match_the_version(self):
        p = self.drop(); p["glossary_source"] = "x"
        self.assertFalse(check_notice(self.write("gs.json", p))["verified"])

    def test_cra_srp_2_under_an_srp_notice_1_glossary_is_refused(self):
        p = SRPNotice("vulnerability", "early_warning", dict(EW), glossary_version=G0929).payload()
        r = check_notice(self.write("dg.json", p))
        self.assertFalse(r["verified"]); self.assertIn("no release writes that combination", r["reasons"][0])

    def test_values_the_canonical_profile_refuses_are_reasons(self):
        with open(V060_NA, encoding="utf-8") as f:
            base = json.load(f)
        for val in (1.5, 2 ** 60):
            p = copy.deepcopy(base); p["fields"]["component_name"] = val
            r = check_notice(self.write("f.json", p))          # used to raise TypeError out of check_notice
            self.assertFalse(r["verified"]); self.assertIn("not rebuildable", r["reasons"][0])
        p = self.drop(); p["generated_utc"] = 1.5
        self.assertFalse(check_notice(self.write("gu.json", p))["verified"])
        for gu in (1, None, [], "yesterday"):
            p = _rehash(dict(self.drop(), generated_utc=gu))
            self.assertFalse(check_notice(self.write("gu2.json", p))["verified"], gu)

    def test_json_equality_not_python_equality(self):
        p = SRPNotice("vulnerability", "early_warning", dict(EW)).payload()
        self.assertIs(p["complete"], True); p["complete"] = 1                  # 1 == True in Python, not in JSON
        self.assertFalse(check_notice(self.write("c.json", p))["verified"])

    def test_hash_covers_glossary_version(self):
        n = SRPNotice("vulnerability", "early_warning", dict(EW))
        from dataclasses import asdict
        body = asdict(n)
        self.assertEqual(n.canonical_hash(), sha3_hex(body))
        body.pop("glossary_version")
        self.assertNotEqual(n.canonical_hash(), sha3_hex(body))

    def test_template_values(self):
        t = template("vulnerability", "early_warning")
        self.assertEqual(t["title"], ""); self.assertEqual(t["member_states_available"], [])


class TestLedgerNegatives(_Tmp, unittest.TestCase):
    def setUp(self):
        super().setUp()
        led = os.path.join(self.d, "l.jsonl"); drop = os.path.join(self.d, "drop")
        self.write("ew.json", EW)
        rc, out, err = self.cli("notice", "--ledger", led, "--product", "p", "--version", "1", "--stage", "early_warning",
                                "--fields", os.path.join(self.d, "ew.json"), "--drop", drop)
        self.assertEqual(rc, 0, err)
        self.led, self.f = led, os.path.join(drop, json.loads(out)["drop_file"])

    def test_control(self):
        self.assertTrue(check_notice(self.f, self.led)["verified"])

    def test_missing_ledger(self):
        self.assertFalse(check_notice(self.f, os.path.join(self.d, "none.jsonl"))["verified"])

    def test_broken_chain(self):
        with open(self.led, encoding="utf-8") as f:
            lines = f.read().splitlines(True)
        e = json.loads(lines[0]); e["data"]["product_id"] = "x"
        with open(self.led, "w", encoding="utf-8") as f:
            f.write(json.dumps(e) + "\n" + "".join(lines[1:]))
        self.assertFalse(check_notice(self.f, self.led)["verified"])

    def test_same_content_other_bytes_is_not_bound(self):
        with open(self.f, encoding="utf-8") as f:
            p = json.load(f)
        with open(self.f, "w", encoding="utf-8") as f:
            json.dump(p, f, indent=3)
        r = check_notice(self.f, self.led)
        self.assertTrue(check_notice(self.f)["verified"]); self.assertFalse(r["verified"]); self.assertIn("drop_sha3", r["reasons"][0])

    def test_two_records_for_one_notice(self):
        with open(self.led, encoding="utf-8") as f:
            lines = f.read().splitlines(True)
        self.assertEqual(sum('"cra_srp_notice"' in x for x in lines), 1)
        rc, out, err = self.cli("check-notice", self.f, "--ledger", self.led)
        self.assertEqual(rc, 0, out)
        with open(self.f, encoding="utf-8") as f:
            p = json.load(f)
        from omega_cra_evol.locker import EvidenceLocker
        n = SRPNotice(p["stream"], p["stage"], p["fields"], generated_utc=p["generated_utc"], notice_id=p["notice_id"])
        EvidenceLocker(self.led, "p", "1").record_notice(n, {"status": "not_written"})
        self.assertFalse(check_notice(self.f, self.led)["verified"])


    def _forged_ledger(self, change, rehash=True):
        """A second, chain-valid ledger holding the same notice record with one change."""
        from omega_cra_evol.ledger import Ledger
        with open(self.led, encoding="utf-8") as f:
            rec = [json.loads(x)["data"] for x in f if '"cra_srp_notice"' in x][0]
        rec = dict(rec); change(rec)
        if rehash:
            rec["record_sha3"] = sha3_hex({k: v for k, v in rec.items() if k != "record_sha3"})
        led2 = os.path.join(self.d, "l2.jsonl")
        Ledger(led2).append(rec)
        return led2

    def test_forged_control(self):
        self.assertTrue(check_notice(self.f, self._forged_ledger(lambda r: None))["verified"])

    def test_record_that_disagrees_with_the_file(self):
        r = check_notice(self.f, self._forged_ledger(lambda r: r.update(complete=False)))
        self.assertFalse(r["verified"]); self.assertIn("ledger record complete", " ".join(r["reasons"]))

    def test_record_digest_that_does_not_recompute(self):
        r = check_notice(self.f, self._forged_ledger(lambda r: r.update(stage="notification"), rehash=False))
        self.assertFalse(r["verified"]); self.assertIn("record_sha3", " ".join(r["reasons"]))

    def test_unreadable_ledger(self):
        with open(self.led, "a", encoding="utf-8") as f:
            f.write("{not json\n")
        r = check_notice(self.f, self.led)
        self.assertFalse(r["verified"]); self.assertIn("ledger", " ".join(r["reasons"]))


class TestMoreRefusals(_Tmp, unittest.TestCase):
    def test_unknown_schema_is_a_reason(self):
        p = SRPNotice("vulnerability", "early_warning", dict(EW)).payload(); p["schema"] = "cra-srp/4"
        r = check_notice(self.write("s.json", p))
        self.assertFalse(r["verified"]); self.assertIn("not cra-srp/1, cra-srp/2 or cra-srp/3", r["reasons"][0])
        p["schema"] = "cra-srp/3"           # exists since 0.8.0 (rule 10): a cra-srp/2 payload relabelled lacks source and filing
        r = check_notice(self.write("s3.json", p))
        self.assertFalse(r["verified"]); self.assertIn("missing top-level keys for cra-srp/3: ['filing', 'source']", r["reasons"][0])

    def test_a_carried_value_missing_from_the_file_fields(self):
        p = SRPNotice("vulnerability", "notification", {"general_information": "g"},
                      previous_fields=dict(EW, vulnerability_occurred_datetime_utc="2026-10-30T00:00:00Z")).payload()
        self.assertIn("vulnerability_occurred_datetime_utc", p["fields"])        # v26a copied (By default copied)
        del p["fields"]["vulnerability_occurred_datetime_utc"]                 # notice_sha3 still covers it
        r = check_notice(self.write("c.json", p))
        self.assertFalse(r["verified"]); self.assertIn("fields change when rebuilt", " ".join(r["reasons"]))

    def test_previous_datetimes_parsed_under_srp_notice_2_only(self):
        with self.assertRaises(ValueError):
            SRPNotice("vulnerability", "notification", {"general_information": "g"},
                      previous_fields=dict(EW, corrective_available_date="yesterday"))
        n72_0929 = {"general_information": "g", "vulnerability_occurred_datetime_utc": "2026-10-30T00:00:00Z"}
        SRPNotice("vulnerability", "notification", n72_0929, previous_fields=dict(EW, corrective_available_date="yesterday"),
                  glossary_version=G0929)                                      # srp-notice/1 frozen: not parsed there


class TestCli(_Tmp, unittest.TestCase):
    def test_a_new_notice_is_built_under_the_current_glossary_only(self):
        f = self.write("ew.json", EW)
        rc, out, err = self.cli("notice", "--ledger", os.path.join(self.d, "l.jsonl"), "--product", "p", "--version", "1",
                                "--stage", "early_warning", "--fields", f, "--drop", os.path.join(self.d, "drop"), "--glossary", G0929)
        self.assertEqual(rc, 2, err); self.assertFalse(os.path.exists(os.path.join(self.d, "drop")))
        rc, out, err = self.cli("schema", "--stream", "vulnerability", "--glossary", G0929)    # reading an old glossary stays
        self.assertEqual(rc, 0); self.assertEqual(json.loads(out)["glossary_version"], G0929)
        self.assertEqual(CURRENT_GLOSSARY, "enisa_srp_glossary_20261112")

    def test_a_refused_binding_writes_no_drop_file(self):
        led = os.path.join(self.d, "l.jsonl"); drop = os.path.join(self.d, "drop")
        rc, _, err = self.cli("vuln", "--ledger", led, "--product", "p", "--version", "1", "--id", "CVE-2026-0002",
                              "--aware", "2026-11-01T08:00:00Z", "--exploited", "--allow-overdue")
        self.assertEqual(rc, 0, err)
        f = self.write("ew.json", dict(EW, awareness_datetime_utc="2026-11-01T09:00:00Z"))
        rc, _, err = self.cli("notice", "--ledger", led, "--product", "p", "--version", "1", "--stage", "early_warning",
                              "--fields", f, "--drop", drop)
        self.assertEqual(rc, 1); self.assertIn("differs from the recorded awareness", err)
        self.assertEqual(os.listdir(drop) if os.path.isdir(drop) else [], [])


class TestDrift(_Tmp, unittest.TestCase):
    HTML = os.path.join(ROOT, "tests", "fixtures", "enisa", "enisa_srp_glossary_20261112.html")
    SNAP = os.path.join(ROOT, "spec", "sources", "enisa_srp_glossary_20261112.json")

    def run_check(self, html):
        out = io.StringIO()
        return srp_glossary.check(html, self.SNAP, out=out), out.getvalue()

    def test_version_line_and_notes_are_compared(self):
        with open(self.HTML, encoding="utf-8") as f:
            html = f.read()
        self.assertEqual(self.run_check(html)[0], 0)
        rc, out = self.run_check(html.replace("Version 1.6. Last update: 21 October 2026", "Version 1.7. Last update: 20 November 2026"))
        self.assertEqual(rc, 1, out); self.assertIn("version line", out)
        i = html.rfind("</table>") + 8
        rc, out = self.run_check(html[:i] + "<p>[1] A note on a field.</p>" + html[i:])
        self.assertEqual(rc, 1, out); self.assertIn("notes outside the table", out)

    def test_every_snapshot_has_its_page_record_and_the_newest_is_the_code_s(self):
        names = sorted(n for n in os.listdir(os.path.dirname(self.SNAP)) if n.startswith("enisa_srp_glossary_") and n.endswith(".json"))
        self.assertEqual(sorted(srp_glossary.PAGE), names)
        self.assertEqual(os.path.basename(srp_glossary.newest_snapshot()), CURRENT_GLOSSARY + ".json")

    def test_local_errors_are_2_never_1(self):
        s = os.path.join(ROOT, "scripts", "srp_glossary.py")
        for args in (["check", "--html", os.path.join(self.d, "none.html")], ["check", "--html", self.HTML, "--snapshot", os.path.join(self.d, "none.json")]):
            r = subprocess.run([sys.executable, "-I", s, *args], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_fetch_retries_429_and_5xx_only(self):
        seq, hits = [], []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                code = seq.pop(0) if seq else 200
                hits.append(code); self.send_response(code); self.end_headers()
                if code == 200:
                    self.wfile.write(b"<html>ok</html>")
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_port}/"
        try:
            seq[:] = [429, 503]; hits.clear()
            self.assertEqual(srp_glossary.fetch(url, attempts=3, wait=0), "<html>ok</html>"); self.assertEqual(hits, [429, 503, 200])
            seq[:] = [404]; hits.clear()
            with self.assertRaises(Exception):
                srp_glossary.fetch(url, attempts=3, wait=0)
            self.assertEqual(hits, [404])
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
