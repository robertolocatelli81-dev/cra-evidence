# SPDX-License-Identifier: AGPL-3.0-or-later
"""scripts/srp_glossary.py: the extractor reproduces the vendored snapshot from the saved page byte for byte, and the drift
check exits 0 on the same glossary, 1 with a readable diff on any change, 2 when there is no glossary to read. The saved
page is ENISA's CRA SRP Glossary of 21/10/2026 as fetched on 12/11/2026 (tests/fixtures/enisa/, reproduction authorised
with acknowledgement of the source)."""
import hashlib, io, os, re, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import srp_glossary                                                                 # noqa: E402

SRC = os.path.join(ROOT, "spec", "sources")
HTML = os.path.join(ROOT, "tests", "fixtures", "enisa", "enisa_srp_glossary_20261112.html")
G16 = "enisa_srp_glossary_20261112"


class TestExtractor(unittest.TestCase):
    def test_extractor_reproduces_the_vendored_snapshot_byte_for_byte(self):
        with open(HTML, "rb") as f:
            raw = f.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "fb24151b894277d03cc3c745b6d5c29c57de72cbfc7e9b1b356f6af4bc2fbc33")
        with open(os.path.join(SRC, G16 + ".json"), encoding="utf-8") as f:
            self.assertEqual(srp_glossary.serialise(srp_glossary.extract(raw.decode("utf-8"))), f.read())
        self.assertEqual(srp_glossary.page_version(raw.decode("utf-8")), "Version 1.6. Last update: 21 October 2026")


class TestDriftCheck(unittest.TestCase):
    def run_check(self, html):
        out = io.StringIO()
        rc = srp_glossary.check(html, os.path.join(SRC, G16 + ".json"), out=out)
        return rc, out.getvalue()

    def setUp(self):
        with open(HTML, encoding="utf-8") as f:
            self.html = f.read()

    def test_equal_is_0_and_any_change_is_1_with_a_readable_diff(self):
        self.assertEqual(srp_glossary.newest_snapshot(), os.path.join(SRC, G16 + ".json"))
        rc, out = self.run_check(self.html); self.assertEqual(rc, 0, out); self.assertIn("identical: 49 rows, 43 numbered fields", out)
        cases = [("Optional upon PEC activation", "Required", "row v29. [72h]: 'Optional upon PEC activation' -> 'Required'"),
                 ("<strong>AR Note</strong>", "<strong>AR Notes</strong>", "row 40. [Field]: 'AR Note' -> 'AR Notes'"),
                 ("(max. 800 characters)", "(max. 900 characters)", "row v30. [How you may complete it]")]
        for a, b, expect in cases:
            self.assertEqual(self.html.count(a), 1, a)
            rc, out = self.run_check(self.html.replace(a, b))
            self.assertEqual(rc, 1, out); self.assertIn("DRIFT", out); self.assertIn(expect, out)
        i = self.html.index("<tr>", self.html.index("<strong>41.</strong>") - 200)
        rc, out = self.run_check(self.html[:i] + self.html[self.html.index("</tr>", i) + 5:])     # a row removed
        self.assertEqual(rc, 1); self.assertIn("row 41. removed", out)

    def test_extraction_rules_on_a_synthetic_table(self):
        head = "<tr>" + "".join(f"<th>{h}</th>" for h in srp_glossary.HEADER) + "</tr>"
        cells = ["1.", "a<br>b", "c<p>d</p>", "e&nbsp;f\u00a0g", "<li>h</li><li>i</li>", " j \n k ", "&amp;", "R", "N/A", "N/A"]
        snap = srp_glossary.extract("<table>" + head + "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr></table>")
        self.assertEqual(snap["rows"], [["1.", "a b", "c d", "e f g", "h i", "j k", "&", "R", "N/A", "N/A"]])

    def test_no_table_or_another_table_is_2(self):
        self.assertEqual(self.run_check("<html><body>maintenance</body></html>")[0], 2)
        self.assertEqual(self.run_check("<table><tr><td>a</td></tr></table>")[0], 2)
        self.assertEqual(self.run_check(self.html + "<table><tr><td>x</td></tr></table>")[0], 2)

    def test_command_line_offline(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "srp_glossary.py"), "check", "--html", HTML],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "x.html")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.html.replace("Optional upon PEC activation", "Required"))
            r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "srp_glossary.py"), "check", "--html", p],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 1, r.stdout); self.assertIn("row v29.", r.stdout)
            r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "srp_glossary.py"), "check", "--url", "http://127.0.0.1:9/"],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2, r.stdout); self.assertIn("FETCH FAILED", r.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_workflow_is_pinned_read_only_and_runs_the_check(self):
        with open(os.path.join(ROOT, ".github", "workflows", "srp-glossary-drift.yml"), encoding="utf-8") as f:
            wf = f.read()
        self.assertIn("schedule:", wf); self.assertIn("cron:", wf); self.assertIn("contents: read", wf)
        self.assertIn("python3 scripts/srp_glossary.py check", wf); self.assertNotIn("${{ secrets", wf); self.assertNotIn("write", wf.split("permissions:")[1].split("jobs:")[0])
        uses = re.findall(r"uses:\s*(\S+)", wf)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
