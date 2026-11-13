# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026, the rename to omega-cra-evol. Rules on the whole tree (every file, history and data included), checked
on every run:
  1. the earlier name is written only in its own forms: never the two words with capitals joined by a space, a
     hyphen or an underscore, never the two words separated by white space in any case, never the two words joined
     in any case (the earlier class name included: it is not kept);
  2. (no exception: the locker class is EvidenceLocker);
  3. the earlier project name in lower case (`cra-evidence`, `cra_evidence`) is this project's own earlier name and is
     allowed (history, frozen identifiers, the alias); README carries it in the one rename line only.
The forbidden strings are assembled from pieces, so that this file carries none of them. Positive controls: the same
function reports planted occurrences."""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B = "CRA", "Evidence"
CLASS = A + B + "Locker"
FORBIDDEN = [
    re.compile(A + r"[ \u00a0_-]" + B),                         # the two words with those capitals, joined or spaced
    re.compile(r"(?i)\b" + A.lower() + r"[\s\u00a0]+" + B.lower()),   # the two words in any case, separated by white space
    re.compile(r"(?i)" + A.lower() + B.lower()),                       # the two words joined, any case
]
SKIP_DIRS = {".git", "__pycache__", "target", "build", "dist", "node_modules", ".eggs"}


def others_in(text):
    return [m.group(0) for p in FORBIDDEN for m in p.finditer(text)]


def files():
    for d, dirs, names in os.walk(ROOT):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.endswith(".egg-info"))
        for fn in sorted(names):
            p = os.path.join(d, fn)
            rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
            if "/lax_control_tmp_" in "/" + rel:       # a mutated copy one suite writes while it runs
                continue
            try:
                with open(p, "rb") as f:
                    yield rel, f.read().decode("utf-8", "replace")
            except OSError:
                continue


class TheEarlierNameInItsOwnForms(unittest.TestCase):
    def test_no_other_form_of_the_earlier_name(self):
        found, n = {}, 0
        for rel, text in files():
            n += 1
            hits = others_in(text) + others_in(rel)
            if hits:
                found[rel] = hits[:3]
        self.assertGreater(n, 300, "the walk must have seen the repository")
        self.assertEqual(found, {})

    def test_positive_control(self):
        for bad in (A + " " + B, "the " + A + "-" + B + " platform", A + "_" + B, A.lower() + " " + B.lower() + " pack",
                    A + chr(0xA0) + B.lower(), "pip install " + A.lower() + B.lower(), A + B + " pack",
                    "x/" + A.lower() + B.lower() + "/y", A.upper() + B.upper(), A.lower() + B + "Locker", CLASS):
            self.assertTrue(others_in(bad), bad)
        for ok in ("cra-evidence", "cra_evidence_pack/1", "omega-cra-evol", "the cra command; evidence pack", "EvidenceLocker",
                   "CRA Art. 14 evidence"):
            self.assertEqual(others_in(ok), [], ok)


class TheEarlierProjectName(unittest.TestCase):
    def test_readme_names_it_in_the_rename_line_only(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertTrue(readme.startswith("# omega-cra-evol\n"))
        lines = [l for l in readme.splitlines() if "cra-evidence" in l or "cra_evidence" in l]
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(lines[0].startswith("_Renamed from `cra-evidence` to `omega-cra-evol` in 0.10.0"), lines[0])

    def test_metadata_carries_the_new_name(self):
        for rel in ("pyproject.toml", "CITATION.cff", "Dockerfile", "action.yml"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn("cra-evidence", text, rel)
            self.assertIn("omega-cra-evol", text, rel)


if __name__ == "__main__":
    unittest.main()
