# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026, the rename to omega-cra-evol. Rules on the whole tree (every file, history and data included), checked
on every run:
  1. no file names another party's product: the words "CRA" and "Evidence" joined by a space, a hyphen or an
     underscore with those capitals, the two words separated by white space in any case, or joined in any case
     (a package or domain name) — except this project's earlier class name;
  2. that class name appears only where it is the subject: the deprecated aliases, the changelog and their tests;
  3. the earlier project name in lower case (`cra-evidence`, `cra_evidence`) is this project's own earlier name and is
     allowed (history, frozen identifiers, the alias); README carries it in the one rename line only.
The forbidden strings are assembled from pieces, so that this file carries none of them. Positive controls: the same
function reports planted occurrences."""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B = "CRA", "Evidence"
CLASS = A + B + "Locker"
FORBIDDEN = [
    re.compile(A + r"[  _-]" + B),                         # the two words with those capitals, joined or spaced
    re.compile(r"(?i)\b" + A.lower() + r"[\s ]+" + B.lower()),   # the two words in any case, separated by white space
    re.compile(r"(?i)" + A.lower() + B.lower() + r"(?!Locker)"),       # joined, any case (a package or domain name)
    re.compile(r"(?i:" + A.lower() + B.lower() + r"locker)(?<!" + CLASS + r")"),   # the class name in another case
]
CLASS_ALLOWED_IN = ("CHANGELOG.md", "cra_evidence/", "omega_cra_evol/__init__.py", "omega_cra_evol/locker.py",
                    "tests/test_rename_20261113.py")
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


class NoOtherPartyIsNamed(unittest.TestCase):
    def test_no_file_names_another_product(self):
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
                    A + chr(0xA0) + B.lower(), "pip install " + A.lower() + B.lower(), A + B + " Ltd",
                    "https://" + A.lower() + B.lower() + ".example", A.upper() + B.upper(), A.lower() + B + "Locker"):
            self.assertTrue(others_in(bad), bad)
        for ok in ("cra-evidence", "cra_evidence_pack/1", "omega-cra-evol", "the cra command; evidence pack", CLASS,
                   "CRA Art. 14 evidence"):
            self.assertEqual(others_in(ok), [], ok)


class TheEarlierClassName(unittest.TestCase):
    def test_only_where_it_is_the_subject(self):
        found = sorted(rel for rel, text in files() if CLASS in text)
        self.assertEqual([r for r in found if not r.startswith(CLASS_ALLOWED_IN)], [])
        self.assertIn("omega_cra_evol/locker.py", found)        # the walk saw the alias


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
