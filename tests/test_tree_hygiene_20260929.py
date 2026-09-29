# SPDX-License-Identifier: AGPL-3.0-or-later
"""29/09/2026: the Syft and cdxgen fixtures of 20/09/2026, and the example ledger that stores one of them, carried the
working path of the machine they were generated on (a user's home directory under a scratch path). Regenerated from a
neutral directory; this test keeps it that way: no file of the repository may carry a path under a home directory or
a machine-specific scratch path. The one absolute path allowed is the neutral sample directory the fixtures were
scanned from. Positive control: a file with such a path must be reported by the same function. The forbidden strings are assembled at run time so that this file carries none of them."""
import os, re, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", "node_modules", "target", ".pytest_cache", "build", "dist"}
SKIP_SUFFIXES = (".pyc", ".png", ".jpg", ".gz", ".zip", ".whl")
ALLOWED_TMP = "/tmp/tiny-cra-sample/"                                       # the neutral directory the sample was scanned from
# the patterns are assembled from pieces so that this file does not itself carry the strings it forbids (the walk reads it)
HOME, USERS = "/" + "home/", "/" + "Users/"
LEAKS = [re.compile(p) for p in (
    HOME + r"[A-Za-z0-9_.-]+/",                                             # a user's home directory
    USERS + r"[A-Za-z0-9_.-]+/",                                            # the same on macOS
    r"C:\\Users\\",                                                         # the same on Windows
    r"/tmp/(?!tiny-cra-sample/)[A-Za-z0-9_.-]*[0-9]{3,}",                   # a scratch path with a numeric id (uid, pid, session)
    "-" + r"home-[A-Za-z0-9]+-",                                            # a home path flattened into a directory name
)]


def leaks_in(text):
    """every (pattern, match) found in the text — the tree must have none"""
    return [(p.pattern, m.group(0)) for p in LEAKS for m in p.finditer(text)]


def repository_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            if not f.endswith(SKIP_SUFFIXES):
                yield os.path.join(dirpath, f)


class TreeHygiene(unittest.TestCase):
    def test_no_file_carries_a_local_path(self):
        found = {}
        n = 0
        for path in repository_files():
            n += 1
            with open(path, "rb") as f:
                text = f.read().decode("utf-8", "replace")
            hits = leaks_in(text)
            if hits:
                found[os.path.relpath(path, ROOT)] = hits[:3]
        self.assertGreater(n, 50, "the walk must have seen the repository")
        self.assertEqual(found, {})

    def test_the_fixtures_and_the_example_name_the_neutral_directory_only(self):
        # the Syft CycloneDX fixture and the example ledger carry the scanned lockfile as a `file` component: its path
        # must be the neutral one and nothing else absolute
        for rel in ("tests/fixtures/real_tools/syft-1.52.0_cyclonedx-1.7.json", "examples/self_evidence/cra.ledger.jsonl"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                text = f.read()
            absolute = set(re.findall(r'"(/[^"]*)"', text))
            self.assertTrue(all(a.startswith(ALLOWED_TMP) or a.startswith("/package-lock.json") for a in absolute), (rel, absolute))
            self.assertIn(ALLOWED_TMP + "package-lock.json", text, rel)

    def test_positive_control_a_local_path_is_reported(self):
        # the samples are assembled at run time so that this file itself carries none of them (the walk reads it too)
        for sample in (HOME + "someone/project/x.json", "scratch-1000/-" + "home-someone-project-package/9ffad4ee/scratchpad/x",
                       "/tmp/" + "scratch-1000/x", USERS + "someone/x", "C:\\Users" + "\\someone\\x"):
            self.assertTrue(leaks_in(sample), sample)
        self.assertEqual(leaks_in(ALLOWED_TMP + "package-lock.json"), [])
        self.assertEqual(leaks_in("/usr/lib/python3/dist-packages"), [])
        with tempfile.TemporaryDirectory() as d:                              # the walk's reader, on a planted file
            p = os.path.join(d, "planted.json")
            with open(p, "w") as f:
                f.write('{"name": "' + HOME + 'someone/src/package-lock.json"}')
            with open(p, "rb") as f:
                self.assertTrue(leaks_in(f.read().decode("utf-8", "replace")))


if __name__ == "__main__":
    unittest.main()
