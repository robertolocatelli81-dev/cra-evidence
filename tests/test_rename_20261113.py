# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026, 0.10.0: the project is omega-cra-evol. The distribution, the package, the two commands and the version
string carry the new name everywhere they are compared (pyproject, Dockerfile, container workflow, action); the
earlier import name `cra_evidence`, `python -m cra_evidence.cli` and the class name `CRAEvidenceLocker` keep working
with a DeprecationWarning until a release on or after 2027-03-31, and every name reached through them is the SAME
object as under the new name (one implementation). Real processes, so that this run's import state hides nothing.
Positive control: with warnings as errors the earlier names fail and the new ones do not."""
import json, os, pkgutil, re, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import omega_cra_evol  # noqa: E402

OLD, NEW, DIST = "cra_evidence", "omega_cra_evol", "omega-cra-evol"
ENV = dict(os.environ, PYTHONPATH=ROOT)
ENV.pop("PYTHONWARNINGS", None)
PACK = os.path.join(ROOT, "tests", "fixtures", "signed_pack", "p.json")
SUBMODULES = sorted(m.name for m in pkgutil.iter_modules(omega_cra_evol.__path__))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def pyproject_version():
    return re.search(r'^version = "([^"]+)"$', read("pyproject.toml"), re.M).group(1)


def py(*args):
    return subprocess.run([sys.executable, "-B", *args], capture_output=True, text=True, env=ENV, cwd=tempfile.gettempdir())


class Names(unittest.TestCase):
    def test_distribution_package_commands(self):
        t = read("pyproject.toml")
        self.assertRegex(t, r'(?m)^name = "omega-cra-evol"$')
        self.assertIn('cra = "omega_cra_evol.cli:main"\n', t)
        self.assertIn('omega-cra-evol = "omega_cra_evol.cli:main"\n', t)
        self.assertRegex(t, r'(?m)^packages = \["omega_cra_evol", "cra_evidence"\]')
        self.assertEqual(omega_cra_evol.__version__, pyproject_version())
        self.assertEqual(pyproject_version(), "0.10.0")

    def test_version_string_of_the_command(self):
        for mod in (NEW, OLD):
            r = py("-m", mod + ".cli", "--version")
            self.assertEqual((r.returncode, r.stdout), (0, f"{DIST} {pyproject_version()}\n"), (mod, r.stderr))

    def test_every_comparison_of_the_version_string_uses_the_new_name(self):
        d = read("Dockerfile")
        self.assertIn('test "$(cra --version)" = "omega-cra-evol ${CRA_VERSION}"', d)
        self.assertIn('test "$(omega-cra-evol --version)" = "omega-cra-evol ${CRA_VERSION}"', d)
        self.assertIn('org.opencontainers.image.source="https://github.com/robertolocatelli81-dev/omega-cra-evol"', d)
        self.assertIn('org.opencontainers.image.title="omega-cra-evol"', d)
        c = read(".github", "workflows", "container.yml")
        self.assertIn('test "$(docker run --rm "$IMAGE:$V" --version)" = "omega-cra-evol $V"', c)
        self.assertIn("IMAGE: ghcr.io/robertolocatelli81-dev/omega-cra-evol\n", c)
        a = read("action.yml")
        self.assertIn("REPO: robertolocatelli81-dev/omega-cra-evol\n", a)
        self.assertIn("#   - uses: robertolocatelli81-dev/omega-cra-evol@v" + pyproject_version() + "\n", a)
        self.assertIn('version=f"omega-cra-evol {__version__}"', read("omega_cra_evol", "cli.py"))
        # nothing compares against the earlier name any more
        for rel, text in (("Dockerfile", d), ("container.yml", c), ("action.yml", a)):
            self.assertNotIn("cra-evidence", text, rel)
            self.assertNotIn("cra_evidence", text, rel)

    def test_positive_control_the_comparison_sees_a_wrong_name(self):
        self.assertNotIn('= "omega-cra-evol ${CRA_VERSION}"', read("Dockerfile").replace("omega-cra-evol ${CRA_VERSION}", "x ${CRA_VERSION}"))


class Alias(unittest.TestCase):
    def test_every_submodule_and_public_name_is_the_same_object(self):
        code = f"""
import importlib, warnings
warnings.simplefilter("ignore")
import {OLD}, {NEW}
subs = {SUBMODULES!r}
for s in subs:
    assert importlib.import_module("{OLD}." + s) is importlib.import_module("{NEW}." + s), s
from {OLD} import CRAEvidenceLocker, EvidenceLocker, SBOMRecord, SRPNotice, VulnerabilityRecord, verify_pack, __version__
from {OLD}.locker import CRAEvidenceLocker as viaLocker, PACK_KIND
from {OLD}.ledger import Ledger
from {OLD}.cli import main
import {OLD}.cli as c, {OLD}.signing as sg
assert CRAEvidenceLocker is viaLocker is EvidenceLocker is {NEW}.EvidenceLocker
assert CRAEvidenceLocker.__name__ == "EvidenceLocker"
assert (SBOMRecord, SRPNotice, VulnerabilityRecord) == ({NEW}.SBOMRecord, {NEW}.SRPNotice, {NEW}.VulnerabilityRecord)
assert callable(verify_pack) and verify_pack is {NEW}.verify_pack and {OLD}.verify_pack is {NEW}.verify_pack
assert __version__ == {NEW}.__version__ and Ledger is {NEW}.ledger.Ledger and main is {NEW}.cli.main
assert c is {NEW}.cli and sg is {NEW}.signing
for name in dir({NEW}):
    if not name.startswith("_"):
        assert getattr({OLD}, name) is getattr({NEW}, name), name
print(len(subs), "ok")
"""
        r = py("-c", code)
        self.assertEqual((r.returncode, r.stdout), (0, f"{len(SUBMODULES)} ok\n"), r.stderr)
        self.assertGreaterEqual(len(SUBMODULES), 17)
        self.assertIn("cli", SUBMODULES)

    def test_importing_the_earlier_name_warns_names_the_new_one_and_the_date(self):
        r = py("-c", f"import {OLD}")                      # in __main__: Python shows a DeprecationWarning by default
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stderr, r"(?m)^<string>:1: DeprecationWarning: the import name 'cra_evidence' is deprecated: "
                                   r"use 'omega_cra_evol' .*2027-03-31")   # attributed to the importing line
        for imp in (f"from {OLD}.ledger import Ledger", f"import {OLD}.signing"):
            r = py("-c", imp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("DeprecationWarning", r.stderr, imp)

    def test_the_earlier_class_name_warns_from_each_place(self):
        for imp in (f"from {NEW} import CRAEvidenceLocker", f"from {NEW}.locker import CRAEvidenceLocker",
                    f"import warnings; warnings.simplefilter('ignore'); import {OLD}; warnings.resetwarnings(); "
                    f"warnings.simplefilter('default'); from {OLD} import CRAEvidenceLocker"):
            r = py("-c", imp + f"; from {NEW} import EvidenceLocker; assert CRAEvidenceLocker is EvidenceLocker")
            self.assertEqual(r.returncode, 0, (imp, r.stderr))
            self.assertIn("DeprecationWarning: CRAEvidenceLocker is deprecated: use EvidenceLocker", r.stderr, imp)
        r = py("-c", f"import {NEW}; {NEW}.NoSuchName")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("AttributeError", r.stderr)

    def test_positive_control_warnings_as_errors(self):
        for imp in (f"import {OLD}", f"from {NEW} import CRAEvidenceLocker"):
            r = py("-W", "error::DeprecationWarning", "-c", imp)
            self.assertEqual(r.returncode, 1, imp)
            self.assertIn("DeprecationWarning", r.stderr)
        r = py("-W", "error", "-c", f"import {NEW}, {NEW}.cli, {NEW}.kms, {NEW}.feeds, {NEW}.longterm; "
                                    f"from {NEW} import EvidenceLocker; print('clean')")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "clean\n", ""))

    def test_the_new_package_never_imports_the_earlier_name(self):
        for m in SUBMODULES + ["__init__"]:
            self.assertIsNone(re.search(r"^\s*(import|from)\s+%s\b" % OLD, read(NEW, m + ".py"), re.M), m)
        r = py("-c", f"import sys, {NEW}, {NEW}.cli; print(sorted(m for m in sys.modules if m.startswith('{OLD}')))")
        self.assertEqual((r.returncode, r.stdout), (0, "[]\n"), r.stderr)


class CommandLine(unittest.TestCase):
    def test_python_m_under_the_earlier_name_gives_the_same_outcome_and_warns(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        bad = os.path.join(d, "p.json")
        with open(PACK, encoding="utf-8") as f:
            p = json.load(f)
        p["product_id"] = "x"
        with open(bad, "w", encoding="utf-8") as f:
            json.dump(p, f)
        cases = (["--version"], ["verify", PACK], ["verify", bad], ["verify"], ["no-such-command"])
        codes = []
        for args in cases:
            new = py("-m", NEW + ".cli", *args)
            old = py("-m", OLD + ".cli", *args)
            self.assertEqual((old.returncode, old.stdout), (new.returncode, new.stdout), args)
            self.assertIn("DeprecationWarning: 'python -m cra_evidence.cli' is deprecated", old.stderr, args)
            self.assertNotIn("DeprecationWarning", new.stderr, args)
            self.assertTrue(old.stderr.endswith(new.stderr), (args, old.stderr, new.stderr))   # the command's own stderr follows
            codes.append(new.returncode)
        self.assertEqual(codes[0], 0)
        self.assertIn(codes[1], (0, 77))                  # 77: signed pack, `cryptography` not installed
        self.assertEqual(codes[2], 1)                     # a finding against the pack
        self.assertEqual(codes[3:], [2, 2], codes)        # usage errors

    @unittest.skipUnless(shutil.which(DIST) and shutil.which("cra") and
                         os.path.dirname(shutil.which(DIST)) == os.path.dirname(shutil.which("cra")),
                         "the two commands are not installed side by side in this environment")
    def test_the_installed_commands_are_the_same_entry_point(self):
        for cmd in (DIST, "cra"):
            r = subprocess.run([cmd, "--version"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(r.stdout.startswith(DIST + " "), r.stdout)


if __name__ == "__main__":
    unittest.main()
