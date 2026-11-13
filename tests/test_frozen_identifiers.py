# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026, the rename to omega-cra-evol (0.10.0). Some identifiers carry the earlier project name INSIDE evidence
already written and signed; renaming them would make every verifier refuse what was made before. This file keeps them:
  - the identifiers in the code are the ones written before the rename (pack `kind`, CycloneDX property names, profile
    value and generator, states vocabulary, the two art14-filing TypeURIs, `source.tool` of a notice built here), and
    the three verifiers in other languages carry the same pack `kind`;
  - the evidence made before the rename (the vectors, the committed example, the vendored fixtures) is byte for byte
    what it was on the 0.9.0 commit f2967a9, and the committed example (made by 0.4.0) still verifies;
  - what is made now carries the same identifiers.
Positive controls: one changed byte moves a directory digest; a pack whose `kind` follows the new name is refused."""
import hashlib, json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import EvidenceLocker, verify_pack  # noqa: E402
from omega_cra_evol.art14_attest import TYPE_URI, TYPE_URI_V02  # noqa: E402
from omega_cra_evol.locker import PACK_KIND  # noqa: E402
from omega_cra_evol.sbom import sbom_from_installed  # noqa: E402
from omega_cra_evol.srp_notice import SOURCE_TOOLS  # noqa: E402
from omega_cra_evol.verify_pack import STATES_VOCABULARY  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
NODE = shutil.which("node")

EARLIER = "cra-evidence"
REPO_URL = "https://github.com/robertolocatelli81-dev/" + EARLIER
FROZEN = {
    "pack kind": (PACK_KIND, "cra_evidence_pack/1"),
    "states vocabulary": (STATES_VOCABULARY, EARLIER + "/states-1"),
    "art14-filing v0.1 TypeURI": (TYPE_URI, REPO_URL + "/tree/master/spec/art14-filing/v0.1"),
    "art14-filing v0.2 TypeURI": (TYPE_URI_V02, REPO_URL + "/tree/master/spec/art14-filing/v0.2"),
    "source.tool of a notice built here": (SOURCE_TOOLS[0], EARLIER),
}

# (number of files, sha256 of the lines "<sha256 of the file>  <path>\n" sorted by path), taken with `git show` on the
# 0.9.0 commit f2967a9, before the rename
DIGESTS = {
    "examples/self_evidence": (6, "cd46fea3319c9f0cbfc92a99a6f24f73393f74adb9fd1bc0df7fd4ae224342fc"),
    "spec/art14-filing/v0.1/vectors": (60, "0719fb38a5c736d3202b291a34ff294b6b86ae13ecad9cede0795a9a3939fcb6"),
    "spec/art14-filing/v0.2/vectors": (61, "6a8ab1446df359f46e5c331f2859d01974b7019d2a6bf95a6c85f78fd8c82d7e"),
    "tests/fixtures": (89, "48a1ff375d36a88e0572497d80e9c2eb6cf1cdf478a488417f0e3a5aec6d65d5"),
}


def tree_digest(root, rel):
    lines = []
    for d, dirs, files in os.walk(os.path.join(root, rel)):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for fn in files:
            p = os.path.join(d, fn)
            with open(p, "rb") as f:
                lines.append((os.path.relpath(p, root).replace(os.sep, "/"), hashlib.sha256(f.read()).hexdigest()))
    lines.sort()
    return len(lines), hashlib.sha256("".join(f"{h}  {p}\n" for p, h in lines).encode()).hexdigest()


def cli(*args):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-B", "-m", "omega_cra_evol.cli", *args], capture_output=True, text=True, cwd=ROOT, env=env)


class IdentifiersInTheCode(unittest.TestCase):
    def test_each_identifier_is_the_one_written_before_the_rename(self):
        for what, (got, want) in FROZEN.items():
            self.assertEqual(got, want, what)

    def test_the_verifiers_in_other_languages_carry_the_same_pack_kind(self):
        for rel in ("verifiers/js/cra-verify.mjs", "verifiers/go/main.go", "verifiers/rust/src/main.rs"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                self.assertIn('"cra_evidence_pack/1"', f.read(), rel)

    def test_an_export_made_now_carries_the_same_property_names_profile_and_generator(self):
        rec = sbom_from_installed("p", "1", ["no-such-dist-xyz"])
        self.assertEqual(rec.source["generator"], EARLIER + ":importlib.metadata")
        for v in ("1.6", "1.7"):
            props = {p["name"]: p["value"] for p in rec.to_cyclonedx_min(v)["metadata"]["properties"]}
            self.assertTrue({EARLIER + ":profile", EARLIER + ":depth_note", EARLIER + ":sbom_sha3"} <= set(props), props)
            self.assertTrue(props[EARLIER + ":profile"].startswith(EARLIER + "-min "), props)
            self.assertEqual([k for k in props if not k.startswith(EARLIER + ":")], [])

    def test_a_pack_made_now_carries_the_same_kind_and_verifies(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        lk = EvidenceLocker(os.path.join(d, "l.jsonl"), "p", "1")
        lk.record_sbom(sbom_from_installed("p", "1", ["no-such-dist-xyz"]))
        pack = lk.evidence_pack(os.path.join(d, "p.json"))
        self.assertEqual(pack["kind"], "cra_evidence_pack/1")
        r = verify_pack(os.path.join(d, "p.json"))
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["states_vocabulary"], EARLIER + "/states-1")


class EvidenceMadeBeforeTheRename(unittest.TestCase):
    def test_byte_for_byte_what_it_was(self):
        for rel, want in DIGESTS.items():
            self.assertEqual(tree_digest(ROOT, rel), want, rel)

    def test_positive_control_one_byte_moves_the_digest(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        shutil.copytree(os.path.join(ROOT, "examples", "self_evidence"), os.path.join(d, "examples", "self_evidence"))
        self.assertEqual(tree_digest(d, "examples/self_evidence"), DIGESTS["examples/self_evidence"])   # the copy is equal
        p = os.path.join(d, "examples", "self_evidence", "trust.json")
        with open(p, "ab") as f:
            f.write(b" ")
        self.assertNotEqual(tree_digest(d, "examples/self_evidence"), DIGESTS["examples/self_evidence"])

    def test_the_example_made_by_040_still_verifies(self):
        ex = os.path.join("examples", "self_evidence")
        r = cli("verify", os.path.join(ex, "cra_pack.json"), "--trust-store", os.path.join(ex, "trust.json"))
        out = json.loads(r.stdout)
        if HAVE_CRYPTO:
            self.assertEqual((r.returncode, out["ok"], out["authenticity"]), (0, True, "trusted-signed"), r.stderr)
        else:   # the signature cannot be checked without `cryptography`: not assessed, as before the rename
            self.assertEqual(r.returncode, 77, r.stderr)
        self.assertEqual(out["admission"], "admitted")


class PositiveControlTheNewNameIsNotAKind(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
        lk = EvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        lk.record_sbom(sbom_from_installed("p", "1", ["no-such-dist-xyz"]))
        lk.evidence_pack(os.path.join(self.d, "p.json"))
        with open(os.path.join(self.d, "p.json"), encoding="utf-8") as f:
            p = json.load(f)
        p["kind"] = "omega_cra_evol_pack/1"
        self.bad = os.path.join(self.d, "renamed.json")
        with open(self.bad, "w", encoding="utf-8") as f:
            json.dump(p, f)

    def test_the_reference_verifier_refuses_it(self):
        r = verify_pack(self.bad, ledger_path=os.path.join(self.d, "l.jsonl"))
        self.assertFalse(r["ok"])
        self.assertEqual((r["admission"], r["refusal_class"]), ("refused", "format_unsupported"))

    @unittest.skipUnless(NODE, "node not installed")
    def test_the_js_verifier_refuses_it(self):
        r = subprocess.run([NODE, os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs"), self.bad, "--ledger",
                            os.path.join(self.d, "l.jsonl")], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertFalse(json.loads(r.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
