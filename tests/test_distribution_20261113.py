# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — installable without PyPI: the container image (Dockerfile, container/requirements-sign.txt,
.github/workflows/container.yml) and the GitHub Action (action.yml). These tests keep the pins that make both
reproducible and closed: the base image by digest, every requirement of the image by hash, every action by commit
SHA, the build context limited to the released wheel and the requirements, and the action's default version equal to
the package version (a release whose action pointed at another version would run other code). No YAML library: the
minimal CI job has no dependency, so the files are read as text. Each check has a positive control on a broken copy."""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def package_version(pyproject):
    m = re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', pyproject, re.M)
    return m.group(1) if m else None


def action_default_version(action):
    m = re.search(r'^  version:\n(?:    .*\n)*?    default: "([^"]*)"$', action, re.M)
    return m.group(1) if m else None


def unpinned_uses(text):
    """every `uses:` that is not owner/repo@<40-hex commit>"""
    bad = []
    for m in re.finditer(r'^\s*-?\s*uses:\s*(\S+)', text, re.M):
        ref = m.group(1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", ref):
            bad.append(ref)
    return bad


def base_images(dockerfile):
    return re.findall(r"^FROM\s+(\S+)", dockerfile, re.M)


def pinned_image(ref):
    return re.fullmatch(r"[a-z0-9./-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}", ref) is not None


def requirement_problems(text):
    """each requirement must be name==version followed by at least one --hash=sha256:<64 hex>, nothing else"""
    logical = re.sub(r"\\\n\s*", " ", "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#")))
    problems, n = [], 0
    for line in logical.splitlines():
        if not line.strip():
            continue
        n += 1
        parts = line.split()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9.]*", parts[0]):
            problems.append(f"not pinned with ==: {parts[0]}")
        hashes = parts[1:]
        if not hashes or not all(re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", h) for h in hashes):
            problems.append(f"missing or malformed --hash: {line.strip()}")
    if n == 0:
        problems.append("no requirement")
    return problems


class TestActionVersion(unittest.TestCase):
    def test_action_default_is_the_package_version(self):
        v = package_version(read("pyproject.toml"))
        self.assertIsNotNone(v)
        self.assertEqual(action_default_version(read("action.yml")), v)

    def test_positive_control(self):
        broken = read("action.yml").replace(f'default: "{package_version(read("pyproject.toml"))}"', 'default: "0.0.1"', 1)
        self.assertNotEqual(action_default_version(broken), package_version(read("pyproject.toml")))


class TestPins(unittest.TestCase):
    FILES = [("action.yml",), (".github", "workflows", "container.yml"), (".github", "workflows", "pypi.yml"),
             (".github", "workflows", "srp-glossary-drift.yml")]

    def test_every_action_pinned_by_commit(self):
        for p in self.FILES:
            self.assertEqual(unpinned_uses(read(*p)), [], os.path.join(*p))

    def test_container_workflow_uses_actions(self):   # the check above must have something to check
        self.assertGreaterEqual(len(re.findall(r"uses:", read(".github", "workflows", "container.yml"))), 2)

    def test_positive_control_unpinned(self):
        self.assertEqual(unpinned_uses("      - uses: actions/checkout@v7\n"), ["actions/checkout@v7"])
        self.assertEqual(unpinned_uses("      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b\n"),
                         ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b"])

    def test_base_image_by_digest(self):
        froms = base_images(read("Dockerfile"))
        self.assertEqual(len(froms), 1)
        self.assertTrue(pinned_image(froms[0]), froms[0])
        self.assertFalse(pinned_image("docker.io/library/python:3.12-slim"))          # positive control

    def test_requirements_by_hash(self):
        self.assertEqual(requirement_problems(read("container", "requirements-sign.txt")), [])
        self.assertTrue(requirement_problems("cryptography>=41 \\\n    --hash=sha256:" + "0" * 64 + "\n"))   # positive controls
        self.assertTrue(requirement_problems("cryptography==50.0.2\n"))
        self.assertTrue(requirement_problems("# nothing\n"))

    def test_dockerfile_installs_with_hashes_and_without_index_for_the_wheel(self):
        d = read("Dockerfile")
        self.assertIn("--require-hashes --only-binary=:all: -r /tmp/requirements-sign.txt", d)
        self.assertIn("--no-deps --no-index /tmp/dist/cra_evidence-${CRA_VERSION}-py3-none-any.whl", d)
        self.assertRegex(d, r"(?m)^USER 10001$")


class TestBuildContext(unittest.TestCase):
    def test_dockerignore_admits_only_the_wheel_and_the_requirements(self):
        lines = [l for l in read(".dockerignore").splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, ["*", "!dist/cra_evidence-*-py3-none-any.whl", "!container/requirements-sign.txt"])


class TestContainerWorkflow(unittest.TestCase):
    def test_wheel_checked_against_sha256sums_and_pack_verified_before_push(self):
        w = read(".github", "workflows", "container.yml")
        i_check, i_verify, i_push, i_attest = (w.index("sha256sum -c SHA256SUMS"), w.index("trusted-signed"),
                                               w.index("docker push"), w.index("actions/attest@"))
        self.assertLess(i_check, i_verify)
        self.assertLess(i_verify, i_push)
        self.assertLess(i_push, i_attest)
        self.assertIn("push-to-registry: true", w)
        self.assertIn("permissions: {}", w)

    def test_action_verifies_provenance_of_the_pulled_digest_before_running(self):
        a = read("action.yml")
        self.assertLess(a.index("gh attestation verify \"oci://$image@$digest\""), a.index("docker run"))
        self.assertIn('--signer-workflow "$REPO/.github/workflows/container.yml"', a)
        self.assertIn('"$IMAGE" "${argv[@]}"', a)      # runs by digest (IMAGE = image@digest), arguments never through a shell
        self.assertIn("set -f", a)


if __name__ == "__main__":
    unittest.main()
