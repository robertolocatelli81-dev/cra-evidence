# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — installable without PyPI: the container image (Dockerfile, container/requirements-sign.txt,
.github/workflows/container.yml) and the GitHub Action (action.yml). These tests keep the pins that make both
reproducible and closed: the base image by digest, every requirement of the image by hash, every action by commit
SHA, the build context limited to the released wheel and the requirements, and the action's default version equal to
the package version (a release whose action pointed at another version would run other code). No YAML library: the
minimal CI job has no dependency, so the files are read as text. Each check has a positive control on a broken copy."""
import os, re, shutil, stat, subprocess, tempfile, unittest

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


def action_input_default(action, name):
    m = re.search(r'^  ' + re.escape(name) + r':\n(?:    .*\n)*?    default: "([^"]*)"$', action, re.M)
    return m.group(1) if m else None


def step_script(action, step_id):
    """the `run: |` block of the composite step `step_id`, dedented (no YAML library: the layout of action.yml)"""
    m = re.search(r"^    - id: " + re.escape(step_id) + r"\n(?:      (?!run:).*\n)*      run: \|\n((?:        .*\n|\n)+)", action, re.M)
    if not m:
        return None
    return "".join(l[8:] if l.strip() else "\n" for l in m.group(1).splitlines(True))


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
        self.assertIn("--no-deps --no-index /tmp/dist/omega_cra_evol-${CRA_VERSION}-py3-none-any.whl", d)
        self.assertRegex(d, r"(?m)^USER 10001$")


def dockerignore_rules(text):
    return [l for l in text.splitlines() if l and not l.startswith("#")]


class TestBuildContext(unittest.TestCase):
    ALLOWED = ["*", "!dist/omega_cra_evol-*-py3-none-any.whl", "!container/requirements-sign.txt"]

    def test_dockerignore_admits_only_the_wheel_and_the_requirements(self):
        self.assertEqual(dockerignore_rules(read(".dockerignore")), self.ALLOWED)

    def test_positive_control(self):
        self.assertNotEqual(dockerignore_rules(read(".dockerignore") + "!scripts\n"), self.ALLOWED)


def workflow_order_problems(w):
    marks = ["sha256sum -c SHA256SUMS", "trusted-signed", "docker push", "actions/attest@"]
    if any(m not in w for m in marks):
        return ["missing: " + ", ".join(m for m in marks if m not in w)]
    pos = [w.index(m) for m in marks]
    return [f"{a} not before {b}" for a, b, i, j in zip(marks, marks[1:], pos, pos[1:]) if not i < j]


class TestContainerWorkflow(unittest.TestCase):
    def test_wheel_checked_against_sha256sums_and_pack_verified_before_push(self):
        w = read(".github", "workflows", "container.yml")
        self.assertEqual(workflow_order_problems(w), [])
        self.assertIn("push-to-registry: true", w)
        self.assertIn("permissions: {}", w)
        self.assertIn('[ "$GITHUB_REF" = "refs/tags/$TAG" ]', w)      # a dispatch runs the tag's own Dockerfile
        self.assertNotIn("artifact-metadata", w)                       # create-storage-record: false needs no such permission
        job = re.search(r"^    permissions:\n((?:      .*\n)+)", w, re.M).group(1).split()
        self.assertEqual(job, ["contents:", "read", "packages:", "write", "id-token:", "write", "attestations:", "write"])
        for guard in ("(d['ok'], d['authenticity']) == (True, 'trusted-signed')",      # the release's pack verifies
                      'cmp -s "rel/omega-cra-evol-$V-cra_pack.json" rel/tampered.json && {',   # the tampered copy differs
                      'test "$rc" -eq 1 ||',                                             # and is refused with exit 1
                      "subject-digest: ${{ steps.push.outputs.digest }}"):               # attested = pushed digest
            self.assertIn(guard, w)

    def test_action_runs_the_verified_digest(self):
        self.assertIn("IMAGE: ${{ steps.verify.outputs.image }}", read("action.yml"))

    def test_positive_control_order(self):
        w = read(".github", "workflows", "container.yml")
        self.assertTrue(workflow_order_problems(w.replace("sha256sum -c SHA256SUMS", "true")))
        self.assertTrue(workflow_order_problems("docker push\nsha256sum -c SHA256SUMS\ntrusted-signed\nactions/attest@"))


def _stub_bin(d):
    """docker and gh stubs: each call appends its argv (one argument per line, then a line ---) to <d>/calls"""
    script = """#!/bin/bash
{ echo "$(basename "$0")"; printf '%s\\n' "$@"; echo ---; } >> "$STUB_DIR/calls"
if [ "$(basename "$0")" = docker ] && [ "$1" = inspect ]; then
  for r in $STUB_REPODIGESTS; do printf '%s ' "$r"; done; echo; exit 0
fi
if [ "$(basename "$0")" = gh ]; then exit "${STUB_GH_RC:-0}"; fi
if [ "$1" = run ]; then exit "${STUB_RUN_RC:-0}"; fi
exit 0
"""
    for name in ("docker", "gh"):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(script)
        os.chmod(p, stat.S_IRWXU)


@unittest.skipUnless(shutil.which("bash"), "the action's steps are bash")
class TestActionSteps(unittest.TestCase):
    """the two composite steps of action.yml, run with bash against docker/gh stubs"""
    IMG = "ghcr.io/robertolocatelli81-dev/omega-cra-evol"
    DIGEST = "sha256:" + "ab" * 32

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        _stub_bin(self.d)

    def step(self, step_id, env, script=None):
        script = script if script is not None else step_script(read("action.yml"), step_id)
        self.assertIsNotNone(script)
        out = os.path.join(self.d, "out")
        for p in (out, os.path.join(self.d, "calls")):
            with open(p, "w"):
                pass
        e = {"PATH": self.d + os.pathsep + os.environ.get("PATH", ""), "STUB_DIR": self.d, "GITHUB_OUTPUT": out,
             "GITHUB_WORKSPACE": self.d, "HOME": self.d}
        e.update(env)
        r = subprocess.run(["bash", "-c", script], env=e, cwd=self.d, capture_output=True, text=True)
        with open(os.path.join(self.d, "calls")) as f:
            calls = [c.strip("\n").split("\n") for c in f.read().split("---\n") if c.strip()]
        with open(out) as f:
            return r.returncode, f.read(), calls

    def verify(self, **env):
        base = {"V": "0.10.0", "GH_TOKEN": "x", "REPO": "robertolocatelli81-dev/omega-cra-evol",
                "STUB_REPODIGESTS": f"a.example/mirror@sha256:{'cd' * 32} {self.IMG}@{self.DIGEST}"}
        base.update(env)
        return self.step("verify", base)

    def test_verify_pins_the_digest_and_the_exact_signer_at_the_tag(self):
        rc, out, calls = self.verify()
        self.assertEqual(rc, 0)
        self.assertIn(f"image={self.IMG}@{self.DIGEST}", out)      # the other repository's digest sorts first: not taken
        gh = [c for c in calls if c[0] == "gh"]
        self.assertEqual(len(gh), 1)
        argv = gh[0][1:]
        self.assertEqual(argv[:3], ["attestation", "verify", f"oci://{self.IMG}@{self.DIGEST}"])
        for flag, val in (("--repo", "robertolocatelli81-dev/omega-cra-evol"), ("--source-ref", "refs/tags/v0.10.0"),
                          ("--cert-identity", "https://github.com/robertolocatelli81-dev/omega-cra-evol/.github/workflows/container.yml@refs/tags/v0.10.0")):
            self.assertEqual(argv[argv.index(flag) + 1], val)
        self.assertIn("--deny-self-hosted-runners", argv)

    def test_verify_fails_closed(self):
        for env in ({"STUB_GH_RC": "1"},                                        # attestation refused
                    {"STUB_REPODIGESTS": f"a.example/mirror@{self.DIGEST}"},    # no digest of this repository
                    {"STUB_REPODIGESTS": f"{self.IMG}@sha256:XYZ"},             # malformed digest
                    {"STUB_REPODIGESTS": f"{self.IMG}@sha256:ab;id"},
                    {"V": "0.7.1;id"}, {"V": "latest"}):
            rc, out, _ = self.verify(**env)
            self.assertNotEqual(rc, 0, env)
            self.assertNotIn("image=", out, env)

    def run_step(self, args, script=None, **env):
        base = {"IMAGE": f"{self.IMG}@{self.DIGEST}", "CRA_ARGS": args,
                "NET": action_input_default(read("action.yml"), "network")}
        base.update(env)
        return self.step("run", base, script)

    def test_run_by_digest_offline_without_shell(self):
        self.assertEqual(action_input_default(read("action.yml"), "network"), "none")
        with open(os.path.join(self.d, "a.json"), "w"):
            pass
        rc, out, calls = self.run_step("verify $(touch PWNED) ; `id` *.json ~ 'a b'\n  --ledger\tl")
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(self.d, "PWNED")))
        argv = [c for c in calls if c[0] == "docker"][0][1:]
        i = argv.index(f"{self.IMG}@{self.DIGEST}")
        self.assertEqual(argv[i + 1:], ["verify", "$(touch", "PWNED)", ";", "`id`", "*.json", "~", "'a", "b'", "--ledger", "l"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        self.assertIn("exit-code=0", out)

    def test_run_refusals_and_exit_code(self):
        self.assertNotEqual(self.run_step("x", NET="host")[0], 0)
        self.assertNotEqual(self.run_step("x", NET="none --privileged")[0], 0)
        self.assertNotEqual(self.run_step(" \n\t ")[0], 0)
        rc, out, _ = self.run_step("verify p.json", STUB_RUN_RC="3")
        self.assertEqual((rc, out.strip()), (3, "exit-code=3"))

    def test_positive_control_broken_copies(self):
        a = read("action.yml")
        self.assertEqual(action_input_default(a.replace('default: "none"', 'default: "bridge"'), "network"), "bridge")
        self.assertIsNone(step_script(a, "no-such-step"))
        evil = step_script(a, "run").replace('read -r -d \'\' -a argv <<< "$CRA_ARGS" || true', 'eval "argv=($CRA_ARGS)"')
        self.assertNotEqual(evil, step_script(a, "run"))
        self.run_step("$(touch PWNED)", script=evil)
        self.assertTrue(os.path.exists(os.path.join(self.d, "PWNED")))          # the test sees a shell when there is one
        lax = step_script(a, "verify").replace('--source-ref "refs/tags/v$V" ', "")
        self.assertNotEqual(lax, step_script(a, "verify"))
        rc, _, calls = self.step("verify", {"V": "0.10.0", "GH_TOKEN": "x", "REPO": "robertolocatelli81-dev/omega-cra-evol",
                                            "STUB_REPODIGESTS": f"{self.IMG}@{self.DIGEST}"}, lax)
        self.assertNotIn("--source-ref", [c for c in calls if c[0] == "gh"][0])


if __name__ == "__main__":
    unittest.main()
