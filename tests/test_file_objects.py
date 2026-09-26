"""25/09/2026 — files a verifier must not read, a present-and-null fingerprint, and the verifier's own errors.

Measured on 0.3.1 + HEAD 51ecbb3 (malformed-input review, four minds): a FIFO in place of the pack, the signature
sidecar, the tip or the trust store blocked the reference (and the three independent verifiers); a symlink to
/dev/zero was read until the process was killed for memory; `fingerprint: null` in the sidecar passed while an int
failed; the Go/JS verifiers reported their own internal errors as a plain FAIL. Every test here was RED on that code
(a FIFO test ends on the timeout below, never by hanging the suite) and is GREEN after the fix. The three independent
verifiers are held to the same rules by verifiers/differential.py (cases pack_fifo … internal_error_injected_on_intact_pack)."""
import json, os, shutil, subprocess, sys, tempfile, unittest

try:
    import resource
except ImportError:   # non-POSIX
    resource = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence.locker import CRAEvidenceLocker
from cra_evidence.verify_pack import verify_pack
from cra_evidence.vuln import VulnerabilityRecord

try:
    from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False

CAP = 64 << 20          # the declared per-document bound (MAX_DOC_BYTES = MAX_LINE_BYTES)
TIMEOUT = 20            # a verifier blocked on a FIFO is a failed test, never a hung suite
MEM = 1500 << 20        # RLIMIT_DATA of the child: /dev/zero read whole must not take the host down
KEY = "ab" * 32


def _limit():
    resource.setrlimit(resource.RLIMIT_DATA, (MEM, MEM))


def cli(*args, env=None):
    """(exit, parsed JSON or None, stderr) of `cra verify`, in a child with a timeout and a memory bound."""
    try:
        r = subprocess.run([sys.executable, "-m", "cra_evidence.cli", "verify", *args], capture_output=True, text=True, timeout=TIMEOUT,
                           cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT, **(env or {})}, preexec_fn=_limit if resource else None)
    except subprocess.TimeoutExpired:
        return "BLOCKED", None, ""
    try:
        return r.returncode, json.loads(r.stdout), r.stderr
    except ValueError:
        return r.returncode, None, r.stderr


def rj(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def wj(p, obj):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def fail_detail(j, layer):
    return next((l["detail"] for l in j["layers"] if l["layer"] == layer and l["status"] == "FAIL"), None)


@unittest.skipIf(not hasattr(os, "mkfifo"), "needs POSIX FIFOs and symlinks")
class TestFileObjects(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.lk = CRAEvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")
        self.lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2026-1", True, "2026-09-01T00:00:00Z"))
        self.pack = os.path.join(self.d, "p.json")
        self.lk.evidence_pack(self.pack)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def swap(self, path, kind):
        if os.path.lexists(path):
            os.remove(path)
        os.mkfifo(path) if kind == "fifo" else os.symlink("/dev/zero", path)

    def assert_fail(self, layer, why, *args):
        code, j, err = cli(self.pack, *args)
        self.assertEqual(code, 1, f"{layer}: exit {code} {err[-200:]}")
        self.assertIs(j["ok"], False)
        self.assertIs(j["assessed"], True)            # an unreadable input IS a finding about what was handed over
        self.assertIn(why, fail_detail(j, layer) or "", j["layers"])

    def test_pack_fifo_and_devzero(self):
        for kind in ("fifo", "devzero"):
            self.swap(self.pack, kind)
            self.assert_fail("pack-json", "not a regular file")

    def test_sidecar_fifo_and_devzero(self):
        for kind in ("fifo", "devzero"):
            self.swap(self.pack + ".sig.json", kind)
            self.assert_fail("producer-signature", "not a regular file")

    def test_ledger_fifo_and_devzero_explicit_and_implicit(self):
        led = os.path.join(self.d, "l.jsonl")
        for kind in ("fifo", "devzero"):
            self.swap(led, kind)
            self.assert_fail("ledger-chain", "not a regular file", "--ledger", led)
            self.assert_fail("ledger-chain", "not a regular file")   # present but not a file: never a silent "ledger not next to the pack"

    def test_tip_fifo_and_devzero_with_log_key(self):
        for kind in ("fifo", "devzero"):
            self.swap(os.path.join(self.d, "l.jsonl.tip.json"), kind)
            self.assert_fail("signed-tip", "not a regular file", "--log-pubkey", KEY)

    def test_trust_store_fifo_and_devzero_are_unreadable(self):
        t = os.path.join(self.d, "trust.json")
        for kind in ("fifo", "devzero"):
            self.swap(t, kind)
            code, j, err = cli(self.pack, "--trust-store", t)
            self.assertEqual(code, 2)
            self.assertIsNone(j)
            self.assertIn("not a regular file", err)

    def test_one_byte_over_the_bound_is_refused_unread(self):
        with open(self.pack, "ab") as f:
            f.write(b" " * (CAP + 1 - os.path.getsize(self.pack)))
        self.assert_fail("pack-json", f"larger than {CAP} bytes")
        t = os.path.join(self.d, "trust.json")
        with open(t, "wb") as f:
            f.write(b"{}" + b" " * (CAP - 1))
        code, j, err = cli(self.pack, "--trust-store", t)
        self.assertEqual((code, j), (2, None))
        self.assertIn(f"larger than {CAP} bytes", err)

    def test_exactly_at_the_bound_is_read(self):   # positive control of the bound (trailing spaces change no digest)
        with open(self.pack, "ab") as f:
            f.write(b" " * (CAP - os.path.getsize(self.pack)))
        r = verify_pack(self.pack)
        self.assertTrue(r["ok"], r["layers"])
        self.assertEqual(r["authenticity"], "anchored")

    def test_injected_internal_error_is_inconclusive_not_adverse(self):
        base = verify_pack(self.pack)
        self.assertTrue(base["ok"])                   # the same intact pack, without the fault
        os.environ["CRA_VERIFY_INJECT_FAULT"] = "1"
        try:
            r = verify_pack(self.pack)
        finally:
            del os.environ["CRA_VERIFY_INJECT_FAULT"]
        self.assertEqual((r["ok"], r["assessed"], r["authenticity"]), (False, False, "FAIL"))
        self.assertEqual([l["layer"] for l in r["layers"]], ["verifier-exception"])
        code, j, _ = cli(self.pack, env={"CRA_VERIFY_INJECT_FAULT": "1"})
        self.assertEqual((code, j["assessed"]), (1, False))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography needed to sign")
    def test_fingerprint_null_is_malformed_absent_is_not_declared(self):
        keygen(os.path.join(self.d, "k.key")); key = load_key(os.path.join(self.d, "k.key"))
        sign_pack(self.pack, key, "acme-ci")
        sp = sidecar_path(self.pack); side = rj(sp)
        self.assertRegex(side["fingerprint"], r"^[0-9a-f]{16}$")   # what the signer writes: never null
        side["fingerprint"] = None; wj(sp, side)
        r = verify_pack(self.pack)
        self.assertFalse(r["ok"])
        self.assertIn("fingerprint", fail_detail(r, "producer-signature") or "")
        del side["fingerprint"]; wj(sp, side)
        self.assertEqual(verify_pack(self.pack)["authenticity"], "signed")


class WeakEd25519Keys20260925(unittest.TestCase):
    """A forged sidecar carrying a small-order key, pinned in the trust store, was trusted-signed (with the identity
    key, R=identity, S=0 verifies on every message under OpenSSL; other small-order points on a share of messages).
    Also the long-term seal primitive."""
    @unittest.skipUnless(HAVE_CRYPTO, "cryptography needed to sign the forged sidecar")
    def test_forged_sidecar_with_pinned_small_order_key_is_refused(self):
        import json as _json, tempfile as _tf
        from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path, weak_ed25519_key
        from cra_evidence.ledger import load_trust_store
        with _tf.TemporaryDirectory() as d:
            keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
            lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "p", "1", tip_key=key)
            lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2026-1", True, "2026-09-01T00:00:00Z"))
            pack = os.path.join(d, "p.json"); lk.evidence_pack(pack); sign_pack(pack, key, "acme-ci")
            sp = sidecar_path(pack); sd = _json.load(open(sp))
            ident = "01" + "00" * 31
            sd["public_key_hex"] = ident; sd["signature_hex"] = "01" + "00" * 63; sd.pop("fingerprint", None); _json.dump(sd, open(sp, "w"))
            r = verify_pack(pack, None, load_trust_store(_json.dumps({"acme-ci": ident})))
            self.assertFalse(r["ok"]); self.assertEqual(r["authenticity"], "FAIL")
            self.assertTrue(weak_ed25519_key(ident)); self.assertTrue(weak_ed25519_key("ed" + "ff" * 30 + "7f"))

    def test_longterm_primitive_refuses_weak_key(self):
        from cra_evidence.longterm import _ed_verify
        self.assertFalse(_ed_verify("01" + "00" * 31, "01" + "00" * 63, b"any message"))


if __name__ == "__main__":
    unittest.main()
