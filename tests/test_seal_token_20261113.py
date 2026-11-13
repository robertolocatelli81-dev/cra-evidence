# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra seal` checks the SHAPE of the time token it stores (cra_evidence/rfc3161_token.py), never its signature or time.

The tokens below were made on 13/11/2026 with `openssl ts` (OpenSSL 3.0) by a throw-away TSA whose self-signed
certificate is not kept: TEST-ONLY, no trust attached. Each test fails on the code of f937be1, which stored any
non-empty string as a token under any --ts-source label."""
import base64, importlib.util, json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence.rfc3161_token import TokenRefused, check_token, rfc3161_imprint, OID_SHA3_256, OTS_MAGIC  # noqa: E402

PS = "3c5278f66d55d52adcb9727b66ec93d984302e19e812c68f656df493d4b8e988"   # the digest the tokens were requested for
RESP_SHA3 = ("MIIDsTADAgEAMIIDqAYJKoZIhvcNAQcCoIIDmTCCA5UCAQMxDzANBglghkgBZQMEAgEFADBoBgsqhkiG9w0BCRABBKBZBFcwVQIB"
    "AQYEKgMEATAxMA0GCWCGSAFlAwQCCAUABCA8Unj2bVXVKty5cntm7JPZhDAuGegSxo9lbfST1LjpiAIBAhgPMjAyNjExMTMxMzUy"
    "MDVaMAMCAQGgggG+MIIBujCCAV+gAwIBAgIUIj8TqG5oqA1u4RwraWTk+/c1dBwwCgYIKoZIzj0EAwIwJjEkMCIGA1UEAwwbTkVN"
    "RVNJUyB0ZXN0IFRTQSAobm90IHJlYWwpMB4XDTI2MTExMzEzNTIwNVoXDTI2MTIxMzEzNTIwNVowJjEkMCIGA1UEAwwbTkVNRVNJ"
    "UyB0ZXN0IFRTQSAobm90IHJlYWwpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmMsnWjtzIWUUCfIXNSw+qEVdFUbGaZjOgD31"
    "gJJYIhYuMSEDO3LKad8Io6Yc0d+2FlI3tqXJzAz8BUcjzkv39KNrMGkwHQYDVR0OBBYEFAE0WyB4VwIeZNfesMYa4Qr+AElYMB8G"
    "A1UdIwQYMBaAFAE0WyB4VwIeZNfesMYa4Qr+AElYMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwCgYI"
    "KoZIzj0EAwIDSQAwRgIhANN1SaRFaabEx64uAisrTahtH+6YwSmLgZzVe4Cf6tF6AiEA5nOi/BVK3ytVOm+b6ey+bTDsjfXuZGBQ"
    "d/w2DP/od5QxggFRMIIBTQIBATA+MCYxJDAiBgNVBAMMG05FTUVTSVMgdGVzdCBUU0EgKG5vdCByZWFsKQIUIj8TqG5oqA1u4Rwr"
    "aWTk+/c1dBwwDQYJYIZIAWUDBAIBBQCggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjEx"
    "MTMxMzUyMDVaMC8GCSqGSIb3DQEJBDEiBCD1Chh2EgfdqA+iIJcQJiNPHCblcJ75SCce+1xSiZkArzA3BgsqhkiG9w0BCRACLzEo"
    "MCYwJDAiBCB1xg9K5TuZJx3npgS5U0Xf9zAN9Tr/RdVDswJ3aTmH7jAKBggqhkjOPQQDAgRGMEQCIAXERSJSGHn1y1KRIfttdkws"
    "NfE3GSwdNxDnh9vqK9JMAiAiEJ+htZWTs5IRKijd1EjgLLz2rNlGi1mCuAp5qQTWTw==")
TOKEN_SHA3 = ("MIIDqAYJKoZIhvcNAQcCoIIDmTCCA5UCAQMxDzANBglghkgBZQMEAgEFADBoBgsqhkiG9w0BCRABBKBZBFcwVQIBAQYEKgMEATAx"
    "MA0GCWCGSAFlAwQCCAUABCA8Unj2bVXVKty5cntm7JPZhDAuGegSxo9lbfST1LjpiAIBAhgPMjAyNjExMTMxMzUyMDVaMAMCAQGg"
    "ggG+MIIBujCCAV+gAwIBAgIUIj8TqG5oqA1u4RwraWTk+/c1dBwwCgYIKoZIzj0EAwIwJjEkMCIGA1UEAwwbTkVNRVNJUyB0ZXN0"
    "IFRTQSAobm90IHJlYWwpMB4XDTI2MTExMzEzNTIwNVoXDTI2MTIxMzEzNTIwNVowJjEkMCIGA1UEAwwbTkVNRVNJUyB0ZXN0IFRT"
    "QSAobm90IHJlYWwpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmMsnWjtzIWUUCfIXNSw+qEVdFUbGaZjOgD31gJJYIhYuMSED"
    "O3LKad8Io6Yc0d+2FlI3tqXJzAz8BUcjzkv39KNrMGkwHQYDVR0OBBYEFAE0WyB4VwIeZNfesMYa4Qr+AElYMB8GA1UdIwQYMBaA"
    "FAE0WyB4VwIeZNfesMYa4Qr+AElYMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwCgYIKoZIzj0EAwID"
    "SQAwRgIhANN1SaRFaabEx64uAisrTahtH+6YwSmLgZzVe4Cf6tF6AiEA5nOi/BVK3ytVOm+b6ey+bTDsjfXuZGBQd/w2DP/od5Qx"
    "ggFRMIIBTQIBATA+MCYxJDAiBgNVBAMMG05FTUVTSVMgdGVzdCBUU0EgKG5vdCByZWFsKQIUIj8TqG5oqA1u4RwraWTk+/c1dBww"
    "DQYJYIZIAWUDBAIBBQCggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjExMTMxMzUyMDVa"
    "MC8GCSqGSIb3DQEJBDEiBCD1Chh2EgfdqA+iIJcQJiNPHCblcJ75SCce+1xSiZkArzA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCB1"
    "xg9K5TuZJx3npgS5U0Xf9zAN9Tr/RdVDswJ3aTmH7jAKBggqhkjOPQQDAgRGMEQCIAXERSJSGHn1y1KRIfttdkwsNfE3GSwdNxDn"
    "h9vqK9JMAiAiEJ+htZWTs5IRKijd1EjgLLz2rNlGi1mCuAp5qQTWTw==")
RESP_SHA256 = ("MIIDsjADAgEAMIIDqQYJKoZIhvcNAQcCoIIDmjCCA5YCAQMxDzANBglghkgBZQMEAgEFADBoBgsqhkiG9w0BCRABBKBZBFcwVQIB"
    "AQYEKgMEATAxMA0GCWCGSAFlAwQCAQUABCA8Unj2bVXVKty5cntm7JPZhDAuGegSxo9lbfST1LjpiAIBAxgPMjAyNjExMTMxMzU0"
    "NDBaMAMCAQGgggG+MIIBujCCAV+gAwIBAgIUIj8TqG5oqA1u4RwraWTk+/c1dBwwCgYIKoZIzj0EAwIwJjEkMCIGA1UEAwwbTkVN"
    "RVNJUyB0ZXN0IFRTQSAobm90IHJlYWwpMB4XDTI2MTExMzEzNTIwNVoXDTI2MTIxMzEzNTIwNVowJjEkMCIGA1UEAwwbTkVNRVNJ"
    "UyB0ZXN0IFRTQSAobm90IHJlYWwpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmMsnWjtzIWUUCfIXNSw+qEVdFUbGaZjOgD31"
    "gJJYIhYuMSEDO3LKad8Io6Yc0d+2FlI3tqXJzAz8BUcjzkv39KNrMGkwHQYDVR0OBBYEFAE0WyB4VwIeZNfesMYa4Qr+AElYMB8G"
    "A1UdIwQYMBaAFAE0WyB4VwIeZNfesMYa4Qr+AElYMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwCgYI"
    "KoZIzj0EAwIDSQAwRgIhANN1SaRFaabEx64uAisrTahtH+6YwSmLgZzVe4Cf6tF6AiEA5nOi/BVK3ytVOm+b6ey+bTDsjfXuZGBQ"
    "d/w2DP/od5QxggFSMIIBTgIBATA+MCYxJDAiBgNVBAMMG05FTUVTSVMgdGVzdCBUU0EgKG5vdCByZWFsKQIUIj8TqG5oqA1u4Rwr"
    "aWTk+/c1dBwwDQYJYIZIAWUDBAIBBQCggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjEx"
    "MTMxMzU0NDBaMC8GCSqGSIb3DQEJBDEiBCBsA5mHA6NO/JfF0Kf2cLA38D48n3x0mwvmfZFOPTpEJTA3BgsqhkiG9w0BCRACLzEo"
    "MCYwJDAiBCB1xg9K5TuZJx3npgS5U0Xf9zAN9Tr/RdVDswJ3aTmH7jAKBggqhkjOPQQDAgRHMEUCICX5at5vE28vvMexlyBcbslY"
    "Udk0+YtOkZ8NeBYSRT+uAiEAhoKBOkBTg9X/3TdO2p6EFtjTKUAKfHsHXcZ1u3NOKFY=")
RESP_REJECTED = ("MDcwNQIBAjAsDCpNZXNzYWdlIGRpZ2VzdCBhbGdvcml0aG0gaXMgbm90IHN1cHBvcnRlZC4DAgeA")

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None


def _lines(p):
    with open(p) as f:
        return sum(1 for _ in f)


class TokenShape(unittest.TestCase):
    def test_well_formed_tokens_pass(self):
        for tok in (RESP_SHA3, TOKEN_SHA3):
            check_token("rfc3161", tok, PS)
            self.assertEqual(rfc3161_imprint(base64.b64decode(tok)), (OID_SHA3_256, bytes.fromhex(PS)))
        check_token("ots", base64.b64encode(OTS_MAGIC + b"\x01\x08" + bytes(32)).decode(), PS)
        check_token("asserted", None, PS)

    def test_refused(self):
        raw = base64.b64decode(RESP_SHA3)
        bad = {
            "garbage AAAA": ("rfc3161", "AAAA", PS),
            "not base64": ("rfc3161", "x", PS),
            "url-safe alphabet": ("rfc3161", RESP_SHA3.replace("+", "-").replace("/", "_"), PS) if ("+" in RESP_SHA3 or "/" in RESP_SHA3) else ("rfc3161", "!!", PS),
            "other digest": ("rfc3161", RESP_SHA3, "00" * 32),
            "sha-256 imprint": ("rfc3161", RESP_SHA256, PS),
            "rejected response": ("rfc3161", RESP_REJECTED, PS),
            "trailing byte": ("rfc3161", base64.b64encode(raw + b"\x00").decode(), PS),
            "truncated": ("rfc3161", base64.b64encode(raw[:-1]).decode(), PS),
            "empty": ("rfc3161", "", PS),
            "none": ("rfc3161", None, PS),
            "ots without header": ("ots", RESP_SHA3, PS),
            "asserted with a token": ("asserted", RESP_SHA3, PS),
            "unknown source": ("rfc3161-verified", RESP_SHA3, PS),
            "empty source": ("", RESP_SHA3, PS),
        }
        for name, args in bad.items():
            with self.subTest(name):
                with self.assertRaises(TokenRefused):
                    check_token(*args)

    def test_every_single_byte_change_is_refused_or_keeps_the_imprint(self):
        """no flipped byte may yield an exception other than TokenRefused; a flip inside the signature can keep the
        imprint (the signature is not verified here: stated)"""
        raw = bytearray(base64.b64decode(RESP_SHA3))
        refused = 0
        for i in range(len(raw)):
            b = bytearray(raw); b[i] ^= 0x01
            try:
                check_token("rfc3161", base64.b64encode(bytes(b)).decode(), PS)
            except TokenRefused:
                refused += 1
        self.assertGreater(refused, 0)


@unittest.skipUnless(HAVE_CRYPTO, "a seal is signed: cryptography needed")
class SealLibrary(unittest.TestCase):
    def test_well_formed_token_is_stored_and_still_assumed(self):
        from cra_evidence.locker import CRAEvidenceLocker
        d = tempfile.mkdtemp()
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "p", "1")
        seal = lk.seal_longterm(PS, ts_source="rfc3161", token_b64=RESP_SHA3, external_digest=True)
        self.assertEqual(seal["records"][-1]["token_b64"], RESP_SHA3)
        from cra_evidence.longterm import LongTermEvidence
        self.assertIn("ASSUMED", LongTermEvidence.from_dict(seal).verify(now=0.0)["temporal_trust"])
        with self.assertRaises(TokenRefused):
            lk.seal_longterm(PS, ts_source="rfc3161", token_b64="AAAA", external_digest=True)


@unittest.skipUnless(HAVE_CRYPTO, "a seal is signed: cryptography needed")
class SealCLI(unittest.TestCase):
    def run_cra(self, *args, cwd):
        return subprocess.run([sys.executable, "-m", "cra_evidence.cli", *args], cwd=cwd, capture_output=True, text=True,
                              env=dict(os.environ, PYTHONPATH=ROOT))

    def test_seal(self):
        d = tempfile.mkdtemp()
        led = os.path.join(d, "l.jsonl")
        sb = os.path.join(ROOT, "tests", "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json")
        base = ["--ledger", led, "--product", "p", "--version", "1"]
        self.assertEqual(self.run_cra("sbom", *base, "--from-cyclonedx", sb, cwd=d).returncode, 0)
        r = self.run_cra("pack", *base, "--out", os.path.join(d, "pack.json"), cwd=d)
        ps = json.loads(r.stdout)["pack_sha3"]
        n0 = _lines(led)
        for args in (["--ts-source", "rfc3161", "--token-b64", "AAAA"], ["--ts-source", "rfc3161", "--token-b64", RESP_SHA3],
                     ["--ts-source", "asserted", "--token-b64", "AAAA"]):
            r = self.run_cra("seal", *base, "--pack-sha3", ps, *args, cwd=d)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertEqual(json.loads(r.stdout)["sealed"], False)
        r = self.run_cra("seal", *base, "--pack-sha3", ps, "--ts-source", "rfc3161-verified", "--token-b64", "AAAA", cwd=d)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(_lines(led), n0)          # nothing recorded
        r = self.run_cra("seal", *base, "--pack-sha3", ps, cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ASSUMED", json.loads(r.stdout)["verify"]["temporal_trust"])


if __name__ == "__main__":
    unittest.main()
