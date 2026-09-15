"""SigV4 derivation against the official AWS example (docs: 'Examples of the complete Signature Version 4 signing
process'): secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, 20150830, us-east-1, iam → known signing key. The
KMS round-trip itself needs a real account (skipped here; exercised on the author's key at release time)."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.kms import derive_signing_key, sigv4_headers, KMSSigner


class TestSigV4(unittest.TestCase):
    def test_official_vector(self):
        k = derive_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
        self.assertEqual(k.hex(), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")

    def test_headers_shape_and_token(self):
        h = sigv4_headers("kms.eu-central-1.amazonaws.com", "eu-central-1", "kms", "TrentService.Sign", b"{}", "AKIA", "s", "tok", "20260915T120000Z", "20260915")
        self.assertTrue(h["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA/20260915/eu-central-1/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature="))
        self.assertEqual(h["X-Amz-Security-Token"], "tok")

    def test_guards(self):
        with self.assertRaises(RuntimeError):      # no credentials → refuse, never a request
            KMSSigner("k", "eu-central-1", access_key="", secret_key="")
        with self.assertRaises(ValueError):        # plain-http remote endpoint would leak the token
            KMSSigner("k", "eu-central-1", access_key="a", secret_key="b", endpoint="http://example.com")


if __name__ == "__main__":
    unittest.main(verbosity=1)
