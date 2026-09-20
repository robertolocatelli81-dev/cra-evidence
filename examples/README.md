# Examples

`self_evidence/` is this repository applied to itself: its own SBOM (installed floor), a recorded vulnerability
event with the Art. 14 clock, an early-warning notice payload in the SRP vocabulary (dry-run, never submitted),
the evidence pack anchored into the ledger, its signature and its long-term seal. Regenerate with
`python examples/self_evidence.py` and verify with `cra verify examples/self_evidence/cra_pack.json --trust-store examples/self_evidence/trust.json`
(the signature is made with an ephemeral key each run; the public key is in `trust.json`).
