# Examples

`self_evidence/` is this repository applied to itself: its own SBOM (installed floor), a recorded vulnerability
event with the Art. 14 clock, an early-warning notice payload in the SRP vocabulary (dry-run, never submitted),
the evidence pack anchored into the ledger, its signature and its long-term seal. Regenerate with
`python examples/self_evidence.py` and verify with `cra verify examples/self_evidence/cra_pack.json --trust-store examples/self_evidence/trust.json`
(the signature is made with an ephemeral key each run; the public key is in `trust.json`).

The committed files were generated on 29/09/2026 by this script, for version 0.4.0 (the script reads the package
version) and under the glossary snapshot of 25/09/2026 (the drop file's `glossary_source` says so). The notice is an
early warning: the field ENISA added on 25/09/2026 (v26a, occurrence instant) is optional at that stage, so the payload
is complete. The stored source document is the Syft fixture re-run the same day from a neutral directory
(`/tmp/tiny-cra-sample`), which is the path its `file` component carries. Regenerating the example changes every hash,
the signature and the drop file's name (a fresh notice id): the script clears the previous run first.
