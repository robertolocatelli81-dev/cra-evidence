# cra-evidence

Firm-side, offline-verifiable evidence for the EU **Cyber Resilience Act** (Regulation (EU) 2024/2847):
the SBOM record, the Art. 14 clock (24 h / 72 h / final report), notices aligned with ENISA's Single Reporting
Platform field schema, and a crypto-agile seal for the retention window — all in one hash-chained ledger that the
**cryptovalid** verifiers (four independent re-implementations, Python/JS/Go/Rust, by the same author) also accept.

Reporting obligations for manufacturers apply since **11 September 2026**; the ENISA Single Reporting Platform is
operational since the same day (sources in `spec/LEGAL_BASIS.md`). Full application, including the SBOM in the
technical documentation, on 11 December 2027; open-source stewards report from that date.

## What it proves, and what it does not

It proves that these records — SBOMs, vulnerability-handling events, the notice payloads with their deadlines,
the seals — existed in this order and have not changed since (SHA-256 hash chain, content-bound record digests,
pack anchored into the chain, optional Ed25519 signature covering signer and time, signed chain tip that exposes a
truncated tail), and it lets anyone verify that **offline**, with this tool or with cryptovalid's verifiers.

It is **not** a conformity assessment, **not** CE marking, **not** the official CSIRT/ENISA channel (the SRP is a
human web portal with EU Login; no machine API was documented on 15/09/2026 — this tool prepares and validates the
payload and records it, a person submits it), and **not** an objective time anchor unless you attach an RFC 3161 /
OpenTimestamps token. Whether a vulnerability is "actively exploited" is your determination; CISA KEV and the ENISA
EUVD known-exploited lists are surfaced as a signal, not as the decision.

## Install

```
pip install .            # no runtime dependency; add [sign] for Ed25519 signatures / signed tips / seals (cryptography)
pip install ".[sign]"
```

## Ten minutes, end to end

```
cra keygen ~/.cra/log.key                                                    # once
cra sbom  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --from-cyclonedx syft.cdx.json
cra vuln  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key \
          --id CVE-2026-32202 --aware 2026-09-12T08:00:00Z --exploited --source cisa_kev   # checked against KEV now
cra vuln  ... --ew-sent 2026-09-12T20:00:00Z --notified 2026-09-14T09:00:00Z                # exit 1 while a deadline is overdue
cra schema --stream vulnerability > fields.json                              # fill the SRP fields
cra notice --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key \
          --stage early_warning --fields fields.json --drop ./srp_drop         # exit 1 while required fields are missing
cra pack  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --out cra_pack.json
cra sign  cra_pack.json --key ~/.cra/log.key --signer-id myapp-ci
cra seal  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --pack-sha3 <pack_sha3>
cra verify cra_pack.json --trust-store trust.json --log-pubkey <hex>          # exit 0 only if authenticity is not FAIL
cra feeds CVE-2026-32202                                                     # OSV positive control + KEV/EUVD signal
```

`cra verify` reports layers (pack JSON, kind, declared limits, pack digest, the pack's own verification snapshot,
ledger chain + record binding + anchor, declared ledger state, signed tip, producer signature, trust store) and one
authenticity verdict: `trusted-signed` > `signed` > `anchored` > `FAIL`. Without the trusted log key the tip is not
checked and the verdict says so; with a trust store an unsigned pack is a FAIL.

## Measured, not promised

- Every tamper the tests can build — a pack field, a ledger record with a stale digest, a re-chained record, a
  pack from another ledger, a pack re-hashed after signing, a wrong key pinned, a truncated tail (with the signed
  tip), a torn last line, four processes appending at once — is a named FAIL; the tests are red on the previous
  behaviour before each guard was added.
- Interoperability is measured: a ledger written here verifies unchanged with cryptovalid v0.11.4's reference
  verifier, and the truncated tail is seen through the signed tip (`tests/test_feeds_and_interop.py`, run in CI
  against the published wheel).
- The Art. 14 clock is tested on explicit instants (no wall clock in tests): early warning and notification from
  awareness; final report 14 days after the corrective measure is available, undetermined until it exists; severe
  incident (`--incident`) final report one calendar month after the *submission* of the incident notification
  (Art. 14(4)(c)), undetermined until that submission is recorded; overdue is computed from the recorded submission
  instants, never from a status word; no obligation for a non-exploited vulnerability.
- Standard documents travel with the record: a CycloneDX VEX, CSAF 2.0 or OpenVEX document is embedded verbatim and
  content-bound next to the vulnerability event, so the vendor-neutral exchange format is what the auditor sees.
- OSV pagination is followed and batches are chunked; a truncated answer is an explicit error, never a shorter list.
- Pre-publication review by five models (two providers) in two rounds, plus the author: 31 findings turned into
  tests (`tests/test_council_r1.py`, `tests/test_council_r2.py`), each red before its fix; the legal points were
  re-read on EUR-Lex and ENISA before the fix.
- The SRP schema is the 39-field ENISA glossary, stage by stage, derived by a test from the dated snapshot vendored
  in `spec/sources/` (`spec/SRP_FIELDS.md`); "complete" is never declared by silence — the payload lists what is
  missing; a notice cannot carry an awareness instant different from the recorded vulnerability event without a
  declared reason.
- The CycloneDX export validates against the official 1.6 JSON schema (vendored in `spec/schemas/`, checked in CI);
  SPDX is out of scope (ingest a CycloneDX from your generator instead).
- Feeds: OSV.dev is only believed after its positive control (a version with public CVEs) lights up; network
  failures are explicit errors, never empty results.

## Where it stands against the field (read on 15/09/2026)

Syft/Trivy/cdxgen generate better SBOMs than any Python-only floor — so this tool ingests their CycloneDX instead of
competing with them. Dependency-Track, Mend, Snyk, Cloudsmith, Anchore track vulnerabilities and licences at scale
— this tool does not replace them; their VEX/CSAF documents can be embedded verbatim, content-bound, next to the
event. Sigstore/cosign, in-toto and SLSA already give signed, tamper-evident, offline-verifiable attestations of
artefacts and SBOMs. Dedicated CRA products (e.g. "CRA Evidence") draft the notices and track the deadlines as a
SaaS with an audit trail and "SRP-ready when the API launches". What this tool adds to that field is narrower and
specific: **the Art. 14 clock and the ENISA SRP field schema as evidence**, in one hash-chained record whose
verification does not depend on the producer — the chain, the anchor, the signature and the tip are checked by
independent re-implementations in four languages, and the seal is designed to be renewed across the 10-year window.

Next decade, as far as the sources go: CycloneDX 1.7 (ECMA-424, released 2025-10-21) is the current specification
and this tool's 1.6 export stays valid under it; the SRP has no machine interface today (ENISA documents a web
portal) and this tool will adopt one if it appears; NIST IR 8547 — an initial public draft, not a final standard —
proposes deprecating the quantum-vulnerable signatures (Ed25519 included) after 2030 and disallowing them after
2035 (https://csrc.nist.gov/pubs/ir/8547/ipd), inside the retention window that starts today. That is why the seal
is a renewable chain, its verification policy defaults to those dates instead of "valid forever", the signer
registry is pluggable (a hybrid ML-DSA-65 signer plugs in with three functions) and the hash of the seal chain is
named per record and replaceable too. A time token (RFC 3161 / OpenTimestamps) is stored with a seal when you have
one; this tool does not verify it — your verifier's temporal oracle does.

## Licence

AGPL-3.0-or-later for this repository; a commercial licence of the same code is available from the author for
organisations that cannot adopt AGPL (roberto.locatelli.81@gmail.com). Copyright Roberto Locatelli, 2026.

## Provenance of this work

Written by Noûs, an AI agent under a revocable mandate from the author, who reviews and is accountable for what is
published; every claim above is backed by a test or a cited source, and the limits are stated where they apply.
