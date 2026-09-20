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
human web portal with EU Login; no machine API was documented on 15/09/2026, nor on 20/09/2026 — this tool prepares and validates the
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
cra sbom  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --from-cyclonedx syft.cdx.json   # or --from-spdx sbom.spdx.json
cra vuln  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key \
          --id CVE-2026-32202 --aware 2026-09-12T08:00:00Z --exploited --source cisa_kev   # checked against KEV now
cra vuln  ... --ew-sent 2026-09-12T20:00:00Z --notified 2026-09-14T09:00:00Z                # exit 1 while a deadline is overdue
cra schema --stream vulnerability --template early_warning > ew.json         # fillable template for that stage
cra notice --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key \
          --stage early_warning --fields ew.json --drop ./srp_drop             # exit 1 while required fields are missing
cra notice ... --stage notification --fields n72.json --previous ew.json ...  # carried-forward fields copied from the previous stage
cra pack  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --out cra_pack.json \
          --support-period-end 2031-12-31T00:00:00Z                           # retention = 10 years or support period, whichever is longer
cra sign  cra_pack.json --key ~/.cra/log.key --signer-id myapp-ci
cra seal  --ledger cra.ledger.jsonl --product myapp --version 2.3 --tip-key ~/.cra/log.key --pack-sha3 <pack_sha3>
cra verify cra_pack.json --trust-store trust.json --log-pubkey <hex> --require-sources   # exit 0 only if authenticity is not FAIL (and every stored SBOM document re-hashes)
cra feeds CVE-2026-32202                                                     # OSV positive control (with CVE alias) + KEV/EUVD signal; exit 1 if any feed fails
```

`cra verify` reports layers (pack JSON, kind, declared limits, pack digest, the pack's own verification snapshot,
ledger chain + record binding + anchor, declared ledger state, stored SBOM source documents, signed tip, producer
signature, trust store) and one
authenticity verdict: `trusted-signed` > `signed` > `anchored` > `FAIL`. Without the trusted log key the tip is not
checked and the verdict says so; with a trust store an unsigned pack is a FAIL.

## Measured, not promised

- Every tamper the tests can build — a pack field, a ledger record with a stale digest, a re-chained record, a
  pack from another ledger, a pack re-hashed after signing, a wrong key pinned, a truncated tail (with the signed
  tip), a torn last line, four processes appending at once — is a named FAIL; the tests are red on the previous
  behaviour before each guard was added.
- The generator's SBOM is the evidence, not our re-encoding of it (0.3.0). `cra sbom --from-cyclonedx/--from-spdx`
  hashes the exact bytes of the document (SHA-256) into the record and stores a copy in `<ledger>.sources/`; the
  record keeps a normalised index (name, version, type, purl, CPE, SHA-256, licence; nested components walked;
  duplicates counted, never hidden) and what the document declared (generator and version, spec version,
  components, dependency edges, component types). All four verifiers re-hash the stored bytes (`source-documents`
  layer: mismatch = FAIL, absent = SKIP or FAIL with `--require-sources`). Measured on 20/09/2026 with the real
  generators on a 419-component npm tree — Syft 1.52.0, Trivy 0.74.0, cdxgen 12.8.4, all three emitting CycloneDX
  1.7 by default now — and scored with sbomqs 2.1.2: the 0.2.0 re-encoding scored *below* every original
  (Syft 5.3 → 4.2, cdxgen 6.6 → 4.4, Trivy 4.8 → 3.7 out of 10), which is why the original is kept; the 0.3.0 index
  export scores 5.3 / 5.5 / 4.9 on the same inputs (bom-ref, serialNumber, tools, component type, CPE, licence
  expressions, and a dependency graph only from edges the producer knows: the installed floor's Requires-Dist graph with PEP 508 markers evaluated for this interpreter — `dependsOn: []` is CycloneDX's positive statement "no dependencies", so it is emitted only for a component whose metadata was actually read, and the composition is declared `unknown` otherwise (`incomplete` would assert that more exist); never re-invented for an ingested document).
  Six unmodified generator documents are vendored as fixtures (`tests/fixtures/real_tools/`): the tests read the
  same dependency with the same purl, version and licence from every one of them and validate the exports with
  jsonschema; CI validates the four CycloneDX fixtures and every export with the official CycloneDX CLI 0.33.1, and the two SPDX
  fixtures with the official `pyspdxtools` 0.8.5, each with a positive control.
- Interoperability is measured: a ledger written here verifies unchanged with cryptovalid v0.15.0's reference
  verifier, and the truncated tail is seen through the signed tip (`tests/test_feeds_and_interop.py`, run in CI
  against the published wheel; re-measured 20/09/2026).
- The Art. 14 clock is tested on explicit instants (no wall clock in tests): early warning and notification from
  awareness; final report 14 days after the corrective measure is available, undetermined until it exists; severe
  incident (`--incident`) final report one calendar month after the *submission* of the incident notification
  (Art. 14(4)(c)), undetermined until that submission is recorded; overdue is computed from the recorded submission
  instants, never from a status word; no obligation for a non-exploited vulnerability.
- Standard documents travel with the record: a CycloneDX VEX, CSAF 2.0 or OpenVEX document is embedded verbatim and
  content-bound next to the vulnerability event, so the vendor-neutral exchange format is what the auditor sees.
- OSV pagination is followed and batches are chunked; a truncated answer is an explicit error, never a shorter list.
  The batch endpoint returns condensed records (id + modified — verified live), so aliases (GHSA ↔ CVE ↔ PYSEC) are
  resolved per id and the positive control passes only when a CVE alias comes back: KEV and EUVD key on CVEs.
- A `--source cisa_kev|enisa_euvd` provenance is stored only after the catalogue confirms the id now (or is labelled
  `asserted:` on request), and a confirmed catalogue hit sets the exploitation flag: provenance and clock cannot diverge.
- The seal signs its own time, time-source and token together with the whole previous chain; the verifier's policy
  defaults to the NIST IR 8547 draft dates for both the signature and the hash, and says when a renewal is due.
- Pre-publication review by five models (two providers) in three rounds, plus the author: 44 findings turned into
  tests (`tests/test_council_r1.py` … `r3.py`), each red before its fix; 0.3.0: three more rounds (Opus, Sonnet, Haiku;
  Gemini Pro out of credits that day), 20 findings (listed in the CHANGELOG), each re-measured and turned into an oracle
  case or a test; CI now also runs the suites with no optional dependency at all; the legal points were re-read on EUR-Lex
  and ENISA, and the OSV API behaviour checked live, before the fix.
- The SRP schema is the 39-field ENISA glossary, stage by stage, derived by a test from the dated snapshot vendored
  in `spec/sources/` (`spec/SRP_FIELDS.md`); "complete" is never declared by silence — the payload lists what is
  missing; a notice cannot carry an awareness instant different from the recorded vulnerability event without a
  declared reason.
- The CycloneDX index export written into the record (1.6 by default, `cra sbom --spec-version 1.7` or `to_cyclonedx_min("1.7")`) validates against the official 1.6 and 1.7 JSON schemas
  (vendored in `spec/schemas/`, checked by the tests) and against the official CycloneDX CLI 0.33.1 with
  `--fail-on-errors` (checked in CI, with a positive control that the CLI rejects a broken document). SPDX 2.2/2.3
  JSON and 3.0 JSON-LD are ingested (`--from-spdx`, since 0.2.0); there is no SPDX export.
- Feeds: OSV.dev is only believed after its positive control (a version with public CVEs) lights up; network
  failures are explicit errors, never empty results.

## Where it stands against the field (read on 15/09/2026, re-measured with the tools on 20/09/2026)

Syft/Trivy/cdxgen generate better SBOMs than any Python-only floor — so this tool ingests their CycloneDX or SPDX
instead of competing with them, and since 0.3.0 keeps their document byte-exact as the evidence (0.2.0 re-encoded
it and lost bom-refs, the dependency graph, CPEs and the tool provenance: measured, above). Dependency-Track, Mend, Snyk, Cloudsmith, Anchore track vulnerabilities and licences at scale
— this tool does not replace them; their VEX/CSAF documents can be embedded verbatim, content-bound, next to the
event. Sigstore/cosign, in-toto and SLSA already give signed, tamper-evident, offline-verifiable attestations of
artefacts and SBOMs. Dedicated CRA products (e.g. "CRA Evidence") draft the notices and track the deadlines as a
SaaS with an audit trail and "SRP-ready when the API launches". What this tool adds to that field is narrower and
specific: **the Art. 14 clock and the ENISA SRP field schema as evidence**, in one hash-chained record whose
verification does not depend on the producer — the chain, the anchor, the signature and the tip are checked by
independent re-implementations in four languages, and the seal is designed to be renewed across the 10-year window.

Next decade, as far as the sources go: CycloneDX 1.7 (ECMA-424, released 2025-10-21) is the current specification —
Syft 1.52.0, Trivy 0.74.0 and cdxgen 12.8.4 emit it by default (measured 20/09/2026) — and this tool ingests it and
exports 1.6 or 1.7, both validated; the SRP has no machine interface today (ENISA's FAQ, re-read 20/09/2026: "no Application Programming Interface (API)
will be provided at the initial release of the SRP … API functionality may be considered in a future phase"; the
39-field glossary re-downloaded the same day is identical to the vendored snapshot) and this tool will adopt one if it
appears — the Digital Omnibus proposal (COM, 19/11/2025, procedure 2025/0360(COD), not adopted) would build a single
entry point for incident reporting on the CRA platform; NIST IR 8547 — an initial public draft, not a final standard —
proposes deprecating the quantum-vulnerable signatures (Ed25519 included) after 2030 and disallowing them after
2035 (https://csrc.nist.gov/pubs/ir/8547/ipd), inside the retention window that starts today. That is why the seal
is a renewable chain, its verification policy defaults to those dates instead of "valid forever", the signer
registry is pluggable (a hybrid ML-DSA-65 signer plugs in with three functions) and the hash of the seal chain is
named per record and replaceable too. A time token (RFC 3161 / OpenTimestamps) is stored with a seal when you have
one; this tool does not verify it — your verifier's temporal oracle does.

## Independent verifiers (JavaScript, Go, Rust — and a JDK-only Java verifier for the ledger)

The ledger inside every pack follows the cryptovalid profile, so it can also be re-verified by cryptovalid's
single-file Java verifier (`verifiers/java/CvVerify.java` in cryptovalid-opencore ≥ 0.13.0, JDK standard library
only: hash chain, Ed25519 and — from JDK 24 — ML-DSA-65 signatures, signed chain tip). For a firm whose toolchain is
the JVM this means the CRA evidence is checkable with nothing but a JDK; the pack layers above the ledger (sidecar
signature, trust store, seal) are checked by the four verifiers of this repository.

`verifiers/` holds three re-implementations of `cra verify` written from the profile — Node (no dependencies), Go
(standard library only), Rust (pure-Rust JSON/SHA-256/SHA3-256, `ed25519-dalek` for signatures) — with the same
command line and the same verdict, plus a differential oracle that CI runs on 55 intact and tampered fixtures: the
four verifiers must agree on every one, verdict and failing layers alike (measured 20/09/2026: 0 divergences). An auditor can therefore verify a pack,
its ledger, its signature and its signed tip without executing the producer's code. Details in `verifiers/README.md`.

## Signing with AWS KMS

`cra sign pack.json --signer-id <id> --aws-kms-key-id <id> --aws-region <region>` signs the sidecar with an Ed25519
key held in AWS KMS (key spec ECC_NIST_EDWARDS25519): the private key never leaves the HSM, the request is SigV4 over
HTTPS with the standard library only, and the public key goes into your trust store for `trusted-signed`. The
release packs of this repository are signed that way.


## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/cra-evidence/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with firms that must report under the Cyber Resilience Act and want their SBOM, Art. 14 clock and SRP notices as verifiable evidence. Write with the use case; the answer says what is measured and what is not.
- **Licence**: AGPL-3.0-or-later: study, test and use it freely; a service built on it must share its changes; a **commercial licence of the same code** is available from the author for organisations that cannot adopt AGPL.
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## Licence

AGPL-3.0-or-later for this repository; a commercial licence of the same code is available from the author for
organisations that cannot adopt AGPL (roberto.locatelli.81@gmail.com). Copyright Roberto Locatelli, 2026.

## Provenance of this work

Written by Noûs, an AI agent under a revocable mandate from the author, who reviews and is accountable for what is
published; every claim above is backed by a test or a cited source, and the limits are stated where they apply.
