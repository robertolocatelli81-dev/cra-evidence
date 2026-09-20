# Changelog

## 0.3.0 — 2026-09-20
The generator's SBOM document is the evidence. Measured with the real generators (Syft 1.52.0, Trivy 0.74.0, cdxgen
12.8.4 — all emitting CycloneDX 1.7 by default) and sbomqs 2.1.2 on a 419-component npm tree: 0.2.0 stored only its
own re-encoding of an ingested SBOM, which scored below every original (5.3→4.2, 6.6→4.4, 4.8→3.7). Now `cra sbom
--from-cyclonedx/--from-spdx` hashes the document's exact bytes (SHA-256) into the record, copies it to
`<ledger>.sources/<sha256>.json` (`--no-store-source` keeps the hash only; the store never overwrites different bytes;
a file changed between ingest and record is refused), and every verifier — Python, JS, Go, Rust — re-hashes it
(`source-documents` layer: mismatch FAIL, absent SKIP, `--require-sources` makes absence a FAIL). The record's index
now carries component type, CPE and what the document declared (generator + version, spec version, components incl.
nested, duplicates merged, dependency edges, component types); nested `components[].components` are walked; a
malformed hash is dropped as in the SPDX path; SPDX `primaryPackagePurpose` maps to the type and `cpe23Type` refs are
read. Export: CycloneDX 1.6 or 1.7 (official 1.7 schema vendored), with serialNumber, `metadata.tools`, bom-refs
(unique), component types, CPEs, SPDX licence *expressions* (`Apache-2.0 OR BSD-3-Clause`), and `dependencies` only
from edges the producer knows — the installed floor's Requires-Dist graph as walked, top-level or transitive — never re-invented for an ingested graph; the installed floor reads PEP 639
`License-Expression` (the legacy `License` field is empty in cryptography ≥ 42 — 0.2.0 recorded no licence there).
Validated with the official CycloneDX CLI 0.33.1 and pyspdxtools 0.8.5 in CI (positive controls included) and with jsonschema in the tests.
Six unmodified generator documents vendored as fixtures. Differential oracle: 39 cases (incl. hostile `source.sha256` values: int, object, null, empty, upper-case, traversal, non-ASCII; `--require-sources` with the ledger missing), and the failing layers must
agree too (ablation caught; before the fix Go/Rust skipped a non-string hash while Python/JS failed — found by self-review and by Haiku in round 1). Interop re-measured against cryptovalid 0.15.0. Legal basis re-read 20/09/2026 (ENISA
FAQ: no API at initial release; glossary unchanged; Digital Omnibus 2025/0360(COD) still a proposal).

## 0.2.0 — 2026-09-15
SPDX ingest: `sbom_from_spdx()` / `cra sbom --from-spdx` read SPDX 2.2/2.3 JSON (`packages`, purl external refs,
SHA-256 checksums, supplier/originator, concluded→declared licence) and SPDX 3.0 JSON-LD (`software_Package`,
`software_packageUrl`, `verifiedUsing` Hash, `suppliedBy` resolved to the agent, licences via hasConcludedLicense /
hasDeclaredLicense relationships); the product described by the document is not a component; `NOASSERTION` versions
are not resolved and never meet the Annex I floor. Field names checked on the official spdx/spdx-examples documents,
vendored as fixtures. Suggested by the Gemini Pro competitor review of 15/09/2026 (Yocto and other industrial
generators emit SPDX natively).

## 0.1.1 — 2026-09-15
Independent verifiers in JavaScript (Node, no dependencies), Go (standard library) and Rust (pure-Rust JSON/SHA-256/
SHA3-256 + ed25519-dalek) with the same CLI and verdict as `cra verify`; differential oracle on 26 intact/tampered
fixtures (0 divergences), required in CI. `cra sign --aws-kms-key-id`: Ed25519 signing in AWS KMS (SigV4, standard
library; derivation validated on the official AWS vector). Release packs signed with the author's KMS key; trust
store published with each release. Clean-clone bench: 5 passes, 7/7 suites (67 tests) each.

## 0.1.0 — 2026-09-15
First public release. SBOM records (schema-valid CycloneDX 1.6 subset; ingest of any CycloneDX; VEX/CSAF documents
embedded content-bound), Art. 14 clock on recorded submission instants (vulnerabilities and severe incidents; calendar
month per Art. 14(4)(c)), SRP-aligned notices (39-field ENISA glossary derived from a vendored dated snapshot, per-stage
R/O/A/C rules, PEC options), hash-chained ledger in the cryptovalid profile (flock fail-closed, torn tail refused,
floats/NaN/unportable ints/lone surrogates refused, signed chain tip), evidence pack anchored + Ed25519 sidecar whose
signature covers signer and time, crypto-agile seal (renewable chain, pinned key, hash named per record, NIST IR 8547
dates as default policy, time token stored when given), offline verifier with layers and authenticity levels (tip
checked with a trusted log key), OSV (chunked, paginated, aliases, aligned to input) / CISA KEV / ENISA EUVD feeds with
positive controls (OSV aliases resolved per id, since the batch endpoint is condensed). Seal signs its own fields;
hash policy applied to every record; carried-forward SRP fields copied from the previous stage or counted missing;
incident final-report deadline never invented in a notice; licences exported as SPDX id or free-text name; pack
written atomically after its anchor; a required ledger that is missing is a FAIL. Interop measured against
cryptovalid v0.11.4. Three council rounds (five models, two providers): 44 findings → tests.
