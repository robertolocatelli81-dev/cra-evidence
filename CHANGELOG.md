# Changelog

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
