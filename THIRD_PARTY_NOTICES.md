# Third-party material

Everything below is used under its own licence and attributed here; nothing proprietary or patented from third
parties is included in this repository.

| what | where | origin / licence |
|---|---|---|
| CycloneDX JSON schemas 1.6 and 1.7 (`bom-1.6.schema.json`, `bom-1.7.schema.json`, `jsf-0.82.schema.json`) | `spec/schemas/` | OWASP CycloneDX, Apache License 2.0 — https://github.com/CycloneDX/specification |
| SPDX licence-id list (`spdx.schema.json`) | `spec/schemas/`, `cra_evidence/data/` | CycloneDX distribution of the SPDX License List (Apache-2.0 packaging; the list itself is CC0/SPDX) |
| ENISA CRA SRP Glossary table (39 fields), snapshot of 15/09/2026 | `spec/sources/enisa_srp_glossary_20260915.json` | ENISA, reproduction authorised provided the source is acknowledged — https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2 |
| Regulation (EU) 2024/2847 quotations | `spec/LEGAL_BASIS.md`, docstrings | EUR-Lex, © European Union, reuse authorised (Commission Decision 2011/833/EU) |
| Strict JSON parser, canonical encoder, SHA-256/SHA3-256 (Go: `verifiers/go/canonical.go`, `prescan.go`; Rust: `json.rs`, `keccak.rs`, `sha256.rs`; JS: canonical functions) | `verifiers/` | cryptovalid-opencore, same author, AGPL-3.0-or-later — https://github.com/robertolocatelli81-dev/cryptovalid-opencore |
| SPDX example documents (`spdx-2.3-*.spdx.json`, `spdx-3.0-*.spdx3.json`), unmodified, used only as test fixtures | `tests/fixtures/spdx/` | spdx/spdx-examples, GPL-3.0 (compatible with AGPL-3.0-or-later per GPLv3 §13) — https://github.com/spdx/spdx-examples |
| `ed25519-dalek` (Rust verifier only, fetched at build time) | `verifiers/rust/Cargo.toml` | BSD-3-Clause — https://github.com/dalek-cryptography/curve25519-dalek |
| `cryptography` (optional `sign` extra, fetched at install time) | `pyproject.toml` | Apache-2.0 / BSD-3-Clause — https://github.com/pyca/cryptography |

No AWS SDK is vendored: the KMS client is HTTP + SigV4 written here. No keys, credentials or personal data other than
the author's contact are in the repository or its history (checked with gitleaks on every push).
| Generator outputs used as fixtures (`tests/fixtures/real_tools/`): Syft 1.52.0 (Anchore, Apache-2.0), Trivy 0.74.0 (Aqua Security, Apache-2.0), cdxgen 12.8.4 (CycloneDX/AppThreat, Apache-2.0) run on 20/09/2026 on a one-dependency npm project | `tests/fixtures/real_tools/` | the documents are the tools' unmodified output (data, not code); base64-js 1.5.1 is MIT |
