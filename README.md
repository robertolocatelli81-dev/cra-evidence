# omega-cra-evol

_Renamed from `cra-evidence` to `omega-cra-evol` in 0.10.0 (13/11/2026). The earlier name was not available as a PyPI project name. Formats, exit codes and verification are unchanged; packs, ledgers and attestations made with earlier versions verify as before._

**Manufacturers of products with digital elements on the EU market now report in hours.** Under the Cyber Resilience
Act (Regulation (EU) 2024/2847), Article 14 applies since **11 September 2026**, also to products placed on the market
before 11 December 2027 (Art. 69(3)), and open-source software stewards report from 11 December 2027 (Art. 24(3), 71(2)).
On becoming aware of an actively exploited vulnerability or a severe incident, the manufacturer sends, through ENISA's
Single Reporting Platform (SRP):

- an **early warning within 24 hours**,
- a **notification within 72 hours**,
- a **final report** — no later than 14 days after a corrective or mitigating measure is available (vulnerability),
  within one month after the submission of the incident notification (severe incident).

The technical documentation stays at the disposal of market surveillance authorities for **at least 10 years** after
the product is placed on the market, or for the support period if longer (Art. 13(13)). Sources and re-reading dates:
[`spec/LEGAL_BASIS.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/LEGAL_BASIS.md).

The SRP is a web portal. What was notified, under which ENISA field glossary, how complete, when the clock started and
when it was filed lives in the firm's own tools — and may have to be shown, years later, to someone who does not run them.
**omega-cra-evol** keeps it in one hash-chained ledger (SBOMs byte for byte, the Art. 14 clock, notices in the ENISA SRP
field vocabulary, signed evidence packs and renewable seals) and signs a notice as an in-toto attestation that
anyone can verify **offline**.

## Demo: from sbomify to a verified attestation

[sbomify](https://github.com/sbomify/sbomify) records CRA Art. 14 reports and their filings. The two documents below
are real responses of its API (`GET /api/v1/compliance/cra-reports/{id}` and `…/filings/{filing_id}`) at commit
4ef6128, on synthetic data, vendored byte for byte in `tests/fixtures/sbomify_4ef6128/`. From a checkout, after
`pip install ".[sign]"`:

```bash
F=tests/fixtures/sbomify_4ef6128
cra keygen psirt.key > psirt.pub.json
python3 -c 'import json; print(json.dumps({"acme-psirt": json.load(open("psirt.pub.json"))["public_key_hex"]}))' > trust.json
cra import sbomify --ledger cra.ledger.jsonl --product acme-d1 --version 1.0.7 \
    --report $F/report_JBuMp9bYI2aN.json --filing $F/filing_JBuMp9bYI2aN_early_warning_1.json \
    --drop-dir ./srp_drop --source-version 4ef61281e69d693e3560185bf81ec5474179ea98
cra attest srp_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl \
    --key psirt.key --signer-id acme-psirt --out ew.intoto.json
cra verify-attestation ew.intoto.json --trust-store trust.json \
    --drop srp_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl
```

Output (trimmed):

```
cra import sbomify        "imported": true,  "absent_at_source": ["1", "4", "7a", "41"],
                          "stage": "early_warning", "complete": false,
                          "missing_required": ["notification_type", "manufacturer_name"],
                          "deadline_utc": "2026-11-14T01:00:00+00:00",
                          "filing": "declared by sbomify: what it recorded about each filing, not a proof of submission"
cra attest                "attested": true, "keyid": "acme-psirt"
cra verify-attestation    "verified": true, "trusted": true, "statement": "accepted",
                          "drop": "PASS", "ledger": "PASS", "product": "PASS", "reasons": []      (exit 0)
```

The imported early warning is recorded as incomplete: glossary rows 1 (notification type) and 4 (manufacturer name),
required at the early warning, are not in sbomify's filing document (sbomify keeps the type as the report's `kind`,
which becomes the notice's `stream`); they are listed in `absent_at_source` with rows 7a and 41, never filled in. Change one byte of the drop file and `cra verify-attestation` exits 1 with
`"drop": "FAIL"` and reason `subject_digest`.

The same attestation for a notice built here, without sbomify:

```bash
cat > ew.json <<'EOF'
{"notification_type": "Vulnerability", "title": "Synthetic example (fictitious product Acme D1)",
 "summary": "Synthetic example: the CVE / EUVD identifiers are real public records, used here only for their form.",
 "manufacturer_name": "Acme (fictitious)", "member_states_available": ["IT"], "product_name": "Acme D1",
 "product_version": "1.0.7", "awareness_datetime_utc": "2026-11-12T08:00:00Z",
 "cve_id": "CVE-2024-3094", "euvd_id": "EUVD-2024-31700"}
EOF
cra notice --ledger cra.ledger.jsonl --product acme-d1 --version 1.0.7 --stage early_warning --fields ew.json --drop native_drop
cra attest native_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl --key psirt.key --signer-id acme-psirt \
    --case-reference example-csirt 2026-000123 --out native.intoto.json
cra verify-attestation native.intoto.json --trust-store trust.json --drop native_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl
```

Same folder, same key → `"complete": true`,
`"deadline_utc": "2026-11-13T08:00:00+00:00"`, `"status": "prepared_not_sent"`; then `"verified": true`, exit 0, and:

```
"vulnerability_ids": {"declared": [{"id": "CVE-2024-3094", "scheme": "cve"}, {"id": "EUVD-2024-31700", "scheme": "euvd"}],
                      "notice":   [{"id": "CVE-2024-3094", "scheme": "cve"}, {"id": "EUVD-2024-31700", "scheme": "euvd"}],
                      "result": "matched"},
"case_reference":    {"declared": {"id": "2026-000123", "issuer": "example-csirt"}, "result": "declared by the signer, not checkable"}
```

The statement is `art14-filing` v0.2: it carries the notice's CVE and EUVD identifiers (read from the notice, never
typed) and, if given, the reference a coordinator gave to the case. A coordinator can receive the statement **without**
the notice file — the statement names the notice by its digests, not its text: the same command without `--drop` still
verifies the signature and the ledger entry, and reports the identifiers as `"declared, not checked (no drop file
given)"`. With the notice file they must be exactly the notice's: one more, one fewer, or none while the notice has
some, and the statement is refused (`vulnerability_ids`). `--predicate v0.1` writes a v0.1 statement (the format of 0.8.0),
which says nothing about identifiers.
`cra schema --stream vulnerability --template early_warning` prints a fillable template of a stage.

## Proofs

- **Specification before code:** the attestation format is [`spec/art14-filing/v0.1/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/art14-filing/v0.1/README.md)
  (in-toto Statement v1 in a DSSE envelope, Ed25519, closed predicate) and its delta
  [`v0.2`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/art14-filing/v0.2/README.md) (vulnerability identifiers, case reference); the notice rules and the sbomify mapping are in
  [`spec/SRP_FIELDS.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/SRP_FIELDS.md); the receipt of `cra verify` in [`spec/RECEIPT.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/RECEIPT.md).
- **Attestation vectors:** [`spec/art14-filing/v0.1/vectors/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/tree/v0.10.0/spec/art14-filing/v0.1/vectors/) — 52 envelopes —
  and [`v0.2/vectors/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/tree/v0.10.0/spec/art14-filing/v0.2/vectors/) — 53, with real CVE / EUVD identifiers in synthetic notices;
  each `manifest.json` gives every envelope's expected exit code and exact set of reason codes, for any other
  implementation to run.
- **Verifiers in other languages, by the same author:** [`verifiers/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/verifiers/README.md) re-implements `cra verify`
  in JavaScript (Node, no dependencies), Go (standard library) and Rust; `verifiers/differential.py` builds intact and
  tampered packs and requires the same verdict and the same failing layers from all of them. The ledger also follows
  the profile of cryptovalid's verifiers (same author).
- **CI** ([`.github/workflows/ci.yml`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/.github/workflows/ci.yml)): the suites on Python 3.9, 3.11 and 3.12, with
  cryptography only and with no optional dependency; the differential oracle across Python, JS, Go and Rust; the
  official CycloneDX CLI and SPDX tools on the SBOM fixtures; gitleaks on the whole history. A weekly workflow
  re-reads ENISA's SRP glossary page and fails on any difference from the vendored snapshot.
- **Public demo:** [omega-cra-evol-demo](https://github.com/robertolocatelli81-dev/omega-cra-evol-demo) installs a release
  three ways (index, attested image, GitHub Action) on clean GitHub-hosted runners, every week, and verifies the
  release's signed evidence pack with each (the index job also requires a tampered copy to fail).
- **Attested container image and GitHub Action:** below, under Install.
- **Archived:** Zenodo concept DOI [10.5281/zenodo.24172960](https://doi.org/10.5281/zenodo.24172960) (resolves to the
  latest version); `CITATION.cff`.

## What is measured

Re-run on 13/11/2026 on this release's code (omega-cra-evol 0.10.0; `git archive` of the commit, fresh
virtual environments):

- The test suite: 466 tests, OK on Python 3.9.25, 3.11.2, 3.12.15 and 3.13.15 with `[sign]`, jsonschema, referencing and the
  cryptovalid wheel; 1 skipped (the live feeds check, which needs the network).
- The attestation vectors: v0.1, 52 (10 valid, 42 each breaking one rule), and v0.2, 53 (10 valid, 43 refused): each
  gives the exit code and exactly the set of reason codes its `manifest.json` expects.
- A v0.1 statement keeps its receipt: on the 52 v0.1 vectors of 0.8.0, the receipts of 0.8.0 and of this code are
  byte for byte the same on 51; the 52nd used the v0.2 TypeURI as its "wrong" value and is now judged as v0.2.
- The vendored sbomify documents (3 reports, 9 filings, all five stages: early warning, notification, intermediate,
  final report, users informed): every filing imports, and each of the 9 notices is attested (v0.2) and verifies with
  its drop file and ledger.
- The differential oracle: 186 intact and tampered cases, Python, JavaScript, Go and Rust verifiers, 0 divergences.
- The notice schema follows ENISA's SRP glossary "Version 1.6" of 21/10/2026: 49 table rows, 43 numbered fields, in
  `spec/sources/enisa_srp_glossary_20261112.json`.

## Install

```
pip install --index-url https://robertolocatelli81-dev.github.io/pypi/ omega-cra-evol      # wheel of the GitHub Release
pip install ".[sign]"    # from a checkout; no runtime dependency, [sign] adds Ed25519 signatures / signed tips / seals
```

The command is `cra` (also installed as `omega-cra-evol`, the name `pipx run` and `uvx` look for); the Python package is
`omega_cra_evol`.

Container image (Linux x86_64, `[sign]` included, build provenance attested by the release workflow):

```
gh attestation verify oci://ghcr.io/robertolocatelli81-dev/omega-cra-evol:0.10.0 --repo robertolocatelli81-dev/omega-cra-evol \
  --cert-identity https://github.com/robertolocatelli81-dev/omega-cra-evol/.github/workflows/container.yml@refs/tags/v0.10.0 \
  --source-ref refs/tags/v0.10.0 --deny-self-hosted-runners
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/robertolocatelli81-dev/omega-cra-evol:0.10.0 verify pack.json --ledger cra.ledger.jsonl
```

GitHub Action (verifies the provenance of the image digest it pulled, then runs `cra` in the workspace, without
network by default):

```yaml
- uses: robertolocatelli81-dev/omega-cra-evol@v0.10.0
  with:
    args: verify dist/pack.json --ledger evidence/cra.ledger.jsonl --trust-store evidence/trust.json
```

## Commands

| Command | What it does |
|---|---|
| `cra sbom --from-cyclonedx F` / `--from-spdx F` | records an SBOM; the generator's document is hashed and stored byte for byte |
| `cra vuln --id ID --aware T [--exploited] [--incident]` | records a vulnerability or severe-incident event and computes the Art. 14 deadlines from the declared awareness instant |
| `cra schema --stream S --template STAGE` | prints the fields of a stage in the ENISA glossary vocabulary |
| `cra notice --stage STAGE --fields F --drop D` | builds the notice payload, lists missing required fields, records it; never submits it |
| `cra import sbomify --report R --filing F …` | imports the notices recorded in sbomify, documents kept byte for byte |
| `cra check-notice DROP [--ledger L]` | re-checks a notice under the glossary it records |
| `cra attest DROP` / `cra verify-attestation ENV` | signs / verifies the `art14-filing` attestation of a notice: v0.2 (default: with its CVE / EUVD identifiers and an optional case reference) or v0.1 |
| `cra pack`, `cra sign`, `cra seal`, `cra verify` | evidence pack anchored in the ledger, Ed25519 signature (seed file or AWS KMS), renewable seal, offline verification |
| `cra feeds ID` | read-only network checks: OSV positive control, CISA KEV / ENISA EUVD exploitation signal |
| `cra obligations` | which obligations are in force for a role at an instant, and the horizons counted in years (Art. 13, 14, 24(3), 69, 71); both readings of a start date, 00:00 UTC and 00:00 Brussels; never reads the clock |

Every subcommand has `--help`. `cra verify` gives one authenticity verdict (`trusted-signed` > `signed` > `anchored` >
`FAIL`) and exits 0 verified, 1 a finding against the pack, 77 not assessed, 2 unusable input, 74 receipt not written
([`spec/RECEIPT.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.10.0/spec/RECEIPT.md)).

## Guarantees and assumptions

- **What a verified attestation guarantees** (with `--drop` and `--ledger`): these exact notice bytes, under this glossary and these rules, with this
  completeness and deadline, sit at this entry of an intact ledger, and a key in your trust store signed the statement.
- **Not a conformity assessment, not CE marking**, not legal advice.
- **Not the official CSIRT/ENISA channel.** The SRP is a web portal; ENISA's FAQ (re-read 12/11/2026) says no API is
  provided at its initial release. A person submits the notice; this tool prepares, records and verifies it.
- **The awareness instant is the manufacturer's declaration** (glossary rows v26 / i37): the evidence shows that it was
  recorded, and when, not that it is true. Whether a vulnerability is actively exploited is the manufacturer's
  determination; KEV and EUVD are surfaced as signals.
- **An imported filing record is the source tool's declaration, not proof of submission.** The same holds for a
  filing declared with `cra attest --filed-at`.
- **Identifiers and case reference (v0.2):** the CVE / EUVD identifiers are compared with the notice only when the
  notice file is given; a case reference is the signer's declaration, which no file can check.
- **Time:** the ledger orders records; it is an objective time anchor only with an attached RFC 3161 / OpenTimestamps
  token, which this tool stores after checking its shape (`cra seal`: an RFC 3161 token must carry a SHA3-256 imprint
  of the sealed digest) and does not verify (signature, TSA certificate, time: `temporal_trust` stays ASSUMED).
- **Verifiers:** the JavaScript, Go and Rust verifiers and cryptovalid's are by the same author as this tool; they are
  separate implementations of a written profile, not separate parties.

## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/omega-cra-evol/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with firms that must report under the Cyber Resilience Act and want their SBOM, Art. 14 clock and SRP notices as verifiable evidence. Write with the use case; the answer says what is measured and what is not.
- **Citation**: concept DOI [10.5281/zenodo.24172960](https://doi.org/10.5281/zenodo.24172960) (resolves to the latest version; DOI of 0.9.0: [10.5281/zenodo.24203603](https://doi.org/10.5281/zenodo.24203603)); `CITATION.cff` in this repository.
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## Licence

AGPL-3.0-or-later for this repository; a commercial licence of the same code is available from the author for
organisations that cannot adopt AGPL (roberto.locatelli.81@gmail.com). Copyright Roberto Locatelli, 2026.
