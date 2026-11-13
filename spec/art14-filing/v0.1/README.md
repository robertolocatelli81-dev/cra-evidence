# Predicate type `art14-filing` v0.1 — an EU CRA Article 14 notice, its stage, and what is recorded about its filing

TypeURI: `https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.1`

Status: draft, written before the code (13/11/2026). Normative for cra-evidence from the release that implements it.
The in-toto rules cited here were read on 13/11/2026 at in-toto/attestation `50bf017` (spec v1.2: `spec/v1/README.md`,
`statement.md`, `envelope.md`, `field_types.md`, `docs/new_predicate_guidelines.md`) and secure-systems-lab/dsse
`437a330` (`protocol.md`, `envelope.md`). The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

Regulation (EU) 2024/2847, Article 14, obliges a manufacturer to notify an actively exploited vulnerability or a
severe incident through ENISA's Single Reporting Platform (SRP): an early warning within 24 hours of becoming aware, a
notification within 72 hours, and a final report (14(2), 14(4)); an intermediate report when the CSIRT designated as
coordinator requests one (14(6)); and to inform the impacted users (14(8)). Article 13(13) keeps the technical
documentation at the disposal of market surveillance authorities for at least 10 years.

The SRP is a web portal; the manufacturer's evidence of what it notified, and when, lives in its own tools. A statement
of this type lets a third party check offline, years later and without the manufacturer's tools:

1. **which notice** (the exact bytes of the notice payload — the subject);
2. **under which ENISA field glossary** and rules it was built, and whether it was complete for its stage;
3. **what the manufacturer's tool recorded about its filing** (SRP reference, time, person) — as a *declaration*;
4. **which source** the notice came from (this tool, or another tool's export, with that export's own digest);
5. **where it sits** in the manufacturer's hash-chained ledger.

What it does **not** prove: that the notice reached the SRP or was accepted by a CSIRT (ENISA's FAQ, read on
12/11/2026: no API at the initial release; notifications are submitted through the platform interface); that the
awareness instant is true (it is the
manufacturer's statement, §4.4); conformity with the Regulation. Article 25 security attestations of free and
open-source software (the subject of the Eclipse ORC "cra-attestations" work) are a different object.

## 2. Envelope and statement

- **Envelope:** DSSE, `payloadType` `application/vnd.in-toto+json`, signatures over
  `PAE(UTF8(payloadType), payload)` as in DSSE `protocol.md`. Ed25519 (RFC 8032), 64-byte signature; the `keyid` of a
  signature is the signer id of the trust store (§5). Producers write standard base64 with padding; verifiers accept
  the standard and the URL-safe alphabet (DSSE `protocol.md`).
- **Statement:** in-toto Statement v1, `_type` `https://in-toto.io/Statement/v1`, `predicateType` the TypeURI above.
- **Subject:** exactly one element: `name` `srp-notice:<stream>:<stage>`, `digest`
  `{"sha256": <64 lowercase hex>, "sha3_256": <64 lowercase hex>}` of the exact bytes of the notice file (a `cra-srp/2`
  drop file written by `cra notice`, or a `cra-srp/3` drop file of an imported notice; spec/SRP_FIELDS.md), both required (algorithm names as in in-toto `digest_set.md`; `sha3_256` is the digest
  the ledger records as `drop_sha3`). Matching is by digest only (in-toto `statement.md`).

## 3. Parsing rules

- **Statement layer (in-toto rules apply):** consumers MUST ignore unrecognized Statement fields (in-toto
  `spec/v1/README.md`, "Parsing rules"). cra-evidence's verifier ignores them for the verdict and **lists them** in its
  receipt (`statement_unrecognized`), so that nothing is ignored silently.
- **Predicate (closed — "unless otherwise noted in the predicate specification", same rule):** this predicate opts out
  of ignoring. Every object of §4 has a closed list of keys; an unknown key, a missing required key, a wrong JSON type,
  a duplicate key anywhere in the payload, a value outside its enumeration, or a timestamp that is not RFC 3339 UTC with
  `Z` and at most 6 fractional digits makes the statement **refused with a reason**. A new optional field is a new
  minor version (`v0.2`, a new TypeURI because 0.X versions are major versions in in-toto's rules).
- **Monotonic principle (in-toto):** a policy over this type SHOULD be written as "allow if a statement shows X"
  (e.g. "allow if, for this vulnerability, a statement with `stage` `early_warning`, `complete` true and `filing.filedAt`
  not later than `deadlineAt` exists"); ignoring a statement then never turns a deny into an allow.

## 4. Predicate

Field names are lowerCamelCase; every timestamp is RFC 3339 with `Z` and says in its name what instant it is.

```jsonc
{
  "regulation": "EU 2024/2847 Art. 14",          // fixed string
  "stream": "vulnerability",                      // "vulnerability" | "incident"
  "stage": "early_warning",                       // "early_warning" | "notification" | "intermediate" | "final_report" | "users_informed"
  "product": {"id": "acme-router", "version": "4.2.1"},
  "glossaryVersion": "enisa_srp_glossary_20261112",
  "noticeRules": "srp-notice/2",
  "complete": true,                               // true | false | null (null: the glossary has no column for this stage)
  "missingRequired": [],                          // field names; [] when complete is true or null
  "awareAt": "2026-11-13T08:00:00Z",              // the manufacturer's declared awareness instant (§4.4)
  "deadlineAt": "2026-11-14T08:00:00Z",           // computed from awareAt for early_warning / notification; null otherwise
  "filing": {                                     // null when nothing was recorded about a filing
    "declaredBy": "sbomify",                      // "cra-evidence" | "sbomify" (= source.tool)
    "srpReference": "SRP-2026-000123",            // string, "" when the tool recorded none
    "filedAt": "2026-11-13T09:12:00Z",
    "filedBy": "psirt@example.com"                // string, "" when the tool recorded none
  },
  "source": {
    "tool": "sbomify",                            // "cra-evidence" | "sbomify"
    "toolVersion": "4ef61281e69d693e3560185bf81ec5474179ea98",
    "documentSha256": "<64 hex>",                 // the exact bytes received from the source (export file), or of the notice file when tool = cra-evidence
    "absentAtSource": ["1", "4", "7a", "41"]      // glossary row numbers the source does not carry (never invented, §4.3)
  },
  "ledger": {
    "entryIndex": 7,                              // the ledger entry's `idx` (0-based) holding the cra_srp_notice record
    "entryHash": "<64 hex>"                       // that entry's `self_hash` (cra_evidence/ledger.py: SHA-256 of the canonical entry)
  },
  "attestedAt": "2026-11-13T09:15:03Z"            // when this statement was produced
}
```

### 4.1 Required and optional

All keys above are required; `filing` and `deadlineAt` may be `null`; `complete` may be `null` only for the stages
`intermediate` and `users_informed`. `filing.declaredBy` MUST equal `source.tool`.

Notices built by cra-evidence (`cra-srp/2` drop files, written by `cra notice`): `source.tool` is `"cra-evidence"`,
`source.toolVersion` the cra-evidence version that writes the statement, `source.documentSha256` the subject's `sha256`
(the notice file is its own source document) and `source.absentAtSource` `[]`; `filing` is `null` unless the operator
declares it when attesting (`cra attest --filed-at` [`--srp-reference`] [`--filed-by`]), and then `filing.declaredBy`
is `"cra-evidence"`: a declaration of the operator, recorded nowhere else, not a proof of submission. A statement
whose `source.tool` is `"cra-evidence"` with another `documentSha256` or a non-empty `absentAtSource` is refused.

### 4.2 Consistency rules (checked by the verifier)

1. The notice file (subject) parses as a `cra-srp/2` or `cra-srp/3` drop file whose `stream`, `stage` and
   `glossary_version` equal the predicate's `stream`, `stage` and `glossaryVersion`. Drop files carry no product and no
   rules: `noticeRules` MUST equal the rules of `glossaryVersion` (spec/SRP_FIELDS.md, "Glossary versions"; checked on
   the statement itself), and `product` is checked against the ledger (rule 3). For a `cra-srp/2` drop file
   `source.tool` MUST be `"cra-evidence"`; for a `cra-srp/3` one, `source` and `filing` MUST equal its `source` and
   `filing` blocks.
2. Rebuilding the notice under its recorded glossary (as `cra check-notice` does) gives the same `complete` and
   `missingRequired`, and for `early_warning` / `notification` the same `deadlineAt`.
3. When a ledger is given: the chain verifies; entry `entryIndex` exists and its `self_hash` is `entryHash`; its data
   is a `cra_srp_notice` record whose `drop.drop_sha3` equals the subject's `sha3_256` and whose `stream`, `stage`,
   `glossary_version`, `complete` and `missing_required` equal the predicate's. Without a ledger the receipt says
   `ledger: not_evaluated` — never `PASS`.
   The product: records written from cra-evidence 0.8.0 on carry `product_id` and `product_version` (the locker is
   per product); when the entry carries them they MUST equal `product.id` and `product.version` (receipt
   `product: PASS` / `FAIL`). An entry written before carries no product: the receipt says `product: not_evaluated`, as
   it does without a ledger — the drop file never carries the product.
4. `attestedAt` is not earlier than `filing.filedAt` when both are present.

### 4.3 Imported notices (`source.tool` other than `cra-evidence`)

- The source document is kept **byte for byte** next to the ledger; `documentSha256` is the sha256 of those bytes.
- Every non-empty (field, value) pair of the source ends up in exactly one place: a field of the notice, its
  `previous_fields`, or the importer's list of unmapped pairs. An import whose unmapped list is not empty is refused
  (nothing written). A value that does not convert (e.g. a product type outside the glossary's three) is refused,
  never replaced by a default.
- Glossary rows the source does not carry are listed in `absentAtSource`; they are not filled in.
- `filing` reproduces what the source recorded. It is a **declaration of that tool**, not a proof of submission.

### 4.4 The awareness instant

`awareAt` is the manufacturer's declaration (glossary rows v26 / i37). It is never derived from a scanner, an
advisory feed or an analysis state change. The statement proves that this value was recorded, and when; not that it
is true.

## 5. Signing and trust

- A statement is signed with the manufacturer's Ed25519 key (a local key or AWS KMS, as `cra sign`). The trust store is
  the one of `cra verify` (`{signer_id: public_key_hex}`).
- **Verification:** the envelope decodes (base64 either alphabet, else refused); `payloadType` equals
  `application/vnd.in-toto+json`; for each signature the trust store key named by `keyid` is used (`keyid` selects a
  candidate key only; it decides nothing, DSSE `protocol.md`); the statement is **trusted** if at least one signature
  verifies with a trusted key. Every signature that does not verify, and every `keyid` absent from the trust store, is
  listed in the receipt. The payload checked by §3–§4 is the exact verified byte string (DSSE: never re-parse the
  envelope after verification).
- An Ed25519 public key of small order is refused (as for the ledger tip, spec/RECEIPT.md).

## 6. Vectors

`spec/art14-filing/v0.1/vectors/` holds valid statements and, for each rule of §2–§5, a statement that breaks it with
the expected refusal reason. Every verifier of this format MUST give the expected verdict on every vector.

## 7. Change log

- v0.1 (13/11/2026): first draft. Same day, before any release: rule 1 compares stream, stage and glossary only
  (drop files carry no product and no rules); `product` checked against the ledger entry; `cra-srp/2` drop files (notices
  built by cra-evidence) admitted as subjects.
