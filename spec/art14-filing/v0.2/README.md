# Predicate type `art14-filing` v0.2 — v0.1 plus the vulnerability identifiers and the case reference

TypeURI: `https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.2`

Status: draft, written before the code (13/11/2026). Normative for cra-evidence from the release that implements it.
This document is a delta over [`v0.1`](../v0.1/README.md): every rule of v0.1 (§2 envelope and statement, §3 parsing,
§4 predicate, §4.1–§4.4, §5 signing and trust) applies unchanged to a v0.2 statement, except where §2–§5 below say
otherwise. The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Why a new version

A v0.1 statement names the notice by its digest, its stream, stage and product. It carries no identifier of the
vulnerability: a recipient who is not given the notice file cannot tell two statements of the same product and stage
apart, nor match a statement to the case it follows (a coordinating CSIRT, a CNA, another coordinator). v0.2 adds two
**optional** predicate fields for that:

- `vulnerabilityIds` — the CVE and EUVD identifiers of the vulnerability, the two the ENISA SRP glossary has fields for
  (rows v19 `cve_id` and v20 `euvd_id`, spec/SRP_FIELDS.md);
- `caseReference` — the reference that whoever follows the case gave to it, and who gave it.

v0.1 stays valid: the verifier accepts both TypeURIs; a v0.1 statement is judged by the v0.1 rules and gets the same
receipt as before (§6). A new optional field is a new minor version and a new TypeURI (v0.1 §3).

## 2. Predicate

The v0.1 predicate, with two more keys that MAY be present. The closed list of keys of the predicate object is the
v0.1 list plus `vulnerabilityIds` and `caseReference`; a v0.1 statement (v0.1 TypeURI) that carries either key is
refused as before (`predicate_unknown_key`).

```jsonc
{
  // … every key of v0.1 §4, unchanged …
  "vulnerabilityIds": [                                  // optional; when present: 1 or 2 entries
    {"scheme": "cve",  "id": "CVE-2024-3094"},
    {"scheme": "euvd", "id": "EUVD-2024-31700"}
  ],
  "caseReference": {"issuer": "CSIRT-IT", "id": "2026-000123"}   // optional
}
```

### 2.1 `vulnerabilityIds`

A list of objects; each object has exactly the keys `scheme` and `id`, both strings.

| rule | refused with |
|---|---|
| the value is a list; each entry an object; `scheme` and `id` strings | `predicate_type_error` |
| each object has exactly `scheme` and `id` | `predicate_unknown_key` / `predicate_missing_key` |
| `scheme` is `"cve"` or `"euvd"` | `predicate_enum` |
| `scheme` `"cve"`: `id` matches `^CVE-[0-9]{4}-[0-9]{4,19}$` (ASCII digits) | `predicate_identifier` |
| `scheme` `"euvd"`: `id` matches `^EUVD-[0-9]{4}-[0-9]{1,19}$` (ASCII digits) | `predicate_identifier` |
| the list is not empty (no identifiers: the key is omitted) | `predicate_rule` |
| at most one entry per scheme (so at most 2 entries) | `predicate_rule` |
| entries in the order of `scheme`: `"cve"` before `"euvd"` | `predicate_rule` |

Why these choices:

- **The two schemes and one entry per scheme.** The SRP glossary has one `cve_id` field and one `euvd_id` field per
  notice (rows v19, v20, text of at most 255 characters): one notice is about one vulnerability. A statement says what
  its notice says, so it carries at most one identifier of each scheme. An identifier of the manufacturer, of a
  CSIRT or of any other body is not a vulnerability identifier of these two schemes: it goes in `caseReference`, with
  `issuer` naming who gave it (the manufacturer for its own internal id).
- **One form for "no identifiers".** An empty list and an absent key would mean the same; only the absent key is
  admitted, so that two statements with the same content are the same bytes.
- **One order.** With at most one entry per scheme, ordering by scheme fixes the order (no second sort key needed).
- **The CVE form** is the `cveId` pattern of the CVE JSON record format, read on 13/11/2026 in
  `https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/CVE_Record_Format.json` (main at commit
  `ce5f5c865f14dc40a6548d36b74751abca1c588a`; file sha256
  `33f7517424facfc712c7b808be1b6503fc74b2e6b85979bbaacb9b623ddfde67`): "the string 'CVE', followed by the year,
  followed by a 4 to 19 digit number", `"pattern": "^CVE-[0-9]{4}-[0-9]{4,19}$"`. The pattern is applied as a full
  match on the whole string, with `[0-9]` meaning the ASCII digits only.
- **The EUVD form.** ENISA publishes no grammar of the EUVD identifier in the pages read on 13/11/2026 (the API
  documentation at `https://euvd.enisa.europa.eu/apidoc`, served by the script `main.61fcf30f.js`, sha256
  `b824a45aae9afea9abbeb402b101e3070b8207a19712f72990259f85b8554ecd`, gives the examples `EUVD-2025-4893` and
  `EUVD-2021-9696`). The form above is our reading, written down here so that it is the same in every verifier:
  `EUVD-`, a four-digit year, `-`, a sequence number of 1 to 19 ASCII digits. Measured the same day on ENISA's API
  (`https://euvdservices.enisa.europa.eu/api/enisaid?id=…`): records exist for `EUVD-2023-1234`, `EUVD-2023-2533`
  (4-digit sequence numbers), `EUVD-2024-31700` (5) and others; none for `EUVD-2023-1`, `-12`, `-123`. The lower bound
  1 is kept because no published rule excludes shorter numbers; the upper bound 19 is the CVE one. If ENISA publishes a
  grammar, the form is re-read and a narrower one is a new version of this predicate.
- **No normalisation.** Identifiers are compared as exact strings. A lower-case `cve-2024-3094` is not in the CVE form
  and is refused, never upper-cased: what is signed is what is compared.

### 2.2 `caseReference`

An object with exactly the keys `issuer` and `id`.

| rule | refused with |
|---|---|
| an object (`null` is not admitted: without a reference the key is omitted); `issuer` and `id` strings | `predicate_type_error` |
| exactly `issuer` and `id` | `predicate_unknown_key` / `predicate_missing_key` |
| each of `issuer`, `id`: 1 to 255 characters (Unicode code points), no control character (Unicode category Cc: U+0000..U+001F, U+007F..U+009F), not starting or ending with U+0020 | `predicate_identifier` |

`issuer` says who gave the reference: a CSIRT, a CNA, another coordinator of the disclosure, the market surveillance
authority, or the manufacturer itself. 255 is the bound the glossary uses for its identifier fields (rows v19, v20).

**Nothing can check a case reference.** No file the verifier reads contains it. The receipt always says
`declared by the signer, not checkable` (§5). It is a signed declaration, nothing more.

## 3. The identifiers against the notice (verifier, with `--drop`)

The identifiers **of the notice** are read from the drop file (the subject, `cra-srp/2` or `cra-srp/3`): for each of
`cve_id` (scheme `cve`) and `euvd_id` (scheme `euvd`), the value of `fields`, or, when `fields` has no present value
for it, the value of `previous_fields` (the "C" fields carried from the earlier stage: spec/SRP_FIELDS.md rule 8, as `cra notice` and the
ledger binding read them). A value is present unless it is missing, `null`, or a string
made only of whitespace (Python `str.isspace`) or empty.

Rule 5 (new, v0.2 statements only; checked when the drop file is given and passes the v0.1 rules 1–2):

> The set of `(scheme, id)` pairs of `vulnerabilityIds` (empty when the key is absent) MUST equal the set of the
> notice's identifiers. Otherwise the statement is refused with `vulnerability_ids`, and the reason says which
> identifiers are only in the statement and which only in the notice.

One rule, closed, with no exception:

- a statement with identifiers the notice does not carry: refused;
- a notice with identifiers the statement does not carry — **including a statement with no `vulnerabilityIds` at all**
  — refused. A v0.2 statement without identifiers says "this notice carries none"; to sign a statement that says
  nothing about identifiers, write v0.1 (`cra attest --predicate v0.1`), whose rules do not read them;
- a notice value that is not in its scheme's form (e.g. `"cve-2024-3094"`, two identifiers in one field) can be equal
  to no statement entry, so the statement is refused; the reason names the notice value.

Why one rule: the alternative ("the statement may omit what the notice carries") makes a missing identifier
undetectable when the notice is given, and needs a second rule to say which omissions are allowed.

**Without the drop file** (e.g. a coordinator under embargo who receives the statement only): nothing is compared;
the receipt lists the declared identifiers and says `declared, not checked (no drop file given)`.

## 4. What a v0.2 statement does not prove

The v0.1 list (v0.1 §1) holds unchanged — not that the notice reached the SRP or was accepted by a CSIRT, not that the
awareness instant is true, not conformity with the Regulation — plus:

- without the notice file, that the declared identifiers are those of the notice, or the right ones for the case;
- that `caseReference` exists at its issuer, or that the issuer gave it.

## 5. Receipt of `cra verify-attestation`

For a v0.2 statement that is accepted (signature trusted, statement and predicate pass), the receipt has two more
keys:

```jsonc
"vulnerability_ids": {
  "declared": [{"scheme": "cve", "id": "CVE-2024-3094"}],   // as in the statement; [] when the key is absent
  "notice": [{"scheme": "cve", "id": "CVE-2024-3094"}],     // read from the drop file (§3); null without --drop
  "result": "matched"                                       // see below
},
"case_reference": {
  "declared": {"issuer": "CSIRT-IT", "id": "2026-000123"},  // null when the key is absent
  "result": "declared by the signer, not checkable"         // "none declared" when absent
}
```

`vulnerability_ids.result`: `matched` (rule 5 holds); `FAIL` (rule 5 does not hold: reason `vulnerability_ids`);
`declared, not checked (no drop file given)`; `not_evaluated (the drop file did not pass rules 1-2)` (the drop file was
given but refused earlier, so the notice's identifiers were not read). `notice` lists the identifiers the notice
carries in the order of §2.1; a notice value that is not in its scheme's form is listed as it is.

`predicate_type` in the receipt is the TypeURI of the statement once its payload has been read (a trusted signature);
before that point (an envelope not trusted or not decodable) the receipt keeps the v0.1 TypeURI, as the verifier of
v0.1 wrote it, so that every v0.1 receipt stays byte for byte the same.

A v0.1 statement gets neither key: its receipt is the one the v0.1 verifier gives (measured byte for byte on the
v0.1 vectors, CHANGELOG 0.9.0).

## 6. Producing (`cra attest`)

`cra attest` writes v0.2 by default:

- `vulnerabilityIds` is **read from the notice** (§3), never typed by the operator: a statement whose identifiers
  differ from its notice's would be refused by rule 5 as soon as the notice is given, so there is no option to state
  others. A notice whose identifier is not in its scheme's form is refused (exit 1, nothing written), with the value
  named; a notice with no identifiers gives a statement without the key.
- `caseReference` from `--case-reference ISSUER ID`, checked by §2.2 before anything is written.
- `--predicate v0.1` writes a v0.1 statement exactly as cra-evidence 0.8.0 did (same bytes for the same inputs and
  instant); `--case-reference` is refused with it.

The statement payload is the JSON text of the statement with keys sorted, separators `,` `:`, strings in UTF-8 (not
ASCII-escaped). Every member name of a statement that `cra attest` writes is ASCII, so this text is the RFC 8785 (JCS)
serialisation of the statement (measured on every vector of v0.1 and v0.2; the DSSE signature covers these exact
bytes, and a verifier never re-serialises them).

## 7. Confidentiality

A v0.1 statement already tells its recipient "for product X a notice of stage S was prepared". With
`vulnerabilityIds` it also tells **which** vulnerability. Under embargo, give a v0.2 statement with identifiers only to
whoever already knows the case (the coordinator), or sign a v0.1 statement. Both fields are optional for this reason.
No cryptographic commitment (e.g. a salted digest of the identifier) is defined: it would double the rules and nobody
has asked for it.

A statement does not carry the text of the notice: the drop file is the subject, named by its digests only. A
coordinator that receives the statement without the drop file learns the stage, product, deadlines, completeness,
the identifiers and the case reference, not the notice's content.

## 8. Vectors

`spec/art14-filing/v0.2/vectors/` (generated by `scripts/gen_art14_v02_vectors.py`) holds valid statements and, for
each rule of §2–§3, statements that break it, with the expected exit code, reason codes and receipt values in
`manifest.json`. The notices are synthetic (`Acme … (synthetic)`, built with `cra notice`); the identifiers in them
are real public records, chosen for their form, and say nothing about the synthetic products:

| CVE | EUVD | read on 13/11/2026 at | sha256 of the bytes read |
|---|---|---|---|
| CVE-2024-3094 | EUVD-2024-31700 | `https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-31700` (aliases `CVE-2024-3094`, `GHSA-rxwq-x6h5-x525`) | `86cc1fe94acf45605c88ebe2a5ac5af0fc6777a8658958654ede5341a493f7ef` |
| CVE-2021-44228 | EUVD-2021-34768 | `https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2021-34768` (alias `CVE-2021-44228`) | `635ac52ff6373d68b149cdc2815c2ce9c620eb93eb5c44019b952a5cfa6b603f` |
| CVE-2024-21762 | EUVD-2024-19376 | `https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-19376` (aliases `CVE-2024-21762`, `GHSA-v4hq-m4wr-6pmj`) | `b32f0605419cad03c891ad69f62baa1125848d7bc5df34da4b8b679b699bdb23` |

(The API answers change as ENISA updates a record: the digests are of the bytes read that day.)

## 9. Change log

- v0.2 (13/11/2026): first draft — `vulnerabilityIds`, `caseReference`, rule 5, receipt keys.
