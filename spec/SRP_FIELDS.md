# SRP field schema (Art. 14 notifications)

Current glossary: ENISA CRA SRP Glossary, page "Version 1.6. Last update: 21 October 2026", read 2026-11-12
(https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2; raw page sha256
`fb24151b894277d03cc3c745b6d5c29c57de72cbfc7e9b1b356f6af4bc2fbc33`), table extracted with `scripts/srp_glossary.py`
into `spec/sources/enisa_srp_glossary_20261112.json`. A notice built today records
`"glossary_version": "enisa_srp_glossary_20261112"`. The per-stage codes in the tables at the end are DERIVED from the
vendored snapshots by `tests/test_srp_glossary_16.py` (the test fails if the module and a snapshot disagree).

Field names are ours (snake_case) and map 1:1 to the glossary rows. `manufacturer_name` is system-generated in the
portal; here it is a plain field so the payload is self-contained. The SRP is a web portal
(https://portal.cra-srp.enisa.europa.eu/, EU Login + MFA, Assigned Representative role); ENISA's FAQ says no API is
provided at the initial release. This tool builds and checks the payload per stage and writes a dry-run drop file;
submission is a human act.

## Glossary versions

ENISA's page number is not an identifier: the tables of 10/09/2026 and of 25/09/2026 were both published as
"Version 1.3" and differ by one row (measured). A version is therefore named by the vendored snapshot.

| `glossary_version` | page | read | numbered rows | rules | used by |
|---|---|---|---|---|---|
| `enisa_srp_glossary_20260915` | "Version 1.3. Last update: 10 September 2026" (line read on the copy of 20/09/2026, whose table equals this snapshot byte for byte) | 2026-09-15 | 39 | `srp-notice/1` | cra-evidence 0.1.0 – 0.3.3 |
| `enisa_srp_glossary_20260929` | "Version 1.3. Last update: 25 September 2026" | 2026-09-29 | 40 (+v26a) | `srp-notice/1` | cra-evidence 0.4.0 – 0.6.0 |
| `enisa_srp_glossary_20261010` | "Version 1.4. Last update: 01 October 2026" | 2026-10-10 | 42 (+40, +41) | history only: no notice was built under it | — |
| `enisa_srp_glossary_20261112` | "Version 1.6. Last update: 21 October 2026" | 2026-11-12 | 43 (+7a) | `srp-notice/2` | from this change on |

What changed from 20260929 to 20261112 (measured row by row on the two snapshots; every row present in 20260929 is
still present, in the same order):
- New rows: **7a** "Additional Information" (Both; Optional / N/A / N/A; max. 255 characters), **40** "AR Note" and
  **41** "CSIRT Note" (Both; Optional at every stage; in a second "Common fields" section after the incident rows). 40
  and 41 first appeared in the page of 01/10/2026; 7a in the page of 21/10/2026.
- Renamed labels (the field and its meaning are kept): 1 "Notification type (Actively Exploited Vulnerability/Severe
  Incident)", 5 "Member States where product available (CSIRT Designated as Coordinator and Concerned CSIRTs)", 11
  "End of the support indicator", v24 "Description of the severity of the vulnerability", v25 "Description of the
  impact of the vulnerability", v26 and i37 without the footnote marks [1]/[2], v28 "Particularly Exceptional
  Circumstances (PEC)". Our field names do not change.
- 72 h and final report: rows 1–14 (without 7a), v19, v20 and v26 pass from "By default copied from previous step, or
  updated" to **N/A** at both stages; 15, v21, i31, i32 and i39 pass to N/A at the final report; 18 at the final report
  passes from Optional to N/A; v26a passes to "By default copied from previous step" at 72 h and N/A at the final report;
  i37 passes from Required to N/A at 72 h and to N/A at the final report; **i38 passes from Required to Optional at
  72 h** and to N/A at the final report; v30 passes to N/A at the early warning and the final report.
- Conditional cells: v22 "Optional(after completion of v17)" at the early warning and "Optional (after completion of
  v17)" at 72 h; v29 "Optional upon PEC activation" and v30 "Optional under PEC activation" at 72 h.
- v26 and i37 at the early warning read "Mandatory" instead of "Required".
- i31 "Expected format" passes from "Select one: Yes, No, Unknown" to "Free text" ("Mention "Yes" … "No" … or
  "Unknown" … Provide additional information, if available (max. 255 characters)").

## Reading the glossary cells

| glossary cell | code | meaning here |
|---|---|---|
| Required, Mandatory | **R** | must be present at this stage, or the notice is incomplete |
| Optional | **O** | may be present |
| Required if such information available | **A** | the manufacturer's call; never counted as missing |
| By default copied from previous step, or updated; By default copied from previous step | **C** | copied from the previous stage's payload (`previous_fields`, `cra notice --previous`) when this payload does not carry it; may be given here |
| N/A | **-** | not a field of this stage |
| Optional(after completion of v17), Optional (after completion of v17) | **O** + condition `user_measures` | may be present only when v17 is present in this payload or the previous one |
| Optional upon PEC activation, Optional under PEC activation | **O** + condition `particular_exceptional_circumstances` | may be present only when v28 is present and non-empty in this payload |

"Mandatory" is read as Required: the two rows that carry it (v26, i37: the awareness instant at the early warning)
were "Required" in every earlier version, and the glossary spells the conditional category "Required if such
information available". A cell text not in this table is not guessed: the derivation test fails on it, and so does
the drift check (`scripts/srp_glossary.py check`).

## Notice rules `srp-notice/2` (glossary `enisa_srp_glossary_20261112`)

ENISA's FAQ (read 2026-11-12): "The fields displayed and their requirements may differ depending on the notification
type and reporting stage." A value the portal does not display at a stage cannot be entered there; a payload that
carries it does not describe what the portal will hold. The rules, each a refusal with a reason (the notice is not
built, `cra notice` exits 1 and writes nothing):

1. **Unknown field.** A key of `fields` or of `previous_fields` that is not a field of the stream under the recorded
   glossary is refused. An old label (e.g. "End of support indicator") or a field of the other stream is unknown.
2. **Field not at this stage.** A field whose cell is N/A at this stage and that is present in `fields` is refused
   ("not a field of this stage under enisa_srp_glossary_20261112"). The fields entered at an earlier stage go in
   `previous_fields`, not in `fields`. N/A fields are never copied forward.
3. **Condition not met.** v22 (`corrective_available_date`) at the early warning or at 72 h without v17
   (`user_measures`) in `fields` or `previous_fields`; v29 (`pec_delay_reason`) or v30 (`further_information_cdac`) at 72 h
   without a non-empty v28 (`particular_exceptional_circumstances`) in `fields`: refused.
4. **Not the manufacturer's field.** Row 41 "CSIRT Note" is "entered by the designated CSIRT": a notice built by the
   manufacturer's representative that carries `csirt_note` is refused. The field stays in the schema (rows map 1:1).
5. **Type.** text and datetime fields are JSON strings; `list` and `enum-list` fields are lists of strings; an `enum`
   value is one of its strings. Any other JSON type (number, boolean, object, a nested list) is refused. Lengths are
   counted on the string. `fields` and `previous_fields` are JSON objects; a duplicate key in the file given to
   `cra notice --fields/--previous` or `cra check-notice` is refused.
6. **Missing required.** A field coded R at this stage (or C, when it was R at an earlier stage) and absent is not a
   refusal: the notice is built and recorded with `"complete": false` and the field in `missing_required`, and
   `cra notice` exits 1. "Complete" is never declared by silence. This is the evidence that a draft existed, complete
   or not, before the deadline.
7. **Deadline.** The awareness instant (v26/i37) is a field of the early warning only. At 72 h the deadline is
   awareness + 72 h with the awareness taken from `previous_fields`; without it the deadline is `null`
   (undetermined, never invented). The final report deadline is unchanged (vulnerability: v22 + 14 days; incident:
   one calendar month from the submission of the 72 h notification, recorded in the vulnerability record).
8. **Binding to the vulnerability record.** The awareness instant and the CVE/EUVD ids used to bind a notice to the
   recorded vulnerability event are read from `fields`, else from `previous_fields`.

## Rules `srp-notice/1` (glossaries `enisa_srp_glossary_20260915`, `enisa_srp_glossary_20260929`)

Frozen as they were in cra-evidence 0.6.0, so that a notice recorded then is judged now as it was judged then: unknown
field refused; N/A field present accepted; C fields copied from `previous_fields`; R/C missing reported; i31 an enum
Yes/No/Unknown; values of any JSON type accepted as before. Two rules are added to both versions because they cannot
change the verdict on a recorded notice (the drop files of 0.6.0 do not carry `previous_fields`, and a parsed file has
no duplicate keys left): an unknown key in `previous_fields` is refused, and so is a duplicate key in the files given to
`cra notice --fields/--previous`.

## Recording the version; reading old records

- Drop file (`cra notice --drop`): `"schema": "cra-srp/2"`, with `"glossary_version"` and `"previous_fields"` (the
  previous stage's payload as given, or `null`). `notice_sha3` covers `glossary_version` too.
- Ledger record `cra_srp_notice`: gains `"glossary_version"`. Records are digested as written (`record_sha3`), so the
  records written before keep verifying with every verifier; the external verifiers (JavaScript, Go, Rust, Java) check
  chain, digests, anchor, signature and tip, and do not read the notice fields or the glossary.
- Old drop files (`"schema": "cra-srp/1"`, no `glossary_version`): the version is read from the exact
  `glossary_source` string they carry — "ENISA CRA SRP Glossary (39 fields), read 2026-09-15" with or without the
  snapshot sentence → `enisa_srp_glossary_20260915`; "ENISA CRA SRP Glossary (40 fields; page dated 25 September 2026),
  read 2026-09-29 — …" → `enisa_srp_glossary_20260929`. Any other string is refused, not guessed. Their `notice_sha3`
  was computed without `glossary_version`, and over `previous_fields` when `--previous` was used; those files do not
  carry `previous_fields`, so for them the hash is recomputed only when it was built without `--previous`.
- Old ledger records (no `glossary_version`): the version is the one of the drop file the record names
  (`drop.drop_file`) and binds (`drop.drop_sha3`).
- `cra check-notice DROP [--ledger LEDGER]` rebuilds the notice under the RECORDED version and its rules, and compares
  `complete`, `missing_required`, `deadline_utc` and `notice_sha3` with what the file says. With `--ledger` it also
  verifies the chain and finds the record by `notice_id`: the file's SHA3-256 must equal the record's `drop.drop_sha3`,
  and `stream`, `stage`, `complete`, `missing_required`, `notice_sha3` (and `glossary_version` when recorded) must
  agree. A legacy file built with `--previous` is verified through the ledger's `drop_sha3` only. Exit 0 = verified,
  1 = not verified (reasons listed), 2 = usage.

Deadlines: EW = awareness + 24 h; N = awareness + 72 h; FR (vulnerability) = 14 days after the corrective/mitigating
measure is available (undetermined until then, Art. 14(2)(c)); FR (incident) = one calendar month after the
submission of the incident notification (Art. 14(4)(c); undetermined until that submission is recorded).

PEC options (rows v28/v29, Art. 16(2) third subparagraph): `no_other_member_state` = actively exploited, and according to the information available in no other Member State than the one of the coordinating CSIRT; `contrary_to_essential_interests` = immediate further dissemination would likely supply information whose disclosure would be contrary to the essential interests of that Member State; `imminent_high_risk` = the notified vulnerability poses an imminent high cybersecurity risk stemming from the further dissemination.

<!-- tables: generated by scripts/gen_srp_fields.py from cra_evidence/srp_notice.py; tests/test_srp_glossary_16.py checks them -->

## Tables of `enisa_srp_glossary_20261112` (Version 1.6. Last update: 21 October 2026; rules srp-notice/2)

### Common fields (19)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| 1 | `notification_type` | R | - | - | enum ['Vulnerability', 'Incident'] |
| 2 | `title` | R | - | - | text (max 255) |
| 3 | `summary` | R | - | - | text (max 4000) |
| 4 | `manufacturer_name` | R | - | - | text (max 255) |
| 5 | `member_states_available` | R | - | - | list |
| 6 | `product_name` | R | - | - | text (max 255) |
| 7 | `product_version` | R | - | - | text (max 255) |
| 7a | `additional_information` | O | - | - | text (max 255) |
| 8 | `product_type` | O | - | - | enum ['Default', 'Important', 'Critical'] |
| 9 | `product_class` | O | - | - | enum ['Class I', 'Class II'] |
| 10 | `product_category` | O | - | - | text (max 255) |
| 11 | `end_of_support` | O | - | - | enum ['Yes', 'No'] |
| 12 | `component_name` | O | - | - | text (max 255) |
| 13 | `mitigating_measure_expected_shortly` | O | - | - | enum ['Yes', 'No'] |
| 14 | `user_action_reduce_impact` | O | - | - | text (max 4000) |
| 15 | `sensitivity_justification` | O | O | - | text (max 255) |
| 16 | `corrective_measures_taken` | O | O | R | text (max 2000) |
| 17 | `user_measures` | O | O | R | text (max 4000) |
| 18 | `attack_vector` | - | O | - | text (max 255) |

### Actively exploited vulnerability (13)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| v19 | `cve_id` | O | - | - | text (max 255) |
| v20 | `euvd_id` | O | - | - | text (max 255) |
| v21 | `general_information` | O | R | - | text (max 4000) |
| v22 | `corrective_available_date` | O | O | R | datetime-utc — early_warning: only with `user_measures`; notification: only with `user_measures` |
| v23 | `security_update_details` | O | O | R | text (max 2000) |
| v24 | `severity_description` | O | O | R | text (max 4000) |
| v25 | `impact_description` | O | O | R | text (max 4000) |
| v26 | `awareness_datetime_utc` | R | - | - | datetime-utc |
| v26a | `vulnerability_occurred_datetime_utc` | O | C | - | datetime-utc |
| v27 | `malicious_actor` | O | O | A | text (max 100) |
| v28 | `particular_exceptional_circumstances` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] |
| v29 | `pec_delay_reason` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] — notification: only with `particular_exceptional_circumstances` |
| v30 | `further_information_cdac` | - | O | - | text (max 800) — notification: only with `particular_exceptional_circumstances` |

### Severe incident (9)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| i31 | `suspected_malicious` | R | C | - | text (max 255) |
| i32 | `incident_nature` | O | R | - | text (max 4000) |
| i33 | `mitigation_measures` | O | O | R | text (max 4000) |
| i34 | `severity_description` | O | O | R | text (max 4000) |
| i35 | `impact_description` | O | O | R | text (max 4000) |
| i36 | `threat_type_root_cause` | O | O | R | text (max 255) |
| i37 | `awareness_datetime_utc` | R | - | - | datetime-utc |
| i38 | `incident_datetime_utc` | O | O | - | datetime-utc |
| i39 | `initial_assessment` | O | R | - | text (max 4000) |

### Common fields (2)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| 40 | `ar_note` | O | O | O | text (no maximum in the glossary) |
| 41 | `csirt_note` | O | O | O | text (no maximum in the glossary) — entered by the CSIRT: refused in a notice |

## Tables of `enisa_srp_glossary_20260929` (Version 1.3. Last update: 25 September 2026; rules srp-notice/1)

### Common fields (18)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| 1 | `notification_type` | R | C | C | enum ['Vulnerability', 'Incident'] |
| 2 | `title` | R | C | C | text (max 255) |
| 3 | `summary` | R | C | C | text (max 4000) |
| 4 | `manufacturer_name` | R | C | C | text (max 255) |
| 5 | `member_states_available` | R | C | C | list |
| 6 | `product_name` | R | C | C | text (max 255) |
| 7 | `product_version` | R | C | C | text (max 255) |
| 8 | `product_type` | O | C | C | enum ['Default', 'Important', 'Critical'] |
| 9 | `product_class` | O | C | C | enum ['Class I', 'Class II'] |
| 10 | `product_category` | O | C | C | text (max 255) |
| 11 | `end_of_support` | O | C | C | enum ['Yes', 'No'] |
| 12 | `component_name` | O | C | C | text (max 255) |
| 13 | `mitigating_measure_expected_shortly` | O | C | C | enum ['Yes', 'No'] |
| 14 | `user_action_reduce_impact` | O | C | C | text (max 4000) |
| 15 | `sensitivity_justification` | O | O | C | text (max 255) |
| 16 | `corrective_measures_taken` | O | O | R | text (max 2000) |
| 17 | `user_measures` | O | O | R | text (max 4000) |
| 18 | `attack_vector` | - | O | O | text (max 255) |

### Actively exploited vulnerability (13)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| v19 | `cve_id` | O | C | C | text (max 255) |
| v20 | `euvd_id` | O | C | C | text (max 255) |
| v21 | `general_information` | O | R | C | text (max 4000) |
| v22 | `corrective_available_date` | O | O | R | datetime-utc |
| v23 | `security_update_details` | O | O | R | text (max 2000) |
| v24 | `severity_description` | O | O | R | text (max 4000) |
| v25 | `impact_description` | O | O | R | text (max 4000) |
| v26 | `awareness_datetime_utc` | R | C | C | datetime-utc |
| v26a | `vulnerability_occurred_datetime_utc` | O | R | C | datetime-utc |
| v27 | `malicious_actor` | O | O | A | text (max 100) |
| v28 | `particular_exceptional_circumstances` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] |
| v29 | `pec_delay_reason` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] |
| v30 | `further_information_cdac` | O | O | C | text (max 800) |

### Severe incident (9)

| row | field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|---|
| i31 | `suspected_malicious` | R | C | C | enum ['Yes', 'No', 'Unknown'] |
| i32 | `incident_nature` | O | R | C | text (max 4000) |
| i33 | `mitigation_measures` | O | O | R | text (max 4000) |
| i34 | `severity_description` | O | O | R | text (max 4000) |
| i35 | `impact_description` | O | O | R | text (max 4000) |
| i36 | `threat_type_root_cause` | O | O | R | text (max 255) |
| i37 | `awareness_datetime_utc` | R | R | C | datetime-utc |
| i38 | `incident_datetime_utc` | O | R | O | datetime-utc |
| i39 | `initial_assessment` | O | R | C | text (max 4000) |

`enisa_srp_glossary_20260915` is `enisa_srp_glossary_20260929` without row v26a (`vulnerability_occurred_datetime_utc`).

<!-- end of tables -->
