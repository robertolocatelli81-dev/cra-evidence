# SRP field schema (Art. 14 notifications)

Source: ENISA CRA SRP Glossary (39 fields), read 2026-09-15 — snapshot vendored in spec/sources/enisa_srp_glossary_20260915.json; per-stage codes derived from it by tests/test_council_r2.py
(https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2). The per-stage
codes below are DERIVED from the vendored snapshot by `tests/test_council_r2.py` (the test fails if this module and
the snapshot disagree). Legend: **R** = required at this stage; **O** = optional; **A** = required if such information is available; **C** = carried forward from the previous stage (copied by default, may be updated); **-** = not at this stage. `manufacturer_name` is system-generated in the portal; here it is a plain
field so the payload is self-contained. Field names are ours (snake_case) and map 1:1 to the glossary rows in order.

Only **R** fields count as "missing"; **C** fields are carried forward from the previous stage (the portal copies
them), **A** is the manufacturer's call. The SRP is a web portal (https://portal.cra-srp.enisa.europa.eu/, EU Login +
MFA, Assigned Representative role); no machine-to-machine API was documented on 15/09/2026. This tool builds and
validates the payload per stage and writes a dry-run drop file; submission is a human act. Deadlines: EW = awareness
+ 24 h; N = awareness + 72 h; FR (vulnerability) = 14 days after the corrective/mitigating measure is available
(undetermined until then, Art. 14(2)(c)); FR (incident) = one calendar month after the submission of the incident
notification (Art. 14(4)(c); undetermined until that submission is recorded).

PEC options (rows v28/v29, Art. 16(2) third subparagraph): `no_other_member_state` = actively exploited, and according to the information available in no other Member State than the one of the coordinating CSIRT; `contrary_to_essential_interests` = immediate further dissemination would likely supply information whose disclosure would be contrary to the essential interests of that Member State; `imminent_high_risk` = the notified vulnerability poses an imminent high cybersecurity risk stemming from the further dissemination.

## Common fields (18)

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

## Actively exploited vulnerability (12)

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
| v27 | `malicious_actor` | O | O | A | text (max 100) |
| v28 | `particular_exceptional_circumstances` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] |
| v29 | `pec_delay_reason` | - | O | - | enum-list ['no_other_member_state', 'contrary_to_essential_interests', 'imminent_high_risk'] |
| v30 | `further_information_cdac` | O | O | C | text (max 800) |

## Severe incident (9)

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
