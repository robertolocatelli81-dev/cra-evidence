# SRP field schema (Art. 14 notifications)

Source: ENISA CRA SRP Glossary (39 fields), read 2026-09-15 — https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2
(39 fields: 18 common, 12 for an actively exploited vulnerability, 9 for a severe incident). Legend: R = required at
that stage, O = optional, A = required if available, - = not at that stage. `manufacturer_name` is system-generated in
the portal; here it is a plain field so the payload is self-contained. Field names are ours (snake_case) and map 1:1
to the glossary labels in the order listed by ENISA.

The SRP is a web portal (https://portal.cra-srp.enisa.europa.eu/, EU Login + MFA, Assigned Representative role); no
machine-to-machine API was documented on 15/09/2026. This tool builds and validates the payload per stage and writes
a dry-run drop file; submission is a human act. Deadlines: EW = awareness + 24 h; N = awareness + 72 h; FR
(vulnerability) = 14 days after the corrective/mitigating measure is available (undetermined until then); FR
(incident) = 72 h notification + one month.

## Common fields (18)

| field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|
| `notification_type` | R | R | R | enum ['Vulnerability', 'Incident'] |
| `title` | R | R | R | text (max 255) |
| `summary` | R | R | R | text (max 4000) |
| `manufacturer_name` | R | R | R | text (max 255) |
| `member_states_available` | R | R | R | list |
| `product_name` | R | R | R | text (max 255) |
| `product_version` | R | R | R | text (max 255) |
| `product_type` | O | O | O | enum ['Default', 'Important', 'Critical'] |
| `product_class` | O | O | O | enum ['Class I', 'Class II'] |
| `product_category` | O | O | O | text (max 255) |
| `end_of_support` | O | O | O | enum ['Yes', 'No'] |
| `component_name` | O | O | O | text (max 255) |
| `mitigating_measure_expected_shortly` | O | O | O | enum ['Yes', 'No'] |
| `user_action_reduce_impact` | O | O | O | text (max 4000) |
| `sensitivity_justification` | O | O | - | text (max 255) |
| `corrective_measures_taken` | O | O | R | text (max 2000) |
| `user_measures` | O | O | R | text (max 4000) |
| `attack_vector` | - | O | O | text (max 255) |

## Actively exploited vulnerability (12)

| field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|
| `cve_id` | O | O | O | text (max 255) |
| `euvd_id` | O | O | O | text (max 255) |
| `general_information` | O | R | O | text (max 4000) |
| `corrective_available_date` | O | O | R | datetime-utc |
| `security_update_details` | O | O | R | text (max 2000) |
| `severity_description` | O | O | R | text (max 4000) |
| `impact_description` | O | O | R | text (max 4000) |
| `awareness_datetime_utc` | R | R | R | datetime-utc |
| `malicious_actor` | A | O | A | text (max 100) |
| `particular_exceptional_circumstances` | - | R | - | enum-list |
| `pec_delay_reason` | - | R | - | text |
| `further_information_cdac` | O | O | O | text (max 800) |

## Severe incident (9)

| field | EW 24h | N 72h | FR | format |
|---|---|---|---|---|
| `suspected_malicious` | R | R | R | enum ['Yes', 'No', 'Unknown'] |
| `incident_nature` | O | R | O | text (max 4000) |
| `mitigation_measures` | O | O | R | text (max 4000) |
| `severity_description` | O | O | R | text (max 4000) |
| `impact_description` | O | O | R | text (max 4000) |
| `threat_type_root_cause` | O | O | R | text (max 255) |
| `awareness_datetime_utc` | R | R | - | datetime-utc |
| `incident_datetime_utc` | O | R | O | datetime-utc |
| `initial_assessment` | O | R | O | text (max 4000) |
