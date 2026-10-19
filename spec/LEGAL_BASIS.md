# Legal basis — as read from primary sources on 15/09/2026, re-checked on 20/09/2026 and 29/09/2026

Regulation (EU) 2024/2847 (Cyber Resilience Act). Sources consulted on 15/09/2026:
- European Commission, "Cyber Resilience Act — Reporting obligations": https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- ENISA, Single Reporting Platform: https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp
  (portal https://portal.cra-srp.enisa.europa.eu/, "operational as of 11 September 2026"), CRA SRP Glossary (39 fields on
  15/09/2026; the vendored table had 44 rows — 3 section headers, 2 unnumbered continuation rows, 39 numbered fields — dated
  snapshot in `spec/sources/enisa_srp_glossary_20260915.json`, kept for history; the reference since 29/09/2026 is
  `spec/sources/enisa_srp_glossary_20260929.json`, 45 rows, 40 numbered fields — see the re-check below), AR User Manual, PEC guidance.
- EUR-Lex, Regulation (EU) 2024/2847, OJ L 2024/2847: https://eur-lex.europa.eu/eli/reg/2024/2847/oj (Art. 13(13), 14, 16, 24, 71 re-read).
- CycloneDX specification overview (1.7 current, ECMA-424): https://cyclonedx.org/specification/overview/; JSON schemas 1.6 and 1.7 vendored in `spec/schemas/` (Apache-2.0, OWASP CycloneDX).
- ENISA, "The CRA Single Reporting Platform is launched" (news, September 2026).

Re-check of 20/09/2026 (what changed: nothing in the obligations):
- ENISA SRP FAQ (https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions):
  "no Application Programming Interface (API) will be provided at the initial release of the SRP, so notifications must
  be submitted through the platform interface. API functionality may be considered in a future phase of the SRP";
  voluntary notifications (Art. 15) "in a future phase".
- CRA SRP Glossary re-downloaded and diffed against the vendored snapshot of 15/09/2026: same header, same 44 rows (39 fields), 0
  differences (`spec/sources/enisa_srp_glossary_20260915.json` stays the reference).
- Digital Omnibus (Commission proposal of 19/11/2025, procedure 2025/0360(COD), summary on the Parliament's Legislative
  Observatory): a single entry point for cyber incident reporting ("report once, share many") to be built by ENISA on
  the CRA reporting platform; a PROPOSAL, not adopted — the Art. 14 deadlines and the SRP as the channel are unchanged.
- The Commission's cybersecurity package of 20/01/2026 (Cybersecurity Act revision, NIS2 amendments) does not amend
  Regulation (EU) 2024/2847.

Re-check of 29/09/2026 (what changed: one glossary field; nothing in the obligations):
- CRA SRP Glossary, page "Version 1.3. Last update: 25 September 2026", extracted from the raw HTML with the same method as
  the 15/09/2026 snapshot (the method reproduces the 15/09/2026 file byte-exact) and diffed row by row: header identical; the
  44 rows of 15/09/2026 all present, unchanged and in the same order; one row inserted between v26 and v27 — **v26a, "Date and
  time when the Actively Exploited Vulnerability occurred (UTC time)"** (AEV; Optional at the early warning, Required at the
  72 h notification, copied forward at the final report). New snapshot `spec/sources/enisa_srp_glossary_20260929.json` (45
  rows, 40 numbered fields: 18 common, 13 AEV, 9 SI); schema field `vulnerability_occurred_datetime_utc`. The page's footnotes
  outside the table ([1] on v26: "This field will be available in the next release of the Platform"; [2] on i37: "In the
  current release this field is named: Date and time when the incident was detected (UTC time)") are not part of either
  snapshot; whether they changed between 15/09 and 25/09 is not measured. The Art. 14 deadlines are unchanged.

Re-check of 17/10/2026 (what changed: nothing in the obligations; the provisions below are newly used by
`cra_evidence/applicability.py` and `cra obligations`). EUR-Lex returned no text to the fetcher that day; the articles
were read on the Official Journal text as reproduced article by article by springlex.eu
(https://www.springlex.eu/en/packages/cra/cra-regulation/article-71/, …/article-69/, …/article-24/, …/article-13/,
…/article-14/) — a secondary reproduction, to be re-read on EUR-Lex:
- Art. 71(2): the Regulation applies from 11 December 2027; Article 14 from 11 September 2026; Chapter IV (Art. 35-51)
  from 11 June 2026.
- Art. 69(2)-(3): a product placed on the market before 11 December 2027 is subject to the requirements only if it is
  substantially modified from that date; by derogation, Article 14 applies to every product in scope placed on the
  market before that date.
- Art. 24(3): Art. 14(1) applies to open-source software stewards to the extent they are involved in the development of
  the product, Art. 14(3) to the extent a severe incident affects the network and information systems they provide for
  that development. ENISA's SRP FAQ (https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions,
  "Updated: 15 October 2026") puts stewards' reporting from 11 December 2027, still says no API at the initial release
  ("may be considered in a future phase"), and voluntary notifications (Art. 15) not yet implemented.
- Art. 13(8) (support period at least five years, shorter only for a shorter expected use), 13(9) (a security update
  available at least 10 years after issue or the remainder of the support period, whichever is longer), 14(8) (inform
  the impacted users, and where appropriate all users; no hour count is given).
- Commission guidance on the application of the CRA, C(2026) 5252, 27/07/2026, non-binding
  (https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation):
  support periods, substantial modification, open source, reporting. Its text was NOT read for this re-check.
- Harmonised standards (EN 40000 series, CEN/CENELEC JTC 13): none cited in the Official Journal; prEN 40000-1-3
  (vulnerability handling) still a draft — read in secondary trackers only, not on the CEN/CENELEC portal.
- Open, not decided by this tool: an actively exploited vulnerability the manufacturer became aware of BEFORE
  11/09/2026. `VulnerabilityRecord.deadlines()` counts 24 h / 72 h from the recorded awareness whatever its date, so
  such a record is overdue at once (by code reading). Whether the clock should instead start on 11/09/2026, or not at
  all, is a legal reading for the author (and the Commission guidance above), not for the arithmetic.

| Obligation | What this tool does | Reference |
|---|---|---|
| Actively exploited vulnerabilities: early warning within 24 h of awareness, notification within 72 h, final report no later than 14 days after a corrective or mitigating measure is available (Art. 14(2)(a)-(c)); severe incidents: 24 h, 72 h, final report "within one month after the submission of the incident notification" (Art. 14(4)(a)-(c)); reporting once through the Single Reporting Platform to the CSIRT designated as coordinator and ENISA | `VulnerabilityRecord.deadlines()/overdue()` with the clock anchored exactly as above (the incident final report is anchored to the recorded submission instant, calendar month; undetermined until recorded); `SRPNotice` builds the payload per stage in the glossary vocabulary and lists what is still missing; nothing is submitted (human portal) | Art. 14, Art. 16; applying from 11 September 2026 (Art. 71) — text re-read on EUR-Lex (OJ L, 2024/2847) on 15/09/2026 |
| Software bill of materials in a commonly used, machine-readable format covering at least the top-level dependencies, in the technical documentation | `SBOMRecord` (CycloneDX 1.6/1.7 subset; the generator's document is stored byte-exact since 0.3.0), from the installed environment (floor) or by ingesting a full generator's CycloneDX or SPDX document (stored byte-exact); an empty SBOM is recorded as not meeting the floor | Annex I Part II(1); full application 11 December 2027 |
| Technical documentation and EU declaration of conformity kept at the disposal of the market surveillance authorities for at least 10 years after the product is placed on the market or for the support period, whichever is longer | evidence pack (records the support period end when given, so the retention horizon is the right one) + hash-chained ledger + crypto-agile long-term seal, renewable before an algorithm is retired (NIST IR 8547 initial public draft, https://csrc.nist.gov/pubs/ir/8547/ipd: quantum-vulnerable signatures deprecated after 2030, disallowed after 2035 — used as the verifier's default policy) | Art. 13(13) (retention), Art. 31 (technical documentation content) |
| Open-source software stewards: reporting obligations from 11 December 2027 | same tooling; the stream/stage model is identical; `reporting_in_force("open_source_steward", …)` / `cra obligations --role open_source_steward` says from when, with the Art. 24(3) scope condition recorded and never checked | Art. 24(3), Art. 71(2) |
| Products placed on the market before 11 December 2027: Art. 14 applies to them; the requirements only after a substantial modification from that date | `legacy_product_scope()` / `cra obligations --placed-on-market [--substantially-modified]`; scope (Art. 2) and "substantial" are not decided | Art. 69(2)-(3) |
| Support period at least five years (shorter only for a shorter expected use); each security update available 10 years or the remainder of the support period | `support_period()` (`meets_minimum` / `shorter_declared` / `below_minimum`, exit 1 on the last), `update_available_until()`, `retention_until()` | Art. 13(8), 13(9), 13(13) |
| Inform the impacted users of an actively exploited vulnerability or severe incident | `user_information()` records the instant; no deadline is computed (the Regulation gives no hour count) | Art. 14(8) |

What this tool is NOT (and says so in every pack): a conformity assessment, CE marking, the official CSIRT/ENISA channel,
an objective time anchor (unless an RFC 3161 / OpenTimestamps token is attached), legal advice. Numbers such as "24 h"
are the law's; whether a given vulnerability is "actively exploited" is the manufacturer's determination — KEV/EUVD
membership is a signal this tool surfaces, not the determination.
