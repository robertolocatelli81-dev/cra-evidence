# Legal basis — as read from primary sources on 15/09/2026, re-checked on 20/09/2026, 29/09/2026 and 19/10/2026

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

Re-check of 17/10/2026 by Athena, the project's confined research agent (EUR-Lex served no text to her fetcher; she read
a secondary reproduction), reviewed by Noûs on 19/10/2026 against the primary texts below. What changed: no obligation;
the provisions are newly used by `cra_evidence/applicability.py`, `cra obligations` and `VulnerabilityRecord.overdue()`.
- Regulation (EU) 2024/2847, OJ L, 2024/2847, 20.11.2024, Official Journal XHTML from the Publications Office
  (http://publications.europa.eu/resource/celex/32024R2847 → cellar 21b7d4eb-a6e2-11ef-85f0-01aa75ed71a1.0006.03, sha256
  fe0cca4a0caec50e7cf5a91432b94a19b211f86be8584fdba56372bdcea571ed, downloaded 19/10/2026):
  - Art. 71(2): applies from 11 December 2027; "However, Article 14 shall apply from 11 September 2026 and Chapter IV
    (Articles 35 to 51) shall apply from 11 June 2026."
  - Art. 69(2): products placed on the market before 11 December 2027 are subject to the requirements "only if, from that
    date, those products are subject to a substantial modification"; Art. 69(3): by derogation, Article 14 applies to all
    products in scope placed on the market before 11 December 2027.
  - Art. 24(3): Art. 14(1) applies to open-source software stewards "to the extent that they are involved in the
    development of the products with digital elements"; Art. 14(3) **and (8)** "to the extent that severe incidents ... affect network and
    information systems provided by the open-source software stewards for the development of such products". (The
    17/10 draft named 14(3) only: corrected.) Art. 24 applies from 11 December 2027 (Art. 71(2)).
  - Art. 13(8) third subparagraph ("at least five years"; for a shorter expected use, "the expected use time"), 13(9)
    ("a minimum of 10 years or for the remainder of the support period, whichever is longer"), 13(13) ("at least 10
    years after the product ... has been placed on the market or for the support period, whichever is longer").
  - Art. 14(1) and (3): the manufacturer notifies what "it becomes aware of"; Art. 14(8): inform the impacted users, no
    hour count.
- Regulation (EEC, Euratom) No 1182/71 (http://publications.europa.eu/resource/celex/31971R1182, sha256
  d04e07610a25c0dad545733afff515b670eb5a428480c71a6cd7a3a4732c74a5): Art. 4(2), application fixed at a given date occurs "at
  the beginning of the first hour of the day falling on that date"; Art. 3(1) second subparagraph and 3(2)(c), a period in
  years from an event excludes the day of the event and ends "with the expiry of the last hour" of the same date in the
  last year (the month's last day when that date does not exist). No time zone is named. 1182/71 speaks of acts of the
  Council or the Commission; applying it to this Regulation is this tool's reading. Art. 3(4) (a last day on a Saturday,
  Sunday or public holiday) is not applied.
- Commission guidance C(2026) 5252 (27/07/2026), annex, document 131456 (sha256 fe209c25…8234), §217, pp. 75–76 (the
  covering note approves the content of the DRAFT guidance and says it will be formally adopted, and apply, once all
  language versions are available; its formal adoption was not checked on 19/10/2026) —
  NON-BINDING: the obligation applies when the manufacturer "becomes aware of active exploitation"; a vulnerability "of
  whose active exploitation it had already become aware before 11 September 2026" is not reported (no retroactive
  reporting); a vulnerability known before that date whose active exploitation becomes known after it is reported. The
  84 pages name no time zone, midnight or start hour (searched 18/10/2026). §216: a steward's obligation likewise applies
  "upon becoming aware of an actively exploited vulnerability".
- Rule applied (Roberto, 18/10/2026): the trigger is the awareness of the ACTIVE EXPLOITATION (or of the severe incident),
  separate from the awareness of the vulnerability; every date threshold is computed at 00:00 UTC and at 00:00
  Europe/Brussels (11/09/2026: 2026-09-10T22:00:00Z, CEST; 11/12/2027: 2027-12-10T23:00:00Z, CET — checked against the
  IANA zone day by day 2000–2040 in the tests); when the two readings disagree the result is
  `depends_on_time_zone_reading` with both answers, never one picked in silence. The year horizons (13(8), 13(9), 13(13))
  are given under both readings, with the later one as `latest_until_utc`. Two readings only: the local midnight of the
  Member States at UTC+3 in September (Bulgaria, Cyprus, Estonia, Finland, Greece, Latvia, Lithuania, Romania:
  2026-09-10T21:00:00Z) and of the outermost regions (UTC−4 to UTC+4: from 2026-09-10T20:00:00Z to 2026-09-11T04:00:00Z)
  are not computed; a net answer is net between these two readings only. The 24 h / 72 h / 14-day / one-month counts
  of Art. 14 run from the instant itself (1182/71 Art. 3(1)-(2), which would leave out the hour or the day of the
  event, is NOT applied to them: their ends are up to one hour, or one day, earlier than under it).
- Not re-read on 19/10/2026: the ENISA SRP FAQ ("Updated: 15 October 2026" per Athena: steward reporting from 11/12/2027,
  no API at the initial release, voluntary notifications not implemented) and the EN 40000 standardisation status
  (secondary trackers only).

| Obligation | What this tool does | Reference |
|---|---|---|
| Actively exploited vulnerabilities: early warning within 24 h of awareness, notification within 72 h, final report no later than 14 days after a corrective or mitigating measure is available (Art. 14(2)(a)-(c)); severe incidents: 24 h, 72 h, final report "within one month after the submission of the incident notification" (Art. 14(4)(a)-(c)); reporting once through the Single Reporting Platform to the CSIRT designated as coordinator and ENISA | `VulnerabilityRecord.deadlines()/overdue()` with the clock anchored exactly as above (the incident final report is anchored to the recorded submission instant, calendar month; undetermined until recorded); `SRPNotice` builds the payload per stage in the glossary vocabulary and lists what is still missing; nothing is submitted (human portal) | Art. 14, Art. 16; applying from 11 September 2026 (Art. 71) — text re-read on EUR-Lex (OJ L, 2024/2847) on 15/09/2026 |
| Software bill of materials in a commonly used, machine-readable format covering at least the top-level dependencies, in the technical documentation | `SBOMRecord` (CycloneDX 1.6/1.7 subset; the generator's document is stored byte-exact since 0.3.0), from the installed environment (floor) or by ingesting a full generator's CycloneDX or SPDX document (stored byte-exact); an empty SBOM is recorded as not meeting the floor | Annex I Part II(1); full application 11 December 2027 |
| Technical documentation and EU declaration of conformity kept at the disposal of the market surveillance authorities for at least 10 years after the product is placed on the market or for the support period, whichever is longer | evidence pack (records the support period end when given, so the retention horizon is the right one) + hash-chained ledger + crypto-agile long-term seal, renewable before an algorithm is retired (NIST IR 8547 initial public draft, https://csrc.nist.gov/pubs/ir/8547/ipd: quantum-vulnerable signatures deprecated after 2030, disallowed after 2035 — used as the verifier's default policy) | Art. 13(13) (retention), Art. 31 (technical documentation content) |
| Art. 14 applies from 11 September 2026; the obligation arises on awareness of ACTIVE EXPLOITATION (not of the vulnerability) | `art14_obligation()` / `cra obligations --exploitation-aware [--vulnerability-aware]` / `VulnerabilityRecord.overdue()["art14_obligation"]`: obligation, no obligation, or depends on the time-zone reading (both answers) | Art. 14(1)/(3), Art. 71(2); guidance C(2026) 5252 §217 (non-binding); Reg. 1182/71 Art. 4(2) |
| Open-source software stewards: reporting obligations from 11 December 2027 (Art. 14(1); 14(3) and (8) for severe incidents) | same tooling; the stream/stage model is identical, but `cra vuln` computes the manufacturer's start (11/09/2026): for a steward, before 11/12/2027 its `overdue` flags do not apply; `reporting_in_force("open_source_steward", …)` / `cra obligations --role open_source_steward` says from when, under both readings, with the Art. 24(3) scope condition recorded and never checked | Art. 24(3), Art. 71(2) |
| Products placed on the market before 11 December 2027: Art. 14 applies to them; the requirements only after a substantial modification from that date | `legacy_product_scope()` / `cra obligations --placed-on-market [--substantially-modified]`; scope (Art. 2) and "substantial" are not decided | Art. 69(2)-(3) |
| Support period at least five years (shorter only for a shorter expected use); each security update available 10 years or the remainder of the support period | `support_period()` (`meets_minimum` / `shorter_declared` / `below_minimum` / `depends_on_time_zone_reading`; `cra obligations` exits 1 when below under one reading where the requirements reach the product, Art. 69(2), and marks the horizons `requirements_apply`), `update_available_until()`, `retention_until()` (both readings, 1182/71 Art. 3) | Art. 13(8), 13(9), 13(13) |
| Inform the impacted users of an actively exploited vulnerability or severe incident | `user_information()` records the instant; no deadline is computed (the Regulation gives no hour count) | Art. 14(8) |

What this tool is NOT (and says so in every pack): a conformity assessment, CE marking, the official CSIRT/ENISA channel,
an objective time anchor (unless an RFC 3161 / OpenTimestamps token is attached), legal advice. Numbers such as "24 h"
are the law's; whether a given vulnerability is "actively exploited" is the manufacturer's determination — KEV/EUVD
membership is a signal this tool surfaces, not the determination.
