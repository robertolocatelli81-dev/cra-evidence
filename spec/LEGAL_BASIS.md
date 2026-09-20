# Legal basis — as read from primary sources on 15/09/2026, re-checked on 20/09/2026

Regulation (EU) 2024/2847 (Cyber Resilience Act). Sources consulted on 15/09/2026:
- European Commission, "Cyber Resilience Act — Reporting obligations": https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- ENISA, Single Reporting Platform: https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp
  (portal https://portal.cra-srp.enisa.europa.eu/, "operational as of 11 September 2026"), CRA SRP Glossary (39 fields; the
  vendored table has 44 rows — 3 section headers, 2 unnumbered continuation rows, 39 numbered fields — dated snapshot in
  `spec/sources/enisa_srp_glossary_20260915.json`), AR User Manual, PEC guidance.
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

| Obligation | What this tool does | Reference |
|---|---|---|
| Actively exploited vulnerabilities: early warning within 24 h of awareness, notification within 72 h, final report no later than 14 days after a corrective or mitigating measure is available (Art. 14(2)(a)-(c)); severe incidents: 24 h, 72 h, final report "within one month after the submission of the incident notification" (Art. 14(4)(a)-(c)); reporting once through the Single Reporting Platform to the CSIRT designated as coordinator and ENISA | `VulnerabilityRecord.deadlines()/overdue()` with the clock anchored exactly as above (the incident final report is anchored to the recorded submission instant, calendar month; undetermined until recorded); `SRPNotice` builds the payload per stage in the glossary vocabulary and lists what is still missing; nothing is submitted (human portal) | Art. 14, Art. 16; applying from 11 September 2026 (Art. 71) — text re-read on EUR-Lex (OJ L, 2024/2847) on 15/09/2026 |
| Software bill of materials in a commonly used, machine-readable format covering at least the top-level dependencies, in the technical documentation | `SBOMRecord` (CycloneDX 1.6/1.7 subset; the generator's document is stored byte-exact since 0.3.0), from the installed environment (floor) or by ingesting a full generator's CycloneDX or SPDX document (stored byte-exact); an empty SBOM is recorded as not meeting the floor | Annex I Part II(1); full application 11 December 2027 |
| Technical documentation and EU declaration of conformity kept at the disposal of the market surveillance authorities for at least 10 years after the product is placed on the market or for the support period, whichever is longer | evidence pack (records the support period end when given, so the retention horizon is the right one) + hash-chained ledger + crypto-agile long-term seal, renewable before an algorithm is retired (NIST IR 8547 initial public draft, https://csrc.nist.gov/pubs/ir/8547/ipd: quantum-vulnerable signatures deprecated after 2030, disallowed after 2035 — used as the verifier's default policy) | Art. 13(13) (retention), Art. 31 (technical documentation content) |
| Open-source software stewards: reporting obligations from 11 December 2027 | same tooling; the stream/stage model is identical | Art. 24, Art. 71 |

What this tool is NOT (and says so in every pack): a conformity assessment, CE marking, the official CSIRT/ENISA channel,
an objective time anchor (unless an RFC 3161 / OpenTimestamps token is attached), legal advice. Numbers such as "24 h"
are the law's; whether a given vulnerability is "actively exploited" is the manufacturer's determination — KEV/EUVD
membership is a signal this tool surfaces, not the determination.
