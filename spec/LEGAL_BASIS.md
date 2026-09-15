# Legal basis — as read from primary sources on 15/09/2026

Regulation (EU) 2024/2847 (Cyber Resilience Act). Sources consulted on 15/09/2026:
- European Commission, "Cyber Resilience Act — Reporting obligations": https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- ENISA, Single Reporting Platform: https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp
  (portal https://portal.cra-srp.enisa.europa.eu/, "operational as of 11 September 2026"), CRA SRP Glossary (39 fields), AR User Manual.
- ENISA, "The CRA Single Reporting Platform is launched" (news, September 2026).

| Obligation | What this tool does | Reference |
|---|---|---|
| Actively exploited vulnerabilities and severe incidents must be reported: early warning within 24 h of awareness, notification within 72 h, final report no later than 14 days after a corrective or mitigating measure is available (vulnerability) or one month after the 72 h notification (severe incident); reporting once through the Single Reporting Platform to the CSIRT designated as coordinator and ENISA | `VulnerabilityRecord.deadlines()/overdue()` with the clock anchored exactly as above; `SRPNotice` builds the payload per stage in the glossary vocabulary and lists what is still missing; nothing is submitted (human portal) | Art. 14, Art. 16; applying from 11 September 2026 (Art. 71) |
| Software bill of materials in a commonly used, machine-readable format covering at least the top-level dependencies, in the technical documentation | `SBOMRecord` (CycloneDX 1.6-compatible subset), from the installed environment (floor) or by ingesting a full generator's CycloneDX; an empty SBOM is recorded as not meeting the floor | Annex I Part II(1); full application 11 December 2027 |
| Technical documentation kept at the disposal of authorities for 10 years after placing on the market (or the support period if longer) | evidence pack + hash-chained ledger + crypto-agile long-term seal (renewable before an algorithm is deprecated: NIST IR 8547, https://csrc.nist.gov/pubs/ir/8547/ipd: deprecates pre-quantum signatures by 2030, disallows them by 2035) | Art. 31 (documentation), retention 10 years |
| Open-source software stewards: reporting obligations from 11 December 2027 | same tooling; the stream/stage model is identical | Art. 24, Art. 71 |

What this tool is NOT (and says so in every pack): a conformity assessment, CE marking, the official CSIRT/ENISA channel,
an objective time anchor (unless an RFC 3161 / OpenTimestamps token is attached), legal advice. Numbers such as "24 h"
are the law's; whether a given vulnerability is "actively exploited" is the manufacturer's determination — KEV/EUVD
membership is a signal this tool surfaces, not the determination.
