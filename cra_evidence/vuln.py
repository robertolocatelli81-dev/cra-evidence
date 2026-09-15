# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vulnerability-handling record with the Art. 14 clock (Reg. (EU) 2024/2847).

Deadlines, as stated by the European Commission (digital-strategy.ec.europa.eu/en/policies/cra-reporting, read
15/09/2026): early warning 24 h after awareness; vulnerability notification 72 h after awareness; final report no
later than 14 days after a corrective or mitigating measure is AVAILABLE (not 14 days after awareness — the detail
summaries get wrong); for a severe incident the final report is due one month after the 72 h notification.
The obligation arises only for ACTIVELY EXPLOITED vulnerabilities: a non-exploited one is never "overdue".
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .canonical import sha3_hex

EARLY_WARNING_HOURS = 24
NOTIFICATION_HOURS = 72
FINAL_REPORT_DAYS_AFTER_FIX = 14
INCIDENT_FINAL_AFTER_NOTIFICATION = timedelta(days=30)   # counted from the 72 h notification deadline (awareness + 72 h)
CLOCK_SKEW = timedelta(minutes=5)                        # tolerated skew between the recorder's clock and this host's
KINDS = ("vulnerability", "incident")


def parse_utc(ts: str) -> datetime:
    """ISO-8601 → aware UTC datetime; a naive value is taken as UTC. Raises ValueError."""
    t = ts.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    d = datetime.fromisoformat(t)
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


@dataclass(frozen=True)
class VulnerabilityRecord:
    product_id: str
    vuln_id: str                      # CVE / EUVD / internal id
    actively_exploited: bool
    awareness_utc: str
    status: str = "aware"             # aware | early_warning_sent | notified | fixed | final_reported
    exploitation_source: str = "manual"   # manual | cisa_kev | enisa_euvd | vendor_advisory
    corrective_available_utc: Optional[str] = None
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    details: Dict[str, Any] = field(default_factory=dict)
    kind: str = "vulnerability"       # "vulnerability" (Art. 14(1)) | "incident" (severe incident, Art. 14(3))

    def __post_init__(self):
        if not str(self.vuln_id).strip():
            raise ValueError("vuln_id empty")
        if self.kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        try:
            uuid.UUID(str(self.record_id))
        except ValueError:
            raise ValueError("record_id must be a UUID") from None
        aw = parse_utc(self.awareness_utc)
        # a self-asserted awareness in the future would produce fictitious deadlines and overdue=False forever
        if aw > datetime.now(timezone.utc) + CLOCK_SKEW:
            raise ValueError(f"awareness_utc {self.awareness_utc} is in the future")
        if self.corrective_available_utc is not None and parse_utc(self.corrective_available_utc) < aw:
            raise ValueError("corrective_available_utc earlier than awareness_utc")

    def deadlines(self) -> Dict[str, Optional[str]]:
        t0 = parse_utc(self.awareness_utc)
        fix = parse_utc(self.corrective_available_utc) if self.corrective_available_utc else None
        if self.kind == "incident":
            fr = (t0 + timedelta(hours=NOTIFICATION_HOURS) + INCIDENT_FINAL_AFTER_NOTIFICATION).isoformat(timespec="seconds")
            basis = "severe incident: one month after the 72 h incident notification (Art. 14(4)(c))"
        else:
            fr = (fix + timedelta(days=FINAL_REPORT_DAYS_AFTER_FIX)).isoformat(timespec="seconds") if fix else None
            basis = ("14 days after the corrective/mitigating measure is available" if fix else
                     "undetermined: no corrective measure available yet (Art. 14(2)(c))")
        return {"early_warning_due_utc": (t0 + timedelta(hours=EARLY_WARNING_HOURS)).isoformat(timespec="seconds"),
                "notification_due_utc": (t0 + timedelta(hours=NOTIFICATION_HOURS)).isoformat(timespec="seconds"),
                "final_report_due_utc": fr, "final_report_basis": basis}

    def overdue(self, now_utc: Optional[datetime] = None) -> Dict[str, Any]:
        now = now_utc or datetime.now(timezone.utc)
        d = self.deadlines()
        applicable = bool(self.actively_exploited)
        ew = applicable and self.status == "aware" and now > parse_utc(d["early_warning_due_utc"])
        nt = applicable and self.status in ("aware", "early_warning_sent") and now > parse_utc(d["notification_due_utc"])
        fr = (applicable and d["final_report_due_utc"] is not None and self.status != "final_reported"
              and now > parse_utc(d["final_report_due_utc"]))
        return {"reporting_applicable": applicable, "early_warning_overdue": ew, "notification_overdue": nt,
                "final_report_overdue": fr}

    def canonical_hash(self) -> str:
        # includes record_id on purpose: this is the fingerprint of THIS record instance (what the ledger binds),
        # not a de-duplication key for "the same vulnerability"; compare vuln_id/product_id for that
        return sha3_hex(asdict(self))
