# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vulnerability-handling record with the Art. 14 clock (Reg. (EU) 2024/2847).

Deadlines, as stated by the European Commission (digital-strategy.ec.europa.eu/en/policies/cra-reporting, read
15/09/2026): early warning 24 h after awareness; vulnerability notification 72 h after awareness; final report no
later than 14 days after a corrective or mitigating measure is AVAILABLE (not 14 days after awareness — the detail
summaries get wrong); for a severe incident the final report is due one month after the 72 h notification.
The obligation arises only for ACTIVELY EXPLOITED vulnerabilities: a non-exploited one is never "overdue".
"""
from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .canonical import sha3_hex

EARLY_WARNING_HOURS = 24
NOTIFICATION_HOURS = 72
FINAL_REPORT_DAYS_AFTER_FIX = 14
CLOCK_SKEW = timedelta(minutes=5)                        # tolerated skew between the recorder's clock and this host's
KINDS = ("vulnerability", "incident")


STATUSES = ("aware", "early_warning_sent", "notified", "fixed", "final_reported")


def parse_utc(ts: str) -> datetime:
    """ISO-8601 WITH zone → aware UTC datetime. A naive value is REFUSED: a local time read as UTC would move the
    legal clock by hours. Raises ValueError."""
    t = ts.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)   # +0000 → +00:00 (Python < 3.11)
    d = datetime.fromisoformat(t)
    if d.tzinfo is None:
        raise ValueError(f"{ts!r}: timezone required (use Z or +hh:mm); a naive local time is not a legal instant")
    return d.astimezone(timezone.utc)


def add_months(d: datetime, months: int) -> datetime:
    """Calendar-month arithmetic ('one month' in Art. 14(4)(c)); the day is clamped to the target month's length."""
    y, m = divmod(d.month - 1 + months, 12)
    y, m = d.year + y, m + 1
    last = [31, 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
    return d.replace(year=y, month=m, day=min(d.day, last))


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
    # instants at which each stage was actually SUBMITTED (what overdue() is computed from — a status word cannot
    # extinguish an obligation that was never fulfilled)
    early_warning_sent_utc: Optional[str] = None
    notification_sent_utc: Optional[str] = None
    final_report_sent_utc: Optional[str] = None

    def __post_init__(self):
        if not str(self.vuln_id).strip():
            raise ValueError("vuln_id empty")
        if self.kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        for f_ in ("early_warning_sent_utc", "notification_sent_utc", "final_report_sent_utc"):
            v = getattr(self, f_)
            if v is not None and parse_utc(v) < parse_utc(self.awareness_utc):
                raise ValueError(f"{f_} earlier than awareness_utc")
        try:
            uuid.UUID(str(self.record_id))
        except ValueError:
            raise ValueError("record_id must be a UUID") from None
        aw = parse_utc(self.awareness_utc)
        # a self-asserted awareness in the future would produce fictitious deadlines and overdue=False forever
        if aw > datetime.now(timezone.utc) + CLOCK_SKEW:
            raise ValueError(f"awareness_utc {self.awareness_utc} is in the future")
        if self.corrective_available_utc is not None:
            parse_utc(self.corrective_available_utc)   # may legitimately PRECEDE awareness (a fix shipped before the exploitation was known)

    def deadlines(self) -> Dict[str, Optional[str]]:
        t0 = parse_utc(self.awareness_utc)
        fix = parse_utc(self.corrective_available_utc) if self.corrective_available_utc else None
        if self.kind == "incident":
            # Art. 14(4)(c): "within one month after the submission of the incident notification under point (b)" —
            # anchored to the SUBMISSION instant; undetermined until the notification is recorded, never estimated
            if self.notification_sent_utc:
                fr = add_months(parse_utc(self.notification_sent_utc), 1).isoformat(timespec="seconds")
                basis = "severe incident: one calendar month after the submission of the incident notification (Art. 14(4)(c))"
            else:
                fr, basis = None, "undetermined: record notification_sent_utc (one month after the submission, Art. 14(4)(c))"
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
        applicable = bool(self.actively_exploited) or self.kind == "incident"
        def _state(due_iso, sent_iso):
            if not applicable or due_iso is None:
                return {"overdue": False, "late": False}
            due = parse_utc(due_iso)
            if sent_iso:
                return {"overdue": False, "late": parse_utc(sent_iso) > due, "sent_utc": sent_iso}
            return {"overdue": now > due, "late": False, "sent_utc": None}
        ew = _state(d["early_warning_due_utc"], self.early_warning_sent_utc)
        nt = _state(d["notification_due_utc"], self.notification_sent_utc)
        fr = _state(d["final_report_due_utc"], self.final_report_sent_utc)
        return {"reporting_applicable": applicable, "early_warning_overdue": ew["overdue"], "notification_overdue": nt["overdue"],
                "final_report_overdue": fr["overdue"], "late_submissions": [k for k, v in (("early_warning", ew), ("notification", nt), ("final_report", fr)) if v["late"]],
                "any_overdue": ew["overdue"] or nt["overdue"] or fr["overdue"]}

    def canonical_hash(self) -> str:
        # includes record_id on purpose: this is the fingerprint of THIS record instance (what the ledger binds),
        # not a de-duplication key for "the same vulnerability"; compare vuln_id/product_id for that
        return sha3_hex(asdict(self))
