# SPDX-License-Identifier: AGPL-3.0-or-later
"""Art. 14 notifications aligned with the ENISA Single Reporting Platform (SRP) data model.

Source of the field inventory: ENISA, "CRA SRP Glossary" (enisa.europa.eu/topics/product-security/
single-reporting-platform-srp/cra-srp-glossary2), read 15/09/2026: 39 fields — 18 common, 12 for an actively
exploited vulnerability (AEV), 9 for a severe incident — each with its stage (EW = early warning 24 h, N72 =
notification 72 h, FR = final report) and whether it is required, optional or required-if-available at that stage.

What this module does: builds a stage payload in the SRP vocabulary, lists the fields still MISSING for that
stage (never "complete" by silence), computes the legal deadline, hashes the payload canonically, and writes a
dry-run drop file. What it does NOT do: submit. The SRP is a web portal (portal.cra-srp.enisa.europa.eu, EU Login
+ MFA, Assigned Representative role); no machine-to-machine API was documented on 15/09/2026. Submission is a
human act; this file is the evidence that the payload existed, complete or not, before the deadline.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex
from .vuln import parse_utc, EARLY_WARNING_HOURS, NOTIFICATION_HOURS, FINAL_REPORT_DAYS_AFTER_FIX, INCIDENT_FINAL_AFTER_NOTIFICATION, CLOCK_SKEW

STAGES = ("early_warning", "notification", "final_report")
STREAMS = ("vulnerability", "incident")

# field -> {stage: "R" required | "O" optional | "A" required-if-available | "-" not at this stage}
# (max lengths and enums as published by ENISA; "carried forward" fields keep the previous stage's value)
_C = {"early_warning": "R", "notification": "R", "final_report": "R"}
_O = {"early_warning": "O", "notification": "O", "final_report": "O"}
COMMON_FIELDS: Dict[str, Dict[str, Any]] = {
    "notification_type":         {"stages": _C, "format": "enum", "enum": ["Vulnerability", "Incident"]},
    "title":                     {"stages": _C, "format": "text", "max": 255},
    "summary":                   {"stages": _C, "format": "text", "max": 4000},
    "manufacturer_name":         {"stages": _C, "format": "text", "max": 255, "note": "system-generated in the SRP"},
    "member_states_available":   {"stages": _C, "format": "list", "note": "one or more EU Member States"},
    "product_name":              {"stages": _C, "format": "text", "max": 255},
    "product_version":           {"stages": _C, "format": "text", "max": 255},
    "product_type":              {"stages": _O, "format": "enum", "enum": ["Default", "Important", "Critical"]},
    "product_class":             {"stages": _O, "format": "enum", "enum": ["Class I", "Class II"]},
    "product_category":          {"stages": _O, "format": "text", "max": 255},
    "end_of_support":            {"stages": _O, "format": "enum", "enum": ["Yes", "No"]},
    "component_name":            {"stages": _O, "format": "text", "max": 255},
    "mitigating_measure_expected_shortly": {"stages": _O, "format": "enum", "enum": ["Yes", "No"]},
    "user_action_reduce_impact": {"stages": _O, "format": "text", "max": 4000},
    "sensitivity_justification": {"stages": {"early_warning": "O", "notification": "O", "final_report": "-"}, "format": "text", "max": 255},
    "corrective_measures_taken": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 2000},
    "user_measures":             {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "attack_vector":             {"stages": {"early_warning": "-", "notification": "O", "final_report": "O"}, "format": "text", "max": 255},
}
VULN_FIELDS: Dict[str, Dict[str, Any]] = {
    "cve_id":                    {"stages": _O, "format": "text", "max": 255},
    "euvd_id":                   {"stages": _O, "format": "text", "max": 255},
    "general_information":       {"stages": {"early_warning": "O", "notification": "R", "final_report": "O"}, "format": "text", "max": 4000},
    "corrective_available_date": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "datetime-utc"},
    "security_update_details":   {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 2000},
    "severity_description":      {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "impact_description":        {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "awareness_datetime_utc":    {"stages": _C, "format": "datetime-utc"},
    "malicious_actor":           {"stages": {"early_warning": "A", "notification": "O", "final_report": "A"}, "format": "text", "max": 100},
    "particular_exceptional_circumstances": {"stages": {"early_warning": "-", "notification": "R", "final_report": "-"}, "format": "enum-list"},
    "pec_delay_reason":          {"stages": {"early_warning": "-", "notification": "R", "final_report": "-"}, "format": "text"},
    "further_information_cdac":  {"stages": _O, "format": "text", "max": 800},
}
INCIDENT_FIELDS: Dict[str, Dict[str, Any]] = {
    "suspected_malicious":       {"stages": _C, "format": "enum", "enum": ["Yes", "No", "Unknown"]},
    "incident_nature":           {"stages": {"early_warning": "O", "notification": "R", "final_report": "O"}, "format": "text", "max": 4000},
    "mitigation_measures":       {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "severity_description":      {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "impact_description":        {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000},
    "threat_type_root_cause":    {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 255},
    "awareness_datetime_utc":    {"stages": {"early_warning": "R", "notification": "R", "final_report": "-"}, "format": "datetime-utc"},
    "incident_datetime_utc":     {"stages": {"early_warning": "O", "notification": "R", "final_report": "O"}, "format": "datetime-utc"},
    "initial_assessment":        {"stages": {"early_warning": "O", "notification": "R", "final_report": "O"}, "format": "text", "max": 4000},
}
SRP_GLOSSARY_SOURCE = "ENISA CRA SRP Glossary (39 fields), read 2026-09-15"


def schema(stream: str) -> Dict[str, Dict[str, Any]]:
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of {STREAMS}")
    return {**COMMON_FIELDS, **(VULN_FIELDS if stream == "vulnerability" else INCIDENT_FIELDS)}


def _present(v: Any) -> bool:
    return v is not None and str(v).strip() != "" and v != []


@dataclass(frozen=True)
class SRPNotice:
    stream: str
    stage: str
    fields: Dict[str, Any]
    generated_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    notice_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if self.stream not in STREAMS or self.stage not in STAGES:
            raise ValueError("unknown stream/stage")
        try:
            uuid.UUID(str(self.notice_id))
        except ValueError:
            raise ValueError("notice_id must be a UUID (it becomes a file name)") from None
        sch = schema(self.stream)
        aw = self.fields.get("awareness_datetime_utc")
        if sch["awareness_datetime_utc"]["stages"][self.stage] == "R" and not _present(aw):
            raise ValueError(f"awareness_datetime_utc is required at stage {self.stage}")
        if _present(aw) and parse_utc(str(aw)) > datetime.now(timezone.utc) + CLOCK_SKEW:
            raise ValueError("awareness_datetime_utc is in the future")
        for k, v in self.fields.items():
            if k not in sch:
                raise ValueError(f"field not in the SRP schema for stream {self.stream}: {k}")
            spec = sch[k]
            if spec.get("max") and _present(v) and len(str(v)) > spec["max"]:
                raise ValueError(f"{k}: longer than the SRP maximum ({spec['max']})")
            if spec.get("enum") and _present(v) and str(v) not in spec["enum"]:
                raise ValueError(f"{k}: value {v!r} not in {spec['enum']}")
            if spec["format"] == "datetime-utc" and _present(v):
                parse_utc(str(v))

    def missing(self) -> List[str]:
        """Fields REQUIRED at this stage and absent. Required-if-available ("A") is never counted as missing:
        the manufacturer decides; the payload records the choice."""
        return [k for k, spec in schema(self.stream).items()
                if spec["stages"].get(self.stage) == "R" and not _present(self.fields.get(k))]

    def complete(self) -> bool:
        return not self.missing()

    def deadline_utc(self) -> Optional[str]:
        if not _present(self.fields.get("awareness_datetime_utc")):
            return None   # e.g. incident final report (awareness is "-" at that stage): undetermined here, never invented
        aw = parse_utc(str(self.fields["awareness_datetime_utc"]))
        if self.stage == "early_warning":
            return (aw + timedelta(hours=EARLY_WARNING_HOURS)).isoformat(timespec="seconds")
        if self.stage == "notification":
            return (aw + timedelta(hours=NOTIFICATION_HOURS)).isoformat(timespec="seconds")
        if self.stream == "incident":
            return (aw + timedelta(hours=NOTIFICATION_HOURS) + INCIDENT_FINAL_AFTER_NOTIFICATION).isoformat(timespec="seconds")
        cad = self.fields.get("corrective_available_date")
        if not _present(cad):
            return None   # honest: undetermined until a corrective measure is available (Art. 14(2)(c))
        return (parse_utc(str(cad)) + timedelta(days=FINAL_REPORT_DAYS_AFTER_FIX)).isoformat(timespec="seconds")

    def canonical_hash(self) -> str:
        return sha3_hex(asdict(self))

    def payload(self) -> Dict[str, Any]:
        return {"schema": "cra-srp/1", "glossary_source": SRP_GLOSSARY_SOURCE, "stream": self.stream, "stage": self.stage,
                "notice_id": self.notice_id, "generated_utc": self.generated_utc, "deadline_utc": self.deadline_utc(),
                "fields": dict(self.fields), "complete": self.complete(), "missing_required": self.missing(),
                "notice_sha3": self.canonical_hash(),
                "submission": "NOT submitted by this tool: the SRP is a human web portal (EU Login + MFA, Assigned "
                              "Representative); this payload is the evidence of what existed and when"}


def _sha3_file(p: Path) -> str:
    import hashlib
    return hashlib.sha3_256(p.read_bytes()).hexdigest()


class DryRunDrop:
    """Writes the payload to a drop folder and returns 'prepared_not_sent'. There is deliberately no other transport."""
    def __init__(self, drop_dir: str):
        self.dir = Path(drop_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def prepare(self, notice: SRPNotice) -> Dict[str, Any]:
        p = self.payload_path(notice)
        p.write_text(json.dumps(notice.payload(), indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        # only the file NAME is returned/recorded: an absolute path would leak the operator's directory layout into a
        # ledger meant to be handed to auditors (found by the pre-publication scan, 15/09/2026)
        return {"status": "prepared_not_sent", "drop_file": p.name, "drop_sha3": _sha3_file(p), "complete": notice.complete(),
                "missing_required": notice.missing(), "deadline_utc": notice.deadline_utc(), "notice_sha3": notice.canonical_hash()}

    def payload_path(self, notice: SRPNotice) -> Path:
        return self.dir / f"{notice.stream}_{notice.stage}_{notice.notice_id}.json"
