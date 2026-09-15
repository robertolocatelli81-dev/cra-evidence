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
from .vuln import parse_utc, EARLY_WARNING_HOURS, NOTIFICATION_HOURS, FINAL_REPORT_DAYS_AFTER_FIX, CLOCK_SKEW

STAGES = ("early_warning", "notification", "final_report")
STREAMS = ("vulnerability", "incident")

# field -> {stage: "R" required | "O" optional | "A" required-if-available | "-" not at this stage}
# (max lengths and enums as published by ENISA; "carried forward" fields keep the previous stage's value)
_C = {"early_warning": "R", "notification": "R", "final_report": "R"}
_O = {"early_warning": "O", "notification": "O", "final_report": "O"}
COMMON_FIELDS: Dict[str, Dict[str, Any]] = {
    "notification_type": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Vulnerability", "Incident"], "glossary_row": "1"},
    "title": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "2"},
    "summary": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "3"},
    "manufacturer_name": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "note": "system-generated in the SRP", "glossary_row": "4"},
    "member_states_available": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "list", "note": "one or more EU Member States", "glossary_row": "5"},
    "product_name": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "6"},
    "product_version": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "7"},
    "product_type": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Default", "Important", "Critical"], "glossary_row": "8"},
    "product_class": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Class I", "Class II"], "glossary_row": "9"},
    "product_category": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "10"},
    "end_of_support": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Yes", "No"], "glossary_row": "11"},
    "component_name": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "12"},
    "mitigating_measure_expected_shortly": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Yes", "No"], "glossary_row": "13"},
    "user_action_reduce_impact": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "14"},
    "sensitivity_justification": {"stages": {"early_warning": "O", "notification": "O", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "15"},
    "corrective_measures_taken": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 2000, "glossary_row": "16"},
    "user_measures": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "17"},
    "attack_vector": {"stages": {"early_warning": "-", "notification": "O", "final_report": "O"}, "format": "text", "max": 255, "glossary_row": "18"},
}
VULN_FIELDS: Dict[str, Dict[str, Any]] = {
    "cve_id": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "v19"},
    "euvd_id": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "v20"},
    "general_information": {"stages": {"early_warning": "O", "notification": "R", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "v21"},
    "corrective_available_date": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "datetime-utc", "glossary_row": "v22"},
    "security_update_details": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 2000, "glossary_row": "v23"},
    "severity_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "v24"},
    "impact_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "v25"},
    "awareness_datetime_utc": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "datetime-utc", "glossary_row": "v26"},
    "malicious_actor": {"stages": {"early_warning": "O", "notification": "O", "final_report": "A"}, "format": "text", "max": 100, "glossary_row": "v27"},
    "particular_exceptional_circumstances": {"stages": {"early_warning": "-", "notification": "O", "final_report": "-"}, "format": "enum-list", "glossary_row": "v28", "enum": ["no_other_member_state", "contrary_to_essential_interests", "imminent_high_risk"]},
    "pec_delay_reason": {"stages": {"early_warning": "-", "notification": "O", "final_report": "-"}, "format": "enum-list", "glossary_row": "v29", "enum": ["no_other_member_state", "contrary_to_essential_interests", "imminent_high_risk"]},
    "further_information_cdac": {"stages": {"early_warning": "O", "notification": "O", "final_report": "C"}, "format": "text", "max": 800, "glossary_row": "v30"},
}
INCIDENT_FIELDS: Dict[str, Dict[str, Any]] = {
    "suspected_malicious": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "enum", "enum": ["Yes", "No", "Unknown"], "glossary_row": "i31"},
    "incident_nature": {"stages": {"early_warning": "O", "notification": "R", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "i32"},
    "mitigation_measures": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "i33"},
    "severity_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "i34"},
    "impact_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "i35"},
    "threat_type_root_cause": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 255, "glossary_row": "i36"},
    "awareness_datetime_utc": {"stages": {"early_warning": "R", "notification": "R", "final_report": "C"}, "format": "datetime-utc", "glossary_row": "i37"},
    "incident_datetime_utc": {"stages": {"early_warning": "O", "notification": "R", "final_report": "O"}, "format": "datetime-utc", "glossary_row": "i38"},
    "initial_assessment": {"stages": {"early_warning": "O", "notification": "R", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "i39"},
}
PEC_OPTIONS = {   # Art. 16(2) third subparagraph, as listed in the glossary rows v28/v29 (checkbox options)
    "no_other_member_state": "actively exploited, and according to the information available in no other Member State than the one of the coordinating CSIRT",
    "contrary_to_essential_interests": "immediate further dissemination would likely supply information whose disclosure would be contrary to the essential interests of that Member State",
    "imminent_high_risk": "the notified vulnerability poses an imminent high cybersecurity risk stemming from the further dissemination",
}
STAGE_CODES = {"R": "required at this stage", "O": "optional", "A": "required if such information is available",
               "C": "carried forward from the previous stage (copied by default, may be updated)", "-": "not at this stage"}
SRP_GLOSSARY_SOURCE = "ENISA CRA SRP Glossary (39 fields), read 2026-09-15 — snapshot vendored in spec/sources/enisa_srp_glossary_20260915.json; per-stage codes derived from it by tests/test_council_r2.py"


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
    previous_fields: Optional[Dict[str, Any]] = None   # the previous stage's payload: "C" fields are carried from it

    def __post_init__(self):
        if self.stream not in STREAMS or self.stage not in STAGES:
            raise ValueError("unknown stream/stage")
        if self.previous_fields:
            # "By default copied from previous step, or updated": copy what this payload does not override
            for k, spec in schema(self.stream).items():
                if spec["stages"][self.stage] == "C" and not _present(self.fields.get(k)) and _present(self.previous_fields.get(k)):
                    self.fields[k] = self.previous_fields[k]
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
            if spec.get("enum") and _present(v):
                vals = v if (spec["format"] == "enum-list" and isinstance(v, list)) else [v]
                for one in vals:
                    if str(one) not in spec["enum"]:
                        raise ValueError(f"{k}: value {one!r} not in {spec['enum']}")
            if spec["format"] == "datetime-utc" and _present(v):
                parse_utc(str(v))

    def missing(self) -> List[str]:
        """Fields REQUIRED ("R") or CARRIED ("C") at this stage and absent: a carried field the portal would copy
        from the previous step is missing here unless this payload carries it (pass previous_fields). Required-if-
        available ("A") is never counted as missing: the manufacturer decides; the payload records the choice."""
        earlier = STAGES[:STAGES.index(self.stage)]
        def needed(spec):
            code = spec["stages"].get(self.stage)
            return code == "R" or (code == "C" and any(spec["stages"].get(s0) == "R" for s0 in earlier))
        return [k for k, spec in schema(self.stream).items() if needed(spec) and not _present(self.fields.get(k))]

    def complete(self) -> bool:
        return not self.missing()

    def deadline_utc(self) -> Optional[str]:
        """None = undetermined (never invented): the incident final report runs one calendar month from the
        SUBMISSION of the incident notification (Art. 14(4)(c)) — that instant lives in the vulnerability record
        (`notification_sent_utc`), not in this payload."""
        if not _present(self.fields.get("awareness_datetime_utc")):
            return None
        aw = parse_utc(str(self.fields["awareness_datetime_utc"]))
        if self.stage == "early_warning":
            return (aw + timedelta(hours=EARLY_WARNING_HOURS)).isoformat(timespec="seconds")
        if self.stage == "notification":
            return (aw + timedelta(hours=NOTIFICATION_HOURS)).isoformat(timespec="seconds")
        if self.stream == "incident":
            return None
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
