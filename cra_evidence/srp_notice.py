# SPDX-License-Identifier: AGPL-3.0-or-later
"""Art. 14 notifications aligned with the ENISA Single Reporting Platform (SRP) data model.

Source of the field inventory: ENISA, "CRA SRP Glossary" (enisa.europa.eu/topics/product-security/
single-reporting-platform-srp/cra-srp-glossary2). Current: page "Version 1.6. Last update: 21 October 2026", read
12/11/2026, 43 numbered fields — 21 common, 13 for an actively exploited vulnerability (AEV), 9 for a severe incident —
each with its stage (EW = early warning 24 h, N72 = notification 72 h, FR = final report) and its cell (required,
optional, required-if-available, copied from the previous step, N/A, optional under a condition). The earlier glossaries
(snapshots of 15/09/2026 and 29/09/2026) stay available with the rules they had (`srp-notice/1`): a notice records the
glossary it was built under (`glossary_version`) and is checked under that one. Rules: spec/SRP_FIELDS.md.

What this module does: builds a stage payload in the SRP vocabulary, refuses what the recorded glossary does not
allow, lists the fields still MISSING for that stage (never "complete" by silence), computes the legal deadline, hashes
the payload canonically, and writes a dry-run drop file. What it does NOT do: submit. The SRP is a web portal
(portal.cra-srp.enisa.europa.eu, EU Login + MFA, Assigned Representative role); ENISA's FAQ says no API is provided at
the initial release. Submission is a human act; this file is the evidence that the payload existed, complete or not,
before the deadline.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex
from .outputs import OutputNotWritten, write_file
from .vuln import parse_utc, EARLY_WARNING_HOURS, NOTIFICATION_HOURS, FINAL_REPORT_DAYS_AFTER_FIX, CLOCK_SKEW

STAGES = ("early_warning", "notification", "final_report")
STREAMS = ("vulnerability", "incident")

# ── glossary 20260929 (page "Version 1.3. Last update: 25 September 2026"): the tables of cra-evidence 0.4.0 – 0.6.0,
# kept verbatim. field -> {stage: "R" required | "O" optional | "A" required-if-available | "C" carried | "-" not at this stage}
_C = {"early_warning": "R", "notification": "R", "final_report": "R"}
_O = {"early_warning": "O", "notification": "O", "final_report": "O"}
_COMMON_20260929: Dict[str, Dict[str, Any]] = {
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
_VULN_20260929: Dict[str, Dict[str, Any]] = {
    "cve_id": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "v19"},
    "euvd_id": {"stages": {"early_warning": "O", "notification": "C", "final_report": "C"}, "format": "text", "max": 255, "glossary_row": "v20"},
    "general_information": {"stages": {"early_warning": "O", "notification": "R", "final_report": "C"}, "format": "text", "max": 4000, "glossary_row": "v21"},
    "corrective_available_date": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "datetime-utc", "glossary_row": "v22"},
    "security_update_details": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 2000, "glossary_row": "v23"},
    "severity_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "v24"},
    "impact_description": {"stages": {"early_warning": "O", "notification": "O", "final_report": "R"}, "format": "text", "max": 4000, "glossary_row": "v25"},
    "awareness_datetime_utc": {"stages": {"early_warning": "R", "notification": "C", "final_report": "C"}, "format": "datetime-utc", "glossary_row": "v26"},
    # v26a added by ENISA in the glossary dated 25/09/2026 ("Date and time when the Actively Exploited Vulnerability occurred"):
    # optional at the early warning, REQUIRED at the 72 h notification, carried forward at the final report
    "vulnerability_occurred_datetime_utc": {"stages": {"early_warning": "O", "notification": "R", "final_report": "C"}, "format": "datetime-utc", "glossary_row": "v26a"},
    "malicious_actor": {"stages": {"early_warning": "O", "notification": "O", "final_report": "A"}, "format": "text", "max": 100, "glossary_row": "v27"},
    "particular_exceptional_circumstances": {"stages": {"early_warning": "-", "notification": "O", "final_report": "-"}, "format": "enum-list", "glossary_row": "v28", "enum": ["no_other_member_state", "contrary_to_essential_interests", "imminent_high_risk"]},
    "pec_delay_reason": {"stages": {"early_warning": "-", "notification": "O", "final_report": "-"}, "format": "enum-list", "glossary_row": "v29", "enum": ["no_other_member_state", "contrary_to_essential_interests", "imminent_high_risk"]},
    "further_information_cdac": {"stages": {"early_warning": "O", "notification": "O", "final_report": "C"}, "format": "text", "max": 800, "glossary_row": "v30"},
}
_INCIDENT_20260929: Dict[str, Dict[str, Any]] = {
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


def _f(row: str, codes: str, fmt: str, mx: Optional[int] = None, **kw: Any) -> Dict[str, Any]:
    """codes: three letters for EW, N72, FR (R, O, A, C or -)."""
    d: Dict[str, Any] = {"stages": dict(zip(STAGES, codes)), "format": fmt}
    if mx is not None:
        d["max"] = mx
    d.update(kw)
    d["glossary_row"] = row
    return d


_PEC_ENUM = ["no_other_member_state", "contrary_to_essential_interests", "imminent_high_risk"]
# ── glossary 20261112 (page "Version 1.6. Last update: 21 October 2026"), rules srp-notice/2. "when": the field may be
# present at that stage only if the named field is present (v22 "after completion of v17"; v29/v30 "upon/under PEC
# activation"). "entered_by": "CSIRT" = not a field the manufacturer's representative fills (row 41).
_COMMON_20261112: Dict[str, Dict[str, Any]] = {
    "notification_type": _f("1", "R--", "enum", enum=["Vulnerability", "Incident"]),
    "title": _f("2", "R--", "text", 255),
    "summary": _f("3", "R--", "text", 4000),
    "manufacturer_name": _f("4", "R--", "text", 255, note="system-generated in the SRP"),
    "member_states_available": _f("5", "R--", "list", note="one or more EU Member States"),
    "product_name": _f("6", "R--", "text", 255),
    "product_version": _f("7", "R--", "text", 255),
    "additional_information": _f("7a", "O--", "text", 255),
    "product_type": _f("8", "O--", "enum", enum=["Default", "Important", "Critical"]),
    "product_class": _f("9", "O--", "enum", enum=["Class I", "Class II"]),
    "product_category": _f("10", "O--", "text", 255),
    "end_of_support": _f("11", "O--", "enum", enum=["Yes", "No"]),
    "component_name": _f("12", "O--", "text", 255),
    "mitigating_measure_expected_shortly": _f("13", "O--", "enum", enum=["Yes", "No"]),
    "user_action_reduce_impact": _f("14", "O--", "text", 4000),
    "sensitivity_justification": _f("15", "OO-", "text", 255),
    "corrective_measures_taken": _f("16", "OOR", "text", 2000),
    "user_measures": _f("17", "OOR", "text", 4000),
    "attack_vector": _f("18", "-O-", "text", 255),
}
_VULN_20261112: Dict[str, Dict[str, Any]] = {
    "cve_id": _f("v19", "O--", "text", 255),
    "euvd_id": _f("v20", "O--", "text", 255),
    "general_information": _f("v21", "OR-", "text", 4000),
    "corrective_available_date": _f("v22", "OOR", "datetime-utc", when={"early_warning": "user_measures", "notification": "user_measures"}),
    "security_update_details": _f("v23", "OOR", "text", 2000),
    "severity_description": _f("v24", "OOR", "text", 4000),
    "impact_description": _f("v25", "OOR", "text", 4000),
    "awareness_datetime_utc": _f("v26", "R--", "datetime-utc"),
    "vulnerability_occurred_datetime_utc": _f("v26a", "OC-", "datetime-utc"),
    "malicious_actor": _f("v27", "OOA", "text", 100),
    "particular_exceptional_circumstances": _f("v28", "-O-", "enum-list", enum=list(_PEC_ENUM)),
    "pec_delay_reason": _f("v29", "-O-", "enum-list", enum=list(_PEC_ENUM), when={"notification": "particular_exceptional_circumstances"}),
    "further_information_cdac": _f("v30", "-O-", "text", 800, when={"notification": "particular_exceptional_circumstances"}),
}
_INCIDENT_20261112: Dict[str, Dict[str, Any]] = {
    "suspected_malicious": _f("i31", "RC-", "text", 255, note="free text since the glossary of 21/10/2026: Yes, No or Unknown, with details"),
    "incident_nature": _f("i32", "OR-", "text", 4000),
    "mitigation_measures": _f("i33", "OOR", "text", 4000),
    "severity_description": _f("i34", "OOR", "text", 4000),
    "impact_description": _f("i35", "OOR", "text", 4000),
    "threat_type_root_cause": _f("i36", "OOR", "text", 255),
    "awareness_datetime_utc": _f("i37", "R--", "datetime-utc"),
    "incident_datetime_utc": _f("i38", "OO-", "datetime-utc"),
    "initial_assessment": _f("i39", "OR-", "text", 4000),
}
_TRAILING_20261112: Dict[str, Dict[str, Any]] = {   # second "Common fields" section, after the incident rows
    "ar_note": _f("40", "OOO", "text"),
    "csirt_note": _f("41", "OOO", "text", entered_by="CSIRT"),
}

_COMMON_20260915 = _COMMON_20260929
_VULN_20260915 = {k: v for k, v in _VULN_20260929.items() if k != "vulnerability_occurred_datetime_utc"}   # v26a came on 25/09
_INCIDENT_20260915 = _INCIDENT_20260929

_SOURCE_20260915_SHORT = "ENISA CRA SRP Glossary (39 fields), read 2026-09-15"
_SOURCE_20260915 = (_SOURCE_20260915_SHORT + " — snapshot vendored in spec/sources/enisa_srp_glossary_20260915.json; per-stage codes "
                    "derived from it by tests/test_council_r2.py")
_SOURCE_20260929 = ("ENISA CRA SRP Glossary (40 fields; page dated 25 September 2026), read 2026-09-29 — snapshot vendored in "
                    "spec/sources/enisa_srp_glossary_20260929.json; per-stage codes derived from it by tests/test_council_r2.py")
_SOURCE_20261112 = ("ENISA CRA SRP Glossary (43 fields; page \"Version 1.6. Last update: 21 October 2026\"), read 2026-11-12 — "
                    "snapshot vendored in spec/sources/enisa_srp_glossary_20261112.json; per-stage codes derived from it by "
                    "tests/test_srp_glossary_16.py")

# glossary_version -> tables, rules and the source line. Order of "groups" = order of the rows in the glossary table.
GLOSSARIES: Dict[str, Dict[str, Any]] = {
    "enisa_srp_glossary_20260915": {"rules": "srp-notice/1", "source": _SOURCE_20260915, "page": "Version 1.3. Last update: 10 September 2026",
                                    "groups": [("Both", _COMMON_20260915), ("AEV", _VULN_20260915), ("SI", _INCIDENT_20260915)]},
    "enisa_srp_glossary_20260929": {"rules": "srp-notice/1", "source": _SOURCE_20260929, "page": "Version 1.3. Last update: 25 September 2026",
                                    "groups": [("Both", _COMMON_20260929), ("AEV", _VULN_20260929), ("SI", _INCIDENT_20260929)]},
    "enisa_srp_glossary_20261112": {"rules": "srp-notice/2", "source": _SOURCE_20261112, "page": "Version 1.6. Last update: 21 October 2026",
                                    "groups": [("Both", _COMMON_20261112), ("AEV", _VULN_20261112), ("SI", _INCIDENT_20261112), ("Both", _TRAILING_20261112)]},
}
CURRENT_GLOSSARY = "enisa_srp_glossary_20261112"
# the exact glossary_source strings of the drop files written before glossary_version existed (schema cra-srp/1)
LEGACY_SOURCES = {_SOURCE_20260915_SHORT: "enisa_srp_glossary_20260915", _SOURCE_20260915: "enisa_srp_glossary_20260915",
                  _SOURCE_20260929: "enisa_srp_glossary_20260929"}

# the current tables under their historical names (common = rows 1-18 + 7a + 40/41)
COMMON_FIELDS: Dict[str, Dict[str, Any]] = {**_COMMON_20261112, **_TRAILING_20261112}
VULN_FIELDS = _VULN_20261112
INCIDENT_FIELDS = _INCIDENT_20261112

PEC_OPTIONS = {   # Art. 16(2) third subparagraph, as listed in the glossary rows v28/v29 (checkbox options)
    "no_other_member_state": "actively exploited, and according to the information available in no other Member State than the one of the coordinating CSIRT",
    "contrary_to_essential_interests": "immediate further dissemination would likely supply information whose disclosure would be contrary to the essential interests of that Member State",
    "imminent_high_risk": "the notified vulnerability poses an imminent high cybersecurity risk stemming from the further dissemination",
}
STAGE_CODES = {"R": "required at this stage", "O": "optional", "A": "required if such information is available",
               "C": "carried forward from the previous stage (copied by default, may be updated)", "-": "not at this stage"}
SRP_GLOSSARY_SOURCE = _SOURCE_20261112


def glossary(version: str = CURRENT_GLOSSARY) -> Dict[str, Any]:
    if not isinstance(version, str) or version not in GLOSSARIES:
        raise ValueError(f"unknown glossary_version {version!r}: one of {sorted(GLOSSARIES)}")
    return GLOSSARIES[version]


def schema(stream: str, glossary_version: str = CURRENT_GLOSSARY) -> Dict[str, Dict[str, Any]]:
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of {STREAMS}")
    keep = {"Both", "AEV" if stream == "vulnerability" else "SI"}
    out: Dict[str, Dict[str, Any]] = {}
    for scope, table in glossary(glossary_version)["groups"]:
        if scope in keep:
            out.update(table)
    return out


def _present(v: Any) -> bool:
    return v is not None and str(v).strip() != "" and v != []


def _type_ok(spec: Dict[str, Any], v: Any) -> bool:
    """srp-notice/2 rule 5: the JSON type a field may carry (None = absent)."""
    if v is None:
        return True
    if spec["format"] in ("list", "enum-list"):
        return type(v) is list and all(type(x) is str for x in v)
    return type(v) is str


@dataclass(frozen=True)
class SRPNotice:
    stream: str
    stage: str
    fields: Dict[str, Any]
    generated_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    notice_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    previous_fields: Optional[Dict[str, Any]] = None   # the previous stage's payload: "C" fields are carried from it
    glossary_version: str = CURRENT_GLOSSARY

    def __post_init__(self):
        if self.stream not in STREAMS or self.stage not in STAGES:
            raise ValueError("unknown stream/stage")
        g = glossary(self.glossary_version)
        v2 = g["rules"] == "srp-notice/2"
        if not isinstance(self.fields, dict):
            raise ValueError("fields must be a JSON object")
        if self.previous_fields is not None and not isinstance(self.previous_fields, dict):
            raise ValueError("previous_fields must be a JSON object")
        sch = schema(self.stream, self.glossary_version)
        for k, v in (self.previous_fields or {}).items():
            if k not in sch:
                raise ValueError(f"previous_fields: field not in the SRP schema for stream {self.stream} under {self.glossary_version}: {k}")
            if v2 and not _type_ok(sch[k], v):
                raise ValueError(f"previous_fields: {k}: JSON type {type(v).__name__} not allowed for format {sch[k]['format']}")
        for k in self.fields:
            if k not in sch:
                raise ValueError(f"field not in the SRP schema for stream {self.stream} under {self.glossary_version}: {k}")
        if self.previous_fields:
            # "By default copied from previous step[, or updated]": copy what this payload does not carry. N/A is never copied.
            for k, spec in sch.items():
                if spec["stages"][self.stage] == "C" and not _present(self.fields.get(k)) and _present(self.previous_fields.get(k)):
                    self.fields[k] = self.previous_fields[k]
        try:
            uuid.UUID(str(self.notice_id))
        except ValueError:
            raise ValueError("notice_id must be a UUID (it becomes a file name)") from None
        if v2:
            for k, v in self.fields.items():
                spec = sch[k]
                if not _type_ok(spec, v):
                    raise ValueError(f"{k}: JSON type {type(v).__name__} not allowed for format {spec['format']}")
                if not _present(v):
                    continue
                if spec["stages"][self.stage] == "-":
                    raise ValueError(f"{k} (row {spec['glossary_row']}): not a field of stage {self.stage} under {self.glossary_version} "
                                     f"(glossary: N/A); a value entered at an earlier stage goes in previous_fields")
                if spec.get("entered_by") == "CSIRT":
                    raise ValueError(f"{k} (row {spec['glossary_row']}): entered by the designated CSIRT, not by the manufacturer's representative")
                need = spec.get("when", {}).get(self.stage)
                if need:
                    have = _present(self.fields.get(need)) or (need == "user_measures" and _present((self.previous_fields or {}).get(need)))
                    if not have:
                        raise ValueError(f"{k} (row {spec['glossary_row']}): optional at stage {self.stage} only when {need} "
                                         f"(row {sch[need]['glossary_row']}) is present")
        aw_spec = sch["awareness_datetime_utc"]
        if aw_spec["stages"][self.stage] == "R" and not _present(self.fields.get("awareness_datetime_utc")):
            raise ValueError(f"awareness_datetime_utc is required at stage {self.stage}")
        aw = self.case_value("awareness_datetime_utc")
        if _present(aw) and parse_utc(str(aw)) > datetime.now(timezone.utc) + CLOCK_SKEW:
            raise ValueError("awareness_datetime_utc is in the future")
        for k, v in self.fields.items():
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
        if v2:
            for k, v in (self.previous_fields or {}).items():
                if sch[k]["format"] == "datetime-utc" and _present(v):
                    parse_utc(v)

    def case_value(self, k: str) -> Any:
        """A value of the case: from this payload, else from the previous stage's payload (rule 7/8 of srp-notice/2:
        the awareness instant and the CVE/EUVD ids are early-warning fields)."""
        v = self.fields.get(k)
        if _present(v):
            return v
        return (self.previous_fields or {}).get(k)

    def missing(self) -> List[str]:
        """Fields REQUIRED ("R") or CARRIED ("C") at this stage and absent: a carried field the portal would copy
        from the previous step is missing here unless this payload carries it (pass previous_fields), and only if it
        was required at an earlier stage. Required-if-available ("A") is never counted as missing: the manufacturer
        decides; the payload records the choice."""
        earlier = STAGES[:STAGES.index(self.stage)]
        def needed(spec):
            code = spec["stages"].get(self.stage)
            return code == "R" or (code == "C" and any(spec["stages"].get(s0) == "R" for s0 in earlier))
        return [k for k, spec in schema(self.stream, self.glossary_version).items() if needed(spec) and not _present(self.fields.get(k))]

    def complete(self) -> bool:
        return not self.missing()

    def deadline_utc(self) -> Optional[str]:
        """None = undetermined (never invented): the incident final report runs one calendar month from the
        SUBMISSION of the incident notification (Art. 14(4)(c)) — that instant lives in the vulnerability record
        (`notification_sent_utc`), not in this payload. At 72 h the awareness instant comes from previous_fields when
        this payload does not carry it (glossary 20261112: it is an early-warning field only)."""
        aw0 = self.case_value("awareness_datetime_utc")
        if not _present(aw0):
            return None
        aw = parse_utc(str(aw0))
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
        body = asdict(self)
        if getattr(self, "_unversioned", False):   # a drop file of cra-srp/1: its hash was computed before this field existed
            body.pop("glossary_version")
        return sha3_hex(body)

    def payload(self) -> Dict[str, Any]:
        return {"schema": "cra-srp/2", "glossary_version": self.glossary_version, "glossary_source": glossary(self.glossary_version)["source"],
                "stream": self.stream, "stage": self.stage,
                "notice_id": self.notice_id, "generated_utc": self.generated_utc, "deadline_utc": self.deadline_utc(),
                "fields": dict(self.fields), "previous_fields": (dict(self.previous_fields) if self.previous_fields is not None else None),
                "complete": self.complete(), "missing_required": self.missing(),
                "notice_sha3": self.canonical_hash(),
                "submission": "NOT submitted by this tool: the SRP is a human web portal (EU Login + MFA, Assigned "
                              "Representative); this payload is the evidence of what existed and when"}


def template(stream: str, stage: str, glossary_version: str = CURRENT_GLOSSARY) -> Dict[str, Any]:
    """{field: "" or []} for the fields a manufacturer may fill at this stage (R/C/O/A; N/A and CSIRT-entered left out)."""
    return {k: ([] if spec["format"] in ("list", "enum-list") else "") for k, spec in schema(stream, glossary_version).items()
            if spec["stages"][stage] != "-" and spec.get("entered_by") != "CSIRT"}


def _sha3_file(p: Path) -> str:
    import hashlib
    return hashlib.sha3_256(p.read_bytes()).hexdigest()


class DryRunDrop:
    """Writes the payload to a drop folder and returns 'prepared_not_sent'. There is deliberately no other transport."""
    def __init__(self, drop_dir: str):
        self.dir = Path(drop_dir)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:     # a path under a file, a file in its place, no permission: the drop file cannot be written
            raise OutputNotWritten(f"{drop_dir}: {e.strerror or e}") from None

    def prepare(self, notice: SRPNotice) -> Dict[str, Any]:
        p = self.payload_path(notice)
        write_file(str(p), json.dumps(notice.payload(), indent=1, ensure_ascii=False, sort_keys=True))   # whole or OutputNotWritten
        # only the file NAME is returned/recorded: an absolute path would leak the operator's directory layout into a
        # ledger meant to be handed to auditors (found by the pre-publication scan, 15/09/2026)
        return {"status": "prepared_not_sent", "drop_file": p.name, "drop_sha3": _sha3_file(p), "complete": notice.complete(),
                "missing_required": notice.missing(), "deadline_utc": notice.deadline_utc(), "notice_sha3": notice.canonical_hash()}

    def payload_path(self, notice: SRPNotice) -> Path:
        return self.dir / f"{notice.stream}_{notice.stage}_{notice.notice_id}.json"
