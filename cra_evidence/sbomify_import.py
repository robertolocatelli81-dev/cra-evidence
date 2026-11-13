# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra import sbomify`: Art. 14 notices recorded in sbomify, imported as cra-srp/3 notices (spec/SRP_FIELDS.md, rules 9
and 10 of the amendment of 13/11/2026 and "Importing from sbomify", measured on sbomify's API at commit 4ef6128).

The source is the JSON of sbomify's API, kept byte for byte: the report (`GET /api/v1/compliance/cra-reports/{id}`) and
one document per filing (`.../filings/{filing_id}`, whose `snapshot` holds the report's SRP fields and dates when the
filing was recorded). Every object is closed (an unknown key, a wrong JSON type, a duplicate key is refused), every
non-empty (field, value) pair of a snapshot ends up in exactly one place (fields, previous_fields, later_stage,
readings) or in the list of unmapped pairs, and an import with an unmapped pair, a value that does not convert, a
filing recorded before the glossary of 21/10/2026 or a filing that its report does not list writes nothing.

What the import does NOT do: it does not prove that a notice reached ENISA's platform. `filing` is what sbomify
recorded (reference, instant, person): a declaration of that tool. Rows sbomify does not carry (1, 4, 7a, 41) are
listed in `absent_at_source`, never filled in, so an imported early warning is incomplete until they are given.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .ledger import parse_line, read_regular
from .outputs import OutputNotWritten, commit_tmp, write_tmp
from .srp_notice import (CURRENT_GLOSSARY, PEC_OPTIONS, RULE9_STAGES, STAGES, DryRunDrop, SourcedSRPNotice, _present,
                         _type_ok, schema)
from .vuln import VulnerabilityRecord, parse_utc

TOOL = "sbomify"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
SBOMIFY_STAGES = ("early_warning", "notification", "intermediate", "final_report", "users_informed")
ABSENT_AT_SOURCE = ["1", "4", "7a", "41"]          # 1 = the report's kind, 4 system-generated, 7a new in 1.6, 41 the CSIRT's
# glossary by the filing instant: a filing before the publication of the glossary 1.6 is refused (not mapped for import)
GLOSSARY_FROM = (("2026-10-21T00:00:00Z", "enisa_srp_glossary_20261112"),)
DATE_IDS = ("aware_at", "occurred_at", "measure_available_at")
PEC_IDS = ("pec", "pec_delay_reason")
NO_OPTION = ("", "None", "No", "Not applicable", "N/A")   # exactly these: no option ticked
PRODUCT_TYPES = {"Default": "Default", "Important Product with Digital Elements": "Important",
                 "Critical Product with Digital Elements": "Critical"}
EU_MEMBER_STATES = frozenset(("AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
                              "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "EL"))   # 27 + "EL" (EU usage)

# (scope, sbomify id) -> field. The 39 rows of the spec: 17 common, 13 vulnerability (10 values + 3 dates), 9 incident
# (7 values + 2 dates). The glossary row of each field is read from the glossary, never written here.
MAPPING: Dict[Tuple[str, str], str] = {
    ("both", "title"): "title", ("both", "summary"): "summary", ("both", "member_states"): "member_states_available",
    ("both", "product_name"): "product_name", ("both", "product_version"): "product_version",
    ("both", "product_type"): "product_type", ("both", "product_class"): "product_class",
    ("both", "product_category"): "product_category", ("both", "end_of_support"): "end_of_support",
    ("both", "component_name"): "component_name", ("both", "measure_expected"): "mitigating_measure_expected_shortly",
    ("both", "user_action"): "user_action_reduce_impact", ("both", "sensitivity"): "sensitivity_justification",
    ("both", "measures_taken"): "corrective_measures_taken", ("both", "measures_for_users"): "user_measures",
    ("both", "attack_vector"): "attack_vector", ("both", "ar_note"): "ar_note",
    ("vulnerability", "cve_id"): "cve_id", ("vulnerability", "euvd_id"): "euvd_id",
    ("vulnerability", "general_information"): "general_information",
    ("vulnerability", "measure_available_at"): "corrective_available_date",
    ("vulnerability", "measure_details"): "security_update_details",
    ("vulnerability", "vulnerability_severity"): "severity_description",
    ("vulnerability", "vulnerability_impact"): "impact_description",
    ("vulnerability", "aware_at"): "awareness_datetime_utc",
    ("vulnerability", "occurred_at"): "vulnerability_occurred_datetime_utc",
    ("vulnerability", "malicious_actor"): "malicious_actor",
    ("vulnerability", "pec"): "particular_exceptional_circumstances",
    ("vulnerability", "pec_delay_reason"): "pec_delay_reason",
    ("vulnerability", "further_information"): "further_information_cdac",
    ("incident", "suspected_unlawful"): "suspected_malicious", ("incident", "incident_nature"): "incident_nature",
    ("incident", "incident_mitigation"): "mitigation_measures", ("incident", "incident_severity"): "severity_description",
    ("incident", "incident_impact"): "impact_description", ("incident", "root_cause"): "threat_type_root_cause",
    ("incident", "aware_at"): "awareness_datetime_utc", ("incident", "occurred_at"): "incident_datetime_utc",
    ("incident", "initial_assessment"): "initial_assessment",
}

_REPORT_KEYS = frozenset({"id", "kind", "product_id", "product_name", "advisory_id", "aware_at", "occurred_at",
                          "measure_available_at", "values", "filings", "next_due", "revision"})
_LISTED_FILING_KEYS = frozenset({"id", "stage", "srp_reference", "filed_at", "filed_by"})
_FILING_KEYS = _LISTED_FILING_KEYS | {"snapshot"}
_SNAPSHOT_KEYS = frozenset({"aware_at", "srp_fields", "occurred_at", "measure_available_at"})
_NEXT_DUE_KEYS = frozenset({"stage", "label", "due", "overdue"})
_RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})")


class ImportRefused(ValueError):
    """The import is refused with a reason; nothing was written."""


def lookup(kind: str, sid: str) -> Optional[str]:
    return MAPPING.get(("both", sid)) or MAPPING.get((kind, sid))


# ── closed reading of sbomify's JSON ──────────────────────────────────────────
def load(raw: bytes, name: str) -> Dict[str, Any]:
    """strict JSON (a duplicate key, NaN, a float, invalid UTF-8 or a lone surrogate is refused), an object"""
    try:
        v = parse_line(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise ImportRefused(f"{name}: not strict JSON: {str(e)[:200]}") from None
    if not isinstance(v, dict):
        raise ImportRefused(f"{name}: not a JSON object")
    return v


def _closed(obj: Any, keys: frozenset, where: str) -> None:
    if not isinstance(obj, dict):
        raise ImportRefused(f"{where}: not a JSON object")
    unknown, absent = sorted(set(obj) - keys), sorted(keys - set(obj))
    if unknown:
        raise ImportRefused(f"{where}: unknown keys {unknown}")
    if absent:
        raise ImportRefused(f"{where}: missing keys {absent}")


def _string(v: Any, where: str, nonempty: bool = False) -> str:
    if type(v) is not str or (nonempty and not v):
        raise ImportRefused(f"{where}: {'a non-empty string' if nonempty else 'a string'} expected, got {type(v).__name__}")
    return v


def _instant(v: Any, where: str, nullable: bool = False) -> Optional[str]:
    """RFC 3339 with an offset (a date without a zone is refused, as sbomify refuses it)"""
    if v is None and nullable:
        return None
    _string(v, where)
    if not _RFC3339.fullmatch(v):
        raise ImportRefused(f"{where}: {v!r} is not RFC 3339 with an offset (Z or ±hh:mm; at most 6 fractional digits)")
    from .signing import is_instant
    if not is_instant(v):
        raise ImportRefused(f"{where}: {v!r} is not an existing instant")
    return v


def check_listed_filing(f: Any, where: str) -> None:
    _closed(f, _LISTED_FILING_KEYS, where)
    _string(f["id"], where + ".id", True)
    if f["stage"] not in SBOMIFY_STAGES:
        raise ImportRefused(f"{where}.stage: {f['stage']!r} is not one of {list(SBOMIFY_STAGES)}")
    _string(f["srp_reference"], where + ".srp_reference")
    _instant(f["filed_at"], where + ".filed_at")
    _string(f["filed_by"], where + ".filed_by")


def check_report(rep: Dict[str, Any], name: str) -> None:
    _closed(rep, _REPORT_KEYS, name)
    _string(rep["id"], name + ".id", True)
    if rep["kind"] not in ("vulnerability", "incident"):
        raise ImportRefused(f"{name}.kind: {rep['kind']!r} is not vulnerability or incident")
    _string(rep["product_id"], name + ".product_id")
    _string(rep["product_name"], name + ".product_name")
    if rep["advisory_id"] is not None:
        _string(rep["advisory_id"], name + ".advisory_id")
    _instant(rep["aware_at"], name + ".aware_at")
    _instant(rep["occurred_at"], name + ".occurred_at", nullable=True)
    _instant(rep["measure_available_at"], name + ".measure_available_at", nullable=True)
    if rep["measure_available_at"] is not None and lookup(rep["kind"], "measure_available_at") is None:
        raise ImportRefused(f"{name}.measure_available_at: not a field of a {rep['kind']} report (unmapped)")
    if not isinstance(rep["values"], dict):
        raise ImportRefused(f"{name}.values: not a JSON object")
    for k, v in rep["values"].items():
        if lookup(rep["kind"], k) is None or k in DATE_IDS:
            raise ImportRefused(f"{name}.values: {k!r} is not a {rep['kind']} field of sbomify 4ef6128 (unmapped)")
        if v is not None:
            _string(v, f"{name}.values.{k}")
    if type(rep["filings"]) is not list:
        raise ImportRefused(f"{name}.filings: not a list")
    ids = set()
    for i, f in enumerate(rep["filings"]):
        check_listed_filing(f, f"{name}.filings[{i}]")
        if f["id"] in ids:
            raise ImportRefused(f"{name}.filings: filing id {f['id']} listed twice")
        ids.add(f["id"])
    nd = rep["next_due"]
    if nd is not None:
        _closed(nd, _NEXT_DUE_KEYS, name + ".next_due")
        if nd["stage"] not in SBOMIFY_STAGES:
            raise ImportRefused(f"{name}.next_due.stage: {nd['stage']!r} is not one of {list(SBOMIFY_STAGES)}")
        _string(nd["label"], name + ".next_due.label")
        _instant(nd["due"], name + ".next_due.due")
        if type(nd["overdue"]) is not bool:
            raise ImportRefused(f"{name}.next_due.overdue: a boolean expected")
    _instant(rep["revision"], name + ".revision")


def check_filing(f: Any, name: str) -> None:
    _closed(f, _FILING_KEYS, name)
    check_listed_filing({k: f[k] for k in _LISTED_FILING_KEYS}, name)
    s = f["snapshot"]
    _closed(s, _SNAPSHOT_KEYS, name + ".snapshot")
    for k in DATE_IDS:
        _instant(s[k], f"{name}.snapshot.{k}", nullable=True)
    if not isinstance(s["srp_fields"], dict):
        raise ImportRefused(f"{name}.snapshot.srp_fields: not a JSON object")
    for k, v in s["srp_fields"].items():
        if v is not None:
            _string(v, f"{name}.snapshot.srp_fields.{k}")


def glossary_for(filed_at: str) -> str:
    t = parse_utc(filed_at)
    for start, version in reversed(GLOSSARY_FROM):
        if t >= parse_utc(start):
            return version
    raise ImportRefused(f"filed_at {filed_at} is before {GLOSSARY_FROM[0][0]} (publication of the glossary 1.6): the earlier "
                        f"glossaries are not mapped for import")


# ── closed conversions ────────────────────────────────────────────────────────
def _utc(sid: str, raw: str, norms: List[Dict[str, Any]]) -> str:
    """Z / +00:00 kept as written; any other offset converted to the same instant in UTC (a normalisation)"""
    if raw.endswith("Z") or raw.endswith("+00:00"):
        return raw
    d = datetime.fromisoformat(raw).astimezone(timezone.utc)
    out = d.strftime("%Y-%m-%dT%H:%M:%S") + (f".{d.microsecond:06d}" if d.microsecond else "") + "Z"
    norms.append({"sbomify_id": sid, "from": raw, "to": out, "conversion": "utc_offset"})
    return out


def _check_value(field: str, spec: Dict[str, Any], v: Any, where: str) -> None:
    """the glossary's format for a value that is not checked by the notice itself (previous_fields, later_stage)"""
    if not _type_ok(spec, v):
        raise ImportRefused(f"{where}: {field}: JSON type {type(v).__name__} not allowed for format {spec['format']}")
    if spec.get("max") and len(v) > spec["max"]:
        raise ImportRefused(f"{where}: {field}: longer than the SRP maximum ({spec['max']})")
    if spec.get("enum"):
        for one in (v if spec["format"] == "enum-list" else [v]):
            if one not in spec["enum"]:
                raise ImportRefused(f"{where}: {field}: value {one!r} not in {spec['enum']}")
    if spec["format"] == "datetime-utc":
        parse_utc(v)


def snapshot_items(filing: Dict[str, Any]) -> List[Tuple[str, Any]]:
    s = filing["snapshot"]
    return list(s["srp_fields"].items()) + [(k, s[k]) for k in DATE_IDS]


def place_filing(filing: Dict[str, Any], kind: str, name: str = "filing") -> Dict[str, Any]:
    """Where each pair of the filing's snapshot goes (spec/SRP_FIELDS.md, "Importing from sbomify"), for a filing at
    stage S under the glossary of the instant filed_at: a field the glossary admits at S → fields; else one it admits at
    an earlier stage → previous_fields; else one it admits only later → later_stage (with that stage); a pec /
    pec_delay_reason with no option ticked → readings; at intermediate / users_informed every pair → fields (rule 9).
    A pair whose sbomify id is not in MAPPING for this kind → unmapped (the caller refuses the import). Empty values
    (null, "") of mapped fields are not pairs: listed in empty_at_source. A value that does not convert → ImportRefused."""
    check_filing(filing, name)
    stage = filing["stage"]
    gv = glossary_for(filing["filed_at"])
    sch = schema(kind, gv)
    fields: Dict[str, Any] = {}
    prev: Dict[str, Any] = {}
    later, readings, norms, unmapped, empty = [], [], [], [], []
    for sid, raw in snapshot_items(filing):
        field = lookup(kind, sid)
        if field is None:
            if raw is not None:            # a null date column of the other kind carries nothing; any other key is a pair
                unmapped.append({"sbomify_id": sid, "value": raw})
            elif sid not in DATE_IDS:
                unmapped.append({"sbomify_id": sid, "value": raw})
            continue
        spec = sch[field]
        where = f"{name}: {sid}"
        if sid in PEC_IDS and (raw is None or raw in NO_OPTION):
            if raw is None:
                empty.append(sid)
            else:
                readings.append({"sbomify_id": sid, "field": field, "row": spec["glossary_row"], "value": raw,
                                 "reading": "no option ticked"})
            continue
        if raw is None or raw == "":
            empty.append(sid)
            continue
        if sid in PEC_IDS:
            codes = [k for k, text in PEC_OPTIONS.items() if text == raw]
            if not codes:
                raise ImportRefused(f"{where}: {raw[:120]!r} is not the exact text of one of the three glossary options "
                                    f"(rows v28/v29) nor one of {list(NO_OPTION)}: never guessed")
            value: Any = codes
            norms.append({"sbomify_id": sid, "from": raw, "to": codes, "conversion": "pec_option"})
        elif sid == "product_type":
            if raw not in PRODUCT_TYPES:
                raise ImportRefused(f"{where}: {raw!r} is not one of {list(PRODUCT_TYPES)}")
            value = PRODUCT_TYPES[raw]
            if value != raw:
                norms.append({"sbomify_id": sid, "from": raw, "to": value, "conversion": "product_type"})
        elif sid == "member_states":
            parts = [p.strip() for p in raw.split(",")]
            for p in parts:
                if p not in EU_MEMBER_STATES:
                    raise ImportRefused(f"{where}: {p!r} is not an EU Member State code (ISO 3166-1 alpha-2, or EL)"
                                        if p else f"{where}: empty part in {raw!r}")
            value = parts
            norms.append({"sbomify_id": sid, "from": raw, "to": parts, "conversion": "member_states"})
        elif sid in DATE_IDS:
            value = _utc(sid, raw, norms)
        else:
            value = raw
        if stage in RULE9_STAGES:
            fields[field] = value
            continue
        code = spec["stages"][stage]
        i = STAGES.index(stage)
        if code != "-":
            fields[field] = value
        elif any(spec["stages"][s0] != "-" for s0 in STAGES[:i]):
            _check_value(field, spec, value, where)
            prev[field] = value
        else:
            admits = [s0 for s0 in STAGES[i + 1:] if spec["stages"][s0] != "-"]
            if not admits:
                raise ImportRefused(f"{where}: {field} is admitted at no stage under {gv}")
            _check_value(field, spec, value, where)
            later.append({"sbomify_id": sid, "field": field, "row": spec["glossary_row"], "value": value, "stage": admits[0]})
    for k, v in fields.items():          # what the notice itself does not check (enum of a list value, a date): here
        _check_value(k, sch[k], v, f"{name}: {k}")
    return {"stage": stage, "glossary_version": gv, "fields": fields, "previous_fields": prev or None,
            "later_stage": later, "readings": readings, "normalisations": norms, "unmapped": unmapped,
            "empty_at_source": empty}


# ── the import ────────────────────────────────────────────────────────────────
def _read(path: str) -> bytes:
    try:
        return read_regular(path, MAX_SOURCE_BYTES)
    except OSError as e:
        raise ImportRefused(f"{os.path.basename(path)}: unreadable: {e}") from None


def _sent(rep: Dict[str, Any], stage: str) -> Optional[str]:
    xs = [f["filed_at"] for f in rep["filings"] if f["stage"] == stage]
    return min(xs, key=parse_utc) if xs else None


def plan(report_raw: bytes, filing_raws: List[Tuple[str, bytes]], product_id: str, tool_version: str,
         now: Optional[datetime] = None, new_id: Optional[Callable[[], str]] = None) -> Dict[str, Any]:
    """Everything decided before anything is written: the event, the notices in filed_at order, the source documents.
    ImportRefused on any refusal."""
    new_id = new_id or (lambda: str(uuid.uuid4()))
    now = now or datetime.now(timezone.utc)
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ImportRefused("--source-version: the sbomify version or commit the documents come from is required")
    rep = load(report_raw, "report")
    check_report(rep, "report")
    kind = rep["kind"]
    listed = {f["id"]: f for f in rep["filings"]}
    report_sha = hashlib.sha256(report_raw).hexdigest()
    items = []
    seen = set()
    for i, (name, raw) in enumerate(filing_raws):
        f = load(raw, name)
        check_filing(f, name)
        if f["id"] not in listed:
            raise ImportRefused(f"{name}: filing {f['id']} is not listed in report {rep['id']} (another report's filing?)")
        if {k: f[k] for k in _LISTED_FILING_KEYS} != listed[f["id"]]:
            raise ImportRefused(f"{name}: filing {f['id']} differs from its listing in report {rep['id']} "
                                f"(stage, srp_reference, filed_at or filed_by)")
        if f["id"] in seen:
            raise ImportRefused(f"{name}: filing {f['id']} given twice")
        seen.add(f["id"])
        items.append((parse_utc(f["filed_at"]), i, name, raw, f))
    if not items:
        raise ImportRefused("no filing given")
    items.sort(key=lambda t: (t[0], t[1]))
    values = rep["values"]
    vid = next((values[k].strip() for k in ("cve_id", "euvd_id") if _present(values.get(k))), None) or f"sbomify-report:{rep['id']}"
    status = ("final_reported" if _sent(rep, "final_report") else "notified" if _sent(rep, "notification")
              else "early_warning_sent" if _sent(rep, "early_warning") else "aware")
    try:
        event = VulnerabilityRecord(
            product_id=product_id, vuln_id=vid, actively_exploited=(kind == "vulnerability"), awareness_utc=rep["aware_at"],
            status=status, exploitation_source="declared:sbomify", corrective_available_utc=rep["measure_available_at"],
            record_id=new_id(), kind=kind,
            early_warning_sent_utc=_sent(rep, "early_warning"), notification_sent_utc=_sent(rep, "notification"),
            final_report_sent_utc=_sent(rep, "final_report"),
            details={"source": TOOL, "tool_version": tool_version, "sbomify_report_id": rep["id"],
                     "sbomify_product_id": rep["product_id"], "sbomify_advisory_id": rep["advisory_id"],
                     "report_document_sha256": report_sha,
                     "declared": "aware_at is the manufacturer's declaration as recorded by sbomify; the sent instants "
                                 "are the filings sbomify recorded (a declaration, not a proof of submission)"})
    except ValueError as e:
        raise ImportRefused(f"report {rep['id']}: event refused: {e}") from None
    notices = []
    for _, _, name, raw, f in items:
        placed = place_filing(f, kind, name)
        if placed["unmapped"]:
            raise ImportRefused(f"{name}: unmapped pairs {[(u['sbomify_id'], str(u['value'])[:60]) for u in placed['unmapped']]}")
        source = {"tool": TOOL, "tool_version": tool_version, "document_sha256": hashlib.sha256(raw).hexdigest(),
                  "absent_at_source": list(ABSENT_AT_SOURCE), "later_stage": placed["later_stage"],
                  "readings": placed["readings"], "normalisations": placed["normalisations"]}
        filing = {"declared_by": TOOL, "srp_reference": f["srp_reference"], "filed_at": f["filed_at"], "filed_by": f["filed_by"]}
        try:
            n = SourcedSRPNotice(stream=kind, stage=f["stage"], fields=dict(placed["fields"]),
                                 previous_fields=(dict(placed["previous_fields"]) if placed["previous_fields"] else None),
                                 glossary_version=placed["glossary_version"], notice_id=new_id(),
                                 generated_utc=now.isoformat(timespec="seconds"), source=source, filing=filing)
        except (ValueError, TypeError) as e:
            raise ImportRefused(f"{name}: notice refused under {placed['glossary_version']}: {e}") from None
        notices.append({"name": name, "raw": raw, "filing": f, "placed": placed, "notice": n})
    return {"report": rep, "report_raw": report_raw, "report_sha256": report_sha, "event": event, "notices": notices,
            "tool_version": tool_version}


def _store(path: str, raw: bytes, created: List[str]) -> None:
    """write raw at path (whole or not at all); an existing file must hold exactly these bytes"""
    if os.path.exists(path):
        with open(path, "rb") as f:
            if f.read() != raw:
                raise ImportRefused(f"{path}: already holds different bytes: refusing to overwrite evidence")
        return
    commit_tmp(write_tmp(path, raw), path)
    created.append(path)


def run_import(report_path: str, filing_paths: List[str], locker: Any, drop_dir: str, tool_version: str,
               now: Optional[datetime] = None, new_id: Optional[Callable[[], str]] = None) -> Dict[str, Any]:
    from .locker import source_file, sources_dir
    p = plan(_read(report_path), [(os.path.basename(x), _read(x)) for x in filing_paths], locker.product_id, tool_version,
             now=now, new_id=new_id)
    led = locker.ledger.path
    rep, event = p["report"], p["event"]
    shas = {hashlib.sha256(n["raw"]).hexdigest() for n in p["notices"]}
    existing_event = None
    for e in locker.ledger.entries():
        d = e.get("data") if isinstance(e, dict) else None
        if not isinstance(d, dict):
            continue
        imp = d.get("imported")
        if d.get("kind") == "cra_srp_notice" and isinstance(imp, dict) and imp.get("filing_document_sha256") in shas:
            raise ImportRefused(f"filing document {imp.get('filing_document_sha256')[:16]}… is already imported (ledger entry {e.get('idx')})")
        det = d.get("details")
        if (d.get("kind") == "cra_vuln" and d.get("product_id") == locker.product_id and isinstance(det, dict)
                and det.get("source") == TOOL and det.get("sbomify_report_id") == rep["id"]):
            existing_event = e
    pending = () if existing_event is not None else ({**{k: v for k, v in asdict(event).items() if k != "kind"},
                                                      "kind": "cra_vuln", "event_kind": event.kind},)
    for n in p["notices"]:              # every binding (rule 8) checked before anything is written
        try:
            locker.bind_notice(n["notice"], None, pending=pending)
        except ValueError as e:
            raise ImportRefused(f"{n['name']}: binding to the vulnerability record refused: {e}") from None
    created: List[str] = []
    drop = DryRunDrop(drop_dir)
    try:
        os.makedirs(sources_dir(led), exist_ok=True)
        docs = [(p["report_sha256"], p["report_raw"])] + [(hashlib.sha256(n["raw"]).hexdigest(), n["raw"]) for n in p["notices"]]
        for sha, raw in docs:            # kept byte for byte next to the ledger (spec) and next to the drop files
            _store(source_file(led, sha), raw, created)
            _store(os.path.join(drop_dir, f"sbomify_{sha}.json"), raw, created)
        results = []
        for n in p["notices"]:
            path = drop.payload_path(n["notice"])
            if os.path.exists(path):
                raise ImportRefused(f"{path.name} exists")
            r = drop.prepare(n["notice"])
            created.append(str(path))
            results.append(r)
    except BaseException:
        for c in reversed(created):      # nothing of this import stays behind when it stops before the ledger
            try:
                os.remove(c)
            except OSError:
                pass
        raise
    if existing_event is None:
        ev = locker.record_vulnerability(event)
        event_out = {"recorded": ev["idx"], "vuln_id": event.vuln_id, "record_id": event.record_id}
    else:
        event_out = {"already_recorded": existing_event["idx"], "vuln_id": existing_event["data"].get("vuln_id")}
    out = []
    for n, r in zip(p["notices"], results):
        f, placed, notice = n["filing"], n["placed"], n["notice"]
        e = locker.record_notice(notice, r, imported={
            "tool": TOOL, "tool_version": p["tool_version"], "sbomify_report_id": rep["id"], "sbomify_filing_id": f["id"],
            "filing_document_sha256": notice.source["document_sha256"], "report_document_sha256": p["report_sha256"]})
        out.append({"filing_id": f["id"], "stage": f["stage"], "filed_at": f["filed_at"], "drop_file": r["drop_file"],
                    "recorded": e["idx"], "glossary_version": placed["glossary_version"],
                    "complete": r["complete"], "missing_required": r["missing_required"], "deadline_utc": r["deadline_utc"],
                    "counts": {"fields": len(notice.fields), "previous_fields": len(notice.previous_fields or {}),
                               "later_stage": len(placed["later_stage"]), "readings": len(placed["readings"])},
                    "later_stage": placed["later_stage"], "readings": placed["readings"],
                    "normalisations": placed["normalisations"], "empty_at_source": placed["empty_at_source"]})
    return {"imported": True, "tool": TOOL, "tool_version": p["tool_version"], "report_id": rep["id"], "kind": rep["kind"],
            "report_document_sha256": p["report_sha256"], "event": event_out, "notices": out,
            "absent_at_source": list(ABSENT_AT_SOURCE),
            "filing": "declared by sbomify: what it recorded about each filing, not a proof of submission"}
