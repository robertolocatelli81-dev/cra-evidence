# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check a notice drop file under the glossary it was built with (spec/SRP_FIELDS.md, "Recording the version; reading
old records"): the version is the one the file records (`glossary_version`, schema cra-srp/2) or, for the files written
before that field existed (schema cra-srp/1), the one named by the exact `glossary_source` string they carry. The notice
is rebuilt under that version and its rules, and what the file says (complete, missing_required, deadline_utc,
notice_sha3) must come out again. With a ledger, the chain is verified and the record of the same notice_id must bind
the file's bytes (drop.drop_sha3) and agree with it."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex
from .ledger import Ledger, read_regular
from .srp_notice import GLOSSARIES, LEGACY_SOURCES, SourcedSRPNotice, SRPNotice
from .vuln import parse_utc

_V1_KEYS = frozenset({"schema", "glossary_source", "stream", "stage", "notice_id", "generated_utc", "deadline_utc", "fields",
                      "complete", "missing_required", "notice_sha3", "submission"})
_V2_KEYS = _V1_KEYS | {"glossary_version", "previous_fields"}
_V3_KEYS = _V2_KEYS | {"source", "filing"}     # rule 10 (amendment of 13/11/2026): imported notices
_SUBMISSION = ("NOT submitted by this tool: the SRP is a human web portal (EU Login + MFA, Assigned "
               "Representative); this payload is the evidence of what existed and when")
MAX_DROP_BYTES = 4 * 1024 * 1024


def _no_dup_keys(pairs):
    d: Dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} (readers disagree on which wins: refused)")
        d[k] = v
    return d


def load_json_object(path: str, cap: int = MAX_DROP_BYTES) -> Dict[str, Any]:
    """A JSON object from a file; a duplicate key, a non-object or invalid UTF-8 is a ValueError (never last-wins)."""
    raw = read_regular(path, cap)
    try:
        v = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dup_keys)
    except ValueError as e:
        raise ValueError(f"{os.path.basename(path)}: {e}") from None
    if not isinstance(v, dict):
        raise ValueError(f"{os.path.basename(path)}: not a JSON object")
    return v


def _same(a: Any, b: Any) -> bool:
    """JSON equality: 1 is not true, 1.0 is not 1 (Python's == would say they are)."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def check_notice(drop_path: str, ledger_path: Optional[str] = None) -> Dict[str, Any]:
    reasons: List[str] = []
    notes: List[str] = []
    out: Dict[str, Any] = {"drop_file": os.path.basename(drop_path), "verified": False, "glossary_version": None,
                           "glossary_version_from": None, "notice_sha3": "not_checked", "reasons": reasons, "notes": notes}
    try:
        raw = read_regular(drop_path, MAX_DROP_BYTES)
        p = load_json_object(drop_path)
    except (OSError, ValueError, RecursionError) as e:
        reasons.append(f"drop file unreadable: {type(e).__name__}: {str(e)[:200]}")
        return out
    drop_sha3 = hashlib.sha3_256(raw).hexdigest()
    sch = p.get("schema")
    if sch == "cra-srp/3":
        keys, legacy = _V3_KEYS, False
    elif sch == "cra-srp/2":
        keys, legacy = _V2_KEYS, False
    elif sch == "cra-srp/1":
        keys, legacy = _V1_KEYS, True
    else:
        reasons.append(f"schema {sch!r}: not cra-srp/1, cra-srp/2 or cra-srp/3")
        return out
    unknown, absent = sorted(set(p) - keys), sorted(keys - set(p))
    if unknown:
        reasons.append(f"unknown top-level keys for {sch}: {unknown}")
    if absent:
        reasons.append(f"missing top-level keys for {sch}: {absent}")
    if unknown or absent:
        return out
    if legacy:
        v = LEGACY_SOURCES.get(p["glossary_source"]) if isinstance(p["glossary_source"], str) else None
        if v is None:
            reasons.append(f"glossary_source not one written by cra-evidence before cra-srp/2: {str(p['glossary_source'])[:120]!r}")
            return out
        out["glossary_version_from"] = "glossary_source (cra-srp/1: version not recorded, read from the exact source string)"
    else:
        v = p["glossary_version"]
        if not isinstance(v, str) or v not in GLOSSARIES:
            reasons.append(f"glossary_version {v!r} unknown to this release")
            return out
        if GLOSSARIES[v]["rules"] == "srp-notice/1":   # cra-srp/2 files are written under srp-notice/2 glossaries only
            reasons.append(f"glossary_version {v!r} ({GLOSSARIES[v]['rules']}) in a {sch} file: no release writes that combination")
            return out
        if p["glossary_source"] != GLOSSARIES[v]["source"]:
            reasons.append(f"glossary_source does not match glossary_version {v}")
            return out
        out["glossary_version_from"] = "recorded"
    out["glossary_version"] = v
    out["rules"] = GLOSSARIES[v]["rules"]
    if p["submission"] != _SUBMISSION:
        reasons.append("submission statement altered")
    fields = p["fields"]
    prev = None if legacy else p["previous_fields"]
    kw: Dict[str, Any] = {}
    cls = SRPNotice
    if sch == "cra-srp/3":
        cls = SourcedSRPNotice
        kw = {"source": p["source"], "filing": p["filing"]}
    try:
        n = cls(stream=p["stream"], stage=p["stage"], fields=(dict(fields) if isinstance(fields, dict) else fields),
                generated_utc=p["generated_utc"], notice_id=p["notice_id"],
                previous_fields=(dict(prev) if isinstance(prev, dict) else prev), glossary_version=v, **kw)
    except (ValueError, TypeError, AttributeError) as e:
        reasons.append(f"fields refused under {v} ({GLOSSARIES[v]['rules']}): {str(e)[:300]}")
        return out
    if legacy:
        object.__setattr__(n, "_unversioned", True)
    try:
        if not isinstance(p["generated_utc"], str):
            raise ValueError("generated_utc is not a string")
        parse_utc(p["generated_utc"])
        rebuilt = (("complete", n.complete()), ("missing_required", n.missing()), ("deadline_utc", n.deadline_utc()))
        own_hash = n.canonical_hash()
    except (ValueError, TypeError, OverflowError, RecursionError) as e:   # e.g. a float the canonical profile refuses
        reasons.append(f"not rebuildable under {v}: {type(e).__name__}: {str(e)[:200]}")
        return out
    if n.fields != fields:
        reasons.append("fields change when rebuilt (a carried-forward field was not copied into the file)")
    for k, got in rebuilt:
        if not _same(p[k], got):
            reasons.append(f"{k}: the file says {p[k]!r}, rebuilt under {v} it is {got!r}")
    hash_ok = own_hash == p["notice_sha3"]
    out["notice_sha3"] = "recomputed" if hash_ok else "differs"
    if not hash_ok and legacy:
        notes.append("notice_sha3 is not recomputable from a cra-srp/1 file built with --previous (previous_fields was hashed "
                     "but not written); only the ledger's drop_sha3 can bind such a file")
    if ledger_path:
        rec = _ledger_record(ledger_path, p, reasons, notes)
        if rec is not None:
            d = rec.get("drop") if isinstance(rec.get("drop"), dict) else {}
            if d.get("drop_sha3") != drop_sha3:
                reasons.append("the ledger record does not bind these bytes (drop.drop_sha3 differs)")
            else:
                out["drop_sha3"] = "bound_by_ledger"
                if not hash_ok and legacy:
                    out["notice_sha3"] = "bound_by_ledger"
            if d.get("drop_file") != os.path.basename(drop_path):
                notes.append(f"file name differs from the recorded drop_file {d.get('drop_file')!r}")
            for k in ("stream", "stage", "notice_sha3", "complete", "missing_required", "deadline_utc"):
                if not _same(rec.get(k), p[k]):
                    reasons.append(f"ledger record {k} {rec.get(k)!r} differs from the file {p[k]!r}")
            if sch == "cra-srp/3":
                _check_imported(ledger_path, p, rec, reasons, notes)
            if "glossary_version" in rec:
                if rec["glossary_version"] != v:
                    reasons.append(f"ledger record glossary_version {rec['glossary_version']!r} differs from {v!r}")
            else:
                notes.append("the ledger record does not carry glossary_version (written by cra-evidence 0.6.0 or earlier): "
                             "the version is the drop file's, bound by drop_sha3")
    if sch == "cra-srp/3" and not ledger_path and p["source"]["tool"] != "cra-evidence":
        notes.append("the source document is kept next to the ledger: give --ledger to check it and re-derive the notice from it")
    if out["notice_sha3"] == "differs" and not (legacy and out.get("drop_sha3") == "bound_by_ledger"):
        reasons.append("notice_sha3 does not recompute")
    out["verified"] = not reasons
    return out


def _ledger_record(ledger_path: str, p: Dict[str, Any], reasons: List[str], notes: List[str]) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(ledger_path):
        reasons.append("ledger not found")
        return None
    try:
        entries = list(Ledger(ledger_path).entries())     # read once; the chain is verified on this snapshot
    except (ValueError, TypeError, OSError, RecursionError) as e:
        reasons.append(f"ledger unreadable: {type(e).__name__}: {str(e)[:200]}")
        return None
    ch = Ledger(ledger_path).verify(entries)
    if not ch["chain_ok"]:
        reasons.append(f"ledger chain does not verify: {ch['failures'][:3]}")
        return None
    hits = [e["data"] for e in entries if isinstance(e.get("data"), dict) and e["data"].get("kind") == "cra_srp_notice"
            and e["data"].get("notice_id") == p["notice_id"]]
    if len(hits) != 1:
        reasons.append(f"{len(hits)} ledger records for notice_id {p['notice_id']} (exactly one expected)")
        return None
    rec = hits[0]
    body = {k: x for k, x in rec.items() if k != "record_sha3"}
    if sha3_hex(body) != rec.get("record_sha3"):
        reasons.append("ledger record digest (record_sha3) does not recompute")
        return None
    return rec


def _check_imported(ledger_path: str, p: Dict[str, Any], rec: Dict[str, Any], reasons: List[str], notes: List[str]) -> None:
    """An imported notice (cra-srp/3, source other than cra-evidence): the record names the same source document, the
    document kept next to the ledger has those bytes, and the notice is re-derived from it (the drop file is a function
    of the kept bytes, not merely co-located with them)."""
    src = p["source"]
    if src["tool"] == "cra-evidence":
        return
    imp = rec.get("imported") if isinstance(rec.get("imported"), dict) else {}
    if imp.get("tool") != src["tool"] or imp.get("filing_document_sha256") != src["document_sha256"]:
        reasons.append("the ledger record does not name this notice's source document (imported.tool / filing_document_sha256)")
        return
    from .locker import source_file
    from .sbomify_import import ImportRefused, load, place_filing
    path = source_file(ledger_path, src["document_sha256"])
    try:
        raw = read_regular(path, MAX_DROP_BYTES)
    except OSError as e:
        reasons.append(f"source document {src['document_sha256'][:16]}… not readable next to the ledger: {e}")
        return
    if hashlib.sha256(raw).hexdigest() != src["document_sha256"]:
        reasons.append("the kept source document does not hash to source.document_sha256")
        return
    try:
        filing = load(raw, "source document")
        placed = place_filing(filing, p["stream"], "source document")
    except (ImportRefused, ValueError) as e:
        reasons.append(f"the kept source document does not import: {str(e)[:200]}")
        return
    want = {"stage": placed["stage"], "glossary_version": placed["glossary_version"], "fields": placed["fields"],
            "previous_fields": placed["previous_fields"], "later_stage": placed["later_stage"], "readings": placed["readings"],
            "normalisations": placed["normalisations"],
            "filing": {"declared_by": src["tool"], "srp_reference": filing["srp_reference"], "filed_at": filing["filed_at"],
                       "filed_by": filing["filed_by"]}}
    have = {"stage": p["stage"], "glossary_version": p["glossary_version"], "fields": p["fields"],
            "previous_fields": p["previous_fields"], "later_stage": src["later_stage"], "readings": src["readings"],
            "normalisations": src["normalisations"], "filing": p["filing"]}
    if placed["unmapped"]:
        reasons.append("the kept source document has unmapped pairs")
    for k in want:
        if not _same(want[k], have[k]):
            reasons.append(f"{k}: differs from the notice re-derived from the kept source document")
    if not reasons:
        notes.append("re-derived from the kept source document: identical")
