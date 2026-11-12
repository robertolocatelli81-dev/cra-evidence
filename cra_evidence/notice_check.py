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
from .srp_notice import GLOSSARIES, LEGACY_SOURCES, SRPNotice

_V1_KEYS = frozenset({"schema", "glossary_source", "stream", "stage", "notice_id", "generated_utc", "deadline_utc", "fields",
                      "complete", "missing_required", "notice_sha3", "submission"})
_V2_KEYS = _V1_KEYS | {"glossary_version", "previous_fields"}
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
    if sch == "cra-srp/2":
        keys, legacy = _V2_KEYS, False
    elif sch == "cra-srp/1":
        keys, legacy = _V1_KEYS, True
    else:
        reasons.append(f"schema {sch!r}: not cra-srp/1 or cra-srp/2")
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
    try:
        n = SRPNotice(stream=p["stream"], stage=p["stage"], fields=(dict(fields) if isinstance(fields, dict) else fields),
                      generated_utc=p["generated_utc"], notice_id=p["notice_id"],
                      previous_fields=(dict(prev) if isinstance(prev, dict) else prev), glossary_version=v)
    except (ValueError, TypeError, AttributeError) as e:
        reasons.append(f"fields refused under {v} ({GLOSSARIES[v]['rules']}): {str(e)[:300]}")
        return out
    if legacy:
        object.__setattr__(n, "_unversioned", True)
    if n.fields != fields:
        reasons.append("fields change when rebuilt (a carried-forward field was not copied into the file)")
    for k, got in (("complete", n.complete()), ("missing_required", n.missing()), ("deadline_utc", n.deadline_utc())):
        if p[k] != got:
            reasons.append(f"{k}: the file says {p[k]!r}, rebuilt under {v} it is {got!r}")
    hash_ok = n.canonical_hash() == p["notice_sha3"]
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
                if rec.get(k) != p[k]:
                    reasons.append(f"ledger record {k} {rec.get(k)!r} differs from the file {p[k]!r}")
            if "glossary_version" in rec:
                if rec["glossary_version"] != v:
                    reasons.append(f"ledger record glossary_version {rec['glossary_version']!r} differs from {v!r}")
            else:
                notes.append("the ledger record does not carry glossary_version (written by cra-evidence 0.6.0 or earlier): "
                             "the version is the drop file's, bound by drop_sha3")
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
