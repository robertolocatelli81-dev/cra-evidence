# SPDX-License-Identifier: AGPL-3.0-or-later
"""Predicate type `art14-filing` v0.1 (spec/art14-filing/v0.1/README.md): an in-toto Statement v1 in a DSSE envelope,
signed with Ed25519, about one Art. 14 notice drop file (cra-srp/3) — its stage and glossary, what the tool recorded
about its filing (a declaration), its source, and its place in the ledger.

`build_statement` + `sign_envelope` (`cra attest`) and `verify_envelope` (`cra verify-attestation`). The verifier checks
the envelope first (DSSE: decode, payload type, signatures over PAE with the trust store key selected by keyid), then
parses the exact bytes it verified: the Statement (unrecognized fields ignored for the verdict and listed), the closed
predicate, and, when given, the drop file (§4.2 rules 1-2) and the ledger (rule 3). What a statement does NOT prove:
that the notice reached ENISA's platform, that the awareness instant is true, conformity with the Regulation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .canonical import sha3_hex
from .ledger import Ledger, read_regular
from .srp_notice import ALL_STAGES, GLOSSARIES, RULE9_STAGES, SOURCE_TOOLS, STREAMS, schema
from .vuln import EARLY_WARNING_HOURS, NOTIFICATION_HOURS, parse_utc

TYPE_URI = "https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REGULATION = "EU 2024/2847 Art. 14"
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024

_STATEMENT_KEYS = ("_type", "subject", "predicateType", "predicate")
_PRED_KEYS = frozenset({"regulation", "stream", "stage", "product", "glossaryVersion", "noticeRules", "complete",
                        "missingRequired", "awareAt", "deadlineAt", "filing", "source", "ledger", "attestedAt"})
_PRODUCT_KEYS = frozenset({"id", "version"})
_FILING_KEYS = frozenset({"declaredBy", "srpReference", "filedAt", "filedBy"})
_SOURCE_KEYS = frozenset({"tool", "toolVersion", "documentSha256", "absentAtSource"})
_LEDGER_KEYS = frozenset({"entryIndex", "entryHash"})
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64_STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_B64_URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


class AttestRefused(ValueError):
    """`cra attest` refuses to state what the drop file and the ledger do not show."""


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE protocol.md: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body"""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def z(d: datetime) -> str:
    """RFC 3339 UTC with Z, at most 6 fractional digits (none when the instant has no fraction)"""
    d = d.astimezone(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S") + (f".{d.microsecond:06d}" if d.microsecond else "") + "Z"


def _strict_json(raw: bytes, what: str) -> Any:
    def hook(pairs):
        d: Dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def const(name):
        raise ValueError(f"non-JSON constant {name}")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=hook, parse_constant=const)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise ValueError(f"{what}: {str(e)[:160]}") from None


def b64decode(s: Any) -> bytes:
    """standard or URL-safe alphabet (DSSE protocol.md), padding optional; mixed alphabets and anything else refused"""
    if type(s) is not str:
        raise ValueError("not a string")
    if _B64_STD.fullmatch(s):
        t = s
    elif _B64_URL.fullmatch(s):
        t = s.replace("-", "+").replace("_", "/")
    else:
        raise ValueError("not base64 (standard or URL-safe alphabet)")
    body = t.rstrip("=")
    if "=" in t and len(t) % 4:
        raise ValueError("bad base64 padding")
    if len(body) % 4 == 1:
        raise ValueError("bad base64 length")
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except ValueError as e:
        raise ValueError(f"not base64: {e}") from None


# ── producing ─────────────────────────────────────────────────────────────────
def _case_value(p: Dict[str, Any], k: str) -> Any:
    v = p["fields"].get(k)
    if v not in (None, "", []):
        return v
    return (p.get("previous_fields") or {}).get(k)


def build_statement(drop_path: str, ledger_path: str, product_id: Optional[str] = None, product_version: Optional[str] = None,
                    attested_at: Optional[datetime] = None, filing: Optional[Dict[str, str]] = None) -> bytes:
    """The Statement's exact bytes (canonical JSON, keys sorted). Refused unless the drop file is a cra-srp/2 notice
    (written by `cra notice`) or a cra-srp/3 notice that `cra check-notice` verifies against this ledger.
    product: from the ledger record when it carries it (0.8.0 on; a different --product/--version is refused), else
    from the arguments (required then). filing (cra-srp/2 only): {"srp_reference", "filed_at", "filed_by"} declared
    by the operator of cra-evidence; for cra-srp/3 the filing is the one of the drop file."""
    from . import __version__
    from .notice_check import check_notice, load_json_object
    raw = read_regular(drop_path)
    p = load_json_object(drop_path)
    sch = p.get("schema")
    if sch not in ("cra-srp/2", "cra-srp/3"):
        raise AttestRefused(f"schema {sch!r}: the subject of art14-filing v0.1 is a cra-srp/2 or cra-srp/3 drop file")
    if filing is not None and sch != "cra-srp/2":
        raise AttestRefused("--srp-reference/--filed-at/--filed-by: a cra-srp/3 notice carries the filing its source recorded")
    r = check_notice(drop_path, ledger_path)
    if not r["verified"]:
        raise AttestRefused(f"the drop file does not verify against the ledger: {r['reasons'][:3]}")
    sha3 = hashlib.sha3_256(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()
    hits = []
    for e in Ledger(ledger_path).entries():
        d = e.get("data")
        if (isinstance(d, dict) and d.get("kind") == "cra_srp_notice" and d.get("notice_id") == p["notice_id"]
                and isinstance(d.get("drop"), dict) and d["drop"].get("drop_sha3") == sha3):
            hits.append(e)
    if len(hits) != 1:
        raise AttestRefused(f"{len(hits)} ledger entries record this drop file (exactly one expected)")
    rec = hits[0]["data"]
    if "product_id" in rec or "product_version" in rec:
        for name, given, recorded in (("--product", product_id, rec.get("product_id")),
                                      ("--version", product_version, rec.get("product_version"))):
            if given is not None and given != recorded:
                raise AttestRefused(f"{name} {given!r} differs from the product the ledger records for this notice ({recorded!r})")
        product_id, product_version = rec.get("product_id"), rec.get("product_version")
    for name, v in (("--product", product_id), ("--version", product_version)):
        if not isinstance(v, str) or not v:
            raise AttestRefused(f"{name}: a non-empty string (the ledger record does not carry the product)")
    aw = _case_value(p, "awareness_datetime_utc")
    if not isinstance(aw, str) or not aw:
        raise AttestRefused("the notice carries no awareness instant (awareAt is required)")
    aware = parse_utc(aw)
    stage = p["stage"]
    deadline = None
    if stage == "early_warning":
        deadline = z(aware + timedelta(hours=EARLY_WARNING_HOURS))
    elif stage == "notification":
        deadline = z(aware + timedelta(hours=NOTIFICATION_HOURS))
    if sch == "cra-srp/3":
        src, fil = p["source"], p["filing"]
        source = {"tool": src["tool"], "toolVersion": src["tool_version"], "documentSha256": src["document_sha256"],
                  "absentAtSource": list(src["absent_at_source"])}
        filing_p = (None if fil is None else {"declaredBy": fil["declared_by"], "srpReference": fil["srp_reference"],
                                              "filedAt": z(parse_utc(fil["filed_at"])), "filedBy": fil["filed_by"]})
    else:   # a notice built here: the source is this tool, the document is the notice file itself
        source = {"tool": "cra-evidence", "toolVersion": __version__, "documentSha256": sha256, "absentAtSource": []}
        filing_p = None
        if filing is not None:
            for k in ("srp_reference", "filed_at", "filed_by"):
                if not isinstance(filing.get(k), str):
                    raise AttestRefused(f"filing: {k} must be a string")
            if not filing["filed_at"]:
                raise AttestRefused("--filed-at is required to declare a filing")
            try:
                fat = parse_utc(filing["filed_at"])
            except ValueError as e:
                raise AttestRefused(f"--filed-at: {e}") from None
            filing_p = {"declaredBy": "cra-evidence", "srpReference": filing["srp_reference"], "filedAt": z(fat),
                        "filedBy": filing["filed_by"]}
    now = attested_at or datetime.now(timezone.utc)
    pred = {"regulation": REGULATION, "stream": p["stream"], "stage": stage,
            "product": {"id": product_id, "version": product_version},
            "glossaryVersion": p["glossary_version"], "noticeRules": GLOSSARIES[p["glossary_version"]]["rules"],
            "complete": p["complete"], "missingRequired": list(p["missing_required"]),
            "awareAt": z(aware), "deadlineAt": deadline, "filing": filing_p, "source": source,
            "ledger": {"entryIndex": hits[0]["idx"], "entryHash": hits[0]["self_hash"]},
            "attestedAt": z(now.replace(microsecond=0))}
    st = {"_type": STATEMENT_TYPE, "predicateType": TYPE_URI, "predicate": pred,
          "subject": [{"name": f"srp-notice:{p['stream']}:{stage}", "digest": {"sha256": sha256, "sha3_256": sha3}}]}
    payload = json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    errs = check_statement(payload)[1]      # the producer's statement must pass the verifier's own closed reading
    if errs:
        raise AttestRefused(f"statement refused by its own verifier: {errs}")
    return payload


def sign_envelope(payload: bytes, key: Tuple[Any, str], signer_id: str, payload_type: str = PAYLOAD_TYPE) -> Dict[str, Any]:
    """DSSE envelope; standard base64 with padding; keyid = the signer id of the trust store"""
    if not isinstance(signer_id, str) or not signer_id:
        raise ValueError("signer_id must be a non-empty string")
    sk, _ = key
    sig = sk.sign(pae(payload_type, payload))
    return {"payload": base64.b64encode(payload).decode("ascii"), "payloadType": payload_type,
            "signatures": [{"keyid": signer_id, "sig": base64.b64encode(sig).decode("ascii")}]}


# ── verifying ─────────────────────────────────────────────────────────────────
def _r(reasons: List[Dict[str, str]], code: str, detail: str) -> None:
    reasons.append({"code": code, "detail": detail[:300]})


def _is_ts(v: Any) -> bool:
    from .signing import is_instant
    return type(v) is str and _TS.fullmatch(v) is not None and is_instant(v)


def check_statement(payload: bytes) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, str]], List[str]]:
    """(statement or None, refusal reasons, statement_unrecognized) for the exact verified payload bytes (§2-§4.1)"""
    reasons: List[Dict[str, str]] = []
    unrec: List[str] = []
    try:
        st = _strict_json(payload, "payload")
    except ValueError as e:
        _r(reasons, "duplicate_key" if "duplicate key" in str(e) else "payload_json", str(e))
        return None, reasons, unrec
    if not isinstance(st, dict):
        _r(reasons, "statement_malformed", "the payload is not a JSON object")
        return None, reasons, unrec
    unrec += sorted(k for k in st if k not in _STATEMENT_KEYS)
    missing = [k for k in _STATEMENT_KEYS if k not in st]
    if missing:
        _r(reasons, "statement_malformed", f"Statement fields missing: {missing}")
        return None, reasons, unrec
    if st["_type"] != STATEMENT_TYPE:
        _r(reasons, "statement_type", f"_type {str(st['_type'])[:80]!r} is not {STATEMENT_TYPE}")
    if st["predicateType"] != TYPE_URI:
        _r(reasons, "predicate_type", f"predicateType {str(st['predicateType'])[:120]!r} is not {TYPE_URI}")
    sub = st["subject"]
    if type(sub) is not list or len(sub) != 1 or not isinstance(sub[0], dict):
        _r(reasons, "subject", "subject must be a list of exactly one object")
    else:
        s0 = sub[0]
        unrec += sorted(f"subject[0].{k}" for k in s0 if k not in ("name", "digest"))
        dg = s0.get("digest")
        if type(s0.get("name")) is not str:
            _r(reasons, "subject", "subject[0].name must be a string")
        if not isinstance(dg, dict):
            _r(reasons, "subject", "subject[0].digest must be an object")
        else:
            unrec += sorted(f"subject[0].digest.{k}" for k in dg if k not in ("sha256", "sha3_256"))
            for alg in ("sha256", "sha3_256"):
                if type(dg.get(alg)) is not str or not _HEX64.fullmatch(dg[alg]):
                    _r(reasons, "subject", f"subject[0].digest.{alg}: 64 lower-case hex required")
    if reasons:
        return None, reasons, unrec
    pr = st["predicate"]
    if not isinstance(pr, dict):
        _r(reasons, "predicate_type_error", "predicate must be an object")
        return None, reasons, unrec
    _check_predicate(pr, reasons)
    if not reasons and sub[0]["name"] != f"srp-notice:{pr['stream']}:{pr['stage']}":
        _r(reasons, "subject", f"subject[0].name {sub[0]['name'][:80]!r} is not srp-notice:{pr['stream']}:{pr['stage']}")
    if not reasons and pr["source"]["tool"] == "cra-evidence":
        if pr["source"]["documentSha256"] != sub[0]["digest"]["sha256"]:
            _r(reasons, "predicate_rule", "source.tool cra-evidence: documentSha256 must be the subject's sha256 (§4)")
        if pr["source"]["absentAtSource"]:
            _r(reasons, "predicate_rule", "source.tool cra-evidence: absentAtSource must be [] (§4)")
    return (None if reasons else st), reasons, unrec


def _closed(obj: Dict[str, Any], keys: frozenset, where: str, reasons: List[Dict[str, str]]) -> bool:
    unknown, absent = sorted(set(obj) - keys), sorted(keys - set(obj))
    if unknown:
        _r(reasons, "predicate_unknown_key", f"{where}: unknown keys {unknown}")
    if absent:
        _r(reasons, "predicate_missing_key", f"{where}: missing keys {absent}")
    return not unknown and not absent


def _check_predicate(pr: Dict[str, Any], reasons: List[Dict[str, str]]) -> None:
    n0 = len(reasons)
    if not _closed(pr, _PRED_KEYS, "predicate", reasons):
        return
    def typ(ok: bool, where: str, want: str):
        if not ok:
            _r(reasons, "predicate_type_error", f"{where}: {want} expected")
        return ok
    def enum(v: Any, allowed, where: str):
        if type(v) is not str or v not in allowed:
            _r(reasons, "predicate_enum", f"{where}: {str(v)[:80]!r} is not one of {list(allowed)}")
    def ts(v: Any, where: str, nullable: bool = False):
        if v is None and nullable:
            return
        if type(v) is not str:
            _r(reasons, "predicate_type_error", f"{where}: a string expected")
        elif not _is_ts(v):
            _r(reasons, "predicate_timestamp", f"{where}: {v[:40]!r} is not RFC 3339 UTC with Z and at most 6 fractional digits")
    enum(pr["regulation"], (REGULATION,), "regulation")
    enum(pr["stream"], STREAMS, "stream")
    enum(pr["stage"], ALL_STAGES, "stage")
    if typ(isinstance(pr["product"], dict), "product", "an object") and _closed(pr["product"], _PRODUCT_KEYS, "product", reasons):
        for k in _PRODUCT_KEYS:
            typ(type(pr["product"][k]) is str, f"product.{k}", "a string")
    enum(pr["glossaryVersion"], tuple(GLOSSARIES), "glossaryVersion")
    enum(pr["noticeRules"], ("srp-notice/1", "srp-notice/2"), "noticeRules")
    typ(pr["complete"] is None or type(pr["complete"]) is bool, "complete", "true, false or null")
    typ(type(pr["missingRequired"]) is list and all(type(x) is str for x in pr["missingRequired"]), "missingRequired", "a list of strings")
    ts(pr["awareAt"], "awareAt")
    ts(pr["deadlineAt"], "deadlineAt", nullable=True)
    ts(pr["attestedAt"], "attestedAt")
    fil = pr["filing"]
    if fil is not None and typ(isinstance(fil, dict), "filing", "an object or null") and _closed(fil, _FILING_KEYS, "filing", reasons):
        enum(fil["declaredBy"], SOURCE_TOOLS, "filing.declaredBy")
        typ(type(fil["srpReference"]) is str, "filing.srpReference", "a string")
        typ(type(fil["filedBy"]) is str, "filing.filedBy", "a string")
        ts(fil["filedAt"], "filing.filedAt")
    src = pr["source"]
    if typ(isinstance(src, dict), "source", "an object") and _closed(src, _SOURCE_KEYS, "source", reasons):
        enum(src["tool"], SOURCE_TOOLS, "source.tool")
        typ(type(src["toolVersion"]) is str, "source.toolVersion", "a string")
        if typ(type(src["documentSha256"]) is str, "source.documentSha256", "a string") and not _HEX64.fullmatch(src["documentSha256"]):
            _r(reasons, "predicate_type_error", "source.documentSha256: 64 lower-case hex expected")
        typ(type(src["absentAtSource"]) is list and all(type(x) is str for x in src["absentAtSource"]), "source.absentAtSource", "a list of strings")
    led = pr["ledger"]
    if typ(isinstance(led, dict), "ledger", "an object") and _closed(led, _LEDGER_KEYS, "ledger", reasons):
        i = led["entryIndex"]
        typ(type(i) is int and 0 <= i <= 2 ** 53 - 1, "ledger.entryIndex", "a non-negative integer")
        if typ(type(led["entryHash"]) is str, "ledger.entryHash", "a string") and not _HEX64.fullmatch(led["entryHash"]):
            _r(reasons, "predicate_type_error", "ledger.entryHash: 64 lower-case hex expected")
    if len(reasons) > n0:
        return
    # §4.1 and the predicate's own consistency
    if pr["complete"] is None and pr["stage"] not in RULE9_STAGES:
        _r(reasons, "predicate_rule", f"complete null at stage {pr['stage']} (null only at intermediate / users_informed, §4.1)")
    if pr["stage"] in RULE9_STAGES and pr["complete"] is not None:
        _r(reasons, "predicate_rule", f"complete must be null at stage {pr['stage']} (srp-notice/2 rule 9: never true)")
    if pr["complete"] is not False and pr["missingRequired"]:
        _r(reasons, "predicate_rule", "missingRequired must be [] when complete is true or null")
    if pr["complete"] is False and not pr["missingRequired"]:
        _r(reasons, "predicate_rule", "complete false with missingRequired []")
    if fil is not None and fil["declaredBy"] != src["tool"]:
        _r(reasons, "predicate_rule", "filing.declaredBy must equal source.tool (§4.1)")
    if pr["noticeRules"] != GLOSSARIES[pr["glossaryVersion"]]["rules"]:
        _r(reasons, "predicate_rule", f"noticeRules {pr['noticeRules']} is not the rules of {pr['glossaryVersion']}")
    if pr["stage"] in RULE9_STAGES and GLOSSARIES[pr["glossaryVersion"]]["rules"] != "srp-notice/2":
        _r(reasons, "predicate_rule", f"stage {pr['stage']} exists under srp-notice/2 only")
    sch = schema(pr["stream"], pr["glossaryVersion"])
    bad = [k for k in pr["missingRequired"] if k not in sch]
    if bad:
        _r(reasons, "predicate_rule", f"missingRequired names fields not of stream {pr['stream']}: {bad[:5]}")
    aw = parse_utc(pr["awareAt"])
    want = {"early_warning": z(aw + timedelta(hours=EARLY_WARNING_HOURS)),
            "notification": z(aw + timedelta(hours=NOTIFICATION_HOURS))}.get(pr["stage"])
    if (pr["deadlineAt"] is None) != (want is None) or (want is not None and parse_utc(pr["deadlineAt"]) != parse_utc(want)):
        _r(reasons, "deadline", f"deadlineAt {pr['deadlineAt']!r}: computed from awareAt it is {want!r} at stage {pr['stage']}")
    if fil is not None and parse_utc(pr["attestedAt"]) < parse_utc(fil["filedAt"]):
        _r(reasons, "rule4", "attestedAt is earlier than filing.filedAt (§4.2 rule 4)")


def _same(a: Any, b: Any) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def verify_envelope(env_path: str, trust_store: Dict[str, str], drop_path: Optional[str] = None,
                    ledger_path: Optional[str] = None) -> Dict[str, Any]:
    from .signing import weak_ed25519_key
    reasons: List[Dict[str, str]] = []
    out: Dict[str, Any] = {"envelope": os.path.basename(env_path), "predicate_type": TYPE_URI, "verified": False,
                           "trusted": False, "assessed": True, "signatures": [], "signatures_not_verified": [], "envelope_unrecognized": [],
                           "statement_unrecognized": [], "statement": "not_evaluated",
                           "drop": "not_evaluated", "ledger": "not_evaluated",
                           "product": "not_evaluated (compared with the ledger record only: give --ledger)",
                           "reasons": reasons,
                           "scope": "a declaration recorded and signed by the manufacturer: not a proof that the notice reached "
                                    "ENISA's platform, nor that the awareness instant is true, nor conformity"}
    try:
        env = _strict_json(read_regular(env_path, MAX_ENVELOPE_BYTES), "envelope")
    except (OSError, ValueError) as e:
        _r(reasons, "envelope_malformed", f"envelope unreadable: {e}")
        return out
    if not isinstance(env, dict):
        _r(reasons, "envelope_malformed", "the envelope is not a JSON object")
        return out
    out["envelope_unrecognized"] = sorted(k for k in env if k not in ("payload", "payloadType", "signatures"))
    if type(env.get("payload")) is not str or type(env.get("payloadType")) is not str or type(env.get("signatures")) is not list:
        _r(reasons, "envelope_malformed", "payload and payloadType must be strings and signatures a list (DSSE envelope.md)")
        return out
    try:
        payload = b64decode(env["payload"])
    except ValueError as e:
        _r(reasons, "base64", f"payload: {e}")
        return out
    if env["payloadType"] != PAYLOAD_TYPE:
        _r(reasons, "payload_type", f"payloadType {env['payloadType'][:80]!r} is not {PAYLOAD_TYPE}")
        return out
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        Ed25519PublicKey = None
    msg = pae(PAYLOAD_TYPE, payload)
    trusted_by = []
    # §5: every signature that does not verify and every keyid absent from the trust store is LISTED; they do not refuse
    # a statement that another signature makes trusted (keyid selects a candidate key only, DSSE protocol.md)
    listed: List[Dict[str, str]] = out["signatures_not_verified"]
    for i, s in enumerate(env["signatures"]):
        res: Dict[str, Any] = {"index": i}
        out["signatures"].append(res)
        if not isinstance(s, dict) or type(s.get("sig")) is not str or ("keyid" in s and type(s["keyid"]) is not str):
            res["result"] = "malformed"
            _r(reasons, "envelope_malformed", f"signatures[{i}]: sig must be a string, keyid a string when set")
            continue
        out["envelope_unrecognized"] += sorted(f"signatures[{i}].{k}" for k in s if k not in ("sig", "keyid"))
        kid = s.get("keyid", "")
        res["keyid"] = kid
        try:
            sig = b64decode(s["sig"])
        except ValueError as e:
            res["result"] = "bad_encoding"
            _r(reasons, "base64", f"signatures[{i}].sig: {e}")
            continue
        pub = trust_store.get(kid) if kid else None
        if pub is None:
            res["result"] = "unknown_keyid"
            _r(listed, "unknown_keyid", f"signatures[{i}]: keyid {kid[:80]!r} is not in the trust store")
            continue
        if not isinstance(pub, str) or not _HEX64.fullmatch(pub):
            res["result"] = "trusted_key_malformed"
            _r(reasons, "trusted_key_malformed", f"trust store key of {kid[:80]!r}: 64 lower-case hex required")
            continue
        if weak_ed25519_key(pub):
            res["result"] = "weak_key"
            _r(reasons, "weak_key", f"trust store key of {kid[:80]!r}: small order or non-canonical Ed25519 key, refused")
            continue
        if len(sig) != 64:
            res["result"] = "failed"
            _r(listed, "signature_failed", f"signatures[{i}]: an Ed25519 signature is 64 bytes, got {len(sig)}")
            continue
        if Ed25519PublicKey is None:
            res["result"] = "not_checkable"
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(sig, msg)
        except Exception:  # noqa: BLE001 — InvalidSignature or a key the library refuses: the signature does not verify
            res["result"] = "failed"
            _r(listed, "signature_failed", f"signatures[{i}] (keyid {kid[:80]!r}) does not verify")
            continue
        res["result"] = "verified"
        trusted_by.append(kid)
    out["trusted"] = bool(trusted_by)
    out["trusted_by"] = trusted_by
    if not trusted_by:
        if Ed25519PublicKey is None and any(r.get("result") == "not_checkable" for r in out["signatures"]):
            out["assessed"] = False
            _r(reasons, "not_checkable", "cryptography is not installed: the signatures cannot be checked here "
                                         "(pip install 'cra-evidence[sign]')")
        else:
            _r(reasons, "not_trusted", "no signature verifies with a trusted key")
            reasons.extend(listed)
        return out
    # §3: the exact verified bytes, never the envelope re-parsed
    st, errs, unrec = check_statement(payload)
    out["statement_unrecognized"] = unrec
    if errs:
        reasons.extend(errs)
        out["statement"] = "refused"
        return out
    out["statement"] = "accepted"
    pr = st["predicate"]
    dg = st["subject"][0]["digest"]
    if drop_path:
        _check_drop(drop_path, pr, dg, out, reasons)
    if ledger_path:
        _check_ledger(ledger_path, pr, dg, out, reasons)
    out["verified"] = not reasons
    return out


def _check_drop(drop_path: str, pr: Dict[str, Any], dg: Dict[str, str], out: Dict[str, Any], reasons: List[Dict[str, str]]) -> None:
    from .notice_check import check_notice, load_json_object
    n0 = len(reasons)
    try:
        raw = read_regular(drop_path)
        p = load_json_object(drop_path)
    except (OSError, ValueError) as e:
        _r(reasons, "drop_unreadable", f"drop file unreadable: {e}")
        out["drop"] = "FAIL"
        return
    if hashlib.sha256(raw).hexdigest() != dg["sha256"] or hashlib.sha3_256(raw).hexdigest() != dg["sha3_256"]:
        _r(reasons, "subject_digest", "the drop file's bytes do not match the subject digest (sha256 and sha3_256)")
        out["drop"] = "FAIL"
        return
    sch = p.get("schema")
    if sch not in ("cra-srp/2", "cra-srp/3"):
        _r(reasons, "rule1", f"the subject is not a cra-srp/2 or cra-srp/3 drop file (schema {sch!r})")
        out["drop"] = "FAIL"
        return
    gv = p.get("glossary_version")
    pairs = (("stream", p.get("stream"), pr["stream"]), ("stage", p.get("stage"), pr["stage"]),
             ("glossary_version", gv, pr["glossaryVersion"]))
    for k, have, want in pairs:
        if have != want:
            _r(reasons, "rule1", f"drop file {k} {have!r} differs from the predicate's {want!r} (§4.2 rule 1)")
    r = check_notice(drop_path)           # rule 2: rebuilt under the recorded glossary
    if not r["verified"]:
        _r(reasons, "rule2", f"the drop file does not re-check under its glossary: {r['reasons'][:2]}")
    else:
        if not _same(p["complete"], pr["complete"]) or not _same(p["missing_required"], pr["missingRequired"]):
            _r(reasons, "rule2", "complete / missingRequired differ from the notice rebuilt under its glossary (§4.2 rule 2)")
        if pr["stage"] in ("early_warning", "notification"):
            d = p["deadline_utc"]
            if d is None or parse_utc(d) != parse_utc(pr["deadlineAt"]):
                _r(reasons, "rule2", f"deadlineAt differs from the rebuilt notice's deadline {d!r} (§4.2 rule 2)")
        aw = _case_value(p, "awareness_datetime_utc")
        if not isinstance(aw, str) or parse_utc(aw) != parse_utc(pr["awareAt"]):
            _r(reasons, "drop_mismatch", f"awareAt differs from the notice's awareness instant {aw!r}")
        if sch == "cra-srp/2":   # a notice built here: the filing, if any, is declared in the statement only
            if pr["source"]["tool"] != "cra-evidence":
                _r(reasons, "drop_mismatch", f"a cra-srp/2 drop file is a notice of cra-evidence, not of {pr['source']['tool']!r}")
            out["drop"] = "PASS" if len(reasons) == n0 else "FAIL"
            return
        src, fil = p["source"], p["filing"]
        if (src["tool"], src["tool_version"], src["document_sha256"], src["absent_at_source"]) != (
                pr["source"]["tool"], pr["source"]["toolVersion"], pr["source"]["documentSha256"], pr["source"]["absentAtSource"]):
            _r(reasons, "drop_mismatch", "source differs from the drop file's source block")
        pf = pr["filing"]
        if (fil is None) != (pf is None) or (fil is not None and (
                fil["declared_by"] != pf["declaredBy"] or fil["srp_reference"] != pf["srpReference"]
                or fil["filed_by"] != pf["filedBy"] or parse_utc(fil["filed_at"]) != parse_utc(pf["filedAt"]))):
            _r(reasons, "drop_mismatch", "filing differs from the drop file's filing block")
    out["drop"] = "PASS" if len(reasons) == n0 else "FAIL"


def _check_ledger(ledger_path: str, pr: Dict[str, Any], dg: Dict[str, str], out: Dict[str, Any], reasons: List[Dict[str, str]]) -> None:
    n0 = len(reasons)
    try:
        entries = list(Ledger(ledger_path).entries())
    except (OSError, ValueError, TypeError, RecursionError) as e:
        _r(reasons, "rule3", f"ledger unreadable: {type(e).__name__}: {str(e)[:160]}")
        out["ledger"] = "FAIL"
        return
    ch = Ledger(ledger_path).verify(entries)
    i = pr["ledger"]["entryIndex"]
    out["product"] = "not_evaluated (the ledger entry named by the statement does not pass rule 3)"
    if not ch["chain_ok"]:
        _r(reasons, "rule3", f"the ledger chain does not verify: {ch['failures'][:2]}")
    elif i >= len(entries):
        _r(reasons, "rule3", f"entryIndex {i}: the ledger has {len(entries)} entries")
    else:
        e = entries[i]
        d = e.get("data") if isinstance(e.get("data"), dict) else {}
        if e.get("self_hash") != pr["ledger"]["entryHash"]:
            _r(reasons, "rule3", f"entry {i}: self_hash differs from entryHash")
        elif d.get("kind") != "cra_srp_notice":
            _r(reasons, "rule3", f"entry {i} is not a cra_srp_notice record ({str(d.get('kind'))[:40]!r})")
        elif sha3_hex({k: v for k, v in d.items() if k != "record_sha3"}) != d.get("record_sha3"):
            _r(reasons, "rule3", f"entry {i}: record_sha3 does not recompute")
        else:
            drop = d.get("drop") if isinstance(d.get("drop"), dict) else {}
            if drop.get("drop_sha3") != dg["sha3_256"]:
                _r(reasons, "rule3", f"entry {i}: drop.drop_sha3 differs from the subject's sha3_256")
            for k, want in (("stream", pr["stream"]), ("stage", pr["stage"]), ("glossary_version", pr["glossaryVersion"]),
                            ("complete", pr["complete"]), ("missing_required", pr["missingRequired"])):
                if not _same(d.get(k), want):
                    _r(reasons, "rule3", f"entry {i}: {k} {d.get(k)!r} differs from the predicate's {want!r}")
            if "product_id" in d or "product_version" in d:
                if (d.get("product_id"), d.get("product_version")) == (pr["product"]["id"], pr["product"]["version"]):
                    out["product"] = "PASS"
                else:
                    out["product"] = "FAIL"
                    _r(reasons, "product", f"entry {i} records product {d.get('product_id')!r} {d.get('product_version')!r}, "
                                           f"the predicate says {pr['product']['id']!r} {pr['product']['version']!r}")
            else:
                out["product"] = ("not_evaluated (the ledger record does not carry the product: written by cra-evidence "
                                  "0.7.1 or earlier)")
    out["ledger"] = "PASS" if len(reasons) == n0 else "FAIL"
