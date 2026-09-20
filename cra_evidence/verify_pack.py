# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline verifier of a CRA evidence pack. Layers, each PASS/FAIL/SKIP, then ONE authenticity verdict:
  trusted-signed > signed > anchored (integrity, not identity) > FAIL.
A pack alone proves internal consistency; the ledger next to it proves the pack is anchored into a valid chain; a
signature proves which key produced it; a trust store proves that key is one you chose to trust."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex
from .ledger import Ledger
from .locker import HONEST_SCOPE_MARK, PACK_KIND, RECORD_KINDS, source_file
from .signing import verify_pack_signature, verify_tip


HEX64 = re.compile(r"[0-9a-f]{64}")


def _layer(name: str, status: str, detail: str = "") -> Dict[str, str]:
    return {"layer": name, "status": status, "detail": detail}


def verify_pack(path: str, ledger_path: Optional[str] = None, trust_store: Optional[Dict[str, str]] = None,
                log_pubkey_hex: Optional[str] = None, require_sources: bool = False) -> Dict[str, Any]:
    """Offline verification, layer by layer; one authenticity verdict. Any exception inside is a FAIL layer, never a
    crash (fail-closed). log_pubkey_hex: the trusted key of the ledger's signed tip — with it, a truncated tail
    (records dropped AFTER the anchor) is detected; without it the tip is NOT checked and the verdict says so.
    require_sources: every SBOM source document the ledger records by SHA-256 must be present in <ledger>.sources/
    and hash to the recorded value (a missing one is then a FAIL, otherwise a SKIP that says how many are hash-only)."""
    try:
        return _verify(path, ledger_path, trust_store, log_pubkey_hex, require_sources)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "authenticity": "FAIL", "anchored": False,
                "layers": [_layer("verifier-exception", "FAIL", f"{type(e).__name__}: {str(e)[:160]}")], "pack_sha3": None}


def _source_documents(ledger_path: str, entries: List[Dict[str, Any]], require: bool) -> Dict[str, str]:
    """Layer over the SBOM source documents: for every cra_sbom record with source.sha256, the file
    <ledger>.sources/<sha256>.json must hash to that value when present. A mismatch is a FAIL; absence is a SKIP
    (hash-only evidence) unless required."""
    wanted: Dict[str, int] = {}
    malformed = 0
    for e in entries:
        d = e.get("data") if isinstance(e.get("data"), dict) else {}
        src = d.get("source") if d.get("kind") == "cra_sbom" and isinstance(d.get("source"), dict) else None
        if src is None or src.get("sha256") in (None, ""):
            continue                                          # absent / null / empty: no hash recorded
        h = src["sha256"]
        if not isinstance(h, str) or not HEX64.fullmatch(h):
            malformed += 1                                    # present but not a SHA-256: a FAIL, never a path
            continue
        wanted[h] = wanted.get(h, 0) + 1
    if not wanted and not malformed:
        return _layer("source-documents", "SKIP", "no SBOM source document recorded by hash")
    present, bad, absent = 0, [f"{malformed} record(s) with a malformed source hash"] if malformed else [], 0
    for h in sorted(wanted):
        fp = source_file(ledger_path, h)
        if not os.path.isfile(fp):
            absent += 1
            continue
        with open(fp, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got == h:
            present += 1
        else:
            bad.append(f"{h[:16]}… stored bytes hash to {got[:16]}…")
    if bad:
        return _layer("source-documents", "FAIL", f"{len(bad)} source document(s) do not match their recorded SHA-256: " + "; ".join(bad[:3]))
    if absent:
        return _layer("source-documents", "FAIL" if require else "SKIP",
                      f"{present} of {len(wanted)} source document(s) present and verified; {absent} recorded by hash only" + (" (required)" if require else ""))
    return _layer("source-documents", "PASS", f"{present} source document(s) present, bytes hash to the recorded SHA-256")


def _verify(path, ledger_path, trust_store, log_pubkey_hex, require_sources=False) -> Dict[str, Any]:
    layers: List[Dict[str, str]] = []
    try:
        pack = json.loads(Path(path).read_text(encoding="utf-8"))
        layers.append(_layer("pack-json", "PASS"))
    except (OSError, ValueError) as e:
        return {"ok": False, "authenticity": "FAIL", "anchored": False, "layers": [_layer("pack-json", "FAIL", str(e))], "pack_sha3": None}
    if not isinstance(pack, dict):
        return {"ok": False, "authenticity": "FAIL", "anchored": False, "layers": [_layer("pack-json", "FAIL", "pack is not a JSON object")], "pack_sha3": None}
    layers.append(_layer("pack-kind", "PASS" if pack.get("kind") == PACK_KIND else "FAIL", str(pack.get("kind"))))
    scope = str(pack.get("honest_scope", ""))
    layers.append(_layer("honest-scope", "PASS" if HONEST_SCOPE_MARK in scope else "FAIL",
                         "declared limits present" if HONEST_SCOPE_MARK in scope else f"missing the declared limit {HONEST_SCOPE_MARK!r}"))
    try:
        computed = sha3_hex({k: v for k, v in pack.items() if k != "pack_sha3"})
    except TypeError as e:
        computed = None
        layers.append(_layer("pack-sha3", "FAIL", f"pack not canonicalisable: {e}"))
    if computed is not None:
        layers.append(_layer("pack-sha3", "PASS" if pack.get("pack_sha3") == computed else "FAIL",
                             f"declared {str(pack.get('pack_sha3'))[:16]}… computed {computed[:16]}…"))
    # the pack's own verification snapshot must be clean (a producer must never ship a pack over a broken chain)
    pv = pack.get("verification") if isinstance(pack.get("verification"), dict) else {}
    layers.append(_layer("pack-self-verification", "PASS" if (pv.get("chain_ok") is True and pv.get("record_digests_bound") is True) else "FAIL",
                         f"chain_ok={pv.get('chain_ok')} record_digests_bound={pv.get('record_digests_bound')}"))
    # ledger: explicit path wins; otherwise only the NAME next to the pack (never a path from the pack)
    lp = ledger_path or (os.path.join(os.path.dirname(os.path.abspath(path)), os.path.basename(str(pack.get("ledger_file"))))
                         if pack.get("ledger_file") else None)
    anchored = False
    if (ledger_path or log_pubkey_hex or require_sources) and not (lp and os.path.isfile(lp)):
        # the caller asked for a chain/tip/source check by name: a missing ledger is a FAIL, never a silent skip
        layers.append(_layer("ledger-chain", "FAIL", "ledger explicitly required (ledger_path / log key / require_sources given) but not found"))
    elif lp and os.path.isfile(lp):
        led = Ledger(lp)
        lv = led.verify()
        if not lv["chain_ok"]:
            layers.append(_layer("ledger-chain", "FAIL", "; ".join(lv["failures"][:3])))
        else:
            bound, anchor, anchor_idx, entries = True, False, None, []
            for e in led.entries():
                entries.append(e)
                d = e.get("data") if isinstance(e.get("data"), dict) else {}
                if d.get("kind") in RECORD_KINDS:
                    if sha3_hex({k: v for k, v in d.items() if k != "record_sha3"}) != d.get("record_sha3"):
                        bound = False
                    if d.get("kind") == "cra_pack_anchor" and d.get("anchored_pack_sha3") == pack.get("pack_sha3"):
                        anchor, anchor_idx = True, e.get("idx")
            if not bound:
                layers.append(_layer("ledger-chain", "FAIL", "a record's record_sha3 does not match its content"))
            elif not anchor:
                layers.append(_layer("ledger-chain", "FAIL", "chain valid but THIS pack is not anchored (no cra_pack_anchor entry with its pack_sha3)"))
            else:
                anchored = True
                layers.append(_layer("ledger-chain", "PASS", f"{lv['entries']} entries, records bound, pack anchored at idx {anchor_idx}"))
            # the ledger state the pack DECLARES must be the state the ledger HAS at that point (not decorative)
            n = pack.get("ledger_entries")
            ok_state = (type(n) is int and 0 < n <= len(entries) and entries[n - 1].get("self_hash") == pack.get("ledger_last_self_hash")
                        and (anchor_idx is None or anchor_idx >= n))
            layers.append(_layer("pack-ledger-state", "PASS" if ok_state else "FAIL",
                                 f"declared entries={n} last={str(pack.get('ledger_last_self_hash'))[:12]}…; anchor idx={anchor_idx}"))
            layers.append(_source_documents(lp, entries, require_sources))
            # signed tip: the only thing that sees a truncated TAIL (records after the anchor silently dropped)
            tip_path = lp + ".tip.json"
            if not entries:
                layers.append(_layer("signed-tip", "FAIL", "ledger has no entries"))
            elif log_pubkey_hex:
                if not os.path.exists(tip_path):
                    layers.append(_layer("signed-tip", "FAIL", "trusted log key given but no tip file next to the ledger"))
                else:
                    try:
                        tip = json.loads(Path(tip_path).read_text(encoding="utf-8"))
                        tv = verify_tip(tip, log_pubkey_hex, len(entries), entries[0]["self_hash"], entries[-1]["self_hash"])
                        layers.append(_layer("signed-tip", "PASS" if tv.get("ok") else "FAIL", str(tv.get("error") or "tip verified: no tail truncation")))
                    except Exception as e:  # noqa: BLE001
                        layers.append(_layer("signed-tip", "FAIL", f"tip unreadable: {type(e).__name__}: {str(e)[:80]}"))
            elif os.path.exists(tip_path):
                layers.append(_layer("signed-tip", "SKIP", "tip present but NOT checked: pass the trusted log key (tail truncation undetected)"))
            else:
                layers.append(_layer("signed-tip", "SKIP", "no tip: tail truncation undetectable offline (use a tip key / cryptovalid monitor)"))
    else:
        layers.append(_layer("ledger-chain", "SKIP", "ledger not next to the pack (honest: integrity of the chain not checked)"))
    sig = verify_pack_signature(path, trust_store)
    layers.append(_layer("producer-signature", sig["status"], sig.get("detail", "")))
    if sig["status"] == "FAIL":
        auth = "FAIL"
    elif trust_store is not None and sig["status"] == "SKIP":
        auth = "FAIL"
        layers.append(_layer("trusted-signer", "FAIL", "a trust store was required but the pack is not signed"))
    elif sig["status"] == "PASS" and trust_store is not None and not sig.get("trusted"):
        auth = "FAIL"
        layers.append(_layer("trusted-signer", "FAIL", "valid signature but signer not in the trust store"))
    elif sig["status"] == "PASS" and sig.get("trusted"):
        auth = "trusted-signed"
    elif sig["status"] == "PASS":
        auth = "signed"
    elif anchored:
        auth = "anchored"
    else:
        auth = "FAIL"
    hard_fail = any(l["status"] == "FAIL" for l in layers)
    ok = auth != "FAIL" and not hard_fail
    return {"ok": ok, "authenticity": auth if ok else "FAIL", "anchored": anchored, "layers": layers, "pack_sha3": pack.get("pack_sha3")}
