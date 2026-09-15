# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline verifier of a CRA evidence pack. Layers, each PASS/FAIL/SKIP, then ONE authenticity verdict:
  trusted-signed > signed > anchored (integrity, not identity) > FAIL.
A pack alone proves internal consistency; the ledger next to it proves the pack is anchored into a valid chain; a
signature proves which key produced it; a trust store proves that key is one you chose to trust."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex
from .ledger import Ledger
from .locker import HONEST_SCOPE, PACK_KIND, RECORD_KINDS
from .signing import verify_pack_signature


def _layer(name: str, status: str, detail: str = "") -> Dict[str, str]:
    return {"layer": name, "status": status, "detail": detail}


def verify_pack(path: str, ledger_path: Optional[str] = None, trust_store: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    layers: List[Dict[str, str]] = []
    try:
        pack = json.loads(Path(path).read_text(encoding="utf-8"))
        layers.append(_layer("pack-json", "PASS"))
    except (OSError, ValueError) as e:
        return {"ok": False, "authenticity": "FAIL", "layers": [_layer("pack-json", "FAIL", str(e))]}
    layers.append(_layer("pack-kind", "PASS" if pack.get("kind") == PACK_KIND else "FAIL", str(pack.get("kind"))))
    scope = str(pack.get("honest_scope", ""))
    layers.append(_layer("honest-scope", "PASS" if ("NOT a conformity assessment" in scope and "NOT" in scope) else "FAIL",
                         "declared limits present" if "NOT" in scope else "no declared limit"))
    computed = sha3_hex({k: v for k, v in pack.items() if k != "pack_sha3"})
    layers.append(_layer("pack-sha3", "PASS" if pack.get("pack_sha3") == computed else "FAIL", f"declared {str(pack.get('pack_sha3'))[:16]}… computed {computed[:16]}…"))
    # ledger next to the pack (or explicit)
    # only the NAME of the ledger file is honoured: a pack must never steer the verifier to a ledger elsewhere
    lp = ledger_path or os.path.join(os.path.dirname(os.path.abspath(path)), os.path.basename(str(pack.get("ledger_file", ""))))
    anchored = False
    if pack.get("ledger_file") and os.path.exists(lp):
        led = Ledger(lp)
        lv = led.verify()
        if not lv["chain_ok"]:
            layers.append(_layer("ledger-chain", "FAIL", "; ".join(lv["failures"][:3])))
        else:
            # content-binding of every CRA record + the anchor of THIS pack
            bound = True
            anchor = False
            for e in led.entries():
                d = e.get("data") or {}
                if d.get("kind") in RECORD_KINDS:
                    if sha3_hex({k: v for k, v in d.items() if k != "record_sha3"}) != d.get("record_sha3"):
                        bound = False
                    if d.get("kind") == "cra_pack_anchor" and d.get("anchored_pack_sha3") == pack.get("pack_sha3"):
                        anchor = True
            if not bound:
                layers.append(_layer("ledger-chain", "FAIL", "a record's record_sha3 does not match its content"))
            elif not anchor:
                layers.append(_layer("ledger-chain", "FAIL", "chain valid but THIS pack is not anchored (no cra_pack_anchor entry with its pack_sha3)"))
            else:
                anchored = True
                layers.append(_layer("ledger-chain", "PASS", f"{lv['entries']} entries, records bound, pack anchored"))
    else:
        layers.append(_layer("ledger-chain", "SKIP", "ledger not next to the pack (honest: integrity of the chain not checked)"))
    sig = verify_pack_signature(path, trust_store)
    layers.append(_layer("producer-signature", sig["status"], sig.get("detail", "")))
    if sig["status"] == "FAIL":
        auth = "FAIL"
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
    hard_fail = any(l["status"] == "FAIL" for l in layers if l["layer"] in ("pack-json", "pack-kind", "honest-scope", "pack-sha3", "ledger-chain"))
    ok = auth != "FAIL" and not hard_fail
    return {"ok": ok, "authenticity": auth if ok else "FAIL", "anchored": anchored, "layers": layers, "pack_sha3": pack.get("pack_sha3")}
