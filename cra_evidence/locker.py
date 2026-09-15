# SPDX-License-Identifier: AGPL-3.0-or-later
"""The CRA evidence locker: every SBOM, vulnerability record, SRP notice and long-term seal goes into one
hash-chained ledger; the evidence pack commits to the ledger state and is anchored back into it; the pack can be
signed (Ed25519 sidecar) and sealed for the 10-year retention (crypto-agile archive-timestamp chain).

Honest scope, written into every pack: firm-side evidence — it proves that these records existed, in this order,
unchanged since; it is NOT a conformity assessment, NOT CE marking, NOT the official CSIRT/ENISA channel, and a
self-asserted seal is NOT an objective time anchor (RFC 3161 / OpenTimestamps are).
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical import floatfree, sha3_hex
from .ledger import Ledger
from .longterm import AlgorithmPolicy, LongTermEvidence, Signer
from .sbom import SBOMRecord
from .srp_notice import SRPNotice
from .vuln import VulnerabilityRecord

ATTACHMENT_FORMATS = {"cyclonedx-vex", "csaf-2.0", "openvex", "cyclonedx-sbom", "spdx-3.0"}
RETENTION_YEARS = 10
PACK_KIND = "cra_evidence_pack/1"
LEGAL_BASIS = ("Reg. (EU) 2024/2847 (Cyber Resilience Act): Annex I Part II(1) SBOM; Art. 14 reporting (24 h / 72 h / "
               "final report 14 days after a corrective measure is available; severe incident final report one month after "
               "the 72 h notification) — obligations applying from 11 September 2026; technical documentation kept 10 years")
HONEST_SCOPE = ("firm-side evidence locker: proves that these records existed, in this order, unchanged since (hash chain, "
                "offline-verifiable); it is NOT a conformity assessment, NOT CE marking, NOT the official CSIRT/ENISA "
                "channel (the SRP is a human portal), NOT an objective time anchor unless an RFC 3161 / OTS token is attached")
RECORD_KINDS = ("cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor")


class CRAEvidenceLocker:
    def __init__(self, ledger_path: str, product_id: str, product_version: str, tip_key: Optional[Tuple[Any, str]] = None):
        self.product_id, self.product_version = product_id, product_version
        self.ledger = Ledger(ledger_path, tip_key=tip_key)
        self._lock = threading.Lock()

    def _append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        entry = floatfree(entry)
        entry["record_sha3"] = sha3_hex(entry)      # content-binding: recomputed by verify()
        with self._lock:
            return self.ledger.append(entry)

    def record_sbom(self, sbom: SBOMRecord) -> Dict[str, Any]:
        cdx = sbom.to_cyclonedx_min()
        return self._append({"kind": "cra_sbom", "product_id": self.product_id, "product_version": self.product_version,
                             "sbom": cdx, "component_count": len(cdx["components"]),
                             # conservative by design: zero listed components never EVIDENCES the Annex I floor, even for a
                             # product that truly has no dependencies (state that in the SBOM's note instead)
                             "sbom_floor_met": len(cdx["components"]) > 0})

    def record_vulnerability(self, rec: VulnerabilityRecord, attachments: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """attachments: standard documents embedded content-bound, e.g. [{"format": "cyclonedx-vex", "document": {...}}]
        (formats: ATTACHMENT_FORMATS) — what Dependency-Track/Snyk exchange natively, kept verbatim next to the record."""
        att = []
        for a in attachments or []:
            fmt, doc = a.get("format"), a.get("document")
            if fmt not in ATTACHMENT_FORMATS or not isinstance(doc, dict):
                raise ValueError(f"attachment: format must be one of {sorted(ATTACHMENT_FORMATS)} and document a JSON object")
            doc = floatfree(doc)
            att.append({"format": fmt, "document": doc, "document_sha3": sha3_hex(doc)})
        return self._append({"kind": "cra_vuln", **asdict(rec), "deadlines": rec.deadlines(), "overdue": rec.overdue(),
                             "attachments": att})

    def record_notice(self, notice: SRPNotice, drop_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._append({"kind": "cra_srp_notice", "stream": notice.stream, "stage": notice.stage,
                             "notice_id": notice.notice_id, "notice_sha3": notice.canonical_hash(),
                             "complete": notice.complete(), "missing_required": notice.missing(),
                             "deadline_utc": notice.deadline_utc(), "drop": drop_result or {"status": "not_written"}})

    # ── verification with content-binding ────────────────────────────────
    def verify(self) -> Dict[str, Any]:
        r = self.ledger.verify()
        checked, mismatched = 0, 0
        for e in self.ledger.entries():
            d = e.get("data", {})
            if not isinstance(d, dict) or d.get("kind") not in RECORD_KINDS:
                continue
            checked += 1
            body = {k: v for k, v in d.items() if k != "record_sha3"}
            if sha3_hex(body) != d.get("record_sha3"):
                mismatched += 1
        r["records_checked"] = checked
        r["record_digests_bound"] = mismatched == 0
        if mismatched:
            r["chain_ok"] = False
            r["failures"] = (r.get("failures") or []) + [f"{mismatched} record(s) whose record_sha3 does not match their content"]
        return r

    # ── evidence pack ─────────────────────────────────────────────────────
    def evidence_pack(self, out_path: str) -> Dict[str, Any]:
        v = self.verify()
        if v["entries"] == 0:
            raise ValueError("empty ledger: a pack over zero records would prove nothing (record an SBOM or an event first)")
        if not re.search(r"\bNOT\b", HONEST_SCOPE):
            raise ValueError("honest_scope must declare a limit")
        counts: Dict[str, int] = {}
        for e in self.ledger.entries():
            k = (e.get("data") or {}).get("kind")
            if k:
                counts[k] = counts.get(k, 0) + 1
        pack = {"kind": PACK_KIND, "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "legal_basis": LEGAL_BASIS, "honest_scope": HONEST_SCOPE, "product_id": self.product_id,
                "product_version": self.product_version, "retention_years": RETENTION_YEARS,
                "ledger_file": Path(self.ledger.path).name, "ledger_entries": v["entries"], "ledger_last_self_hash": v["last_self_hash"],
                "record_counts": counts, "verification": {k: v[k] for k in ("chain_ok", "entries", "records_checked", "record_digests_bound")}}
        pack["pack_sha3"] = sha3_hex(pack)
        Path(out_path).write_text(json.dumps(pack, indent=1, sort_keys=True), encoding="utf-8")
        self._append({"kind": "cra_pack_anchor", "anchored_pack_sha3": pack["pack_sha3"], "pack_file": Path(out_path).name})
        return pack

    def seal_longterm(self, pack_sha3: str, alg: str = "ed25519", ts_source: str = "asserted",
                      t: Optional[float] = None) -> Dict[str, Any]:
        lte = LongTermEvidence(evidence_digest=pack_sha3)
        lte.seal(Signer(alg), t=t if t is not None else datetime.now(timezone.utc).timestamp(), ts_source=ts_source)
        d = lte.to_dict()
        self._append({"kind": "cra_longterm_seal", "lte": d, "time_anchor": ts_source, "time_anchor_objective": ts_source != "asserted"})
        return d
