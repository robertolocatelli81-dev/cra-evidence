# SPDX-License-Identifier: AGPL-3.0-or-later
"""The CRA evidence locker: every SBOM, vulnerability record, SRP notice and long-term seal goes into one
hash-chained ledger; the evidence pack commits to the ledger state and is anchored back into it; the pack can be
signed (Ed25519 sidecar) and sealed for the 10-year retention (crypto-agile archive-timestamp chain).

Honest scope, written into every pack: firm-side evidence — it proves that these records existed, in this order,
unchanged since; it is NOT a conformity assessment, NOT CE marking, NOT the official CSIRT/ENISA channel, and a
self-asserted seal is NOT an objective time anchor (RFC 3161 / OpenTimestamps are).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical import floatfree, sha3_hex
from .ledger import Ledger
from .longterm import AlgorithmPolicy, LongTermEvidence, Signer
from .sbom import MAX_SOURCE_BYTES, SBOMRecord, reingest, resolved_components
from .srp_notice import SRPNotice
from .vuln import VulnerabilityRecord, parse_utc

ATTACHMENT_FORMATS = {"cyclonedx-vex", "csaf-2.0", "openvex", "cyclonedx-sbom", "spdx-3.0"}
RETENTION_YEARS = 10
PACK_KIND = "cra_evidence_pack/1"
LEGAL_BASIS = ("Reg. (EU) 2024/2847 (Cyber Resilience Act): Annex I Part II(1) SBOM; Art. 14(2) actively exploited "
               "vulnerability (early warning 24 h, notification 72 h, final report 14 days after a corrective or mitigating "
               "measure is available); Art. 14(4) severe incident (24 h, 72 h, final report one month after the submission of "
               "the incident notification) — reporting obligations applying from 11 September 2026 (Art. 71); technical "
               "documentation and EU declaration of conformity kept at least 10 years after placing on the market or for the "
               "support period, whichever is longer (Art. 13(13))")
HONEST_SCOPE_MARK = "NOT a conformity assessment"
HONEST_SCOPE = ("firm-side evidence locker: proves that these records existed, in this order, unchanged since (hash chain, "
                "offline-verifiable); it is " + HONEST_SCOPE_MARK + ", NOT CE marking, NOT the official CSIRT/ENISA "
                "channel (the SRP is a human portal), NOT an objective time anchor unless an RFC 3161 / OTS token is attached")
RECORD_KINDS = ("cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor")
SOURCES_SUFFIX = ".sources"     # <ledger>.sources/<sha256>.json — the generators' documents, byte-exact, hash-bound in the records


def sources_dir(ledger_path: str) -> str:
    return str(ledger_path) + SOURCES_SUFFIX


def source_file(ledger_path: str, sha256: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha256)):
        raise ValueError("source sha256 must be 64 hex characters")
    return os.path.join(sources_dir(ledger_path), sha256 + ".json")


def _bind(entry: Dict[str, Any]) -> Dict[str, Any]:
    entry = floatfree(entry)
    entry["record_sha3"] = sha3_hex(entry)      # content-binding: recomputed by verify()
    return entry


def _present(v: Any) -> bool:
    return v is not None and str(v).strip() != ""


class CRAEvidenceLocker:
    def __init__(self, ledger_path: str, product_id: str, product_version: str, tip_key: Optional[Tuple[Any, str]] = None,
                 support_period_end: Optional[str] = None, allow_unlocked: bool = False):
        """support_period_end: ISO-8601 instant; the CRA retention is 10 years OR the support period, whichever is
        longer (Art. 13(13)) — recorded in the pack so the seal's renewal horizon is the right one."""
        self.product_id, self.product_version = product_id, product_version
        self.support_period_end = support_period_end
        if support_period_end:
            parse_utc(support_period_end)
        self.tip_key = tip_key
        self.ledger = Ledger(ledger_path, tip_key=tip_key, allow_unlocked=allow_unlocked)
        self._lock = threading.Lock()

    def _append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            return self.ledger.append(_bind(entry))

    def record_sbom(self, sbom: SBOMRecord, source_path: Optional[str] = None, store: bool = True, spec_version: str = "1.6") -> Dict[str, Any]:
        """source_path: the generator's document the record was ingested from. Its exact bytes are hashed (SHA-256)
        into the record (the ingest already fingerprinted them; the file must still hash the same now) and copied to
        `<ledger>.sources/<sha256>.json`, so the evidence is the document Syft/Trivy/cdxgen/Yocto produced — the
        record is its index, not its replacement. If the file changed between ingest and record, or the store already
        holds different bytes under that name, the record is refused. store=False keeps the hash but no copy. An
        ingested SBOM without source_path is refused (its record would carry a hash nothing re-verified)."""
        if (sbom.product_id, sbom.product_version) != (self.product_id, self.product_version):
            raise ValueError(f"SBOM is for {sbom.product_id!r} {sbom.product_version!r}, this locker is for {self.product_id!r} {self.product_version!r}")
        cdx = sbom.to_cyclonedx_min(spec_version)
        resolved = len(resolved_components(sbom))
        source = dict(sbom.source)
        raw = b""
        if source.get("sha256") and source_path is None:
            raise ValueError("this SBOM was ingested from a document: pass source_path so the bytes are re-hashed and stored "
                             "(store=False keeps the hash only) — a record that only LOOKS bound is refused")
        if source_path is not None:
            if not source.get("sha256"):
                raise ValueError("source_path given but this SBOM was not ingested from a document (no fingerprint): "
                                 "a document can only be bound to the index that was read from it")
            if os.path.getsize(source_path) > MAX_SOURCE_BYTES:
                raise ValueError(f"source document exceeds {MAX_SOURCE_BYTES} bytes: refused unread (the verifiers refuse it too)")
            with open(source_path, "rb") as f:
                raw = f.read()                      # read ONCE: the bytes hashed are the bytes stored
            fp = {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw), "file": os.path.basename(source_path)}
            if source["sha256"] != fp["sha256"]:
                raise ValueError("source document changed since it was ingested: re-run the ingest on the current file")
            # the index must be a FUNCTION of the bytes stored, not merely co-located with them: re-derive and compare
            fresh = reingest(raw, source_path, str(source.get("format", "")), sbom.product_id, sbom.product_version)
            volatile = {"file"}
            same = (fresh.components == sbom.components and fresh.edges == sbom.edges and fresh.depth == sbom.depth
                    and {k: v for k, v in fresh.source.items() if k not in volatile} == {k: v for k, v in source.items() if k not in volatile | {"stored_as"}})
            if not same:   # every field the export is built from: components, edges (dependencies), depth (profile label), declared metadata
                raise ValueError("SBOM index does not match the document at source_path (components, edges, depth or declared metadata differ): "
                                 "the record would describe something the stored bytes do not")
            source.update(fp)
        if source_path is not None and store:
            dst = source_file(self.ledger.path, fp["sha256"])
            os.makedirs(sources_dir(self.ledger.path), exist_ok=True)
            if os.path.exists(dst):
                with open(dst, "rb") as f:
                    if f.read() != raw:
                        raise ValueError(f"source store already holds different bytes for {fp['sha256'][:16]}…: refusing to overwrite evidence")
            else:
                tmp = dst + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                os.replace(tmp, dst)
            source["stored_as"] = os.path.basename(dst)
        return self._append({"kind": "cra_sbom", "product_id": self.product_id, "product_version": self.product_version,
                             "sbom": cdx, "component_count": len(cdx["components"]), "resolved_components": resolved,
                             "source": source,
                             # conservative by design: zero RESOLVED components (a declared-but-NOT-INSTALLED dependency
                             # is not one) never EVIDENCES the Annex I floor, even for a product that truly has no
                             # dependencies (state that in the SBOM's note instead)
                             "sbom_floor_met": resolved > 0})

    def record_vulnerability(self, rec: VulnerabilityRecord, attachments: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """attachments: standard documents embedded content-bound, e.g. [{"format": "cyclonedx-vex", "document": {...}}]
        (formats: ATTACHMENT_FORMATS) — what Dependency-Track/Snyk exchange natively, kept verbatim next to the record."""
        if rec.product_id != self.product_id:
            raise ValueError(f"record is for product {rec.product_id!r}, this locker is for {self.product_id!r}")
        att = []
        for a in attachments or []:
            fmt, doc = a.get("format"), a.get("document")
            if fmt not in ATTACHMENT_FORMATS or not isinstance(doc, dict):
                raise ValueError(f"attachment: format must be one of {sorted(ATTACHMENT_FORMATS)} and document a JSON object")
            doc = floatfree(doc)
            att.append({"format": fmt, "document": doc, "document_sha3": sha3_hex(doc)})
        body = asdict(rec)
        body["event_kind"] = body.pop("kind")     # the record's own kind (vulnerability|incident) must never shadow the ledger kind
        return self._append({"kind": "cra_vuln", **body, "deadlines": rec.deadlines(), "overdue": rec.overdue(),
                             "attachments": att})

    def record_notice(self, notice: SRPNotice, drop_result: Optional[Dict[str, Any]] = None,
                      divergence_reason: Optional[str] = None) -> Dict[str, Any]:
        """The notice's awareness instant is bound to the vulnerability record already in the chain for the same id
        (cve_id / euvd_id ↔ vuln_id): a different value is refused unless `divergence_reason` declares why — the legal
        clock cannot be moved in a notice without touching the record that started it."""
        bound_to, aw = [], notice.fields.get("awareness_datetime_utc")
        ids = {str(notice.fields.get(k)).strip().upper() for k in ("cve_id", "euvd_id") if notice.fields.get(k)}
        latest: Dict[str, Dict[str, Any]] = {}     # the LAST record per vuln_id is the current legal state
        if ids:
            for e in self.ledger.entries():
                d = e.get("data") if isinstance(e, dict) else None
                if isinstance(d, dict) and d.get("kind") == "cra_vuln" and d.get("product_id") == self.product_id:
                    vid = str(d.get("vuln_id", "")).strip().upper()
                    if vid in ids:
                        latest[vid] = d
            for d in latest.values():
                bound_to.append(d.get("record_id"))
                if not _present(aw):
                    raise ValueError(f"awareness_datetime_utc is absent but the notice refers to {d.get('vuln_id')}: carry the recorded "
                                     f"awareness {d.get('awareness_utc')} (the legal clock cannot be dropped by omission)")
                if parse_utc(str(aw)) != parse_utc(str(d.get("awareness_utc"))) and not divergence_reason:
                    raise ValueError(f"awareness_datetime_utc {aw} differs from the recorded awareness {d.get('awareness_utc')} "
                                     f"of {d.get('vuln_id')} (record {d.get('record_id')}): give divergence_reason or fix the notice")
        return self._append({"kind": "cra_srp_notice", "stream": notice.stream, "stage": notice.stage,
                             "notice_id": notice.notice_id, "notice_sha3": notice.canonical_hash(),
                             "complete": notice.complete(), "missing_required": notice.missing(),
                             "deadline_utc": notice.deadline_utc(), "drop": drop_result or {"status": "not_written"},
                             "bound_vuln_records": bound_to, "awareness_divergence_reason": divergence_reason})

    # ── verification with content-binding ────────────────────────────────
    def verify(self) -> Dict[str, Any]:
        r = self.ledger.verify()
        checked, mismatched = 0, 0
        try:
            for e in self.ledger.entries():
                d = e.get("data", {}) if isinstance(e, dict) else None
                if not isinstance(d, dict) or d.get("kind") not in RECORD_KINDS:
                    continue
                checked += 1
                body = {k: v for k, v in d.items() if k != "record_sha3"}
                if sha3_hex(body) != d.get("record_sha3"):
                    mismatched += 1
        except (ValueError, TypeError, AttributeError, RecursionError) as ex:   # a verdict, never a crash (fail-closed)
            mismatched += 1
            r["failures"] = (r.get("failures") or []) + [f"record scan aborted: {ex}"]
        r["records_checked"] = checked
        r["record_digests_bound"] = mismatched == 0
        if mismatched:
            r["chain_ok"] = False
            r["failures"] = (r.get("failures") or []) + [f"{mismatched} record(s) whose record_sha3 does not match their content"]
        return r

    # ── evidence pack ─────────────────────────────────────────────────────
    def evidence_pack(self, out_path: str) -> Dict[str, Any]:
        with self._lock:      # snapshot, pack and anchor must be one step: no record may slip in between
            return self._evidence_pack_locked(out_path)

    def _evidence_pack_locked(self, out_path: str) -> Dict[str, Any]:
        v = self.verify()
        if v["entries"] == 0:
            raise ValueError("empty ledger: a pack over zero records would prove nothing (record an SBOM or an event first)")
        if not v["chain_ok"]:
            raise ValueError("ledger does not verify: refusing to write a pack over a broken chain: " + "; ".join(v["failures"][:3]))
        if not re.search(r"\bNOT\b", HONEST_SCOPE):
            raise ValueError("honest_scope must declare a limit")
        counts: Dict[str, int] = {}
        for e in self.ledger.entries():
            d = e.get("data") if isinstance(e, dict) else None
            k = d.get("kind") if isinstance(d, dict) else None
            if k:
                counts[k] = counts.get(k, 0) + 1
        pack = {"kind": PACK_KIND, "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "legal_basis": LEGAL_BASIS, "honest_scope": HONEST_SCOPE, "product_id": self.product_id,
                "product_version": self.product_version, "retention_years": RETENTION_YEARS,
                "retention": {"minimum_years": RETENTION_YEARS, "support_period_end_utc": self.support_period_end,
                              "rule": "10 years after placing on the market or the support period, whichever is longer (Art. 13(13))"},
                "ledger_file": Path(self.ledger.path).name, "ledger_entries": v["entries"], "ledger_last_self_hash": v["last_self_hash"],
                "record_counts": counts, "verification": {k: v[k] for k in ("chain_ok", "entries", "records_checked", "record_digests_bound")}}
        pack["pack_sha3"] = sha3_hex(pack)
        tmp = Path(str(out_path) + ".tmp")
        tmp.write_text(json.dumps(pack, indent=1, sort_keys=True), encoding="utf-8")
        try:
            self.ledger.append(_bind({"kind": "cra_pack_anchor", "anchored_pack_sha3": pack["pack_sha3"], "pack_file": Path(out_path).name}))
        except Exception:
            tmp.unlink(missing_ok=True)      # never leave an un-anchored pack on disk
            raise
        os.replace(tmp, out_path)             # the pack appears only once its anchor is in the chain
        return pack

    def seal_longterm(self, pack_sha3: str, alg: str = "ed25519", ts_source: str = "asserted",
                      t: Optional[float] = None, previous: Optional[Dict[str, Any]] = None,
                      key: Optional[Tuple[Any, str]] = None, token_b64: Optional[str] = None,
                      external_digest: bool = False) -> Dict[str, Any]:
        """Seal (or RENEW, with `previous` = the last seal dict from the ledger) the pack digest. The signing key is the
        locker's log key by default (identity = the key that signs the chain tip); with no key at all the seal is
        ephemeral and says so. ts_source != "asserted" requires the token. Nothing here VERIFIES a time token: the
        record carries it for the verifier's temporal oracle."""
        if not re.fullmatch(r"[0-9a-f]{64}", str(pack_sha3)):
            raise ValueError("pack_sha3 must be a 64-hex SHA3-256 digest")
        if not external_digest:   # by default only a pack ANCHORED in this ledger can be sealed (a seal over nothing is noise)
            anchored = any(isinstance(e, dict) and isinstance(e.get("data"), dict) and e["data"].get("kind") == "cra_pack_anchor"
                           and e["data"].get("anchored_pack_sha3") == pack_sha3 for e in self.ledger.entries())
            if not anchored:
                raise ValueError("digest is not anchored in this ledger (write the pack first, or pass external_digest=True for a foreign digest)")
        lte = LongTermEvidence.from_dict(previous) if previous else LongTermEvidence(evidence_digest=pack_sha3)
        if lte.evidence_digest != pack_sha3:
            raise ValueError("previous seal is over a different digest")
        k = key if key is not None else (self.tip_key if (alg == "ed25519" and self.tip_key is not None) else None)
        signer = Signer(alg, key=k)
        lte.seal(signer, t=t if t is not None else datetime.now(timezone.utc).timestamp(), ts_source=ts_source, token_b64=token_b64)
        d = lte.to_dict()
        self._append({"kind": "cra_longterm_seal", "lte": d, "chain_len": len(lte.records), "renewal": previous is not None,
                      "time_anchor": ts_source, "time_anchor_verified_here": False, "signer_ephemeral": signer.ephemeral,
                      "signer_pub": signer.pub})
        return d
