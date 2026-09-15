# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra` command line. Every subcommand exits 0 only on a verified positive outcome; nothing is ever sent anywhere
except the OSV/KEV/EUVD read-only queries when you ask for them."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

from . import __version__
from .locker import CRAEvidenceLocker
from .sbom import sbom_from_cyclonedx, sbom_from_installed
from .signing import keygen, load_key, sign_pack
from .srp_notice import DryRunDrop, SRPNotice, schema
from .verify_pack import verify_pack
from .vuln import VulnerabilityRecord


def _p(obj: Any) -> None:
    print(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True, default=str))


def _locker(a) -> CRAEvidenceLocker:
    key = load_key(a.tip_key) if getattr(a, "tip_key", None) else None
    return CRAEvidenceLocker(a.ledger, a.product, a.version, tip_key=key)


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(prog="cra", description="CRA evidence locker (SBOM, Art. 14 clock, SRP notices, 10-year seal) — offline-verifiable")
    p.add_argument("--version", action="version", version=f"cra-evidence {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(s):
        s.add_argument("--ledger", required=True); s.add_argument("--product", required=True); s.add_argument("--version", dest="version", required=True)
        s.add_argument("--tip-key", help="Ed25519 seed file: sign the chain tip after each append (cryptovalid_tip/1)")

    s = sub.add_parser("keygen", help="generate an Ed25519 seed file (0600)"); s.add_argument("path")
    s = sub.add_parser("sbom", help="record an SBOM"); common(s)
    s.add_argument("--from-cyclonedx", help="ingest a CycloneDX JSON (Syft, Trivy, cdxgen…)")
    s.add_argument("--installed", nargs="*", help="top-level PyPI names resolved from this environment"); s.add_argument("--transitive", action="store_true")
    s = sub.add_parser("vuln", help="record a vulnerability-handling event"); common(s)
    s.add_argument("--id", required=True); s.add_argument("--aware", required=True, help="awareness instant, ISO-8601 UTC")
    s.add_argument("--exploited", action="store_true"); s.add_argument("--source", default="manual", choices=["manual", "cisa_kev", "enisa_euvd", "vendor_advisory"])
    s.add_argument("--incident", action="store_true", help="severe incident (Art. 14(3)): final report one month after the 72 h notification")
    s.add_argument("--status", default="aware"); s.add_argument("--fix-available", help="ISO-8601 UTC when the corrective measure became available")
    s = sub.add_parser("notice", help="build an SRP-aligned Art. 14 notice (dry-run drop file, never submitted)"); common(s)
    s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"]); s.add_argument("--stage", required=True, choices=["early_warning", "notification", "final_report"])
    s.add_argument("--fields", required=True, help="JSON file with the SRP fields (see `cra schema`)"); s.add_argument("--drop", required=True, help="drop folder")
    s = sub.add_parser("schema", help="print the SRP field schema for a stream"); s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"])
    s = sub.add_parser("pack", help="write the evidence pack and anchor it in the ledger"); common(s); s.add_argument("--out", required=True)
    s = sub.add_parser("sign", help="sign a pack (Ed25519 sidecar)"); s.add_argument("pack"); s.add_argument("--key", required=True); s.add_argument("--signer-id", required=True)
    s = sub.add_parser("seal", help="long-term seal of a pack digest (crypto-agile archive timestamp)"); common(s); s.add_argument("--pack-sha3", required=True); s.add_argument("--ts-source", default="asserted")
    s = sub.add_parser("verify", help="verify a pack offline (exit 0 only if authenticity is not FAIL)"); s.add_argument("pack")
    s.add_argument("--ledger"); s.add_argument("--trust-store", help="JSON {signer_id: public_key_hex}")
    s = sub.add_parser("feeds", help="read-only network checks: OSV positive control, KEV/EUVD exploitation signal for ids"); s.add_argument("ids", nargs="*")
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        _p(keygen(a.path)); return 0
    if a.cmd == "schema":
        _p({"stream": a.stream, "fields": schema(a.stream)}); return 0
    if a.cmd == "sbom":
        lk = _locker(a)
        if a.from_cyclonedx:
            rec = sbom_from_cyclonedx(a.from_cyclonedx, a.product, a.version)
        elif a.installed is not None:
            rec = sbom_from_installed(a.product, a.version, a.installed, transitive=a.transitive)
        else:
            p.error("sbom: give --from-cyclonedx or --installed")
        e = lk.record_sbom(rec); _p({"recorded": e["idx"], "components": len(rec.components), "depth": rec.depth, "floor_met": len(rec.components) > 0})
        return 0 if rec.components else 1
    if a.cmd == "vuln":
        lk = _locker(a)
        rec = VulnerabilityRecord(product_id=a.product, vuln_id=a.id, actively_exploited=a.exploited, awareness_utc=a.aware,
                                  status=a.status, exploitation_source=a.source, corrective_available_utc=a.fix_available, kind=("incident" if a.incident else "vulnerability"))
        e = lk.record_vulnerability(rec); _p({"recorded": e["idx"], "deadlines": rec.deadlines(), "overdue": rec.overdue()})
        return 0
    if a.cmd == "notice":
        lk = _locker(a)
        with open(a.fields, encoding="utf-8") as f:
            fields = json.load(f)
        n = SRPNotice(stream=a.stream, stage=a.stage, fields=fields)
        r = DryRunDrop(a.drop).prepare(n); lk.record_notice(n, r); _p(r)
        return 0 if r["complete"] else 1
    if a.cmd == "pack":
        lk = _locker(a); pk = lk.evidence_pack(a.out); _p({"pack": a.out, "pack_sha3": pk["pack_sha3"], "verification": pk["verification"]})
        return 0 if pk["verification"]["chain_ok"] else 1
    if a.cmd == "sign":
        _p(sign_pack(a.pack, load_key(a.key), a.signer_id)); return 0
    if a.cmd == "seal":
        lk = _locker(a); _p(lk.seal_longterm(a.pack_sha3, ts_source=a.ts_source)); return 0
    if a.cmd == "verify":
        ts = None
        if a.trust_store:
            with open(a.trust_store, encoding="utf-8") as f:
                ts = json.load(f)
        r = verify_pack(a.pack, a.ledger, ts); _p(r)
        return 0 if r["ok"] else 1
    if a.cmd == "feeds":
        from .feeds import cisa_kev_ids, euvd_kev_ids, exploitation_signal, osv_positive_control
        pc = osv_positive_control(); kev = cisa_kev_ids(); eu = euvd_kev_ids()
        out: Dict[str, Any] = {"osv_positive_control": pc, "cisa_kev": {"count": kev["count"], "error": kev["error"]},
                               "enisa_euvd": {"count": eu["count"], "error": eu["error"]}}
        if a.ids:
            out["signal"] = exploitation_signal(a.ids, kev, eu)
        _p(out)
        return 0 if pc["ok"] else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
