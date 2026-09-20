# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra` command line. Exit 0 only on a verified positive outcome: `vuln` exits 1 when an applicable deadline is
overdue, `seal` when the seal does not verify, `notice` when required fields are missing, `verify` when authenticity
is FAIL. Nothing is ever sent anywhere except the OSV/KEV/EUVD read-only queries (`feeds`, and `vuln --source
cisa_kev|enisa_euvd` unless --assert-source)."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

from . import __version__
from .locker import CRAEvidenceLocker
from .sbom import resolved_components, sbom_from_cyclonedx, sbom_from_installed, sbom_from_spdx
from .signing import keygen, load_key, sign_pack
from .srp_notice import DryRunDrop, SRPNotice, schema
from .verify_pack import verify_pack
from .vuln import STATUSES, VulnerabilityRecord
from .longterm import LongTermEvidence
from datetime import datetime, timezone


def _p(obj: Any) -> None:
    print(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True, default=str))


def _locker(a) -> CRAEvidenceLocker:
    key = load_key(a.tip_key) if getattr(a, "tip_key", None) else None
    return CRAEvidenceLocker(a.ledger, a.product, a.version, tip_key=key, support_period_end=getattr(a, "support_period_end", None))


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(prog="cra", description="CRA evidence locker (SBOM, Art. 14 clock, SRP notices, 10-year seal) — offline-verifiable")
    p.add_argument("--version", action="version", version=f"cra-evidence {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(s):
        s.add_argument("--ledger", required=True); s.add_argument("--product", required=True); s.add_argument("--version", dest="version", required=True)
        s.add_argument("--tip-key", help="Ed25519 seed file: sign the chain tip after each append (cryptovalid_tip/1)")
        s.add_argument("--support-period-end", help="ISO-8601 end of the product's support period (retention = 10 years or this, whichever is longer)")

    s = sub.add_parser("keygen", help="generate an Ed25519 seed file (0600)"); s.add_argument("path")
    s = sub.add_parser("sbom", help="record an SBOM"); common(s)
    s.add_argument("--from-cyclonedx", help="ingest a CycloneDX JSON (Syft, Trivy, cdxgen…)")
    s.add_argument("--from-spdx", help="ingest an SPDX 2.2/2.3 JSON or SPDX 3.0 JSON-LD document (Syft, Yocto, Parlay…)")
    s.add_argument("--installed", nargs="*", help="top-level PyPI names resolved from this environment"); s.add_argument("--transitive", action="store_true")
    s.add_argument("--no-store-source", action="store_true", help="do not copy the ingested document to <ledger>.sources/ (its SHA-256 is still recorded)")
    s.add_argument("--spec-version", default="1.6", choices=["1.6", "1.7"], help="CycloneDX version of the index export written into the record (default 1.6)")
    s = sub.add_parser("vuln", help="record a vulnerability-handling event"); common(s)
    s.add_argument("--id", required=True); s.add_argument("--aware", required=True, help="awareness instant, ISO-8601 UTC")
    s.add_argument("--exploited", action="store_true"); s.add_argument("--source", default="manual", choices=["manual", "cisa_kev", "enisa_euvd", "vendor_advisory"])
    s.add_argument("--incident", action="store_true", help="severe incident (Art. 14(3)): final report one month after the 72 h notification")
    s.add_argument("--status", default="aware", choices=list(STATUSES)); s.add_argument("--fix-available", help="ISO-8601 UTC when the corrective measure became available")
    s.add_argument("--ew-sent", help="instant the early warning was submitted (ISO-8601 with zone)")
    s.add_argument("--notified", help="instant the 72 h notification was submitted (ISO-8601 with zone)")
    s.add_argument("--final-sent", help="instant the final report was submitted (ISO-8601 with zone)")
    s.add_argument("--assert-source", action="store_true", help="skip the live KEV/EUVD check for --source cisa_kev/enisa_euvd (recorded as 'asserted:…')")
    s.add_argument("--allow-overdue", action="store_true", help="exit 0 even if an applicable deadline is overdue (default: exit 1)")
    s = sub.add_parser("notice", help="build an SRP-aligned Art. 14 notice (dry-run drop file, never submitted)"); common(s)
    s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"]); s.add_argument("--stage", required=True, choices=["early_warning", "notification", "final_report"])
    s.add_argument("--fields", required=True, help="JSON file with the SRP fields (see `cra schema --template`)"); s.add_argument("--drop", required=True, help="drop folder")
    s.add_argument("--previous", help="JSON file with the previous stage's fields: carried-forward fields are copied from it")
    s.add_argument("--divergence-reason", help="why this notice's awareness differs from the recorded vulnerability event")
    s = sub.add_parser("schema", help="print the SRP field schema for a stream, or a fillable template for a stage"); s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"])
    s.add_argument("--template", choices=["early_warning", "notification", "final_report"], help="print {field: \"\"} for the fields of this stage (R/C/O/A), ready for `cra notice --fields`")
    s = sub.add_parser("pack", help="write the evidence pack and anchor it in the ledger"); common(s); s.add_argument("--out", required=True)
    s = sub.add_parser("sign", help="sign a pack (Ed25519 sidecar) with a seed file or an AWS KMS Ed25519 key (the key never leaves the HSM)"); s.add_argument("pack")
    s.add_argument("--key", help="Ed25519 seed file"); s.add_argument("--signer-id", required=True)
    s.add_argument("--aws-kms-key-id", help="KMS key id/ARN (key spec ECC_NIST_EDWARDS25519); credentials from AWS_* env or --aws-creds-file")
    s.add_argument("--aws-region"); s.add_argument("--aws-creds-file", help="KEY=VALUE file with AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY [/ AWS_SESSION_TOKEN]")
    s = sub.add_parser("seal", help="long-term seal of a pack digest (crypto-agile archive timestamp); --tip-key = the sealing identity"); common(s)
    s.add_argument("--pack-sha3", required=True); s.add_argument("--ts-source", default="asserted"); s.add_argument("--token-b64", help="RFC 3161 / OTS token (required when --ts-source is not 'asserted')")
    s.add_argument("--renew", help="JSON file with the previous seal (lte dict) to extend the chain")
    s = sub.add_parser("verify", help="verify a pack offline (exit 0 only if authenticity is not FAIL)"); s.add_argument("pack")
    s.add_argument("--ledger"); s.add_argument("--trust-store", help="JSON {signer_id: public_key_hex}")
    s.add_argument("--log-pubkey", help="trusted public key (hex) of the ledger's signed tip: detects a truncated tail")
    s.add_argument("--require-sources", action="store_true", help="every SBOM source document recorded by hash must be present next to the ledger and match (absence = FAIL)")
    s = sub.add_parser("feeds", help="read-only network checks: OSV positive control, KEV/EUVD exploitation signal for ids"); s.add_argument("ids", nargs="*")
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        _p(keygen(a.path)); return 0
    if a.cmd == "schema":
        if a.template:
            sch = schema(a.stream)
            _p({k: ("" if spec["format"] not in ("list", "enum-list") else []) for k, spec in sch.items() if spec["stages"][a.template] != "-"}); return 0
        _p({"stream": a.stream, "fields": schema(a.stream)}); return 0
    if a.cmd == "sbom":
        lk = _locker(a)
        if sum(1 for x in (a.from_cyclonedx, a.from_spdx, a.installed is not None) if x) > 1:
            p.error("sbom: --from-cyclonedx, --from-spdx and --installed are mutually exclusive")
        if a.from_cyclonedx:
            rec = sbom_from_cyclonedx(a.from_cyclonedx, a.product, a.version)
        elif a.from_spdx:
            rec = sbom_from_spdx(a.from_spdx, a.product, a.version)
        elif a.installed is not None:
            rec = sbom_from_installed(a.product, a.version, a.installed, transitive=a.transitive)
        else:
            p.error("sbom: give --from-cyclonedx, --from-spdx or --installed")
        src = a.from_cyclonedx or a.from_spdx
        e = lk.record_sbom(rec, source_path=src, store=not a.no_store_source, spec_version=a.spec_version); n = len(resolved_components(rec))
        _p({"recorded": e["idx"], "components": len(rec.components), "resolved": n, "depth": rec.depth, "floor_met": e["data"]["sbom_floor_met"],
            "source": e["data"].get("source")})
        return 0 if e["data"]["sbom_floor_met"] else 1
    if a.cmd == "vuln":
        lk = _locker(a)
        source, exploited = a.source, a.exploited
        if a.source in ("cisa_kev", "enisa_euvd"):
            if a.assert_source:
                source = f"asserted:{a.source}"
            else:   # the provenance label is only stored as such when the feed confirms it now
                from .feeds import cisa_kev_ids, euvd_kev_ids, exploitation_signal
                feed = cisa_kev_ids() if a.source == "cisa_kev" else euvd_kev_ids()
                if feed["error"]:
                    print(f"feed {a.source} unavailable ({feed['error']}): use --assert-source to record an unverified provenance", file=sys.stderr); return 1
                sig = exploitation_signal([a.id], feed if a.source == "cisa_kev" else None, feed if a.source == "enisa_euvd" else None)
                if a.id.upper() not in {k.upper() for k in sig["actively_exploited"]}:
                    print(f"{a.id} is NOT in {a.source} today: refusing to record that provenance (use --assert-source)", file=sys.stderr); return 1
                exploited = True     # confirmed in a known-exploited catalogue: the clock and the provenance cannot diverge
        rec = VulnerabilityRecord(product_id=a.product, vuln_id=a.id, actively_exploited=exploited, awareness_utc=a.aware,
                                  status=a.status, exploitation_source=source, corrective_available_utc=a.fix_available,
                                  kind=("incident" if a.incident else "vulnerability"), early_warning_sent_utc=a.ew_sent,
                                  notification_sent_utc=a.notified, final_report_sent_utc=a.final_sent)
        e = lk.record_vulnerability(rec); od = rec.overdue(); _p({"recorded": e["idx"], "deadlines": rec.deadlines(), "overdue": od})
        return 0 if (not od["any_overdue"] or a.allow_overdue) else 1
    if a.cmd == "notice":
        lk = _locker(a)
        with open(a.fields, encoding="utf-8") as f:
            fields = json.load(f)
        prev = json.load(open(a.previous, encoding="utf-8")) if a.previous else None
        n = SRPNotice(stream=a.stream, stage=a.stage, fields=fields, previous_fields=prev)
        r = DryRunDrop(a.drop).prepare(n); lk.record_notice(n, r, divergence_reason=a.divergence_reason); _p(r)
        return 0 if r["complete"] else 1
    if a.cmd == "pack":
        lk = _locker(a); pk = lk.evidence_pack(a.out); _p({"pack": a.out, "pack_sha3": pk["pack_sha3"], "verification": pk["verification"]})
        return 0 if pk["verification"]["chain_ok"] else 1
    if a.cmd == "sign":
        if a.aws_kms_key_id:
            from .kms import KMSSigner, load_creds_file
            if not a.aws_region:
                p.error("sign: --aws-region is required with --aws-kms-key-id")
            creds = load_creds_file(a.aws_creds_file) if a.aws_creds_file else {}
            signer = KMSSigner(a.aws_kms_key_id, a.aws_region, creds.get("AWS_ACCESS_KEY_ID"), creds.get("AWS_SECRET_ACCESS_KEY"), creds.get("AWS_SESSION_TOKEN"))
            r = sign_pack(a.pack, signer.as_key(), a.signer_id); r["public_key_hex"] = signer.public_key_hex; r["backend"] = "aws-kms"; _p(r); return 0
        if not a.key:
            p.error("sign: give --key or --aws-kms-key-id")
        _p(sign_pack(a.pack, load_key(a.key), a.signer_id)); return 0
    if a.cmd == "seal":
        lk = _locker(a)
        prev = json.load(open(a.renew, encoding="utf-8")) if a.renew else None
        d = lk.seal_longterm(a.pack_sha3, ts_source=a.ts_source, previous=prev, token_b64=a.token_b64)
        v = LongTermEvidence.from_dict(d).verify(now=datetime.now(timezone.utc).timestamp())
        _p({"seal": d, "verify": v})
        return 0 if v["ok"] else 1
    if a.cmd == "verify":
        ts = None
        if a.trust_store:
            from .ledger import parse_line
            with open(a.trust_store, encoding="utf-8") as f:
                ts = parse_line(f.read())            # strict: a duplicate signer_id would make two readers disagree
        r = verify_pack(a.pack, a.ledger, ts, a.log_pubkey, require_sources=a.require_sources); _p(r)
        return 0 if r["ok"] else 1
    if a.cmd == "feeds":
        from .feeds import cisa_kev_ids, euvd_kev_ids, exploitation_signal, osv_positive_control
        pc = osv_positive_control(); kev = cisa_kev_ids(); eu = euvd_kev_ids()
        out: Dict[str, Any] = {"osv_positive_control": pc, "cisa_kev": {"count": kev["count"], "error": kev["error"]},
                               "enisa_euvd": {"count": eu["count"], "error": eu["error"]}}
        if a.ids:
            out["signal"] = exploitation_signal(a.ids, kev, eu)
        _p(out)
        return 0 if (pc["ok"] and not kev["error"] and not eu["error"]) else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
