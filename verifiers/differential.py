#!/usr/bin/env python3
"""Differential oracle: the Python reference and the independent JS / Go / Rust verifiers must give the SAME
verdict (ok, authenticity, anchored) on every fixture — intact and tampered. A verifier that is not installed is
reported as absent (pass --require js,go,rust to make absence a failure, as CI does)."""
import json, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence.canonical import sha3_hex
from cra_evidence.locker import CRAEvidenceLocker
from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path
from cra_evidence.srp_notice import SRPNotice
from cra_evidence.verify_pack import verify_pack
from cra_evidence.vuln import VulnerabilityRecord
from cra_evidence.sbom import sbom_from_cyclonedx
from cra_evidence.locker import source_file

CDX_DOC = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
           "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.52.0"}]}},
           "components": [{"type": "library", "name": "requests", "version": "2.32.5", "purl": "pkg:pypi/requests@2.32.5"},
                          {"type": "file", "name": "/.github/workflows/ci.yml"}]}

AW = "2026-09-01T00:00:00Z"


def build(d, tip=True, sign=False):
    keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
    lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key if tip else None)
    lk.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-1", True, AW, details={"note": "accénti, 日本語, emoji 🧾, \"quotes\" \\ back/slash", "n": 2 ** 53 - 1, "neg": -7, "b": True, "z": None}))
    n = SRPNotice("vulnerability", "early_warning", {"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m",
                                                     "member_states_available": ["IT", "DE"], "product_name": "prodotto-ü", "product_version": "1",
                                                     "awareness_datetime_utc": AW, "cve_id": "CVE-2026-1"})
    lk.record_notice(n)
    pack = os.path.join(d, "p.json"); pk = lk.evidence_pack(pack)
    if sign:
        sign_pack(pack, key, "acme-ci")
    return lk, key, pack, pk


def build_with_source(d, tamper=None):
    """ledger with an INGESTED SBOM whose generator document is stored next to it (source-documents layer);
    tamper: None | "bytes" (one byte appended to the stored document) | "absent" (stored document removed)."""
    keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
    src = os.path.join(d, "syft.cdx.json"); json.dump(CDX_DOC, open(src, "w"))
    lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key)
    rec = lk.record_sbom(sbom_from_cyclonedx(src, "prodotto-ü", "1"), source_path=src)
    pack = os.path.join(d, "p.json"); lk.evidence_pack(pack)
    stored = source_file(os.path.join(d, "l.jsonl"), rec["data"]["source"]["sha256"])
    if tamper == "bytes":
        open(stored, "ab").write(b" ")
    elif tamper == "absent":
        os.remove(stored)
    return {}


def build_with_raw_source(d, value):
    """a producer-written cra_sbom record whose source.sha256 is `value` (hostile or degenerate): the four verifiers must
    agree — null/"" = no hash (SKIP), anything that is not a 64-hex string = FAIL, never a file path"""
    from cra_evidence.locker import _bind
    keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
    lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key)
    lk.ledger.append(_bind({"kind": "cra_sbom", "product_id": "prodotto-ü", "product_version": "1", "sbom": {}, "component_count": 0,
                            "resolved_components": 0, "sbom_floor_met": False, "source": {"sha256": value}}))
    lk.evidence_pack(os.path.join(d, "p.json"))
    return {}


def rehash(pack):
    p = json.load(open(pack)); p.pop("pack_sha3"); p["pack_sha3"] = sha3_hex(p); json.dump(p, open(pack, "w")); return p


def cases(base):
    out = []
    def case(name, fn, **kw):
        d = os.path.join(base, name); os.makedirs(d)
        args = fn(d) or {}
        out.append((name, os.path.join(d, "p.json"), {**kw, **args}))
    case("intact_unsigned", lambda d: build(d)[3] and None)
    case("signed", lambda d: build(d, sign=True)[3] and None)
    def trusted(d):
        lk, key, pack, pk = build(d, sign=True); json.dump({"acme-ci": key[1]}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("signed_trusted", trusted)
    def wrong_trust(d):
        build(d, sign=True); json.dump({"acme-ci": "00" * 32}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("signed_wrong_trust", wrong_trust)
    def unsigned_trust(d):
        build(d); json.dump({"acme-ci": "00" * 32}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("unsigned_with_trust_store", unsigned_trust)
    def with_key(d):
        lk, key, pack, pk = build(d); return {"key": key[1]}
    case("tip_intact", with_key)
    def truncated(d):
        lk, key, pack, pk = build(d); lk.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-2", False, AW))
        p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); open(p, "w").write("\n".join(lines[:-1]) + "\n"); return {"key": key[1]}
    case("tip_tail_truncated", truncated)
    def unsealed(d):
        lk, key, pack, pk = build(d); lk2 = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1"); lk2.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-3", False, AW)); return {"key": key[1]}
    case("tip_unsealed_tail", unsealed)
    def wrong_key(d):
        build(d); return {"key": "11" * 32}
    case("tip_wrong_key", wrong_key)
    def ledger_missing_key(d):
        lk, key, pack, pk = build(d); os.remove(os.path.join(d, "l.jsonl")); return {"key": key[1]}
    case("log_key_but_ledger_missing", ledger_missing_key)
    def tampered(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["product_id"] = "x"; json.dump(j, open(p, "w"))
    case("pack_field_tampered", tampered)
    def rehashed(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["product_id"] = "x"; json.dump(j, open(p, "w")); rehash(p)
    case("pack_rehashed_anchor_mismatch", rehashed)
    def record_broken(d):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); e = json.loads(lines[0]); e["data"]["vuln_id"] = "CVE-9"
        lines[0] = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True); open(p, "w").write("\n".join(lines) + "\n")
    case("record_content_broken", record_broken)
    def relinked(d):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); e = json.loads(lines[1]); e["prev_hash"] = "ab" * 32
        lines[1] = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True); open(p, "w").write("\n".join(lines) + "\n")
    case("chain_relinked", relinked)
    def side_signer(d):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s["signer_id"] = "TUV"; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_signer_changed", side_signer)
    def side_fp(d):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s["fingerprint"] = "0123456789abcdef"; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_fingerprint_changed", side_fp)
    def entries_wrong(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["ledger_entries"] = 99; json.dump(j, open(p, "w")); rehash(p)
    case("ledger_entries_wrong", entries_wrong)
    def snapshot_false_alone(d):
        lk, key, pack, pk = build(d); j = json.load(open(pack)); j["verification"]["chain_ok"] = False; json.dump(j, open(pack, "w")); rehash(pack); os.remove(os.path.join(d, "l.jsonl"))
    case("snapshot_false_pack_alone", snapshot_false_alone)
    def nan_line(d):
        build(d); open(os.path.join(d, "l.jsonl"), "a").write('{"idx": 3, "ts": "x", "prev_hash": "y", "data": {"x": NaN}, "self_hash": "z"}\n')
    case("nan_line", nan_line)
    def dup_line(d):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); lines[0] = lines[0][:-1] + ',"data":{"k":"evil"}}'; open(p, "w").write("\n".join(lines) + "\n")
    case("duplicate_key_line", dup_line)
    def empty(d):
        build(d); open(os.path.join(d, "l.jsonl"), "w").close()
    case("empty_ledger", empty)
    def pack_list(d):
        build(d); open(os.path.join(d, "p.json"), "w").write("[]")
    case("pack_is_a_list", pack_list)
    def alone(d):
        build(d); os.remove(os.path.join(d, "l.jsonl"))
    case("pack_alone_unsigned", alone)
    def alone_signed(d):
        build(d, sign=True); os.remove(os.path.join(d, "l.jsonl"))
    case("pack_alone_signed", alone_signed)
    def explicit_ledger(d):
        build(d); os.makedirs(os.path.join(d, "elsewhere")); shutil.move(os.path.join(d, "l.jsonl"), os.path.join(d, "elsewhere", "l.jsonl")); return {"ledger": os.path.join(d, "elsewhere", "l.jsonl")}
    case("explicit_ledger_path", explicit_ledger)
    def traversal(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["ledger_file"] = "../../l.jsonl"; json.dump(j, open(p, "w")); rehash(p)
    case("ledger_file_traversal", traversal)
    case("sbom_source_intact", lambda d: build_with_source(d))
    case("sbom_source_bytes_tampered", lambda d: build_with_source(d, "bytes"))
    case("sbom_source_absent", lambda d: build_with_source(d, "absent"))
    case("sbom_source_absent_required", lambda d: build_with_source(d, "absent"), require_sources=True)
    case("sbom_source_intact_required", lambda d: build_with_source(d), require_sources=True)
    case("sbom_source_hash_is_int", lambda d: build_with_raw_source(d, 123))
    case("sbom_source_hash_is_null", lambda d: build_with_raw_source(d, None))
    case("sbom_source_hash_is_empty", lambda d: build_with_raw_source(d, ""))
    case("sbom_source_hash_is_traversal", lambda d: build_with_raw_source(d, "../../../etc/passwd"))
    case("sbom_source_hash_is_upper_hex", lambda d: build_with_raw_source(d, "A" * 64))
    case("sbom_source_hash_is_object", lambda d: build_with_raw_source(d, {"x": 1}))
    case("sbom_source_hash_non_ascii", lambda d: build_with_raw_source(d, "a" * 15 + "\u20ac" + "b" * 40))   # a byte slice at 16 would split the €
    def sources_required_ledger_missing(d):
        build_with_source(d); os.remove(os.path.join(d, "l.jsonl"))
    case("sources_required_but_ledger_missing", sources_required_ledger_missing, require_sources=True)
    def dup_in(path, key, evil):
        t = open(path).read(); i = t.index('"' + key + '"'); open(path, "w").write(t[:i] + '"' + key + '":' + json.dumps(evil) + "," + t[i:])
    def pack_dup(d):
        build(d); dup_in(os.path.join(d, "p.json"), "product_id", "EVIL")                 # first value EVIL, true value after
    case("pack_duplicate_key", pack_dup)
    def side_dup(d):
        lk, key, pack, pk = build(d, sign=True); dup_in(str(sidecar_path(pack)), "signer_id", "TUV")
        json.dump({"acme-ci": key[1]}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("sidecar_duplicate_key", side_dup)
    def tip_dup(d):
        lk, key, pack, pk = build(d); dup_in(os.path.join(d, "l.jsonl.tip.json"), "entries", 1); return {"key": key[1]}
    case("tip_duplicate_key", tip_dup)
    def tip_kind(d):
        lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl.tip.json"); t = json.load(open(p)); t["kind"] = "other/1"; json.dump(t, open(p, "w")); return {"key": key[1]}
    case("tip_kind_rewritten", tip_kind)
    def tip_logkey(d):
        lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl.tip.json"); t = json.load(open(p)); t["log_pubkey_hex"] = "22" * 32; json.dump(t, open(p, "w")); return {"key": key[1]}
    case("tip_log_key_rewritten", tip_logkey)
    if os.environ.get("CRA_ORACLE_BIG") == "1":   # 65 MiB line after the anchor: a scanner that stops silently would accept the prefix
        def big_line(d):
            build(d); open(os.path.join(d, "l.jsonl"), "a").write('{"idx": 3, "ts": "x", "prev_hash": "y", "data": {"pad": "' + "a" * (65 << 20) + '"}, "self_hash": "z"}\n')
        case("ledger_line_65MiB_after_anchor", big_line)
        def big_valid(d):   # a WELL-FORMED, correctly chained line above the cap (the producer refuses to write one: built by hand)
            from cra_evidence.ledger import entry_hash
            lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl"); last = json.loads(open(p).read().splitlines()[-1])
            e = {"idx": last["idx"] + 1, "ts": last["ts"], "prev_hash": last["self_hash"], "data": {"pad": "a" * (65 << 20)}}; e["self_hash"] = entry_hash(e)
            open(p, "a").write(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        case("ledger_line_65MiB_valid_record", big_valid)
    if os.geteuid() != 0:   # root reads anything: the case would not be a case
        def unreadable(d):
            build_with_source(d); sd = os.path.join(d, "l.jsonl.sources")
            for f in os.listdir(sd): os.chmod(os.path.join(sd, f), 0)
        case("sbom_source_unreadable", unreadable)
    return out


def run_cli(cmd, pack, opts):
    args = list(cmd) + [pack]
    if opts.get("ledger"): args += ["--ledger", opts["ledger"]]
    if opts.get("trust"): args += ["--trust-store", opts["trust"]]
    if opts.get("key"): args += ["--log-pubkey", opts["key"]]
    if opts.get("require_sources"): args += ["--require-sources"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    try:
        j = json.loads(r.stdout)
    except ValueError:
        return {"error": (r.stderr or r.stdout)[:200], "exit": r.returncode}
    return {"ok": j["ok"], "authenticity": j["authenticity"], "anchored": j["anchored"], "exit": r.returncode,
            "fails": sorted(l["layer"] for l in j["layers"] if l["status"] == "FAIL")}


def main():
    require = set((sys.argv[sys.argv.index("--require") + 1] if "--require" in sys.argv else "").split(",")) - {""}
    vs = {}
    if shutil.which("node"):
        vs["js"] = ["node", os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs")]
    gob = os.environ.get("CRA_VERIFY_GO") or shutil.which("cra-verify-go")
    if gob:
        vs["go"] = [gob]
    rb = os.environ.get("CRA_VERIFY_RUST") or (os.path.join(ROOT, "verifiers", "rust", "target", "release", "cra-verify") if os.path.exists(os.path.join(ROOT, "verifiers", "rust", "target", "release", "cra-verify")) else None)
    if rb:
        vs["rust"] = [rb]
    missing = require - set(vs)
    if missing:
        print("required verifiers absent:", sorted(missing)); return 2
    base = tempfile.mkdtemp()
    diverg, n = [], 0
    for name, pack, opts in cases(base):
        trust = json.load(open(opts["trust"])) if opts.get("trust") else None
        ref = verify_pack(pack, opts.get("ledger"), trust, opts.get("key"), require_sources=bool(opts.get("require_sources")))
        exp = (ref["ok"], ref["authenticity"], ref["anchored"])
        exp_fails = sorted(l["layer"] for l in ref["layers"] if l["status"] == "FAIL")
        row = {"python": exp}
        for lang, cmd in vs.items():
            r = run_cli(cmd, pack, opts)
            got = (r.get("ok"), r.get("authenticity"), r.get("anchored"))
            row[lang] = got
            # the verdict AND the set of failing layers must agree: a FAIL for the wrong reason is a divergence too
            if got != exp or (r.get("exit", 1) == 0) != ref["ok"] or r.get("fails") != exp_fails:
                diverg.append((name, lang, exp, exp_fails, r))
        n += 1
        print(f"{name:32s} python={exp[1]:14s} " + " ".join(f"{l}={row[l][1]}" for l in vs) + (f"  FAIL layers={exp_fails}" if exp_fails else ""))
    print(f"\ncases={n} verifiers={sorted(vs)} divergences={len(diverg)}")
    for d in diverg:
        print("DIVERGENCE", d)
    shutil.rmtree(base, ignore_errors=True)
    return 1 if diverg else 0


if __name__ == "__main__":
    sys.exit(main())
