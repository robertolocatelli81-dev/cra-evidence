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
from cra_evidence.ledger import load_trust_store

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
        out.append((name, args.pop("pack", os.path.join(d, "p.json")), {**kw, **args}))
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
    def source_replaced_by_dir(d):   # something is there but it is not the document: FAIL, never "absent" (round 10, Sonnet)
        build_with_source(d); sd = os.path.join(d, "l.jsonl.sources"); f = os.listdir(sd)[0]; os.remove(os.path.join(sd, f)); os.makedirs(os.path.join(sd, f))
    case("sbom_source_replaced_by_directory", source_replaced_by_dir)
    def source_symlink_to_dir(d):
        build_with_source(d); sd = os.path.join(d, "l.jsonl.sources"); f = os.listdir(sd)[0]; os.remove(os.path.join(sd, f)); os.symlink(d, os.path.join(sd, f))
    case("sbom_source_symlink_to_directory", source_symlink_to_dir)
    def source_dangling(d):
        build_with_source(d); sd = os.path.join(d, "l.jsonl.sources"); f = os.listdir(sd)[0]; os.remove(os.path.join(sd, f)); os.symlink(os.path.join(d, "nowhere"), os.path.join(sd, f))
    case("sbom_source_dangling_symlink", source_dangling)
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
    def floaty(path, key, val):
        t = open(path).read(); i = t.index('"' + key + '":'); j = i + len(key) + 3; k = j
        while t[k] not in ",}": k += 1
        open(path, "w").write(t[:j] + val + t[k:])
    def pack_float(d):
        build(d); floaty(os.path.join(d, "p.json"), "retention_years", "10.0")     # JSON.parse would give 10 and the digest would match
    case("pack_float_integral", pack_float)
    def ledger_float(d):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); lines[0] = lines[0].replace('"idx":0', '"idx":0.0', 1); open(p, "w").write("\n".join(lines) + "\n")
    case("ledger_line_float_integral", ledger_float)
    def tip_float(d):
        lk, key, pack, pk = build(d); floaty(os.path.join(d, "l.jsonl.tip.json"), "entries", "3.0"); return {"key": key[1]}
    case("tip_entries_float", tip_float)
    def side_fp_int(d):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s["fingerprint"] = 123; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_fingerprint_is_int", side_fp_int)
    def pack_not_utf8(d):
        build(d); p = os.path.join(d, "p.json"); b = open(p, "rb").read(); open(p, "wb").write(b.replace(b'"kind"', b'"k\xffnd"', 1))
    case("pack_not_utf8", pack_not_utf8)
    def trust_dup(d):
        lk, key, pack, pk = build(d, sign=True); open(os.path.join(d, "trust.json"), "w").write('{"acme-ci": "' + "00" * 32 + '", "acme-ci": "' + key[1] + '"}'); return {"trust": os.path.join(d, "trust.json")}
    case("trust_store_duplicate_key", trust_dup)
    def trust_list(d):
        build(d, sign=True); open(os.path.join(d, "trust.json"), "w").write("[]"); return {"trust": os.path.join(d, "trust.json")}
    case("trust_store_not_object", trust_list)
    def trust_int(d):
        build(d, sign=True); open(os.path.join(d, "trust.json"), "w").write('{"acme-ci": 5}'); return {"trust": os.path.join(d, "trust.json")}
    case("trust_store_value_not_string", trust_int)
    def relocated_with_sources(d):
        build_with_source(d); os.makedirs(os.path.join(d, "elsewhere")); shutil.move(os.path.join(d, "l.jsonl"), os.path.join(d, "elsewhere", "l.jsonl"))
        shutil.move(os.path.join(d, "l.jsonl.sources"), os.path.join(d, "elsewhere", "l.jsonl.sources")); return {"ledger": os.path.join(d, "elsewhere", "l.jsonl")}
    case("explicit_ledger_path_with_sources", relocated_with_sources)
    def relocated_without_sources(d):
        build_with_source(d); os.makedirs(os.path.join(d, "elsewhere")); shutil.move(os.path.join(d, "l.jsonl"), os.path.join(d, "elsewhere", "l.jsonl")); return {"ledger": os.path.join(d, "elsewhere", "l.jsonl"), "require_sources": True}
    case("explicit_ledger_path_sources_left_behind", relocated_without_sources)
    def tip_field(d, key, val):
        lk, k, pack, pk = build(d); p = os.path.join(d, "l.jsonl.tip.json"); t = json.load(open(p)); t[key] = val; json.dump(t, open(p, "w")); return {"key": k[1]}
    case("tip_entries_is_string", lambda d: tip_field(d, "entries", "3"))
    case("tip_entries_is_bool", lambda d: tip_field(d, "entries", True))
    case("tip_log_key_empty", lambda d: tip_field(d, "log_pubkey_hex", ""))          # "" = absent (cryptovalid profile): PASS everywhere
    case("tip_log_key_not_string", lambda d: tip_field(d, "log_pubkey_hex", 5))
    case("tip_log_key_null", lambda d: tip_field(d, "log_pubkey_hex", None))
    case("tip_ts_non_ascii", lambda d: tip_field(d, "ts", "2026-09-20T10:00:00+0\u00e900"))
    def side_field(d, key, val):
        lk, k, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s[key] = val; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_pubkey_non_ascii", lambda d: side_field(d, "public_key_hex", "a\u00e9a"))
    case("sidecar_signature_non_ascii", lambda d: side_field(d, "signature_hex", "a\u00e9a"))
    def signer_id_int(d):   # signed by the legitimate key holder through the library internals with a non-string signer_id
        from cra_evidence.signing import signed_payload, pack_digest
        keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key")); sk, pk = key
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-1", True, AW)); pack = os.path.join(d, "p.json"); lk.evidence_pack(pack)
        pj = json.load(open(pack)); side = {"signer_id": 5, "public_key_hex": pk, "alg": "Ed25519", "signed_pack_sha3": pack_digest(pj), "signed_utc": AW}
        side["signature_hex"] = sk.sign(signed_payload(side)).hex(); json.dump(side, open(sidecar_path(pack), "w"))
        json.dump({"5": pk}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("sidecar_signer_id_not_string", signer_id_int)
    def no_pack_sha3(d):   # pack without pack_sha3 next to an anchor record without anchored_pack_sha3: nothing may match "nothing"
        from cra_evidence.locker import _bind
        lk, key, pack, pk = build(d); lk.ledger.append(_bind({"kind": "cra_pack_anchor", "pack_file": "p.json"}))
        j = json.load(open(pack)); del j["pack_sha3"]; json.dump(j, open(pack, "w"))
    case("pack_without_sha3_anchor_without_hash", no_pack_sha3)
    def crlf(d):
        build(d); p = os.path.join(d, "l.jsonl"); t = open(p).read(); open(p, "w", newline="").write(t.replace("\n", "\r\n"))
    case("ledger_crlf", crlf)
    # ---- round 4: input hygiene must be ONE rule in the four (blank lines, terminators, integers, UTF-8, unreadable sidecar, field types)
    def ledger_extra_line(d, text):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p, encoding="utf-8").read().splitlines()
        open(p, "w", encoding="utf-8", newline="").write(lines[0] + "\n" + text + "\n" + "\n".join(lines[1:]) + "\n")
    for label, ch in (("nbsp", "\u00a0"), ("u2028", "\u2028"), ("nel_u0085", "\u0085"), ("bom_feff", "\ufeff")):
        case(f"ledger_blank_line_{label}", (lambda ch: lambda d: ledger_extra_line(d, ch))(ch))
    case("ledger_blank_line_ascii_tab_space", lambda d: ledger_extra_line(d, " \t "))
    case("ledger_blank_line_crcr", lambda d: ledger_extra_line(d, "\r\r"))     # "\r\r\n": one \r is the terminator, the other is content → unparsable, in all four
    def side_dangling(d):
        build(d); os.symlink(os.path.join(d, "nowhere.sig.json"), os.path.join(d, "p.json.sig.json"))
    case("sidecar_dangling_symlink", side_dangling)
    def cr_padding(d):   # a run of \r before the newline is CONTENT (one terminator only): the four must agree on what that content is
        build(d); p = os.path.join(d, "l.jsonl"); b = open(p, "rb").read(); i = b.index(b"\n"); open(p, "wb").write(b[:i] + b"\r\r\r" + b[i:])
    case("ledger_line_cr_padding", cr_padding)
    def bigint_in(path, key="x"):
        t = open(path, encoding="utf-8").read(); open(path, "w", encoding="utf-8").write(t[:1] + f'"{key}": 9007199254740993, ' + t[1:])
    def side_bigint(d):
        lk, key, pack, pk = build(d, sign=True); bigint_in(str(sidecar_path(pack))); json.dump({"acme-ci": key[1]}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("sidecar_integer_beyond_2p53", side_bigint)
    def tip_bigint(d):
        lk, key, pack, pk = build(d); bigint_in(os.path.join(d, "l.jsonl.tip.json")); return {"key": key[1]}
    case("tip_integer_beyond_2p53", tip_bigint)
    def pack_bigint(d):
        build(d); bigint_in(os.path.join(d, "p.json"))
    case("pack_integer_beyond_2p53", pack_bigint)
    def inject_byte(path):
        b = open(path, "rb").read(); open(path, "wb").write(b[:1] + b'"note": "\xff", ' + b[1:])
    def side_ff(d):
        lk, key, pack, pk = build(d, sign=True); inject_byte(str(sidecar_path(pack)))
    case("sidecar_not_utf8", side_ff)
    def side_ff_trust(d):
        lk, key, pack, pk = build(d, sign=True); inject_byte(str(sidecar_path(pack))); json.dump({"acme-ci": key[1]}, open(os.path.join(d, "trust.json"), "w")); return {"trust": os.path.join(d, "trust.json")}
    case("sidecar_not_utf8_with_trust", side_ff_trust)
    def tip_ff(d):
        lk, key, pack, pk = build(d); inject_byte(os.path.join(d, "l.jsonl.tip.json")); return {"key": key[1]}
    case("tip_not_utf8", tip_ff)
    def trust_ff(d):
        lk, key, pack, pk = build(d, sign=True); open(os.path.join(d, "trust.json"), "wb").write(b'{"acme-ci": "' + key[1].encode() + b'", "other": "\xff"}'); return {"trust": os.path.join(d, "trust.json")}
    case("trust_store_not_utf8", trust_ff)
    def ledger_ff(d):
        build(d); p = os.path.join(d, "l.jsonl"); b = open(p, "rb").read(); open(p, "wb").write(b.replace(b'"kind"', b'"k\xffnd"', 1))
    case("ledger_line_not_utf8", ledger_ff)
    def side_dir(d):
        build(d); os.makedirs(os.path.join(d, "p.json.sig.json"))
    case("sidecar_is_a_directory", side_dir)
    if os.geteuid() != 0:
        def side_mode0(d):
            lk, key, pack, pk = build(d, sign=True); os.chmod(sidecar_path(pack), 0)
        case("sidecar_unreadable", side_mode0)
    def lf_int(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["ledger_file"] = 1; json.dump(j, open(p, "w")); rehash(p)
    case("ledger_file_not_string", lf_int)
    def lf_slash(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["ledger_file"] = "l.jsonl/"; json.dump(j, open(p, "w")); rehash(p)
    case("ledger_file_trailing_slash", lf_slash)
    def scope_list(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["honest_scope"] = [j["honest_scope"]]; json.dump(j, open(p, "w")); rehash(p)
    case("honest_scope_is_a_list", scope_list)
    def tip_month_13(d):   # signed by the real log key: only its holder can produce it, the four must still agree
        from cra_evidence.signing import tip_payload
        lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl.tip.json"); t = json.load(open(p)); sk, pkh = key
        t["ts"] = "2026-13-01T00:00:00Z"; t["signature_hex"] = sk.sign(tip_payload(t["entries"], t["ledger_id"], t["tip_sha256"], t["ts"])).hex()
        json.dump(t, open(p, "w")); return {"key": key[1]}
    case("tip_ts_month_13_signed", tip_month_13)
    def pack_text(d, fn):   # rewrite the pack's TEXT (not its value) so the canonical form — and pack_sha3 — stays the same
        build(d); p = os.path.join(d, "p.json"); t = open(p, encoding="utf-8").read(); open(p, "w", encoding="utf-8").write(fn(t))
    case("pack_plus_number", lambda d: pack_text(d, lambda t: t.replace('"retention_years": 10', '"retention_years": +10', 1)))
    case("pack_leading_zero_number", lambda d: pack_text(d, lambda t: t.replace('"retention_years": 10', '"retention_years": 010', 1)))
    def raw_tab(d):   # a raw TAB byte inside a string: canonical form identical to the escaped one, so every digest still matches
        keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prod\tuct", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("prod\tuct", "CVE-2026-1", True, AW)); pack = os.path.join(d, "p.json"); lk.evidence_pack(pack)
        t = open(pack, encoding="utf-8").read(); assert "\\t" in t; open(pack, "w", encoding="utf-8").write(t.replace("\\t", "\t"))
    case("pack_raw_control_char_same_digest", raw_tab)
    case("pack_utf8_bom", lambda d: pack_text(d, lambda t: "\ufeff" + t))
    case("pack_lone_surrogate_escape", lambda d: pack_text(d, lambda t: t.replace('"product_version": "1"', '"product_version": "1\\ud800"', 1)))
    def side_missing_field(d):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); del s["signed_utc"]; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_missing_signed_utc", side_missing_field)
    def side_int_field(d):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s["alg"] = 7; json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_alg_not_string", side_int_field)
    def nested(n):
        v = {"x": 1}
        for _ in range(n):
            v = [v]
        return v
    def ledger_depth(d, total):   # a well-formed, correctly chained line whose TOTAL bracket depth is `total` (512 accepted, 513 refused, in all four)
        from cra_evidence.ledger import entry_hash
        lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl"); last = json.loads(open(p).read().splitlines()[-1])
        e = {"idx": last["idx"] + 1, "ts": last["ts"], "prev_hash": last["self_hash"], "data": {"deep": nested(total - 3)}}   # entry{data{deep[…{x}]}}: 3 levels + n arrays
        e["self_hash"] = entry_hash(e) if total <= 512 else "0" * 64
        line = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        from cra_evidence.canonical import nesting_depth; assert nesting_depth(line) == total, nesting_depth(line)
        open(p, "a").write(line + "\n")
    case("ledger_line_depth_512", lambda d: ledger_depth(d, 512))
    case("ledger_line_depth_513", lambda d: ledger_depth(d, 513))
    def pack_depth(d, total):     # pack alone (ledger removed) with a nested extra field, re-hashed: pack-json must agree at the bound
        build(d); os.remove(os.path.join(d, "l.jsonl")); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["deep"] = nested(total - 2)
        json.dump(j, open(p, "w")); from cra_evidence.canonical import nesting_depth; assert nesting_depth(open(p).read()) == total
        if total <= 512: rehash(p)
    case("pack_depth_512", lambda d: pack_depth(d, 512))
    case("pack_depth_513", lambda d: pack_depth(d, 513))
    # ---- round 6: keys named __proto__, hex decoders, CLI flag values (python CLI runs too on these: `cli` rows)
    def proto_in_record(d):
        from cra_evidence.locker import _bind
        lk, key, pack, pk = build(d); lk.ledger.append(_bind({"kind": "note", "__proto__": {"polluted": True}, "n": 1})); lk.evidence_pack(os.path.join(d, "p.json"))
    case("record_key_named___proto__", proto_in_record)
    def proto_in_pack(d):
        build(d); p = os.path.join(d, "p.json"); j = json.load(open(p)); j["__proto__"] = "x"; json.dump(j, open(p, "w")); rehash(p)
    case("pack_key_named___proto__", proto_in_pack)
    def pack_extra_key_untouched(d, key):   # extra top-level key, pack_sha3 NOT recomputed: must FAIL pack-sha3 in all four (JS dropped "__proto__" from its canonical form)
        lk, k, pack, pk = build(d, sign=True); t = open(pack, encoding="utf-8").read(); open(pack, "w", encoding="utf-8").write(t[:1] + f'"{key}": {{"evil": 1}}, ' + t[1:])
    case("pack_extra_key___proto___digest_untouched", lambda d: pack_extra_key_untouched(d, "__proto__"))
    case("pack_extra_key_zz_digest_untouched", lambda d: pack_extra_key_untouched(d, "zz_extra"))   # control
    def entry_extra_key_untouched(d, key):
        build(d); p = os.path.join(d, "l.jsonl"); lines = open(p, encoding="utf-8").read().splitlines()
        lines[0] = lines[0][:1] + f'"{key}": {{"evil": 1}}, ' + lines[0][1:]; open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    case("ledger_entry_extra_key___proto___hash_untouched", lambda d: entry_extra_key_untouched(d, "__proto__"))
    case("ledger_entry_extra_key_zz_hash_untouched", lambda d: entry_extra_key_untouched(d, "zz_extra"))   # control
    def side_sig(d, fn):
        lk, key, pack, pk = build(d, sign=True); s = json.load(open(sidecar_path(pack))); s["signature_hex"] = fn(s["signature_hex"]); json.dump(s, open(sidecar_path(pack), "w"))
    case("sidecar_sig_hex_space", lambda d: side_sig(d, lambda h: h[:2] + " " + h[2:]))
    case("sidecar_sig_hex_plus", lambda d: side_sig(d, lambda h: h[:1] + "+" + h[2:] if h[1] != "+" else h))
    case("sidecar_sig_hex_trailing_char", lambda d: side_sig(d, lambda h: h + "z"))
    case("sidecar_sig_hex_upper", lambda d: side_sig(d, lambda h: h.upper()))
    def tip_sig(d, fn):
        lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl.tip.json"); t = json.load(open(p)); t["signature_hex"] = fn(t["signature_hex"]); json.dump(t, open(p, "w")); return {"key": key[1]}
    case("tip_sig_hex_space", lambda d: tip_sig(d, lambda h: h[:2] + " " + h[2:]))
    case("tip_sig_hex_upper", lambda d: tip_sig(d, lambda h: h.upper()))
    def key_upper(d):
        lk, key, pack, pk = build(d); return {"key": key[1].upper()}
    case("cli_log_pubkey_upper", key_upper, cli=True)
    def key_empty(d):
        build(d); return {"key": ""}
    case("cli_log_pubkey_empty", key_empty, cli=True)
    def trust_empty(d):
        build(d, sign=True); return {"trust": ""}
    case("cli_trust_store_empty", trust_empty, cli=True)
    def ledger_flag_no_value(d):
        build(d); return {"raw_args": ["--ledger"]}
    case("cli_ledger_flag_without_value", ledger_flag_no_value, cli=True)
    def key_flag_no_value(d):
        build(d); return {"raw_args": ["--log-pubkey"]}
    case("cli_log_pubkey_flag_without_value", key_flag_no_value, cli=True)
    def trust_flag_no_value(d):
        build(d, sign=True); return {"raw_args": ["--trust-store"]}
    case("cli_trust_store_flag_without_value", trust_flag_no_value, cli=True)
    def side_signed_over(d, mutate):   # sidecar signed by the real key over a payload whose field is missing / null / not an instant
        from cra_evidence.signing import signed_payload, pack_digest, canonical_bytes
        keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key")); sk, pk = key
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-1", True, AW)); pack = os.path.join(d, "p.json"); lk.evidence_pack(pack)
        pj = json.load(open(pack)); side = {"signer_id": "acme-ci", "public_key_hex": pk, "alg": "Ed25519", "signed_pack_sha3": pack_digest(pj), "signed_utc": AW}
        mutate(side)
        payload = canonical_bytes({"kind": "cra_pack_sig/1", "signed_pack_sha3": side["signed_pack_sha3"], "signer_id": side["signer_id"],
                                   "signed_utc": side.get("signed_utc"), "public_key_hex": side["public_key_hex"], "alg": side.get("alg", "Ed25519")})
        side["signature_hex"] = sk.sign(payload).hex(); json.dump(side, open(sidecar_path(pack), "w"))
    def _del(k):
        def f(side): del side[k]
        return f
    case("sidecar_missing_signed_utc_signed_over_null", lambda d: side_signed_over(d, _del("signed_utc")))
    case("sidecar_signed_utc_null_signed", lambda d: side_signed_over(d, lambda s: s.__setitem__("signed_utc", None)))
    case("sidecar_signed_utc_not_instant_signed", lambda d: side_signed_over(d, lambda s: s.__setitem__("signed_utc", "yesterday")))
    def external_without_hash(d):
        from cra_evidence.locker import _bind
        lk, key, pack, pk = build(d)
        lk.ledger.append(_bind({"kind": "cra_sbom", "product_id": "prodotto-ü", "product_version": "1", "sbom": {}, "component_count": 0,
                                "resolved_components": 0, "sbom_floor_met": False, "source": {"format": "cyclonedx-json", "generator": "syft"}}))
        lk.evidence_pack(os.path.join(d, "p.json")); return {"require_sources": True}
    case("sbom_external_format_without_hash_required", external_without_hash)
    def unknown_flag(d):
        build_with_source(d, "absent"); return {"raw_args": ["--require-source"]}       # a typo must never verify PASS on an absent document
    case("cli_unknown_flag", unknown_flag, cli=True)
    def equals_form(d):   # --flag=value is accepted by argparse: the three accept it too, with the same verdict (tip checked → anchored)
        lk, key, pack, pk = build(d); return {"key": key[1], "raw_args": [f"--log-pubkey={key[1]}"]}   # the reference row takes `key`; the CLIs get both forms
    case("cli_flag_equals_form_ok", equals_form)
    def equals_form_wrong_key(d):
        build(d); return {"key": "11" * 32, "raw_args": ["--log-pubkey=" + "11" * 32]}
    case("cli_flag_equals_form_wrong_key", equals_form_wrong_key)
    def abbreviated(d):
        lk, key, pack, pk = build(d); return {"raw_args": ["--log", key[1]]}
    case("cli_abbreviated_flag", abbreviated, cli=True)
    def two_positionals(d):
        build(d); return {"raw_args": [os.path.join(d, "p.json")]}
    case("cli_two_positionals", two_positionals, cli=True)
    def symlinked_dir_dotdot(d):   # verify d/other/link/../p.json: the OS reads d/p.json; the ledger next to the REAL pack must be found by all four
        build(d); os.makedirs(os.path.join(d, "other")); os.makedirs(os.path.join(d, "real")); os.symlink(os.path.join(d, "real"), os.path.join(d, "other", "link"))
        return {"pack": os.path.join(d, "other", "link", "..", "p.json")}   # OS: d/real/.. = d → d/p.json; lexically: d/other/p.json (absent)
    case("pack_path_through_symlink_and_dotdot", symlinked_dir_dotdot)
    def trailing(d, suffix):   # "p.json/" is ENOTDIR for the OS: pack-json FAIL in all four (pathlib used to normalise it away in the reference)
        build(d); return {"pack": os.path.join(d, "p.json") + suffix}
    case("pack_path_trailing_slash", lambda d: trailing(d, "/"))
    case("pack_path_trailing_slash_dot", lambda d: trailing(d, "/."))
    def rechained_stale_record_sha3(d):   # record content changed, record_sha3 left stale, the WHOLE chain re-linked coherently: only the binding layer sees it
        from cra_evidence.ledger import entry_hash
        build(d); p = os.path.join(d, "l.jsonl"); es = [json.loads(l) for l in open(p).read().splitlines()]
        es[0]["data"]["vuln_id"] = "CVE-9999"; prev = "0" * 64
        for e in es:
            e["prev_hash"] = prev; e["self_hash"] = entry_hash(e); prev = e["self_hash"]
        open(p, "w").write("\n".join(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for e in es) + "\n")
    case("record_rechained_stale_record_sha3", rechained_stale_record_sha3)
    def flag_then_flag(d):
        build(d); return {"raw_args": ["--ledger", "--require-sources"]}   # a value that is a flag is a missing value: usage in all four
    case("cli_value_flag_followed_by_flag", flag_then_flag, cli=True)
    def dash_pack(d):
        build(d); return {"pack": "-"}
    case("cli_pack_is_a_dash", dash_pack, cli=True)
    def long_name(d):   # a 250-byte pack name is legal; its sidecar name (263 bytes) is not: lstat ENAMETOOLONG must be the same verdict in the four
        lk, key, pack, pk = build(d); newp = os.path.join(d, "p" * 246 + ".json"); os.rename(pack, newp)
        j = json.load(open(newp)); json.dump(j, open(newp, "w")); return {"pack": newp}
    case("pack_name_too_long_for_sidecar", long_name)
    if os.geteuid() != 0:
        def ledger_mode0(d):
            build(d); os.chmod(os.path.join(d, "l.jsonl"), 0)
        case("ledger_unreadable", ledger_mode0)
    if os.environ.get("CRA_ORACLE_BIG") == "1":
        def cr_padding_big(d):   # 66 MiB of \r before the newline: content above the bound in all four (Python must not buffer it whole)
            build(d); p = os.path.join(d, "l.jsonl"); b = open(p, "rb").read(); i = b.index(b"\n"); open(p, "wb").write(b[:i] + b"\r" * (66 << 20) + b[i:])
        case("ledger_line_cr_padding_66MiB", cr_padding_big)
        def blank_big(d, n):   # a run of spaces above the bound is refused in all four; at exactly the bound it is a blank line
            build(d); p = os.path.join(d, "l.jsonl"); lines = open(p).read().splitlines(); open(p, "w").write(lines[0] + "\n" + " " * n + "\n" + "\n".join(lines[1:]) + "\n")
        case("ledger_blank_line_exactly_64MiB", lambda d: blank_big(d, 64 << 20))
        case("ledger_blank_line_64MiB_plus_1", lambda d: blank_big(d, (64 << 20) + 1))   # 65 MiB line after the anchor: a scanner that stops silently would accept the prefix
        def big_line(d):
            build(d); open(os.path.join(d, "l.jsonl"), "a").write('{"idx": 3, "ts": "x", "prev_hash": "y", "data": {"pad": "' + "a" * (65 << 20) + '"}, "self_hash": "z"}\n')
        case("ledger_line_65MiB_after_anchor", big_line)
        def big_valid(d):   # a WELL-FORMED, correctly chained line above the cap (the producer refuses to write one: built by hand)
            from cra_evidence.ledger import entry_hash
            lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl"); last = json.loads(open(p).read().splitlines()[-1])
            e = {"idx": last["idx"] + 1, "ts": last["ts"], "prev_hash": last["self_hash"], "data": {"pad": "a" * (65 << 20)}}; e["self_hash"] = entry_hash(e)
            open(p, "a").write(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        case("ledger_line_65MiB_valid_record", big_valid)
        def exact(d, content_len):   # a well-formed, correctly chained line whose CONTENT (no terminator) is exactly content_len bytes
            from cra_evidence.ledger import entry_hash
            lk, key, pack, pk = build(d); p = os.path.join(d, "l.jsonl"); last = json.loads(open(p).read().splitlines()[-1])
            e = {"idx": last["idx"] + 1, "ts": last["ts"], "prev_hash": last["self_hash"], "data": {"pad": ""}}; e["self_hash"] = entry_hash(e)
            base = len(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
            e["data"]["pad"] = "a" * (content_len - base); e["self_hash"] = entry_hash(e)
            line = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True); assert len(line) == content_len
            open(p, "a").write(line + "\n")
        case("ledger_line_exactly_64MiB", lambda d: exact(d, 64 << 20))        # accepted by all four
        case("ledger_line_64MiB_plus_1", lambda d: exact(d, (64 << 20) + 1))   # refused by all four
    if os.geteuid() != 0:   # root reads anything: the case would not be a case
        def unreadable(d):
            build_with_source(d); sd = os.path.join(d, "l.jsonl.sources")
            for f in os.listdir(sd): os.chmod(os.path.join(sd, f), 0)
        case("sbom_source_unreadable", unreadable)
    return out


def run_cli(cmd, pack, opts):
    args = list(cmd) + [pack]
    if opts.get("ledger") is not None: args += ["--ledger", opts["ledger"]]
    if opts.get("trust") is not None: args += ["--trust-store", opts["trust"]]
    if opts.get("key") is not None: args += ["--log-pubkey", opts["key"]]
    if opts.get("require_sources"): args += ["--require-sources"]
    args += opts.get("raw_args", [])
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
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
        src_mtime = max(os.path.getmtime(os.path.join(ROOT, "verifiers", "go", f)) for f in os.listdir(os.path.join(ROOT, "verifiers", "go")) if f.endswith(".go"))
        if os.path.getmtime(gob) < src_mtime:   # a stale binary would measure yesterday's Go (round 6: it did) — refuse, never report it as today's
            print(f"Go binary {gob} is older than verifiers/go/*.go: rebuild it before measuring"); return 2
        vs["go"] = [gob]
    rb = os.environ.get("CRA_VERIFY_RUST") or (os.path.join(ROOT, "verifiers", "rust", "target", "release", "cra-verify") if os.path.exists(os.path.join(ROOT, "verifiers", "rust", "target", "release", "cra-verify")) else None)
    if rb:
        rs_dir = os.path.join(ROOT, "verifiers", "rust", "src")
        if os.path.getmtime(rb) < max(os.path.getmtime(os.path.join(rs_dir, f)) for f in os.listdir(rs_dir) if f.endswith(".rs")):
            print(f"Rust binary {rb} is older than verifiers/rust/src/*.rs: rebuild it before measuring"); return 2
        vs["rust"] = [rb]
    missing = require - set(vs)
    if missing:
        print("required verifiers absent:", sorted(missing)); return 2
    base = tempfile.mkdtemp()
    diverg, n = [], 0
    for name, pack, opts in cases(base):
        if opts.get("cli"):   # CLI boundary case: the Python CLI is a row like the others; every row must be a usage/unreadable error (exit 2, no verdict)
            rows = dict(vs); rows["python-cli"] = [sys.executable, "-m", "cra_evidence.cli", "verify"]
            exp = (None, "unreadable-input", None); row = {}
            for lang, cmd in rows.items():
                r = run_cli(cmd, pack, opts)
                row[lang] = (None, "unreadable-input" if r.get("exit") == 2 and "error" in r else f"exit {r.get('exit')}", None)
                if row[lang] != exp:
                    diverg.append((name, lang, exp, [], r))
            n += 1
            print(f"{name:32s} " + " ".join(f"{l}={row[l][1]}" for l in rows))
            continue
        trust, unreadable = None, False
        if opts.get("trust"):
            try:
                trust = load_trust_store(open(opts["trust"], encoding="utf-8").read())   # exactly what the CLI does
            except ValueError:
                unreadable = True
        if unreadable:   # an unreadable trust store is exit 2 and no verdict in every verifier
            exp, exp_fails, row = (None, "unreadable-input", None), [], {"python": (None, "unreadable-input", None)}
            for lang, cmd in vs.items():
                r = run_cli(cmd, pack, opts)
                row[lang] = (None, "unreadable-input" if r.get("exit") == 2 and "error" in r else f"exit {r.get('exit')}", None)
                if row[lang] != exp:
                    diverg.append((name, lang, exp, exp_fails, r))
            n += 1
            print(f"{name:32s} python={exp[1]:14s} " + " ".join(f"{l}={row[l][1]}" for l in vs))
            continue
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
