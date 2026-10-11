#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generative, DIFFERENTIAL bench for the closed schema of 2026-10-10 (CHANGELOG «closed schema: a field nobody defined is never
silent») across the four verifiers: Python reference (`python -m cra_evidence.cli verify`), JS, Go and Rust.

Method: the expected class of every mutation comes from the CHANGELOG's rule, never from a verifier; each mutation is fed to
every verifier that is available, and three things must hold — (1) every verifier gives the class the rule prescribes,
(2) all verifiers AGREE on (ok, authenticity, anchored, failing layers), (3) a key nobody defined is NAMED in the detail of
the layer that reads the object (producer-signature, pack-schema, ledger-schema).

Mutation classes and the rule behind each expected class:
  sidecar_unknown / sidecar_unknown_multi   .sig.json key nobody defined → FAIL, named in producer-signature (SIDECAR_KEYS)
  sidecar_legacy_no_fingerprint             fingerprint removed → the source's verdict (the rule must not reject too much)
  sidecar_dup_key                           duplicate key in the sidecar text → FAIL (strict acceptance profile)
  pack_unknown_resigned                     pack written with an extra key, re-hashed, re-signed, verified alone → FAIL, named in pack-schema
  pack_known_resigned                       the same pack with every key in the closed list → PASS
  ledger_unknown_appended                   an entry appended after the anchor with a top-level key nobody defined → FAIL, named in ledger-schema
  ledger_unknown_in_data_appended           the same key inside data (SRP_FIELDS rules) → PASS
  ledger_dup_key                            duplicate key in a ledger line → FAIL

Usage: python3 closed_schema_mutants.py [--quick | --n N] [--seed S] [--tree DIR] [--only python,js,go,rust] [--js PATH] [--out F]
  --tree points the bench at ANOTHER copy of the repository (positive control: the tree before the alignment must go red; its Go
  and Rust binaries are built there); --js overrides the Node verifier path (the CI test points it at a lax copy: the bench must go red).
Exit 0 = every mutation in class, every verifier agreeing, every foreign key named; 1 otherwise."""
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TREE = os.path.dirname(HERE)
sys.path.insert(0, DEFAULT_TREE)
from cra_evidence.canonical import sha3_hex  # noqa: E402
from cra_evidence.ledger import entry_hash  # noqa: E402
from cra_evidence.locker import CRAEvidenceLocker, _bind  # noqa: E402
from cra_evidence.signing import keygen, load_key, sign_pack, sidecar_path  # noqa: E402
from cra_evidence.vuln import VulnerabilityRecord  # noqa: E402

# the closed lists, copied from the CHANGELOG / SRP_FIELDS (not read from a verifier)
SIDECAR_KEYS = ("signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "signature_hex", "alg", "fingerprint")
PACK_KEYS = ("kind", "generated_utc", "legal_basis", "honest_scope", "product_id", "product_version", "retention", "retention_years",
             "ledger_file", "ledger_entries", "ledger_last_self_hash", "record_counts", "verification", "pack_sha3")
ENTRY_KEYS = ("idx", "ts", "data", "prev_hash", "self_hash")
KNOWN = set(SIDECAR_KEYS) | set(PACK_KEYS) | set(ENTRY_KEYS)
AW = "2026-09-01T00:00:00Z"

KNOWN_VARIANTS = ["Signer_id", "ALG", "signature_hex ", " signer_id", "Idx", "pack_sha3_", "retention_year", "ledger_files", "verifications"]
JS_SPECIAL = ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf"]
UNICODE_KEYS = ["clé", "ключ", "鍵", "\U0001F511", "ﬁeld", " "]
ODD_KEYS = ["", "0", "-1", "a b", "data.x", "a\"b", "a\\b", "a\nb", "\u0000", "x" * 40, "layer", "ok"]


def rand_key(rng):
    pool = rng.choice([KNOWN_VARIANTS, JS_SPECIAL, UNICODE_KEYS, ODD_KEYS, None, None])
    k = rng.choice(pool) if pool else "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(1, 12)))
    return k if k not in KNOWN else k + "_x"


def rand_value(rng, depth=0):
    c = rng.randint(0, 7 if depth < 2 else 4)
    if c == 0:
        return None
    if c == 1:
        return rng.choice([True, False])
    if c == 2:
        return rng.choice([0, -1, 1, 2 ** 53 - 1, rng.randint(-10 ** 6, 10 ** 6)])
    if c in (3, 4):
        return rng.choice(["", "x", "é", "a\"b", "日本", "\U0001F600", "0" * 64])
    if c == 5:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {rand_key(rng): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))}


# ---------------------------------------------------------------- sources: directories with pack + ledger (+ sidecar)
def make_sources(root):
    out = {}
    def mk(name, sign):
        d = os.path.join(root, name); os.makedirs(d)
        keygen(os.path.join(d, "k.key")); key = load_key(os.path.join(d, "k.key"))
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "prodotto-ü", "1", tip_key=key)
        lk.record_vulnerability(VulnerabilityRecord("prodotto-ü", "CVE-2026-1", True, AW, details={"note": "accénti \U0001F9FE", "n": 2 ** 53 - 1}))
        pack = os.path.join(d, "p.json"); lk.evidence_pack(pack)
        if sign:
            sign_pack(pack, key, "acme-ci")
        out[name] = d
    mk("signed", True)
    mk("unsigned", False)
    return out


def copy_source(src, dst):
    shutil.copytree(src, dst)
    return os.path.join(dst, "p.json")


def rehash(pack):
    with open(pack, encoding="utf-8") as f:
        p = json.load(f)
    p.pop("pack_sha3"); p["pack_sha3"] = sha3_hex(p)
    with open(pack, "w", encoding="utf-8") as f:
        json.dump(p, f, ensure_ascii=False)


def edit_json(path, fn):
    with open(path, encoding="utf-8") as f:
        o = json.load(f)
    fn(o)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(o, f, ensure_ascii=False)


# ---------------------------------------------------------------- mutations: (class, expected ok, named_layer, named_text) or None
def m_sidecar_unknown(rng, p, d, signed):
    if not signed:
        return None
    k = rand_key(rng); edit_json(str(sidecar_path(p)), lambda sd: sd.__setitem__(k, rand_value(rng)))
    return "sidecar_unknown", False, "producer-signature", "sidecar field not in the closed schema: " + k


def m_sidecar_unknown_multi(rng, p, d, signed):
    if not signed:
        return None
    ks = []
    while len(ks) < rng.randint(2, 3):
        k = rand_key(rng)
        if k not in ks:
            ks.append(k)
    if sum(len(k) + 2 for k in ks) > 118:
        return None
    edit_json(str(sidecar_path(p)), lambda sd: [sd.__setitem__(k, rand_value(rng)) for k in ks])
    return "sidecar_unknown_multi", False, "producer-signature", "sidecar field not in the closed schema: " + ", ".join(sorted(ks))


def m_sidecar_legacy(rng, p, d, signed):
    if not signed:
        return None
    edit_json(str(sidecar_path(p)), lambda sd: sd.pop("fingerprint", None))
    return "sidecar_legacy_no_fingerprint", True, None, None


def m_sidecar_dup_key(rng, p, d, signed):
    if not signed:
        return None
    sp = str(sidecar_path(p))
    with open(sp, encoding="utf-8") as f:
        txt = f.read().rstrip().rstrip("}")
    with open(sp, "w", encoding="utf-8") as f:
        f.write(txt + ', "%s": "dup"}' % rng.choice(["signer_id", "alg", "signed_utc"]))
    return "sidecar_dup_key", False, None, None


def _resign(p, d, signed, extra):
    os.remove(os.path.join(d, "l.jsonl"))   # the pack alone: the ledger would fail the anchor for the new digest anyway
    for f_ in os.listdir(d):
        if f_.startswith("l.jsonl"):
            shutil.rmtree(os.path.join(d, f_), ignore_errors=True) if os.path.isdir(os.path.join(d, f_)) else os.remove(os.path.join(d, f_))
    edit_json(p, lambda j: j.update(extra)); rehash(p)
    if signed:
        sign_pack(p, load_key(os.path.join(d, "k.key")), "acme-ci")


def m_pack_unknown_resigned(rng, p, d, signed):
    k = rand_key(rng); _resign(p, d, signed, {k: rand_value(rng)})
    return "pack_unknown_resigned", False, "pack-schema", "unknown top-level field(s): " + k


def m_pack_known_resigned(rng, p, d, signed):
    _resign(p, d, signed, {})
    return "pack_known_resigned", bool(signed), None, None   # an unsigned pack alone has no anchor and no signature: FAIL for THAT reason (agreement only)


def _append(p, d, top_extra, data_extra):
    lp = os.path.join(d, "l.jsonl")
    with open(lp, encoding="utf-8") as f:
        last = json.loads(f.read().splitlines()[-1])
    e = {"idx": last["idx"] + 1, "ts": last["ts"], "prev_hash": last["self_hash"], "data": _bind({"kind": "note", **data_extra})}
    e.update(top_extra); e["self_hash"] = entry_hash(e)
    with open(lp, "a", encoding="utf-8") as f:
        f.write(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
    return e["idx"]


def m_ledger_unknown_appended(rng, p, d, signed):
    k = rand_key(rng); idx = _append(p, d, {k: rand_value(rng)}, {})
    return "ledger_unknown_appended", False, "ledger-schema", f"1 entry(ies) with a top-level field outside the closed schema, first at idx {idx}: {k}"


def m_ledger_unknown_in_data_appended(rng, p, d, signed):
    k = rand_key(rng); _append(p, d, {}, {k: rand_value(rng)})
    return "ledger_unknown_in_data_appended", True, None, None


def m_ledger_dup_key(rng, p, d, signed):
    lp = os.path.join(d, "l.jsonl")
    with open(lp, encoding="utf-8") as f:
        lines = f.read().splitlines()
    lines[0] = lines[0].rstrip().rstrip("}") + ',"ts":"dup"}'
    with open(lp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return "ledger_dup_key", False, None, None


MAKERS = [m_sidecar_unknown, m_sidecar_unknown_multi, m_sidecar_legacy, m_sidecar_dup_key, m_pack_unknown_resigned, m_pack_known_resigned,
          m_ledger_unknown_appended, m_ledger_unknown_in_data_appended, m_ledger_dup_key]


# ---------------------------------------------------------------- the verifiers of a tree
def discover(tree, tmp, only=None, js_override=None):
    """name -> (cmd, cwd, env). Python runs the CLI from the tree (so THAT tree's package is the one measured); Go and Rust are built there."""
    v = {"python": ([sys.executable, "-m", "cra_evidence.cli", "verify"], tree, {"PYTHONPATH": tree}),
         "js": (["node", js_override or os.path.join(tree, "verifiers", "js", "cra-verify.mjs")], None, {})}
    if shutil.which("go"):
        out = os.path.join(tmp, "cra-verify-go")
        r = subprocess.run(["go", "build", "-o", out, "."], cwd=os.path.join(tree, "verifiers", "go"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("go build failed: " + r.stderr[:400])
        v["go"] = ([out], None, {})
    if shutil.which("cargo"):
        r = subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=os.path.join(tree, "verifiers", "rust"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("cargo build failed: " + r.stderr[:400])
        v["rust"] = ([os.path.join(tree, "verifiers", "rust", "target", "release", "cra-verify")], None, {})
    if only:
        v = {k: x for k, x in v.items() if k in only}
    return v


def run_one(cmd, cwd, env, path):
    try:
        out = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=120, cwd=cwd, env={**os.environ, **env})
        r = json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return ("NONJSON/CRASH",), None
    fails = tuple(sorted(ly["layer"] for ly in r.get("layers", []) if ly.get("status") == "FAIL"))
    return (r.get("ok"), r.get("authenticity"), r.get("anchored"), fails), r


def layer_detail(receipt, layer):
    for ly in receipt.get("layers", []):
        if ly.get("layer") == layer:
            return ly.get("detail") or ""
    return ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=None, help="number of mutations (default 600; --quick = 90)")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seed", type=int, default=20261011)
    ap.add_argument("--tree", default=DEFAULT_TREE)
    ap.add_argument("--only", default=None)
    ap.add_argument("--js", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)
    n = a.n or (90 if a.quick else 600)
    rng = random.Random(a.seed)
    tmp = tempfile.mkdtemp(prefix="cra-closed-mutants-")
    try:
        srcs = make_sources(os.path.join(tmp, "src"))
        verifiers = discover(os.path.abspath(a.tree), tmp, set(a.only.split(",")) if a.only else None, a.js)
        print(f"closed-schema bench (cra-evidence): {n} mutations from {len(srcs)} sources, seed {a.seed}, tree {a.tree}")
        print(f"verifiers: {sorted(verifiers)}")
        out_of_class = {k: 0 for k in verifiers}; silent = {k: 0 for k in verifiers}; unnamed = {k: 0 for k in verifiers}
        disagree = 0; per_class = {}; failures = []
        made, i = 0, 0
        while made < n:
            maker = MAKERS[i % len(MAKERS)]; i += 1
            src_name, src_dir = rng.choice(list(srcs.items()))
            case_dir = os.path.join(tmp, "m%d" % made)
            p = copy_source(src_dir, case_dir)
            r = maker(rng, p, case_dir, src_name == "signed")
            if r is None:
                shutil.rmtree(case_dir, ignore_errors=True)
                continue
            cls, expected_ok, layer, text = r
            name = f"{cls}@{src_name}#{made}"
            made += 1
            res = {k: run_one(cmd, cwd, env, p) for k, (cmd, cwd, env) in verifiers.items()}
            tuples = {k: t for k, (t, _) in res.items()}
            pc = per_class.setdefault(cls, {"n": 0, "bad": 0}); pc["n"] += 1
            bad = False
            if len(set(tuples.values())) != 1:
                disagree += 1; bad = True
            for k, (t, rec) in res.items():
                ok = t[0] if len(t) > 1 else None
                if ok is not expected_ok:
                    out_of_class[k] += 1; bad = True
                    if expected_ok is False and ok is True:
                        silent[k] += 1
                if layer and (rec is None or text not in layer_detail(rec, layer)):
                    unnamed[k] += 1; bad = True
            if bad:
                pc["bad"] += 1
                if len(failures) < 40:
                    failures.append({"mutation": name, "expected_ok": expected_ok, "results": {k: list(t) for k, t in tuples.items()}, "named": [layer, text],
                                     "details": {k: layer_detail(rec, layer) for k, (_, rec) in res.items() if rec and layer}})
            if not a.keep:
                shutil.rmtree(case_dir, ignore_errors=True)
        summary = {"mutations": n, "sources": len(srcs), "seed": a.seed, "tree": os.path.abspath(a.tree), "verifiers": sorted(verifiers),
                   "disagreements": disagree, "out_of_class": out_of_class, "silent_pass_on_expected_fail": silent, "unnamed_foreign_key": unnamed,
                   "per_class": per_class, "first_failures": failures}
        print(json.dumps({k: v for k, v in summary.items() if k != "first_failures"}, indent=1, ensure_ascii=False))
        for f_ in failures[:12]:
            print("  [BAD]", f_["mutation"], "expected ok", f_["expected_ok"], f_["results"], "named", f_["named"])
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=1, ensure_ascii=False)
        ok = disagree == 0 and not any(out_of_class.values()) and not any(unnamed.values())
        print("RESULT:", "GREEN" if ok else "RED")
        if a.keep:
            print("corpus kept in", tmp)
        return 0 if ok else 1
    finally:
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
