#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generative bench of the 0.6.0 receipt (spec/RECEIPT.md): admission, refusal_class, states, policy.

Three base packs (signed with a signed tip and a stored source document; unsigned and anchored; the committed
examples/self_evidence) are mutated — every top-level key of the pack removed or given each of 12 values of another
type, 6 unknown top-level keys, every sidecar key removed / retyped / an unknown one added, the sidecar replaced by a
directory, the ledger removed / cut / an entry with an unknown key / a byte changed / a directory / chmod 000, the tip
removed / retyped / another key, the stored source document removed / changed / a directory / chmod 000 — and each file
is verified under several verifier inputs (trust store: none, right, wrong key, other signer; trusted log key: none,
right, wrong; --require-sources; --ledger given), and a share of them with `cryptography` made unimportable.

Controls (each violation is printed; exit 1 if any):
  C1 the receipt is closed: admission ∈ 3 values; refusal_class iff refused; states/policy iff admitted; exactly the five
     subjects; each state and reason in the closed list of its subject; policy.unmet ordered, in the list.
  C2 `ok` equation (spec §4): admitted ∧ no contradicted ∧ no instrument_failure/unreadable element ∧ policy.met.
  C3 assessed:false ⇒ no contradicted ∧ an instrument_failure; a contradicted ⇒ assessed:true.
  C4 no `verified` on a check not run, and no `contradicted` without a check that ran and failed — judged by the
     INDEPENDENT JS verifier's layers on the same file and inputs (runs with cryptography removed are not compared).
  C5 pins: on the same file, the three trust-store inputs give the same set of contradicted subjects; a trust store that
     does not hold the key never gives producer `verified`; the right trust store never lowers the producer state.
  C6 an unknown top-level key added to an admitted pack is refused with `unknown_member`.
  C7 (with --old <0.5.1 tree>) every 0.5.1 field is equal on every input, except the declared change (spec §6).

--sabotage NAME patches the verifier under test; each sabotage must turn the bench red (the bench can fail).
Usage: python verifiers/states_bench.py [--old <tree>] [--sabotage NAME] [--quick] [--no-js] [--json out]"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs")
FIX = os.path.join(ROOT, "tests", "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json")
OLD_FIELDS = ("ok", "assessed", "authenticity", "anchored", "layers", "pack_sha3")
SABOTAGES = ("precedence_reversed", "self_asserted_is_verified", "key_not_given_is_verified", "instrument_is_contradicted",
             "not_anchored_is_verified", "hash_only_is_verified", "refused_with_states", "unknown_member_admitted")
TYPED = [None, True, False, 0, -1, 2 ** 60, "", "x", [], {}, ["x"], {"x": 1}]

# ── runner: executed in a SUBPROCESS with the tree under test first on sys.path ──────────────────────────────────────
RUNNER = r'''
import json, sys
root, sab = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
import importlib
VP = importlib.import_module("cra_evidence.verify_pack"); S = importlib.import_module("cra_evidence.signing")   # the package exports a function named verify_pack
def _ed_missing():
    raise ImportError("cryptography made unimportable by the bench")
real_ed = S._ed
if sab != "-" and hasattr(VP, "_fold"):
    real_fold, real_with = VP._fold, VP._with_admission
    def swap(els, a, b):
        return [b if (e[0], e[1]) == a else e for e in els]
    if sab == "precedence_reversed":
        def f(els):
            if not els: return real_fold(els)
            rank = lambda e: 3 if e[0] == "contradicted" else 2 if e[1] == "instrument_failure" else 1 if e[0] == "not_evaluated" else 0
            o = real_fold(els); o["state"] = min(els, key=rank)[0]; return o
    else:
        pair = {"self_asserted_is_verified": (("not_evaluated", "self_asserted"), ("verified", None)),
                "key_not_given_is_verified": (("not_evaluated", "key_not_given"), ("verified", None)),
                "instrument_is_contradicted": (("not_evaluated", "instrument_failure"), ("contradicted", "signature_invalid")),
                "not_anchored_is_verified": (("contradicted", "not_anchored"), ("verified", None)),
                "hash_only_is_verified": (("not_evaluated", "hash_only"), ("verified", None))}.get(sab)
        f = (lambda els: real_fold(swap(els, *pair))) if pair else real_fold
    VP._fold = f
    if sab == "refused_with_states":
        def w(r, adm, cls=None, states=None, policy=None):
            return real_with(r, adm, cls, states if adm != "refused" else {"sealed_content": {"state": "verified", "reasons": []}}, policy)
        VP._with_admission = w
    if sab == "unknown_member_admitted":
        def w2(r, adm, cls=None, states=None, policy=None):
            if adm == "refused" and cls == "unknown_member":
                return real_with(r, "admitted", None, {k: {"state": "verified", "reasons": []} for k in VP.SUBJECTS}, {"met": True, "unmet": []})
            return real_with(r, adm, cls, states, policy)
        VP._with_admission = w2
for line in sys.stdin:
    c = json.loads(line)
    S._ed = _ed_missing if c["nocrypto"] else real_ed
    try:
        r = VP.verify_pack(c["pack"], c.get("ledger"), c.get("trust"), c.get("key"), require_sources=c.get("req", False))
    except Exception as e:
        r = {"exception": type(e).__name__ + ": " + str(e)[:200]}
    print(json.dumps(r, sort_keys=True), flush=True)
'''


def cli(args, cwd=None, ok_codes=(0,)):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ROOT
    p = subprocess.run([sys.executable, "-B", "-m", "cra_evidence.cli"] + args, capture_output=True, text=True, env=env, cwd=cwd)
    if p.returncode not in ok_codes:
        raise SystemExit(f"bench base build failed: cra {' '.join(args)}: rc {p.returncode} {p.stderr[-400:]}")
    return json.loads(p.stdout) if p.stdout.strip() else None


def build_bases(work):
    """full: SBOM ingested (source stored), pack, signed sidecar, signed tip; unsigned: anchored only; example: the
    committed examples/self_evidence (signed, source stored, no tip)."""
    bases = {}
    d = os.path.join(work, "base_full"); os.makedirs(d)
    tip = cli(["keygen", os.path.join(d, "tip.key")]); sig = cli(["keygen", os.path.join(d, "sig.key")])
    led = os.path.join(d, "cra.ledger.jsonl"); pack = os.path.join(d, "cra_pack.json")
    com = ["--ledger", led, "--product", "p", "--version", "1", "--tip-key", os.path.join(d, "tip.key")]
    cli(["sbom"] + com + ["--from-cyclonedx", FIX]); cli(["pack"] + com + ["--out", pack])
    cli(["sign", pack, "--key", os.path.join(d, "sig.key"), "--signer-id", "ci"])
    os.remove(os.path.join(d, "tip.key")); os.remove(os.path.join(d, "sig.key"))
    bases["full"] = {"dir": d, "signer": "ci", "pub": sig["public_key_hex"], "log": tip["public_key_hex"]}
    d = os.path.join(work, "base_unsigned"); os.makedirs(d)
    led = os.path.join(d, "cra.ledger.jsonl"); pack = os.path.join(d, "cra_pack.json")
    com = ["--ledger", led, "--product", "p", "--version", "1"]
    cli(["sbom"] + com + ["--installed"], ok_codes=(0, 1))   # an empty floor exits 1 and is recorded
    cli(["pack"] + com + ["--out", pack])
    bases["unsigned"] = {"dir": d, "signer": "ci", "pub": sig["public_key_hex"], "log": tip["public_key_hex"]}
    d = os.path.join(work, "base_example"); shutil.copytree(os.path.join(ROOT, "examples", "self_evidence"), d)
    t = json.load(open(os.path.join(d, "trust.json"))); (sid, pub), = t.items()
    os.remove(os.path.join(d, "trust.json"))
    bases["example"] = {"dir": d, "signer": sid, "pub": pub, "log": tip["public_key_hex"]}
    return bases


def jload(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def jdump(o, p):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(o, f)


def mutations(base, quick):
    """(name, function(dir)) pairs; each function changes a fresh copy of the base directory."""
    out = [("intact", lambda d: None)]
    pk = jload(os.path.join(base["dir"], "cra_pack.json"))
    typed = TYPED[:4] if quick else TYPED
    for k in sorted(pk):
        def drop(d, k=k):
            p = jload(os.path.join(d, "cra_pack.json")); del p[k]; jdump(p, os.path.join(d, "cra_pack.json"))
        out.append((f"pack-del-{k}", drop))
        for i, v in enumerate(typed):
            def ret(d, k=k, v=v):
                p = jload(os.path.join(d, "cra_pack.json")); p[k] = v; jdump(p, os.path.join(d, "cra_pack.json"))
            out.append((f"pack-type-{k}-{i}", ret))
    for u in (["x"] if quick else ["x", "Kind", "kind ", "pack_sha3_", "signature", "ledger"]):
        def add(d, u=u):
            p = jload(os.path.join(d, "cra_pack.json")); p[u] = 1; jdump(p, os.path.join(d, "cra_pack.json"))
        out.append((f"pack-unknown-{u}", add))
    sp = os.path.join(base["dir"], "cra_pack.json.sig.json")
    if os.path.exists(sp):
        side = jload(sp)
        for k in sorted(side):
            def sdrop(d, k=k):
                p = os.path.join(d, "cra_pack.json.sig.json"); s = jload(p); del s[k]; jdump(s, p)
            out.append((f"sig-del-{k}", sdrop))
            for i, v in enumerate(typed[:6]):
                def sret(d, k=k, v=v):
                    p = os.path.join(d, "cra_pack.json.sig.json"); s = jload(p); s[k] = v; jdump(s, p)
                out.append((f"sig-type-{k}-{i}", sret))
        def sunk(d):
            p = os.path.join(d, "cra_pack.json.sig.json"); s = jload(p); s["x_unknown"] = "x"; jdump(s, p)
        def sflip(d):
            p = os.path.join(d, "cra_pack.json.sig.json"); s = jload(p)
            s["signature_hex"] = ("0" if s["signature_hex"][0] != "0" else "1") + s["signature_hex"][1:]; jdump(s, p)
        def sdir(d):
            p = os.path.join(d, "cra_pack.json.sig.json"); os.remove(p); os.mkdir(p)
        def srm(d):
            os.remove(os.path.join(d, "cra_pack.json.sig.json"))
        def sjunk(d):
            open(os.path.join(d, "cra_pack.json.sig.json"), "w").write("{not json")
        def sperm(d):
            os.chmod(os.path.join(d, "cra_pack.json.sig.json"), 0)
        out += [("sig-unknown", sunk), ("sig-flip", sflip), ("sig-dir", sdir), ("sig-rm", srm), ("sig-junk", sjunk), ("sig-chmod0", sperm)]
    def lrm(d):
        os.remove(os.path.join(d, "cra.ledger.jsonl"))
    def lcut(d):
        p = os.path.join(d, "cra.ledger.jsonl"); ls = open(p, "rb").read().splitlines(True); open(p, "wb").write(b"".join(ls[:-1]))
    def ltorn(d):
        p = os.path.join(d, "cra.ledger.jsonl"); b = open(p, "rb").read(); open(p, "wb").write(b[:-7])
    def lunk(d):
        p = os.path.join(d, "cra.ledger.jsonl"); ls = open(p, encoding="utf-8").read().splitlines()
        e = json.loads(ls[0]); e["x_unknown"] = 1; ls[0] = json.dumps(e); open(p, "w", encoding="utf-8").write("\n".join(ls) + "\n")
    def lbyte(d):
        p = os.path.join(d, "cra.ledger.jsonl"); ls = open(p, encoding="utf-8").read().splitlines()
        e = json.loads(ls[0]); e["data"]["product_id"] = "other"; ls[0] = json.dumps(e); open(p, "w", encoding="utf-8").write("\n".join(ls) + "\n")
    def ldir(d):
        p = os.path.join(d, "cra.ledger.jsonl"); os.remove(p); os.mkdir(p)
    def lperm(d):
        os.chmod(os.path.join(d, "cra.ledger.jsonl"), 0)
    def lappend(d):   # an entry after the anchor: chain still valid, the tip (if any) names fewer entries
        sys.path.insert(0, ROOT)
        from cra_evidence.ledger import Ledger
        Ledger(os.path.join(d, "cra.ledger.jsonl")).append({"kind": "note", "x": 1})
    def rechain(d, change):
        """change(entries) edits entry data in place; the chain is then recomputed (a consistent rewrite)."""
        sys.path.insert(0, ROOT)
        from cra_evidence.ledger import entry_hash
        p = os.path.join(d, "cra.ledger.jsonl"); es = [json.loads(x) for x in open(p, encoding="utf-8").read().splitlines() if x.strip()]
        change(es)
        prev = "0" * 64
        for e in es:
            e["prev_hash"] = prev; e["self_hash"] = entry_hash({k: v for k, v in e.items() if k != "self_hash"}); prev = e["self_hash"]
        open(p, "w", encoding="utf-8").write("".join(json.dumps(e) + "\n" for e in es))
    def lunbound(d):     # data changed, record_sha3 left stale, chain recomputed
        def ch(es):
            es[0]["data"]["product_id"] = "other"
        rechain(d, ch)
    def lsrcbad(d):      # a source hash that is not hex, record re-bound, chain recomputed
        sys.path.insert(0, ROOT)
        from cra_evidence.canonical import sha3_hex
        def ch(es):
            for e in es:
                src = e["data"].get("source")
                if e["data"].get("kind") == "cra_sbom" and isinstance(src, dict):
                    src["sha256"] = "Z" * 64
                    e["data"]["record_sha3"] = sha3_hex({k: v for k, v in e["data"].items() if k != "record_sha3"})
        rechain(d, ch)
    def rehash(d, key, val):
        sys.path.insert(0, ROOT)
        from cra_evidence.canonical import sha3_hex
        p = jload(os.path.join(d, "cra_pack.json")); p[key] = val
        p["pack_sha3"] = sha3_hex({k: v for k, v in p.items() if k != "pack_sha3"}); jdump(p, os.path.join(d, "cra_pack.json"))
    for key, val in (("verification", {"chain_ok": False, "record_digests_bound": True}), ("verification", {}), ("ledger_entries", 999),
                     ("ledger_last_self_hash", "0" * 64), ("product_id", "re-hashed"), ("ledger_file", "../x"), ("honest_scope", "none")):
        out.append((f"pack-rehash-{key}-{json.dumps(val)[:12]}", lambda d, key=key, val=val: rehash(d, key, val)))
    out += [("ledger-unbound-rechained", lunbound), ("ledger-src-hash-bad", lsrcbad)]
    out += [("ledger-rm", lrm), ("ledger-cut", lcut), ("ledger-torn", ltorn), ("ledger-unknown", lunk), ("ledger-byte", lbyte),
            ("ledger-dir", ldir), ("ledger-chmod0", lperm), ("ledger-append", lappend)]
    tp = os.path.join(base["dir"], "cra.ledger.jsonl.tip.json")
    if os.path.exists(tp):
        tip = jload(tp)
        for k in sorted(tip):
            def tret(d, k=k):
                p = os.path.join(d, "cra.ledger.jsonl.tip.json"); s = jload(p); s[k] = 7; jdump(s, p)
            out.append((f"tip-type-{k}", tret))
        def trm(d):
            os.remove(os.path.join(d, "cra.ledger.jsonl.tip.json"))
        def tjunk(d):
            open(os.path.join(d, "cra.ledger.jsonl.tip.json"), "w").write("[")
        def tperm(d):
            os.chmod(os.path.join(d, "cra.ledger.jsonl.tip.json"), 0)
        out += [("tip-rm", trm), ("tip-junk", tjunk), ("tip-chmod0", tperm)]
    sd = os.path.join(base["dir"], "cra.ledger.jsonl.sources")
    if os.path.isdir(sd) and os.listdir(sd):
        def srcf(d):
            s = os.path.join(d, "cra.ledger.jsonl.sources"); return os.path.join(s, sorted(os.listdir(s))[0])
        def xrm(d):
            os.remove(srcf(d))
        def xchg(d):
            open(srcf(d), "ab").write(b" ")
        def xdir(d):
            f = srcf(d); os.remove(f); os.mkdir(f)
        def xperm(d):
            os.chmod(srcf(d), 0)
        out += [("source-rm", xrm), ("source-changed", xchg), ("source-dir", xdir), ("source-chmod0", xperm)]
    return out


def inputs(base, d, quick):
    """(label, case) pairs: the verifier inputs for one mutated directory."""
    pack, led = os.path.join(d, "cra_pack.json"), os.path.join(d, "cra.ledger.jsonl")
    trusts = {"none": None, "right": {base["signer"]: base["pub"]}, "wrongkey": {base["signer"]: "ab" * 32},
              "othersigner": {"someone-else": base["pub"]}}
    keys = {"nokey": None, "rightkey": base["log"], "wrongkey": "cd" * 32}
    combos = []
    for t in trusts:
        for k in keys:
            for req in (False, True):
                for explicit in (False, True):
                    if quick and (req or explicit) and not (t == "right" and k == "rightkey"):
                        continue
                    combos.append((f"{t}/{k}/{'req' if req else '-'}/{'L' if explicit else '-'}",
                                   {"pack": pack, "ledger": led if explicit else None, "trust": trusts[t], "key": keys[k], "req": req}))
    return combos


def run_receipts(root, cases, sabotage="-"):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, "-B", "-c", RUNNER, root, sabotage], input="".join(json.dumps(c) + "\n" for c in cases),
                       capture_output=True, text=True, env=env)
    if p.returncode != 0:
        raise SystemExit(f"runner failed ({root}): {p.stderr[-800:]}")
    out = [json.loads(x) for x in p.stdout.splitlines()]
    if len(out) != len(cases):
        raise SystemExit(f"runner returned {len(out)} receipts for {len(cases)} cases")
    return out


def run_js(case, work):
    args = ["node", JS, case["pack"]]
    if case.get("ledger"):
        args += ["--ledger", case["ledger"]]
    if case.get("trust") is not None:
        tf = os.path.join(work, "trust_js.json"); jdump(case["trust"], tf); args += ["--trust-store", tf]
    if case.get("key"):
        args += ["--log-pubkey", case["key"]]
    if case.get("req"):
        args += ["--require-sources"]
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout)
    except ValueError:
        return None


def controls(case, r, js, import_vp):
    """The violations of C1–C4 and C6 for one receipt."""
    VP = import_vp
    v = []
    if "exception" in r:
        return ["C1 exception: " + r["exception"]]
    adm = r.get("admission")
    if adm not in ("admitted", "refused", "not_evaluated"):
        return [f"C1 admission {adm!r}"]
    if r.get("states_vocabulary") != "cra-evidence/states-1":
        v.append("C1 states_vocabulary")
    if adm == "refused":
        if r.get("refusal_class") not in VP.REFUSAL_CLASSES:
            v.append(f"C1 refusal_class {r.get('refusal_class')!r}")
        if r.get("states") is not None or r.get("policy") is not None:
            v.append("C1 refused with states/policy")
        if r["ok"]:
            v.append("C2 refused and ok")
        return v
    if adm == "not_evaluated":
        if r.get("states") is not None or r.get("refusal_class") is not None or r["ok"] or r["assessed"]:
            v.append("C1 not_evaluated shape")
        return v
    if r.get("refusal_class") is not None:
        v.append("C1 admitted with a refusal_class")
    st, pol = r.get("states"), r.get("policy")
    if not isinstance(st, dict) or sorted(st) != sorted(VP.SUBJECTS):
        return v + [f"C1 subjects {sorted(st) if isinstance(st, dict) else st!r}"]
    elements = []
    for s, o in st.items():
        con, ne = VP.REASONS[s]
        if set(o) - {"state", "reasons", "detail"} or o.get("state") not in VP.STATES or not isinstance(o.get("reasons"), list):
            v.append(f"C1 {s} shape {o}")
            continue
        for rs in o["reasons"]:
            if rs not in con + ne:
                v.append(f"C1 {s} reason {rs!r} outside the closed list")
            elements.append((s, rs))
        if o["state"] == "verified" and o["reasons"]:
            v.append(f"C1 {s} verified with reasons")
        if o["state"] == "contradicted" and not any(x in con for x in o["reasons"]):
            v.append(f"C1 {s} contradicted without a contradicted reason")
        if o["state"] == "not_evaluated" and (not o["reasons"] or any(x in con for x in o["reasons"])):
            v.append(f"C1 {s} not_evaluated with a contradicted reason (precedence)")
    if not isinstance(pol, dict) or set(pol) != {"met", "unmet"} or pol["met"] != (not pol["unmet"]) \
            or pol["unmet"] != [u for u in VP.POLICY_UNMET if u in pol["unmet"]] or len(set(pol["unmet"])) != len(pol["unmet"]):
        v.append(f"C1 policy {pol}")
        return v
    contradicted = [s for s, o in st.items() if o["state"] == "contradicted"]
    failclosed = [x for _, x in elements if x in VP.FAIL_CLOSED_REASONS]
    want_ok = not contradicted and not failclosed and pol["met"]
    if r["ok"] != want_ok:
        v.append(f"C2 ok {r['ok']} but equation {want_ok} (contradicted {contradicted}, fail-closed {failclosed}, unmet {pol['unmet']})")
    if r["assessed"] is False and (contradicted or "instrument_failure" not in [x for _, x in elements]):
        v.append("C3 assessed:false with a contradicted subject or no instrument_failure")
    if contradicted and r["assessed"] is not True:
        v.append("C3 contradicted with assessed not true")
    if js is not None and not case["nocrypto"]:
        jl = {}
        for x in js.get("layers", []):
            jl.setdefault(x["layer"], []).append(x["status"])
        need = {"sealed_content": ["pack-sha3", "pack-self-verification"], "ledger_anchor": ["ledger-chain", "pack-ledger-state"],
                "signed_tip": ["signed-tip"], "source_documents": ["source-documents"], "producer_signature": ["producer-signature"]}
        for s, o in st.items():
            if o["state"] == "verified":
                if not all(jl.get(n) and all(z == "PASS" for z in jl[n]) for n in need[s]):
                    v.append(f"C4 {s} verified but the JS verifier did not PASS {need[s]}: {[jl.get(n) for n in need[s]]}")
                jsig = [x for x in js.get("layers", []) if x["layer"] == "producer-signature"]
                if s == "producer_signature" and not (jsig and jsig[0].get("detail") == "trusted-signed"):
                    v.append(f"C4 producer verified, JS producer layer {jsig}")
            if o["state"] == "contradicted":
                fail_names = need[s] + (["ledger-schema"] if s == "ledger_anchor" else [])
                if not any("FAIL" in jl.get(n, []) for n in fail_names):
                    v.append(f"C4 {s} contradicted but no JS FAIL in {fail_names}: {[jl.get(n) for n in fail_names]}")
    return v


def main():
    argv = sys.argv[1:]
    old = argv[argv.index("--old") + 1] if "--old" in argv else None
    sab = argv[argv.index("--sabotage") + 1] if "--sabotage" in argv else "-"
    quick, nojs = "--quick" in argv, "--no-js" in argv or not shutil.which("node")
    outj = argv[argv.index("--json") + 1] if "--json" in argv else None
    if sab != "-" and sab not in SABOTAGES:
        raise SystemExit(f"unknown sabotage {sab!r}; one of {SABOTAGES}")
    sys.path.insert(0, ROOT)
    import importlib
    VP = importlib.import_module("cra_evidence.verify_pack")
    work = tempfile.mkdtemp(prefix="cra-states-bench-")
    try:
        bases = build_bases(work)
        cases, meta = [], []
        n_files = 0
        for bname, base in bases.items():
            for mname, fn in mutations(base, quick):
                d = os.path.join(work, f"c{n_files}"); n_files += 1
                shutil.copytree(base["dir"], d, symlinks=True)
                fn(d)
                for label, c in inputs(base, d, quick):
                    for nocrypto in ((False, True) if label.startswith(("right/rightkey", "none/rightkey")) else (False,)):
                        c2 = dict(c, nocrypto=nocrypto)
                        cases.append(c2); meta.append((bname, mname, label, nocrypto))
        rec = run_receipts(ROOT, cases, sab)
        viol = []
        js_runs = 0
        for i, (c, r) in enumerate(zip(cases, rec)):
            js = None
            if not nojs and not c["nocrypto"] and "states" in r and (r.get("states") or {}) and \
                    any(o["state"] in ("verified", "contradicted") for o in r["states"].values()) and (not quick or i % 3 == 0):
                js = run_js(c, work); js_runs += 1
            for x in controls(c, r, js, VP):
                viol.append((meta[i], x))
        # C5 pins, per file and key/req/ledger input: same contradicted set across trust stores; wrong ones never verified
        groups = {}
        for i, (m, r) in enumerate(zip(meta, rec)):
            if r.get("admission") != "admitted":
                continue
            t, rest = m[2].split("/", 1)
            groups.setdefault((m[0], m[1], rest, m[3]), {})[t] = r
        for g, by in groups.items():
            sets = {t: sorted(s for s, o in r["states"].items() if o["state"] == "contradicted") for t, r in by.items()}
            if len({tuple(x) for x in sets.values()}) > 1:
                viol.append((g, f"C5 pins changed the contradicted set: {sets}"))
            for t in ("wrongkey", "othersigner"):
                if t in by and by[t]["states"]["producer_signature"]["state"] == "verified":
                    viol.append((g, f"C5 producer verified under trust store {t}"))
            if "none" in by and "right" in by:
                a, b = by["none"]["states"]["producer_signature"]["state"], by["right"]["states"]["producer_signature"]["state"]
                if a == "verified" or (a != b and not (a == "not_evaluated" and b == "verified")):
                    viol.append((g, f"C5 right trust store moved producer {a} -> {b}"))
        # C6 unknown top-level key on an admitted base
        for i, (m, r) in enumerate(zip(meta, rec)):
            if m[1].startswith("pack-unknown-") and (r.get("admission"), r.get("refusal_class")) != ("refused", "unknown_member"):
                viol.append((m, f"C6 unknown top-level key: {r.get('admission')}/{r.get('refusal_class')}"))
        # C7 the 0.5.1 fields
        c7 = {"compared": 0, "differ": 0, "declared": 0}
        if old:
            orec = run_receipts(old, cases, "-")
            for i, (r, o) in enumerate(zip(rec, orec)):
                c7["compared"] += 1
                a = {k: r.get(k) for k in OLD_FIELDS}; b = {k: o.get(k) for k in OLD_FIELDS}
                if a != b:
                    lay_a = [dict(x) for x in a["layers"] or []]; lay_b = [dict(x) for x in b["layers"] or []]
                    for x in lay_a:
                        if x.get("layer") == "signed-tip" and x.get("assessed") is False and "tip_unchecked" in x.get("detail", ""):
                            x.pop("assessed")
                    declared = cases[i]["nocrypto"] and lay_a == lay_b and a["ok"] == b["ok"] and a["authenticity"] == b["authenticity"]
                    if declared:
                        c7["declared"] += 1
                    else:
                        c7["differ"] += 1
                        viol.append((meta[i], f"C7 0.5.1 fields differ: new {json.dumps(a)[:300]} old {json.dumps(b)[:300]}"))
        counts = {"files": n_files, "receipts": len(rec), "js_runs": js_runs,
                  "admission": {k: sum(1 for r in rec if r.get("admission") == k) for k in ("admitted", "refused", "not_evaluated")},
                  "states_seen": sorted({f"{s}:{o['state']}:{','.join(o['reasons'])}" for r in rec if r.get("states") for s, o in r["states"].items()}),
                  "refusal_classes": sorted({r.get("refusal_class") for r in rec if r.get("refusal_class")}),
                  "policy_unmet_seen": sorted({u for r in rec if r.get("policy") for u in r["policy"]["unmet"]}),
                  "c7": c7, "violations": len(viol), "sabotage": sab}
        kinds = {}
        for m, x in viol:
            kinds.setdefault(x.split(":")[0][:90], []).append((m, x))
        for k_, xs in sorted(kinds.items()):
            print(f"VIOLATION x{len(xs)}", xs[0][0], xs[0][1][:400])
        print(json.dumps({k: v for k, v in counts.items() if k != "states_seen"}, sort_keys=True))
        print("distinct subject/state/reasons seen:", len(counts["states_seen"]))
        if outj:
            with open(outj, "w", encoding="utf-8") as f:
                json.dump(counts, f, indent=1, sort_keys=True)
        return 1 if viol else 0
    finally:
        for r_, ds, fs in os.walk(work):
            for n in ds + fs:
                try:
                    os.chmod(os.path.join(r_, n), stat.S_IRWXU)
                except OSError:
                    pass
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
