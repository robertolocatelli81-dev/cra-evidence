# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate spec/art14-filing/v0.1/vectors/ (spec §6): valid statements and, for each rule of §2-§5, a statement that
breaks it, each with its expected verdict and reason code in manifest.json.

TEST-ONLY KEYS. The signing keys are derived from fixed public strings (seed = SHA-256 of the string): anyone can
rebuild them, so they prove nothing about anyone. Never use them for real evidence.

The notices are the importer's output on the real sbomify fixtures (tests/fixtures/sbomify_4ef6128/: the early
warning and the first intermediate report of s1AfwOnAgUPN), built with a fixed clock and fixed ids, so the vectors
are byte for byte reproducible (tests/test_art14_vectors_20261113.py regenerates them and compares).

usage: python scripts/gen_art14_vectors.py [OUT_DIR]   (default: spec/art14-filing/v0.1/vectors)"""
import base64, hashlib, json, os, shutil, sys, tempfile, uuid
from datetime import datetime, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence import art14_attest as A                     # noqa: E402
from cra_evidence import ledger as L                            # noqa: E402
from cra_evidence.locker import CRAEvidenceLocker               # noqa: E402
from cra_evidence.sbomify_import import run_import              # noqa: E402
from cra_evidence.srp_notice import DryRunDrop, SRPNotice        # noqa: E402

NATIVE_EW = {"notification_type": "Vulnerability", "title": "Second exploited flaw in Acme T100 (synthetic)",
             "summary": "Synthetic early warning built with cra notice.", "manufacturer_name": "Example Widgets GmbH (synthetic)",
             "member_states_available": ["AT", "DE"], "product_name": "Acme Smart Thermostat T100 (synthetic)",
             "product_version": "4.2.4", "awareness_datetime_utc": "2026-11-12T10:00:00Z", "cve_id": "CVE-2099-0002"}
LEGACY = os.path.join(ROOT, "tests", "fixtures", "srp_legacy_nemesis", "vulnerability_early_warning_8d0a9c38-4596-4396-993e-3629d585eb50.json")

TEST_KEY_STRING = "cra-evidence art14-filing v0.1 vectors: TEST-ONLY signing key, public by design, never a real key"
OTHER_KEY_STRING = "cra-evidence art14-filing v0.1 vectors: a second TEST-ONLY key, not in the trust store"
SIGNER = "test-signer"
FIX = os.path.join(ROOT, "tests", "fixtures", "sbomify_4ef6128")
NOW = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
ATTESTED = datetime(2026, 11, 13, 6, 5, 0, tzinfo=timezone.utc)
SMALL_ORDER_KEY = "0100000000000000000000000000000000000000000000000000000000000000"   # the identity point (order 1)
# The cra-evidence version written in `source.toolVersion` of the statements built here (spec v0.1 §4: the version that
# writes the statement). The vectors were written by 0.8.0; the version is fixed here so that a release does not
# change them (13/11/2026, release of 0.9.0: with the package version the vectors would have changed at every release).
VECTORS_TOOL_VERSION = "0.8.0"


def test_key(s):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(s.encode("utf-8")).digest())
    return sk, sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64(b, url=False):
    return (base64.urlsafe_b64encode(b).decode().rstrip("=")) if url else base64.b64encode(b).decode()


def envelope(payload, key, keyid=SIGNER, payload_type=A.PAYLOAD_TYPE, url=False):
    sig = key[0].sign(A.pae(payload_type, payload))
    return {"payload": b64(payload, url), "payloadType": payload_type, "signatures": [{"keyid": keyid, "sig": b64(sig, url)}]}


def build_notices(work):
    """the importer on two real filings, with a fixed clock and fixed ids"""
    n = [0]

    def new_id():
        n[0] += 1
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cra-evidence/art14-filing/v0.1/vectors/{n[0]}"))
    led, drop = os.path.join(work, "ledger.jsonl"), os.path.join(work, "drop")
    with mock.patch.object(L, "_now_ts", lambda: "2026-11-13T06:00:00Z"):
        lk = CRAEvidenceLocker(led, "acme-thermostat-t100", "4.2.4")
        r = run_import(os.path.join(FIX, "report_s1AfwOnAgUPN.json"),
                       [os.path.join(FIX, "filing_s1AfwOnAgUPN_early_warning_1.json"),
                        os.path.join(FIX, "filing_s1AfwOnAgUPN_intermediate_1.json")],
                       lk, drop, "4ef61281e69d693e3560185bf81ec5474179ea98", now=NOW, new_id=new_id)
        # a notice built here (cra-srp/2, as `cra notice` writes it), for another vulnerability of the same product
        n = SRPNotice(stream="vulnerability", stage="early_warning", fields=dict(NATIVE_EW), notice_id=new_id(),
                      generated_utc=NOW.isoformat(timespec="seconds"))
        lk.bind_notice(n)
        dr = DryRunDrop(drop).prepare(n)
        lk.record_notice(n, dr)
    out = {x["stage"]: os.path.join(drop, x["drop_file"]) for x in r["notices"]}
    out["native"] = os.path.join(drop, dr["drop_file"])
    return led, out


def generate(out):
    import cra_evidence
    with mock.patch.object(cra_evidence, "__version__", VECTORS_TOOL_VERSION):
        return _generate(out)


def _generate(out):
    k1, k2 = test_key(TEST_KEY_STRING), test_key(OTHER_KEY_STRING)
    work = tempfile.mkdtemp()
    try:
        led, drops = build_notices(work)
        if os.path.isdir(out):
            shutil.rmtree(out)
        os.makedirs(out)
        shutil.copyfile(led, os.path.join(out, "ledger.jsonl"))
        shutil.copyfile(drops["early_warning"], os.path.join(out, "drop_early_warning.json"))
        shutil.copyfile(drops["intermediate"], os.path.join(out, "drop_intermediate.json"))
        shutil.copyfile(drops["native"], os.path.join(out, "drop_native_early_warning.json"))
        shutil.copyfile(LEGACY, os.path.join(out, "drop_cra_srp_1.json"))
        nat = A.build_statement(drops["native"], led, attested_at=ATTESTED)
        nat_f = A.build_statement(drops["native"], led, attested_at=ATTESTED,
                                  filing={"srp_reference": "SRP-EW-2099-000401", "filed_at": "2026-11-12T20:00:00+01:00",
                                          "filed_by": "psirt@example.com"})
        ew = A.build_statement(drops["early_warning"], led, "acme-thermostat-t100", "4.2.4", attested_at=ATTESTED)
        ir = A.build_statement(drops["intermediate"], led, "acme-thermostat-t100", "4.2.4", attested_at=ATTESTED)
        entries = list(L.Ledger(led).entries())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(os.path.join(out, "trust_store.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({SIGNER: k1[1]}, sort_keys=True) + "\n")
    with open(os.path.join(out, "trust_store_small_order.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({SIGNER: SMALL_ORDER_KEY}, sort_keys=True) + "\n")
    base = json.loads(ew)

    def mut(fn):
        st = json.loads(ew)
        fn(st)
        return dumps(st)

    def pset(path, value):
        def fn(st):
            o = st
            for p in path[:-1]:
                o = o[p]
            o[path[-1]] = value
        return fn

    def pdel(path):
        def fn(st):
            o = st
            for p in path[:-1]:
                o = o[p]
            del o[path[-1]]
        return fn
    vectors = []

    def add(name, env, expect, drop="drop_early_warning.json", ledger="ledger.jsonl", ts="trust_store.json", raw=None, rule=""):
        fn = name + ".intoto.json"
        with open(os.path.join(out, fn), "wb") as f:
            f.write(raw if raw is not None else (json.dumps(env, indent=1, sort_keys=True) + "\n").encode("utf-8"))
        vectors.append({"name": name, "rule": rule, "envelope": fn, "trust_store": ts, "drop": drop, "ledger": ledger, "expect": expect})
    ok = {"verified": True, "exit": 0, "codes": []}

    def bad(*codes):
        return {"verified": False, "exit": 1, "codes": list(codes)}
    # ── valid ──
    def nmut(fn):
        st = json.loads(nat)
        fn(st)
        return dumps(st)
    okp = {**ok, "product": "PASS"}
    add("valid_native_early_warning", envelope(nat, k1), okp, drop="drop_native_early_warning.json",
        rule="§2/§4: a cra-srp/2 notice built by cra notice, source cra-evidence, filing null")
    add("valid_native_with_declared_filing", envelope(nat_f, k1), okp, drop="drop_native_early_warning.json",
        rule="§4: a filing declared when attesting (declaredBy cra-evidence)")
    add("native_document_sha256_not_the_subject", envelope(nmut(pset(["predicate", "source", "documentSha256"], "0" * 64)), k1),
        bad("predicate_rule"), drop="drop_native_early_warning.json", rule="§4: cra-evidence source = the subject's sha256")
    add("native_absent_at_source_not_empty", envelope(nmut(pset(["predicate", "source", "absentAtSource"], ["4"])), k1),
        bad("predicate_rule"), drop="drop_native_early_warning.json", rule="§4: cra-evidence source carries every row it has")
    add("native_drop_claimed_by_sbomify", envelope(nmut(lambda st: st["predicate"]["source"].update(tool="sbomify")), k1),
        bad("drop_mismatch"), drop="drop_native_early_warning.json", ledger=None, rule="§4.2 rule 1: a cra-srp/2 drop is cra-evidence's")
    with open(LEGACY, "rb") as f:
        legacy_raw = f.read()
    def on_legacy(st):
        st["subject"][0]["digest"] = {"sha256": hashlib.sha256(legacy_raw).hexdigest(), "sha3_256": hashlib.sha3_256(legacy_raw).hexdigest()}
        st["predicate"]["source"]["documentSha256"] = st["subject"][0]["digest"]["sha256"]
    add("subject_is_a_cra_srp_1_drop", envelope(nmut(on_legacy), k1),
        bad("rule1"), drop="drop_cra_srp_1.json", ledger=None, rule="§4.2 rule 1: cra-srp/2 or cra-srp/3 only")
    add("product_differs_from_the_ledger", envelope(mut(pset(["predicate", "product", "version"], "4.2.5")), k1), bad("product"),
        rule="§4.2 rule 3: the product the ledger records")
    add("valid_early_warning", envelope(ew, k1), okp, rule="§2-§5: an imported early warning (complete false), drop and ledger checked")
    add("valid_intermediate", envelope(ir, k1), ok, drop="drop_intermediate.json", rule="rule 9: complete null at intermediate")
    add("valid_without_ledger", envelope(ew, k1), {**ok, "ledger": "not_evaluated"}, ledger=None, rule="§4.2 rule 3: no ledger = not_evaluated, never PASS")
    add("valid_without_drop_and_ledger", envelope(ew, k1), {**ok, "drop": "not_evaluated", "ledger": "not_evaluated"}, drop=None, ledger=None,
        rule="signature and closed predicate only")
    add("valid_extra_statement_field", envelope(mut(pset(["comment"], "an unrecognized Statement field")), k1),
        {**ok, "statement_unrecognized": ["comment"]}, rule="§3: unrecognized Statement fields ignored for the verdict and listed")
    add("valid_url_safe_base64_unpadded", envelope(ew, k1, url=True), ok, rule="§5: either base64 alphabet accepted")
    e2 = envelope(ew, k2, keyid="not-in-trust-store")
    e2["signatures"].append(envelope(ew, k1)["signatures"][0])
    add("valid_second_signature_unknown_keyid", e2, {**ok, "listed": ["unknown_keyid"]},
        rule="§5: trusted if one signature verifies with a trusted key; the unknown keyid is listed")
    e3 = envelope(ew, k1)
    e3["x-extension"] = "an unrecognized envelope field"
    add("valid_extra_envelope_field", e3, {**ok, "envelope_unrecognized": ["x-extension"]}, rule="DSSE envelope.md: unrecognized fields ignored (listed)")
    # ── §2 / §5: envelope and signatures ──
    add("payload_type_wrong", envelope(ew, k1, payload_type="application/json"), bad("payload_type"), rule="§2 payloadType")
    e = envelope(ew, k1); e["payload"] = "!!not base64!!"
    add("payload_bad_base64", e, bad("base64"), rule="§5 envelope decodes")
    e = envelope(ew, k1); e["signatures"][0]["sig"] = "@@@@"
    add("signature_bad_base64", e, bad("base64", "not_trusted"), rule="§5 envelope decodes")
    e = envelope(ew, k1); e["payload"] = b64(mut(pset(["predicate", "complete"], True)))
    add("payload_tampered", e, bad("not_trusted", "signature_failed"), rule="§5 signature over PAE")
    add("signed_by_untrusted_key", envelope(ew, k2), bad("not_trusted", "signature_failed"), rule="§5 trusted key")
    add("keyid_not_in_trust_store", envelope(ew, k1, keyid="someone-else"), bad("not_trusted", "unknown_keyid"), rule="§5 keyid selects the candidate key")
    add("small_order_trusted_key", envelope(ew, k1), bad("weak_key", "not_trusted"), ts="trust_store_small_order.json", rule="§5 small-order key refused")
    e = envelope(ew, k1)
    add("envelope_duplicate_key", None, bad("envelope_malformed"), rule="§3 duplicate key",
        raw=('{"payload":"%s","payloadType":"%s","payloadType":"%s","signatures":%s}\n'
             % (e["payload"], A.PAYLOAD_TYPE, A.PAYLOAD_TYPE, json.dumps(e["signatures"]))).encode())
    e = envelope(ew, k1); del e["signatures"]
    add("envelope_without_signatures", e, bad("envelope_malformed"), rule="DSSE envelope.md: signatures required")
    # ── §2: Statement ──
    add("statement_type_wrong", envelope(mut(pset(["_type"], "https://in-toto.io/Statement/v0.1")), k1), bad("statement_type"), rule="§2 _type")
    add("predicate_type_wrong", envelope(mut(pset(["predicateType"], A.TYPE_URI.replace("v0.1", "v0.3"))), k1), bad("predicate_type"),
        rule="§2 predicateType (v0.3: a version not defined; until 0.8.0 this vector used v0.2, defined since)")
    add("two_subjects", envelope(mut(lambda st: st["subject"].append(dict(st["subject"][0]))), k1), bad("subject"), rule="§2 exactly one subject")
    add("subject_name_wrong", envelope(mut(pset(["subject", 0, "name"], "srp-notice:vulnerability:notification")), k1), bad("subject"), rule="§2 subject name")
    add("subject_without_sha3", envelope(mut(pdel(["subject", 0, "digest", "sha3_256"])), k1), bad("subject"), rule="§2 both digests required")
    add("subject_digest_upper_case", envelope(mut(pset(["subject", 0, "digest", "sha256"], base["subject"][0]["digest"]["sha256"].upper())), k1),
        bad("subject"), rule="§2 64 lower-case hex")
    add("subject_digest_of_other_bytes", envelope(mut(pset(["subject", 0, "digest", "sha256"], hashlib.sha256(b"other").hexdigest())), k1),
        bad("subject_digest"), rule="§2 subject = the drop file's bytes")
    # ── §3: closed predicate ──
    add("predicate_unknown_key", envelope(mut(pset(["predicate", "submittedToEnisa"], True)), k1), bad("predicate_unknown_key"), rule="§3 closed predicate")
    add("predicate_unknown_nested_key", envelope(mut(pset(["predicate", "filing", "receipt"], "x")), k1), bad("predicate_unknown_key"), rule="§3 closed at every level")
    add("predicate_missing_key", envelope(mut(pdel(["predicate", "attestedAt"])), k1), bad("predicate_missing_key"), rule="§3 required keys")
    add("predicate_wrong_type", envelope(mut(pset(["predicate", "ledger", "entryIndex"], "1")), k1), bad("predicate_type_error"), rule="§3 JSON types")
    add("predicate_float_index", envelope(mut(pset(["predicate", "ledger", "entryIndex"], 1.5)), k1), bad("predicate_type_error"), rule="§3 JSON types")
    dup = ew.replace(b'"stage":"early_warning"', b'"stage":"early_warning","stage":"early_warning"', 1)
    add("predicate_duplicate_key", envelope(dup, k1), bad("duplicate_key"), rule="§3 duplicate key anywhere in the payload")
    add("predicate_value_outside_enum", envelope(mut(pset(["predicate", "stage"], "draft")), k1), bad("predicate_enum"), rule="§3 enumerations")
    add("timestamp_with_offset", envelope(mut(pset(["predicate", "awareAt"], "2026-11-09T07:30:00+00:00")), k1), bad("predicate_timestamp"),
        rule="§3 RFC 3339 UTC with Z")
    add("timestamp_seven_fraction_digits", envelope(mut(pset(["predicate", "attestedAt"], "2026-11-13T06:05:00.1234567Z")), k1),
        bad("predicate_timestamp"), rule="§3 at most 6 fractional digits")
    # ── §4.1 and §4 ──
    add("complete_null_at_early_warning", envelope(mut(lambda st: st["predicate"].update(complete=None, missingRequired=[])), k1),
        bad("predicate_rule"), rule="§4.1 complete null only at intermediate / users_informed")
    add("declared_by_not_source_tool", envelope(mut(pset(["predicate", "filing", "declaredBy"], "cra-evidence")), k1), bad("predicate_rule"),
        rule="§4.1 filing.declaredBy = source.tool")
    add("missing_required_with_complete_true", envelope(mut(pset(["predicate", "complete"], True)), k1), bad("predicate_rule"),
        rule="§4 missingRequired [] when complete is true")
    add("deadline_not_from_awareness", envelope(mut(pset(["predicate", "deadlineAt"], "2026-11-12T07:30:00Z")), k1), bad("deadline"),
        rule="§4 deadlineAt computed from awareAt")
    # ── §4.2 ──
    add("rule1_glossary_differs", envelope(mut(lambda st: st["predicate"].update(glossaryVersion="enisa_srp_glossary_20260929",
                                                                                     noticeRules="srp-notice/1")), k1),
        bad("rule1"), ledger=None, rule="§4.2 rule 1")
    add("rule2_completeness_differs", envelope(mut(lambda st: st["predicate"].update(complete=True, missingRequired=[])), k1), bad("rule2"),
        ledger=None, rule="§4.2 rule 2")
    add("rule3_entry_hash_differs", envelope(mut(pset(["predicate", "ledger", "entryHash"], "0" * 64)), k1), bad("rule3"), rule="§4.2 rule 3")
    add("rule3_entry_is_the_event", envelope(mut(lambda st: st["predicate"]["ledger"].update(entryIndex=0, entryHash=entries[0]["self_hash"])), k1),
        bad("rule3"), rule="§4.2 rule 3: a cra_srp_notice record")
    other = next(e for e in entries if e["data"].get("stage") == "intermediate")
    add("rule3_entry_of_another_notice", envelope(mut(lambda st: st["predicate"]["ledger"].update(entryIndex=other["idx"], entryHash=other["self_hash"])), k1),
        bad("rule3"), rule="§4.2 rule 3: drop_sha3 and stage of the record")
    add("rule3_entry_index_beyond_ledger", envelope(mut(pset(["predicate", "ledger", "entryIndex"], 99)), k1), bad("rule3"), rule="§4.2 rule 3")
    add("rule4_attested_before_filed", envelope(mut(pset(["predicate", "attestedAt"], "2026-11-09T17:00:00Z")), k1), bad("rule4"), rule="§4.2 rule 4")
    add("aware_at_differs_from_notice", envelope(mut(lambda st: st["predicate"].update(awareAt="2026-11-09T08:30:00Z", deadlineAt="2026-11-10T08:30:00Z")), k1),
        bad("drop_mismatch", "rule2"), rule="§4.4 the recorded awareness instant (and the deadline computed from it)")
    manifest = {"predicate_type": A.TYPE_URI, "payload_type": A.PAYLOAD_TYPE,
                "test_keys": {"warning": "TEST-ONLY keys: seed = SHA-256 of the UTF-8 string below; public by design, never a real key",
                              SIGNER: {"seed_string": TEST_KEY_STRING, "public_key_hex": k1[1]},
                              "not-in-trust-store": {"seed_string": OTHER_KEY_STRING, "public_key_hex": k2[1]}},
                "generated_by": "scripts/gen_art14_vectors.py (deterministic: fixed clock, fixed ids, Ed25519 signatures)",
                "how_to_run": "cra verify-attestation <envelope> --trust-store <trust_store> [--drop <drop>] [--ledger <ledger>]; the exit "
                              "code must be the expected one and the set of reason codes in `reasons` must equal the expected codes",
                "vectors": vectors}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    return manifest


if __name__ == "__main__":
    m = generate(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "spec", "art14-filing", "v0.1", "vectors"))
    print(f"{len(m['vectors'])} vectors")
