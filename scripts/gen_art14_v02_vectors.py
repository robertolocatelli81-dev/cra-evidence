# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate spec/art14-filing/v0.2/vectors/ (spec v0.2 §8): valid v0.2 statements and, for each rule of v0.2 §2-§3,
statements that break it, each with its expected verdict, reason codes and receipt values in manifest.json.

The v0.2 statements are built here WITHOUT the v0.2 producer: a v0.1 statement of `build_statement` (toolVersion VECTORS_TOOL_VERSION) is
re-typed to the v0.2 TypeURI and given the new fields by hand, so the vectors check `cra attest` from a second path
(same author, not the v0.2 producer)
(tests/test_art14_v02_20261113.py compares the producer's payload with them).

TEST-ONLY KEYS: the two keys of the v0.1 vectors (seed = SHA-256 of a fixed public string; never a real key).

The notices are synthetic ("Acme … (synthetic)", built as `cra notice` builds them, fixed clock and ids); the CVE and
EUVD identifiers in them are real public records (spec v0.2 §8: source URLs and digests), chosen for their form. A
refused vector that needs a malformed identifier mutates one of them.

usage: python scripts/gen_art14_v02_vectors.py [OUT_DIR]   (default: spec/art14-filing/v0.2/vectors)"""
import json, os, shutil, sys, tempfile, uuid
from datetime import datetime, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from omega_cra_evol import art14_attest as A                     # noqa: E402
from omega_cra_evol import ledger as L                            # noqa: E402
from omega_cra_evol.locker import EvidenceLocker               # noqa: E402
from omega_cra_evol.srp_notice import DryRunDrop, SRPNotice        # noqa: E402
from gen_art14_vectors import (OTHER_KEY_STRING, SIGNER, TEST_KEY_STRING, VECTORS_TOOL_VERSION, dumps,   # noqa: E402
                               envelope, test_key)

TYPE_V01 = "https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.1"
TYPE_V02 = "https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.2"
PRODUCT, VERSION = "acme-gateway-g2", "2.0.1"
NOW = datetime(2026, 11, 13, 7, 0, 0, tzinfo=timezone.utc)
ATTESTED = datetime(2026, 11, 13, 7, 5, 0, tzinfo=timezone.utc)

# real identifiers (spec v0.2 §8)
XZ = ("CVE-2024-3094", "EUVD-2024-31700")
LOG4J = ("CVE-2021-44228", "EUVD-2021-34768")
FORTI = ("CVE-2024-21762", "EUVD-2024-19376")


def _ew(title, **ids):
    f = {"notification_type": "Vulnerability", "title": title, "summary": "Synthetic early warning built with cra notice.",
         "manufacturer_name": "Example Gateways SpA (synthetic)", "member_states_available": ["IT"],
         "product_name": "Acme Gateway G2 (synthetic)", "product_version": VERSION,
         "awareness_datetime_utc": "2026-11-12T09:00:00Z"}
    f.update(ids)
    return f


NOTICES = {   # name: (stage, fields, previous_fields)
    "cve_euvd": ("early_warning", _ew("Exploited flaw A in Acme G2 (synthetic)", cve_id=XZ[0], euvd_id=XZ[1]), None),
    "cve_only": ("early_warning", _ew("Exploited flaw B in Acme G2 (synthetic)", cve_id=LOG4J[0]), None),
    "no_ids": ("early_warning", _ew("Exploited flaw C in Acme G2 (synthetic)"), None),
    "lower_case": ("early_warning", _ew("Exploited flaw D in Acme G2 (synthetic)", cve_id=XZ[0].lower()), None),
    # intermediate (rule 9): the ids are only in previous_fields, the early warning's values
    "previous": ("intermediate", {"general_information": "Synthetic intermediate report built with cra notice."},
                 _ew("Exploited flaw E in Acme G2 (synthetic)", cve_id=FORTI[0], euvd_id=FORTI[1])),
}


def build_notices(work):
    n = [0]

    def new_id():
        n[0] += 1
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cra-evidence/art14-filing/v0.2/vectors/{n[0]}"))
    led, drop = os.path.join(work, "ledger.jsonl"), os.path.join(work, "drop")
    out = {}
    with mock.patch.object(L, "_now_ts", lambda: "2026-11-13T07:00:00Z"):
        lk = EvidenceLocker(led, PRODUCT, VERSION)
        for name, (stage, fields, prev) in NOTICES.items():
            nt = SRPNotice(stream="vulnerability", stage=stage, fields=dict(fields), notice_id=new_id(),
                           generated_utc=NOW.isoformat(timespec="seconds"),
                           previous_fields=(dict(prev) if prev is not None else None))
            lk.bind_notice(nt)
            dr = DryRunDrop(drop).prepare(nt)
            lk.record_notice(nt, dr)
            out[name] = os.path.join(drop, dr["drop_file"])
    return led, out


def to_v02(payload, ids=None, case=None, type_uri=TYPE_V02):
    st = json.loads(payload)
    st["predicateType"] = type_uri
    if ids is not None:
        st["predicate"]["vulnerabilityIds"] = ids
    if case is not None:
        st["predicate"]["caseReference"] = case
    return st


def generate(out):
    import omega_cra_evol
    with mock.patch.object(omega_cra_evol, "__version__", VECTORS_TOOL_VERSION):   # the version of the v0.1 vectors
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
        files = {}
        for name, path in drops.items():
            files[name] = f"drop_{name}.json"
            shutil.copyfile(path, os.path.join(out, files[name]))
        v01 = {name: A.build_statement(path, led, attested_at=ATTESTED) for name, path in drops.items()}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(os.path.join(out, "trust_store.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({SIGNER: k1[1]}, sort_keys=True) + "\n")

    def cve(i):
        return {"scheme": "cve", "id": i}

    def euvd(i):
        return {"scheme": "euvd", "id": i}
    XZ_IDS = [cve(XZ[0]), euvd(XZ[1])]
    CASE = {"issuer": "Example CSIRT (synthetic case)", "id": "CASE-2026-000123"}
    vectors = []

    def add(name, st, expect, notice, drop=True, ledger=True, raw=None, rule="", key=k1):
        payload = raw if raw is not None else dumps(st)
        fn = name + ".intoto.json"
        with open(os.path.join(out, fn), "w", encoding="utf-8") as f:
            f.write(json.dumps(envelope(payload, key), indent=1, sort_keys=True) + "\n")
        vectors.append({"name": name, "rule": rule, "envelope": fn, "trust_store": "trust_store.json",
                        "drop": files[notice] if drop else None, "ledger": "ledger.jsonl" if ledger else None,
                        "expect": expect})

    def ok(ids_result, case_result="none declared", declared=None, notice_ids=None, **kw):
        e = {"verified": True, "exit": 0, "codes": [], "vulnerability_ids_result": ids_result,
             "case_reference_result": case_result}
        if declared is not None:
            e["vulnerability_ids_declared"] = declared
        if notice_ids is not None:
            e["vulnerability_ids_notice"] = notice_ids
        e.update(kw)
        return e

    def bad(*codes, **kw):
        return {"verified": False, "exit": 1, "codes": list(codes), **kw}
    NC = "declared, not checked (no drop file given)"
    CR = "declared by the signer, not checkable"
    # ── accepted ──
    add("valid_no_identifiers", to_v02(v01["no_ids"]), ok("matched", declared=[], notice_ids=[]), "no_ids",
        rule="§1: v0.2 without the two fields (v0.1 content, v0.2 TypeURI); the notice carries no identifier either")
    add("valid_cve_euvd_matched", to_v02(v01["cve_euvd"], XZ_IDS), ok("matched", declared=XZ_IDS, notice_ids=XZ_IDS), "cve_euvd",
        rule="§3 rule 5: the statement's identifiers equal the notice's")
    add("valid_cve_euvd_without_drop", to_v02(v01["cve_euvd"], XZ_IDS), ok(NC, declared=XZ_IDS, drop="not_evaluated"),
        "cve_euvd", drop=False, rule="§3: without the drop file the identifiers are declared, not checked")
    add("valid_cve_only_without_drop", to_v02(v01["cve_only"], [cve(LOG4J[0])]),
        ok(NC, declared=[cve(LOG4J[0])], drop="not_evaluated"), "cve_only", drop=False,
        rule="§1: same product and stage as valid_cve_euvd_without_drop, other identifiers: the receipts differ")
    add("valid_case_reference_only", to_v02(v01["no_ids"], case=CASE), ok("matched", CR, declared=[], notice_ids=[]), "no_ids",
        rule="§2.2: a case reference alone; never checkable")
    add("valid_identifiers_and_case_reference", to_v02(v01["cve_euvd"], XZ_IDS, CASE), ok("matched", CR, declared=XZ_IDS),
        "cve_euvd", rule="§2: both fields")
    add("valid_identifiers_from_previous_fields", to_v02(v01["previous"], [cve(FORTI[0]), euvd(FORTI[1])]),
        ok("matched", declared=[cve(FORTI[0]), euvd(FORTI[1])], notice_ids=[cve(FORTI[0]), euvd(FORTI[1])]), "previous",
        rule="§3: an intermediate report whose identifiers are in previous_fields (rule 8 of SRP_FIELDS.md)")
    add("valid_case_reference_255_characters", to_v02(v01["no_ids"], case={"issuer": "è" * 255, "id": "x" * 255}),
        ok("matched", CR), "no_ids", rule="§2.2: 255 characters (code points, not bytes) is the bound, accepted")
    add("valid_no_identifiers_without_drop", to_v02(v01["cve_euvd"]), ok(NC, declared=[], drop="not_evaluated"), "cve_euvd",
        drop=False, rule="§3: a v0.2 statement without identifiers about a notice that has them: accepted while the notice is not given")
    # ── §3 rule 5: the identifiers against the notice ──
    V = "vulnerability_ids"
    add("ids_differ_from_notice", to_v02(v01["cve_euvd"], [cve(LOG4J[0]), euvd(XZ[1])]), bad(V, vulnerability_ids_result="FAIL"),
        "cve_euvd", rule="§3 rule 5: an identifier the notice does not carry, one it carries missing")
    add("notice_has_ids_statement_none", to_v02(v01["cve_euvd"]), bad(V, vulnerability_ids_result="FAIL"), "cve_euvd",
        rule="§3 rule 5: no vulnerabilityIds while the notice carries two: refused when the notice is given")
    add("statement_has_ids_notice_none", to_v02(v01["no_ids"], [cve(XZ[0])]), bad(V, vulnerability_ids_result="FAIL"), "no_ids",
        rule="§3 rule 5: an identifier the notice does not carry")
    add("statement_subset_of_notice", to_v02(v01["cve_euvd"], [cve(XZ[0])]), bad(V, vulnerability_ids_result="FAIL"), "cve_euvd",
        rule="§3 rule 5: the EUVD identifier of the notice left out")
    add("notice_value_not_in_form", to_v02(v01["lower_case"], [cve(XZ[0])]), bad(V, vulnerability_ids_result="FAIL"), "lower_case",
        rule="§3 rule 5: the notice's cve_id is lower case: no statement entry can equal it (no normalisation)")
    add("notice_value_not_in_form_statement_none", to_v02(v01["lower_case"]), bad(V, vulnerability_ids_result="FAIL"), "lower_case",
        rule="§3 rule 5: a notice value out of form is still an identifier of the notice")
    # ── §2.1 vulnerabilityIds ──
    E = "predicate_identifier"
    add("scheme_unknown", to_v02(v01["cve_euvd"], [cve(XZ[0]), {"scheme": "ghsa", "id": "GHSA-rxwq-x6h5-x525"}]),
        bad("predicate_enum"), "cve_euvd", rule="§2.1 scheme cve or euvd")
    add("scheme_upper_case", to_v02(v01["cve_euvd"], [{"scheme": "CVE", "id": XZ[0]}]), bad("predicate_enum"), "cve_euvd",
        rule="§2.1 scheme: exact string")
    add("scheme_not_a_string", to_v02(v01["cve_euvd"], [{"scheme": 1, "id": XZ[0]}]), bad("predicate_type_error"), "cve_euvd",
        rule="§2.1 types")
    add("id_not_a_string", to_v02(v01["cve_euvd"], [{"scheme": "cve", "id": 20243094}]), bad("predicate_type_error"), "cve_euvd",
        rule="§2.1 types")
    add("cve_three_digit_sequence", to_v02(v01["cve_euvd"], [cve("CVE-2024-309")]), bad(E), "cve_euvd", rule="§2.1 CVE form: 4 to 19 digits")
    add("cve_twenty_digit_sequence", to_v02(v01["cve_euvd"], [cve("CVE-2024-" + "3" * 20)]), bad(E), "cve_euvd",
        rule="§2.1 CVE form: 4 to 19 digits")
    add("cve_lower_case", to_v02(v01["cve_euvd"], [cve(XZ[0].lower())]), bad(E), "cve_euvd", rule="§2.1 CVE form, no normalisation")
    add("cve_trailing_newline", to_v02(v01["cve_euvd"], [cve(XZ[0] + "\n")]), bad(E), "cve_euvd",
        rule="§2.1 CVE form, full match (a `$` that accepts a final newline would pass it)")
    add("cve_non_ascii_digits", to_v02(v01["cve_euvd"], [cve("CVE-2024-３０９４")]), bad(E), "cve_euvd",
        rule="§2.1 CVE form: ASCII digits only (a Unicode \\d would pass fullwidth digits)")
    add("cve_surrounding_space", to_v02(v01["cve_euvd"], [cve(" " + XZ[0])]), bad(E), "cve_euvd", rule="§2.1 CVE form")
    add("euvd_two_digit_year", to_v02(v01["cve_euvd"], [cve(XZ[0]), euvd("EUVD-24-31700")]), bad(E), "cve_euvd",
        rule="§2.1 EUVD form: four-digit year")
    add("euvd_no_sequence", to_v02(v01["cve_euvd"], [cve(XZ[0]), euvd("EUVD-2024-")]), bad(E), "cve_euvd",
        rule="§2.1 EUVD form: 1 to 19 digits")
    add("euvd_id_under_cve_scheme", to_v02(v01["cve_euvd"], [cve(XZ[1])]), bad(E), "cve_euvd", rule="§2.1 the id in its scheme's form")
    add("list_empty", to_v02(v01["no_ids"], []), bad("predicate_rule"), "no_ids", rule="§2.1 one form for no identifiers: omit the key")
    add("duplicate_entry", to_v02(v01["cve_euvd"], [cve(XZ[0]), cve(XZ[0]), euvd(XZ[1])]), bad("predicate_rule"), "cve_euvd",
        rule="§2.1 no duplicates")
    add("two_cve_entries", to_v02(v01["cve_euvd"], [cve(LOG4J[0]), cve(XZ[0]), euvd(XZ[1])]), bad("predicate_rule"), "cve_euvd",
        rule="§2.1 at most one entry per scheme")
    add("entries_out_of_order", to_v02(v01["cve_euvd"], [euvd(XZ[1]), cve(XZ[0])]), bad("predicate_rule"), "cve_euvd",
        rule="§2.1 cve before euvd")
    add("entry_unknown_key", to_v02(v01["cve_euvd"], [{**cve(XZ[0]), "url": "https://www.cve.org/CVERecord?id=CVE-2024-3094"}, euvd(XZ[1])]),
        bad("predicate_unknown_key"), "cve_euvd", rule="§2.1 closed entry")
    add("entry_missing_id", to_v02(v01["cve_euvd"], [{"scheme": "cve"}]), bad("predicate_missing_key"), "cve_euvd", rule="§2.1 closed entry")
    add("entry_not_an_object", to_v02(v01["cve_euvd"], [XZ[0]]), bad("predicate_type_error"), "cve_euvd", rule="§2.1 entries are objects")
    add("ids_not_a_list", to_v02(v01["cve_euvd"], cve(XZ[0])), bad("predicate_type_error"), "cve_euvd", rule="§2.1 a list")
    add("ids_null", to_v02(v01["cve_euvd"], None) | {"predicate": {**json.loads(v01["cve_euvd"])["predicate"], "vulnerabilityIds": None}},
        bad("predicate_type_error"), "cve_euvd", rule="§2.1 null is not admitted: omit the key")
    st = to_v02(v01["cve_euvd"], XZ_IDS)
    dup = dumps(st).replace(b'{"id":"CVE-2024-3094","scheme":"cve"}', b'{"id":"CVE-2024-3094","id":"CVE-2024-3094","scheme":"cve"}', 1)
    assert dup != dumps(st)
    add("entry_duplicate_key", None, bad("duplicate_key"), "cve_euvd", raw=dup, rule="v0.1 §3: a duplicate key anywhere in the payload")
    # ── §2.2 caseReference ──
    add("case_reference_null", to_v02(v01["no_ids"]) | {"predicate": {**json.loads(v01["no_ids"])["predicate"], "caseReference": None}},
        bad("predicate_type_error"), "no_ids", rule="§2.2 null is not admitted: omit the key")
    add("case_reference_unknown_key", to_v02(v01["no_ids"], case={**CASE, "status": "open"}), bad("predicate_unknown_key"), "no_ids",
        rule="§2.2 closed object")
    add("case_reference_missing_issuer", to_v02(v01["no_ids"], case={"id": CASE["id"]}), bad("predicate_missing_key"), "no_ids",
        rule="§2.2 closed object")
    add("case_reference_id_not_a_string", to_v02(v01["no_ids"], case={**CASE, "id": 123}), bad("predicate_type_error"), "no_ids",
        rule="§2.2 strings")
    add("case_reference_empty_id", to_v02(v01["no_ids"], case={**CASE, "id": ""}), bad(E), "no_ids", rule="§2.2 1 to 255 characters")
    add("case_reference_256_characters", to_v02(v01["no_ids"], case={**CASE, "issuer": "è" * 256}), bad(E), "no_ids",
        rule="§2.2 1 to 255 characters")
    add("case_reference_control_character", to_v02(v01["no_ids"], case={**CASE, "id": "CASE-2026\u0007000123"}), bad(E), "no_ids",
        rule="§2.2 no control character (C0)")
    add("case_reference_c1_control", to_v02(v01["no_ids"], case={**CASE, "id": "CASE-2026\u0085000123"}), bad(E), "no_ids",
        rule="§2.2 no control character (C1: U+0085)")
    add("case_reference_del", to_v02(v01["no_ids"], case={**CASE, "issuer": "CSIRT\u007f"}), bad(E), "no_ids",
        rule="§2.2 no control character (U+007F)")
    add("case_reference_trailing_space", to_v02(v01["no_ids"], case={**CASE, "issuer": "Example CSIRT "}), bad(E), "no_ids",
        rule="§2.2 no leading or trailing U+0020")
    # ── v0.1 stays closed; unknown versions ──
    add("v01_with_vulnerability_ids", to_v02(v01["cve_euvd"], XZ_IDS, type_uri=TYPE_V01), bad("predicate_unknown_key"), "cve_euvd",
        rule="§2: the v0.1 predicate does not admit the new keys")
    add("v01_with_case_reference", to_v02(v01["no_ids"], case=CASE, type_uri=TYPE_V01), bad("predicate_unknown_key"), "no_ids",
        rule="§2: the v0.1 predicate does not admit the new keys")
    add("type_v03_unknown", to_v02(v01["cve_euvd"], XZ_IDS, type_uri=TYPE_V02.replace("v0.2", "v0.3")), bad("predicate_type"),
        "cve_euvd", rule="v0.1 §2: an unknown TypeURI is refused")
    add("v01_statement_still_valid", json.loads(v01["cve_euvd"]), {"verified": True, "exit": 0, "codes": [], "no_v02_keys": True},
        "cve_euvd", rule="§1: a v0.1 statement is judged by v0.1 and its receipt has no v0.2 key")
    add("v02_signed_by_untrusted_key", to_v02(v01["cve_euvd"], XZ_IDS), bad("not_trusted", "signature_failed"), "cve_euvd", key=k2,
        rule="v0.1 §5: unchanged for v0.2")
    manifest = {"predicate_type": TYPE_V02, "payload_type": A.PAYLOAD_TYPE,
                "test_keys": {"warning": "TEST-ONLY keys of the v0.1 vectors: seed = SHA-256 of the UTF-8 string below; public "
                                         "by design, never a real key",
                              SIGNER: {"seed_string": TEST_KEY_STRING, "public_key_hex": k1[1]},
                              "not-in-trust-store": {"seed_string": OTHER_KEY_STRING, "public_key_hex": k2[1]}},
                "identifiers": "CVE-2024-3094/EUVD-2024-31700, CVE-2021-44228/EUVD-2021-34768, CVE-2024-21762/EUVD-2024-19376: "
                               "real public records (spec v0.2 §8), in synthetic notices; refused vectors mutate them",
                "generated_by": "scripts/gen_art14_v02_vectors.py (deterministic: fixed clock, fixed ids, Ed25519 signatures)",
                "how_to_run": "cra verify-attestation <envelope> --trust-store <trust_store> [--drop <drop>] [--ledger <ledger>]; "
                              "the exit code must be the expected one, the set of reason codes in `reasons` must equal the "
                              "expected codes, and each expected receipt value must be the receipt's",
                "vectors": vectors}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    return manifest


if __name__ == "__main__":
    m = generate(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "spec", "art14-filing", "v0.2", "vectors"))
    print(f"{len(m['vectors'])} vectors")
