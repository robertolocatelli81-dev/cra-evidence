"""Apply cra-evidence to cra-evidence itself (the discipline the tool asks of its users)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import CRAEvidenceLocker, SRPNotice, DryRunDrop, VulnerabilityRecord, sbom_from_cyclonedx, sbom_from_installed, verify_pack
from cra_evidence import __version__ as VERSION   # the example is this repository applied to itself: its version is the package's

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "self_evidence")
os.makedirs(out, exist_ok=True)
led = os.path.join(out, "cra.ledger.jsonl")
import shutil
for stale in (led, led + ".tip.json", os.path.join(out, "cra_pack.json.sig.json"), os.path.join(out, "trust.json")):
    if os.path.exists(stale):
        os.remove(stale)
shutil.rmtree(led + ".sources", ignore_errors=True)
shutil.rmtree(os.path.join(out, "drop"), ignore_errors=True)   # the drop file is named by a fresh notice_id each run
lk = CRAEvidenceLocker(led, "cra-evidence", VERSION)
lk.record_sbom(sbom_from_installed("cra-evidence", VERSION, ["cryptography"], transitive=True))
# a generator's document as evidence: Syft 1.52.0's CycloneDX 1.7 of a one-dependency npm project (unmodified fixture),
# its bytes stored next to the ledger and SHA-256-bound in the record (the `source-documents` layer of every verifier)
src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json")
lk.record_sbom(sbom_from_cyclonedx(src, "cra-evidence", VERSION), source_path=src)
v = VulnerabilityRecord("cra-evidence", "EXAMPLE-2026-0001", False, "2026-09-15T08:00:00Z",
                        details={"note": "example record: no known vulnerability in cra-evidence " + VERSION + " at release; not actively exploited → no Art. 14 obligation"})
lk.record_vulnerability(v)
n = SRPNotice("vulnerability", "early_warning", {"notification_type": "Vulnerability", "title": "example (not a real report)",
              "summary": "illustrative payload in the ENISA SRP vocabulary; never submitted", "manufacturer_name": "example manufacturer",
              "member_states_available": ["IT"], "product_name": "cra-evidence", "product_version": VERSION, "awareness_datetime_utc": "2026-09-15T08:00:00Z"})
lk.record_notice(n, DryRunDrop(os.path.join(out, "drop")).prepare(n))   # no cve_id: no vulnerability record to bind to
pack = lk.evidence_pack(os.path.join(out, "cra_pack.json"))
lk.seal_longterm(pack["pack_sha3"], t=1_789_459_200.0)   # 2026-09-15T00:00:00Z, explicit
# signed with an ephemeral key generated here (the seed is not kept): the public key goes into trust.json so the
# reader can reach `trusted-signed`; a real deployment signs with a held key (or AWS KMS: `cra sign --aws-kms-key-id`)
from cra_evidence.signing import keygen, load_key, sign_pack
seed = os.path.join(out, "example.key"); keygen(seed); key = load_key(seed); os.remove(seed)
sign_pack(os.path.join(out, "cra_pack.json"), key, "example-signer")
json.dump({"example-signer": key[1]}, open(os.path.join(out, "trust.json"), "w"), indent=1)
print(json.dumps(verify_pack(os.path.join(out, "cra_pack.json"), trust_store={"example-signer": key[1]}), indent=1))
