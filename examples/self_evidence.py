"""Apply cra-evidence to cra-evidence itself (the discipline the tool asks of its users)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import CRAEvidenceLocker, SRPNotice, DryRunDrop, VulnerabilityRecord, sbom_from_installed, verify_pack

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "self_evidence")
os.makedirs(out, exist_ok=True)
led = os.path.join(out, "cra.ledger.jsonl")
if os.path.exists(led):
    os.remove(led)
lk = CRAEvidenceLocker(led, "cra-evidence", "0.1.0")
lk.record_sbom(sbom_from_installed("cra-evidence", "0.1.0", ["cryptography"], transitive=True))
v = VulnerabilityRecord("cra-evidence", "EXAMPLE-2026-0001", False, "2026-09-15T08:00:00Z",
                        details={"note": "example record: no known vulnerability in cra-evidence 0.1.0 at release; not actively exploited → no Art. 14 obligation"})
lk.record_vulnerability(v)
n = SRPNotice("vulnerability", "early_warning", {"notification_type": "Vulnerability", "title": "example (not a real report)",
              "summary": "illustrative payload in the ENISA SRP vocabulary; never submitted", "manufacturer_name": "example manufacturer",
              "member_states_available": ["IT"], "product_name": "cra-evidence", "product_version": "0.1.0", "awareness_datetime_utc": "2026-09-15T08:00:00Z"})
lk.record_notice(n, DryRunDrop(os.path.join(out, "drop")).prepare(n))   # no cve_id: no vulnerability record to bind to
pack = lk.evidence_pack(os.path.join(out, "cra_pack.json"))
lk.seal_longterm(pack["pack_sha3"], t=1_789_459_200.0)   # 2026-09-15T00:00:00Z, explicit
print(json.dumps(verify_pack(os.path.join(out, "cra_pack.json")), indent=1))
