#!/usr/bin/env python3
"""Build the release assets of cra-evidence WITH cra-evidence (the discipline the tool asks of its users).

OUT/: wheel + sdist (python -m build), CycloneDX SBOM of the wheel (sha256 inside), the CRA evidence pack of this
release (SBOM record + anchored pack in a fresh ledger) and its ledger. Publishes nothing. Exit 1 unless the pack
verifies with the offline verifier.  Usage: python scripts/release_assets.py <version> <out_dir> [tip_key]
"""
import hashlib, json, os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence import CRAEvidenceLocker, SBOMComponent, SBOMRecord, verify_pack

PRODUCT = "cra-evidence"


def main() -> int:
    version, out = sys.argv[1], sys.argv[2]
    tip_key = sys.argv[3] if len(sys.argv) > 3 else None
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(out, exist_ok=True)
    tmp = tempfile.mkdtemp()
    subprocess.run([sys.executable, "-m", "build", "--outdir", tmp, src], check=True, capture_output=True)
    built = []
    for fn in sorted(os.listdir(tmp)):
        data = open(os.path.join(tmp, fn), "rb").read()
        open(os.path.join(out, fn), "wb").write(data)
        built.append({"file": fn, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    wheel = next(b for b in built if b["file"].endswith(".whl"))
    comps = [SBOMComponent(name=PRODUCT, version=version, supplier="Roberto Locatelli", purl=f"pkg:pypi/{PRODUCT}@{version}",
                           sha256=wheel["sha256"], license="AGPL-3.0-or-later")]
    # runtime dependencies: none (stdlib); the optional extra 'sign' (cryptography) is not part of the wheel's requirements
    sbom = SBOMRecord(product_id=PRODUCT, product_version=version, components=comps, depth="top-level-only")
    with open(os.path.join(out, f"{PRODUCT}-{version}-sbom.cdx.json"), "w") as f:
        json.dump(sbom.to_cyclonedx_min(), f, indent=1)
    led = os.path.join(out, f"{PRODUCT}-{version}-cra.ledger.jsonl")
    if os.path.exists(led):
        os.remove(led)
    lk = CRAEvidenceLocker(led, PRODUCT, version, tip_key=tip_key)
    lk.record_sbom(sbom)
    pack_path = os.path.join(out, f"{PRODUCT}-{version}-cra_pack.json")
    pack = lk.evidence_pack(pack_path)
    v = verify_pack(pack_path)
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        for b in built:
            f.write(f"{b['sha256']}  {b['file']}\n")
    print(json.dumps({"built": built, "pack_sha3": pack["pack_sha3"], "verify_ok": v["ok"], "authenticity": v["authenticity"]}, indent=1))
    return 0 if v["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
