# SPDX-License-Identifier: AGPL-3.0-or-later
"""SBOM records for CRA Annex I Part II point 1 ("software bill of materials in a commonly used and machine-readable
format covering at the very least the top-level dependencies").

Two honest ways in: (a) `sbom_from_installed` — this Python environment via importlib.metadata (top-level or
transitive), a floor, not a scanner; (b) `sbom_from_cyclonedx` — ingest a CycloneDX JSON produced by a best-in-class
generator (Syft, Trivy, cdxgen…): the 2026 verdict of the competitor comparison is to interoperate with the leaders
and add what they lack — tamper-evident, offline-verifiable evidence with Art. 14 deadlines. Export is a CycloneDX
1.6-compatible SUBSET (bomFormat, specVersion, metadata, components with purl/hashes/licenses), declared as such.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import sha3_hex


@dataclass(frozen=True)
class SBOMComponent:
    name: str
    version: str
    supplier: str = ""
    purl: str = ""
    sha256: str = ""
    license: str = ""


def dedup(components: List[SBOMComponent]) -> List[SBOMComponent]:
    seen, out = set(), []
    for c in components:
        k = (c.name, c.version, c.purl)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


@dataclass(frozen=True)
class SBOMRecord:
    product_id: str
    product_version: str
    components: List[SBOMComponent]
    depth: str = "top-level-only"       # "transitive" | "external:cyclonedx:<generator>"
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def __post_init__(self):
        # deterministic order: the same environment must give the same SBOM bytes whatever the traversal order
        object.__setattr__(self, "components", sorted(dedup(self.components), key=lambda c: (c.name.lower(), c.version, c.purl)))

    def canonical_hash(self) -> str:
        return sha3_hex(asdict(self))

    def to_cyclonedx_min(self) -> Dict[str, Any]:
        # schema-valid CycloneDX 1.6 (root has additionalProperties:false): our extras live in metadata.properties
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"timestamp": self.generated_utc,
                             "component": {"type": "application", "name": self.product_id, "version": self.product_version},
                             "properties": [
                                 {"name": "cra-evidence:profile", "value": f"cra-evidence-min (depth: {self.depth})"},
                                 {"name": "cra-evidence:depth_note", "value": "'top-level-only' is the literal Annex I floor; most vulnerabilities live in transitive dependencies — prefer a transitive SBOM from a full generator when available"},
                                 {"name": "cra-evidence:sbom_sha3", "value": self.canonical_hash()}]},
                "components": [{"type": "library", "name": c.name, "version": c.version,
                                **({"supplier": {"name": c.supplier}} if c.supplier else {}),
                                **({"purl": c.purl} if c.purl else {}),
                                **({"hashes": [{"alg": "SHA-256", "content": c.sha256}]} if c.sha256 else {}),
                                **({"licenses": [{"license": ({"id": c.license} if is_spdx_id(c.license) else {"name": c.license})}]} if c.license else {})}
                               for c in dedup(self.components)]}


_EXTRA_MARKER = re.compile(r"""extra\s*==\s*['"]""")


def _is_extra_requirement(req: str) -> bool:
    """PEP 508 marker `extra == "x"` in any spacing/quoting: an optional dependency, not part of the runtime SBOM."""
    return bool(_EXTRA_MARKER.search(req))


_SPDX_IDS: Optional[set] = None


def is_spdx_id(value: str) -> bool:
    """True only for an identifier in the SPDX license list vendored with the package (CycloneDX `license.id` is an
    enum of those); anything else is exported as `license.name` (free text), which the schema allows."""
    global _SPDX_IDS
    if _SPDX_IDS is None:
        try:
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "spdx.schema.json")
            with open(p, encoding="utf-8") as f:
                _SPDX_IDS = set(json.load(f).get("enum", []))
        except (OSError, ValueError):
            _SPDX_IDS = set()
    return value in _SPDX_IDS


def resolved_components(record: "SBOMRecord") -> List[SBOMComponent]:
    """Components with a real version (a declared-but-NOT-INSTALLED dependency is not evidence of anything)."""
    return [c for c in record.components if c.version and c.version != "NOT-INSTALLED"]


def pypi_purl(name: str, version: str) -> str:
    """purl for PyPI per the purl spec: name lowercased, runs of [-_.] → '-' (PEP 503 normalisation)."""
    return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name.lower())}@{version}"


PURL_TYPE_TO_OSV = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "maven": "Maven", "golang": "Go", "nuget": "NuGet",
                    "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "cocoapods": "CocoaPods"}


def components_for_osv(record: "SBOMRecord") -> List[Dict[str, str]]:
    """Map an (ingested) SBOM's purls to OSV ecosystems so a Syft/Trivy SBOM of any ecosystem can be queried;
    components without a mappable purl are returned with ecosystem "" (the caller sees what was NOT queried)."""
    out = []
    for c in record.components:
        eco = ""
        if c.purl.startswith("pkg:"):
            typ = c.purl[4:].split("/", 1)[0].split("?")[0]
            eco = PURL_TYPE_TO_OSV.get(typ, "")
        out.append({"name": c.name, "version": c.version, "ecosystem": eco})
    return out


def _req_name(req: str) -> str:
    s = req.split(";")[0].strip()
    for sep in ("[", " ", "(", "<", ">", "=", "!", "~"):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
    return s.strip()


def sbom_from_installed(product_id: str, product_version: str, top_level: List[str], transitive: bool = False) -> SBOMRecord:
    """Components resolved from THIS interpreter's installed distributions. A dependency that is declared but not
    installed is recorded with version 'NOT-INSTALLED' (the floor is honest, not padded)."""
    from importlib import metadata as md
    comps: Dict[str, SBOMComponent] = {}
    todo = list(top_level)
    seen = set()
    while todo:
        name = todo.pop(0)
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = md.distribution(name)
            ver = dist.version
            lic = (dist.metadata.get("License") or "")[:80]
            comps[key] = SBOMComponent(name=dist.metadata["Name"], version=ver, purl=pypi_purl(key, ver), license=lic)
            if transitive:
                for r in dist.requires or []:
                    if _is_extra_requirement(r):
                        continue
                    todo.append(_req_name(r))
        except md.PackageNotFoundError:
            comps[key] = SBOMComponent(name=name, version="NOT-INSTALLED")
    return SBOMRecord(product_id=product_id, product_version=product_version, components=list(comps.values()),
                      depth="transitive" if transitive else "top-level-only")


def sbom_from_cyclonedx(path: str, product_id: str, product_version: str) -> SBOMRecord:
    """Ingest a CycloneDX JSON from ANY generator; malformed components are skipped, a malformed document raises."""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    gen = ""
    try:
        tools = (d.get("metadata", {}) or {}).get("tools", {})
        comp = tools.get("components", tools) if isinstance(tools, dict) else tools
        if isinstance(comp, list) and comp:
            gen = str(comp[0].get("name", ""))
    except Exception:  # noqa: BLE001
        gen = ""
    raw = d.get("components")
    if not isinstance(raw, list):
        raise ValueError("CycloneDX malformed: 'components' must be a list")
    comps: List[SBOMComponent] = []
    for c in raw:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        sha = ""
        for h in (c.get("hashes") if isinstance(c.get("hashes"), list) else []):
            if isinstance(h, dict) and str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
                sha = str(h.get("content", ""))
                break
        lic = ""
        for le in (c.get("licenses") if isinstance(c.get("licenses"), list) else []):
            if isinstance(le, dict):
                li = le.get("license") if isinstance(le.get("license"), dict) else {}
                lic = li.get("id") or li.get("name") or le.get("expression") or ""
                if lic:
                    break
        sup = c.get("supplier")
        comps.append(SBOMComponent(name=str(c["name"]), version=str(c.get("version", "")),
                                   supplier=str(sup.get("name", "")) if isinstance(sup, dict) else "",
                                   purl=str(c.get("purl", "")), sha256=sha, license=str(lic)[:80]))
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps,
                      depth=f"external:cyclonedx:{gen or 'unknown'}")
