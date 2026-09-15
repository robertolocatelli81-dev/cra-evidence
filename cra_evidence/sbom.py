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
from typing import Any, Dict, List, Optional, Tuple

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
    return [c for c in record.components if c.version and c.version not in ("NOT-INSTALLED", "NOASSERTION", "NONE")]


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


# ── SPDX ingest (2.2 / 2.3 JSON and 3.0 JSON-LD) ──────────────────────────────────────────
_NOASSERT = ("", "NOASSERTION", "NONE")


def _clean(v: Any) -> str:
    v = "" if v is None else str(v).strip()
    return "" if v in _NOASSERT else v


def _agent_name(v: Any) -> str:
    """SPDX 2.x supplier/originator: 'Organization: Acme (mail)' / 'Person: Jane' → the name part (only a
    trailing parenthesised e-mail is dropped, 'Foo (Bar) Ltd' keeps its name)."""
    v = _clean(v)
    for pfx in ("Organization:", "Person:"):
        if v.startswith(pfx):
            v = v[len(pfx):].strip()
    return re.sub(r"\s*\([^()]*@[^()]*\)\s*$", "", v).strip() if v else ""


def _sha256_or_empty(v: Any) -> str:
    v = str(v or "").strip().lower()
    return v if re.fullmatch(r"[0-9a-f]{64}", v) else ""       # a malformed checksum is not evidence


def _ld_type(e: Dict[str, Any]) -> str:
    """JSON-LD type in compact (`type`, `software_Package`) or expanded (`@type`, full IRI) form → short name."""
    t = e.get("type", e.get("@type", ""))
    t = t[0] if isinstance(t, list) and t else t
    t = str(t or "")
    return t.rsplit("/", 1)[-1].rsplit("#", 1)[-1]


def _ld_id(e: Dict[str, Any]) -> str:
    return str(e.get("spdxId") or e.get("@id") or "")


def _ld_prop(e: Dict[str, Any], *names: str) -> Any:
    """A property by its compact name or by any expanded IRI ending with it."""
    for n in names:
        if n in e:
            return e[n]
    for k, v in e.items():
        tail = k.rsplit("/", 1)[-1].rsplit("#", 1)[-1]
        if tail in names or tail.split("_", 1)[-1] in names:
            return v
    return None


def _spdx2_components(d: Dict[str, Any]) -> Tuple[List[SBOMComponent], str]:
    rels = [r for r in (d.get("relationships") or []) if isinstance(r, dict)]
    roots = {r.get("relatedSpdxElement") for r in rels if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
    roots |= {r.get("spdxElementId") for r in rels if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == "SPDXRef-DOCUMENT"}
    roots |= set(d.get("documentDescribes") or [])
    comps = []
    for p in d.get("packages", []) or []:
        if not isinstance(p, dict) or not _clean(p.get("name")):
            continue
        if p.get("SPDXID") in roots:
            continue                                     # the product itself is metadata, not a dependency
        purl = next((r.get("referenceLocator", "") for r in (p.get("externalRefs") or [])
                     if isinstance(r, dict) and r.get("referenceType") == "purl"), "")
        sha = next((c.get("checksumValue", "") for c in (p.get("checksums") or [])
                    if isinstance(c, dict) and str(c.get("algorithm", "")).upper() == "SHA256"), "")
        lic = _clean(p.get("licenseConcluded")) or _clean(p.get("licenseDeclared"))
        comps.append(SBOMComponent(name=_clean(p["name"]), version=_clean(p.get("versionInfo")) or "NOASSERTION",
                                   supplier=_agent_name(p.get("supplier")) or _agent_name(p.get("originator")),   # cleaned BEFORE the fallback
                                   purl=_clean(purl), sha256=_sha256_or_empty(sha), license=lic))
    tool = next((c for c in ((d.get("creationInfo") or {}).get("creators") or []) if str(c).startswith("Tool:")), "")
    depth = f"external:{_clean(d.get('spdxVersion')) or 'SPDX-2.x'}:{_agent_name(tool.replace('Tool:', '')) or 'unknown-tool'}"
    if not roots:
        depth += ":no-root-declared"   # the document names no described product: it may be counted among the components (declared)
    return comps, depth


def _spdx3_components(d: Dict[str, Any]) -> Tuple[List[SBOMComponent], str]:
    g = [e for e in (d.get("@graph") or []) if isinstance(e, dict)]
    known = {"software_Package", "Package", "Relationship", "LifecycleScopedRelationship", "SpdxDocument", "software_Sbom", "Sbom",
             "software_File", "File", "CreationInfo", "Tool", "Organization", "Person", "Agent", "simplelicensing_LicenseExpression", "LicenseExpression"}
    if not any(_ld_type(e) in known for e in g):
        raise ValueError("@graph holds no SPDX 3.0 element (no Package/Sbom/SpdxDocument/Relationship): not an SPDX 3.0 document")
    by_id = {_ld_id(e): e for e in g if _ld_id(e)}
    roots = set()
    lic_of: Dict[str, str] = {}

    def _lic_expr(x: Any) -> str:
        le = by_id.get(x) or {}
        expr = _clean(_ld_prop(le, "simplelicensing_licenseExpression", "licenseExpression") or le.get("name"))
        if not expr and isinstance(x, str):
            if x.rstrip("/").endswith(("NoAssertionElement", "NoneElement", "NoAssertionLicense", "NoneLicense")):
                return ""
            if x.startswith("https://spdx.org/licenses/"):          # ListedLicense IRI not embedded in the graph
                expr = x.rsplit("/", 1)[-1]
        return expr
    for e in g:
        t = _ld_type(e)
        if t in ("SpdxDocument", "software_Sbom", "Sbom"):
            re_ = _ld_prop(e, "rootElement")                          # the canonical root marker in SPDX 3.0
            roots |= {x for x in (re_ if isinstance(re_, list) else [re_]) if x}
        if t in ("Relationship", "LifecycleScopedRelationship"):
            rt = _ld_prop(e, "relationshipType")
            to = _ld_prop(e, "to")
            tos = to if isinstance(to, list) else [to]
            frm = _ld_prop(e, "from")
            if rt == "describes":
                roots |= {x for x in tos if x}
            if rt in ("hasConcludedLicense", "hasDeclaredLicense") and frm:
                for x in tos:
                    expr = _lic_expr(x)
                    if expr and (rt == "hasConcludedLicense" or frm not in lic_of):
                        lic_of[frm] = expr
    comps = []
    for e in g:
        if _ld_type(e) not in ("software_Package", "Package") or not _clean(e.get("name")) or _ld_id(e) in roots:
            continue
        sha = next((h.get("hashValue", "") for h in (_ld_prop(e, "verifiedUsing") or [])
                    if isinstance(h, dict) and _ld_type(h) == "Hash" and str(h.get("algorithm", "")).lower().rsplit("/", 1)[-1] == "sha256"), "")
        sup = _ld_prop(e, "suppliedBy")
        sup = sup[0] if isinstance(sup, list) and sup else sup
        supplier = _clean((by_id.get(sup) or {}).get("name")) if isinstance(sup, str) else ""
        if not supplier:
            orig = _ld_prop(e, "originatedBy"); orig = orig[0] if isinstance(orig, list) and orig else orig
            supplier = _clean((by_id.get(orig) or {}).get("name")) if isinstance(orig, str) else ""
        comps.append(SBOMComponent(name=_clean(e["name"]), version=_clean(_ld_prop(e, "software_packageVersion", "packageVersion")) or "NOASSERTION",
                                   supplier=supplier, purl=_clean(_ld_prop(e, "software_packageUrl", "packageUrl")), sha256=_sha256_or_empty(sha),
                                   license=lic_of.get(_ld_id(e), "")))
    tools = [e.get("name") for e in g if _ld_type(e) == "Tool" and e.get("name")]
    depth = f"external:SPDX-3.0:{_clean(tools[0]) if tools else 'unknown-tool'}"
    if not roots:
        depth += ":no-root-declared"
    return comps, depth


def sbom_from_spdx(path: str, product_id: str, product_version: str) -> SBOMRecord:
    """Ingest an SPDX document: 2.2/2.3 JSON (`spdxVersion`, `packages`, `relationships`; DESCRIBES/DESCRIBED_BY
    /documentDescribes name the product) or 3.0 JSON-LD (`@graph` of Package elements in compact `type`/`spdxId`
    or expanded `@type`/`@id`/IRI form; `rootElement` of the Sbom/SpdxDocument or a `describes` relationship names
    the product; licences via hasConcludedLicense/hasDeclaredLicense to an embedded expression or a ListedLicense
    IRI; supplier via `suppliedBy`, then `originatedBy`). The product is metadata, not a component; when no root
    is declared the depth says `:no-root-declared` (the product may then be counted). Field names checked on the
    official spdx/spdx-examples documents (15/09/2026); other generators' output is parsed by these rules, not
    proven against every tool. A document of neither shape raises."""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError("SPDX document is not a JSON object")
    if str(d.get("spdxVersion", "")).startswith("SPDX-2"):
        comps, depth = _spdx2_components(d)
    elif "@graph" in d:
        comps, depth = _spdx3_components(d)
    else:
        raise ValueError("not an SPDX 2.x JSON (spdxVersion) nor an SPDX 3.0 JSON-LD (@graph) document")
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps, depth=depth)
