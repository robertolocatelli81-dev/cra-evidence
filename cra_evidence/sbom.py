# SPDX-License-Identifier: AGPL-3.0-or-later
"""SBOM records for CRA Annex I Part II point 1 ("software bill of materials in a commonly used and machine-readable
format covering at the very least the top-level dependencies").

Two honest ways in: (a) `sbom_from_installed` — this Python environment via importlib.metadata (top-level or
transitive), a floor, not a scanner; (b) `sbom_from_cyclonedx` — ingest a CycloneDX JSON produced by a best-in-class
generator (Syft, Trivy, cdxgen…) or `sbom_from_spdx`: the 2026 verdict of the competitor comparison is to
interoperate with the leaders and add what they lack — tamper-evident, offline-verifiable evidence with Art. 14
deadlines. The record is a normalised INDEX of the generator's document (name/version/type/purl/cpe/sha256/licence,
flattened, de-duplicated); the generator's document itself is the evidence: `source_fingerprint()` binds its exact
bytes (SHA-256) into the record and the locker stores the bytes next to the ledger (measured 20/09/2026 with sbomqs
2.1.2: re-emitting only the index scored lower than every generator's original — 5.3→4.2 Syft, 6.6→4.4 cdxgen,
4.8→3.7 Trivy — so the original is kept, not replaced). Export is a CycloneDX 1.6 or 1.7 SUBSET (bomFormat,
specVersion, serialNumber, metadata with tools/component, components with bom-ref/type/purl/cpe/hashes/licenses,
dependencies only where they are known), declared as such and validated against the official schemas in the tests.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
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
    type: str = "library"      # CycloneDX component type as declared by the generator (library, application, file, …)
    cpe: str = ""


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
    # the generator's document, as measured at ingest: format, generator+version, spec version, what it declared
    # (component count incl. nested, dependency edges, component types) and what the index did to it (merged
    # duplicates) — and, when `source_fingerprint()` was applied, the SHA-256 of its exact bytes
    source: Dict[str, Any] = field(default_factory=dict)
    # dependency edges KNOWN to the producer, as [parent_key, child_key] over `name.lower()` ("" = the product): the
    # installed floor fills them from importlib.metadata `Requires-Dist`; an ingested document leaves them empty (its
    # graph lives in the stored source and is never re-invented)
    edges: List[List[str]] = field(default_factory=list)

    def __post_init__(self):
        # deterministic order: the same environment must give the same SBOM bytes whatever the traversal order
        object.__setattr__(self, "components", sorted(dedup(self.components), key=lambda c: (c.name.lower(), c.version, c.purl)))

    def canonical_hash(self) -> str:
        return sha3_hex(asdict(self))

    def to_cyclonedx_min(self, spec_version: str = "1.6") -> Dict[str, Any]:
        """CycloneDX 1.6 or 1.7 JSON (root has additionalProperties:false; our extras live in metadata.properties).
        bom-ref = purl when the generator gave one, else name@version, made unique; `dependencies` are emitted only
        from `edges` the producer KNOWS (the installed floor: top-level = direct dependencies of the product,
        transitive = the Requires-Dist graph as walked) — for an ingested document the graph is the generator's and
        lives in the stored source, it is never re-invented."""
        if spec_version not in CYCLONEDX_EXPORT_VERSIONS:
            raise ValueError(f"spec_version must be one of {sorted(CYCLONEDX_EXPORT_VERSIONS)}")
        from . import __version__
        comps = dedup(self.components)
        refs, used = [], set()
        for c in comps:
            ref = c.purl or f"{c.name}@{c.version}"
            base, n = ref, 1
            while ref in used:
                n += 1
                ref = f"{base}#{n}"
            used.add(ref)
            refs.append(ref)
        primary_ref = f"{self.product_id}@{self.product_version}"
        while primary_ref in used:
            primary_ref += "#product"
        out = {"bomFormat": "CycloneDX", "specVersion": spec_version, "serialNumber": f"urn:uuid:{self.record_id}", "version": 1,
               "metadata": {"timestamp": self.generated_utc,
                            "tools": {"components": [{"type": "application", "name": "cra-evidence", "version": __version__}]},
                            "component": {"type": "application", "bom-ref": primary_ref, "name": self.product_id, "version": self.product_version},
                            "properties": [
                                {"name": "cra-evidence:profile", "value": f"cra-evidence-min (depth: {self.depth})"},
                                {"name": "cra-evidence:depth_note", "value": "'top-level-only' is the literal Annex I floor; most vulnerabilities live in transitive dependencies — prefer a transitive SBOM from a full generator when available"},
                                {"name": "cra-evidence:sbom_sha3", "value": self.canonical_hash()}]},
               "components": [{"type": c.type if c.type in CYCLONEDX_COMPONENT_TYPES else "library", "bom-ref": ref, "name": c.name, "version": c.version,
                               **({"supplier": {"name": c.supplier}} if c.supplier else {}),
                               **({"purl": c.purl} if c.purl else {}),
                               **({"cpe": c.cpe} if c.cpe else {}),
                               **({"hashes": [{"alg": "SHA-256", "content": c.sha256}]} if c.sha256 else {}),
                               **(_license_entry(c.license) if c.license else {})}
                              for c, ref in zip(comps, refs)]}
        if self.source.get("sha256"):
            out["metadata"]["properties"].append({"name": "cra-evidence:source_sha256", "value": self.source["sha256"]})
        if self.edges:
            # `dependsOn: []` is the POSITIVE statement "has no dependencies" (CycloneDX dependency definition): it is
            # emitted only for a component whose Requires-Dist was actually read; every other component is left out
            # of the graph (= unknown) and the composition is declared incomplete
            ref_of = {_norm_key(c.name): r for c, r in zip(comps, refs)}
            ref_of[""] = primary_ref
            deps: Dict[str, List[str]] = {primary_ref: []}
            for key in self.source.get("requires_dist_read", []):
                if key in ref_of:
                    deps.setdefault(ref_of[key], [])
            for parent, child in self.edges:
                pr, cr = ref_of.get(parent), ref_of.get(child)
                if pr is None or cr is None or pr not in deps:
                    continue
                if cr not in deps[pr]:
                    deps[pr].append(cr)
            out["dependencies"] = [{"ref": r, "dependsOn": d} for r, d in deps.items()]
            if len(deps) < len(refs) + 1:
                out["compositions"] = [{"aggregate": "incomplete", "dependencies": [r for r in refs if r not in deps]}]
        return out


def _license_entry(lic: str) -> Dict[str, Any]:
    if is_spdx_expression(lic):
        return {"licenses": [{"expression": lic}]}
    return {"licenses": [{"license": ({"id": lic} if is_spdx_id(lic) else {"name": lic})}]}


CYCLONEDX_EXPORT_VERSIONS = {"1.6", "1.7"}
CYCLONEDX_COMPONENT_TYPES = {"application", "framework", "library", "container", "platform", "operating-system", "device",
                             "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"}


def source_fingerprint(path: str) -> Dict[str, Any]:
    """The exact bytes of the generator's document: SHA-256, size, file name. What the locker stores and what every
    verifier re-hashes; independent of any JSON re-serialisation (a float, a key order or an escape never changes it)."""
    with open(path, "rb") as f:
        raw = f.read()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw), "file": os.path.basename(path)}


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


_MARKER_ENV = None


def _marker_env() -> Dict[str, str]:
    """PEP 508 environment markers of THIS interpreter (the variables generators evaluate: python_version,
    python_full_version, platform_python_implementation, implementation_name, sys_platform, platform_system,
    platform_machine, os_name)."""
    global _MARKER_ENV
    if _MARKER_ENV is None:
        import platform
        v = sys.version_info
        _MARKER_ENV = {"python_version": f"{v.major}.{v.minor}", "python_full_version": platform.python_version(),
                       "platform_python_implementation": platform.python_implementation(), "implementation_name": sys.implementation.name,
                       "sys_platform": sys.platform, "platform_system": platform.system(), "platform_machine": platform.machine(),
                       "os_name": os.name, "platform_release": platform.release(), "platform_version": platform.version()}
    return _MARKER_ENV


def _ver_key(v: str) -> Tuple[int, ...]:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v))


def _marker_atom(atom: str) -> Optional[bool]:
    """`var op "value"` (either side may be the literal); None when the variable is not one we know."""
    m = re.fullmatch(r"""\s*([A-Za-z_][A-Za-z0-9_.]*|["'][^"']*["'])\s*(===|==|!=|<=|>=|<|>|~=|not in|in)\s*([A-Za-z_][A-Za-z0-9_.]*|["'][^"']*["'])\s*""", atom)
    if not m:
        return None
    env = _marker_env()

    def val(x: str) -> Optional[str]:
        if x[0] in "\"'":
            return x[1:-1]
        return env.get(x) if x in env else None
    left, op, right = val(m.group(1)), m.group(2), val(m.group(3))
    if left is None or right is None:
        return None
    if op in ("in", "not in"):
        return (left in right) == (op == "in")
    if op == "===":
        return left == right
    versionish = m.group(1) in ("python_version", "python_full_version") or m.group(3) in ("python_version", "python_full_version")
    a, b = (_ver_key(left), _ver_key(right)) if versionish else (left, right)
    if op == "~=":
        return a >= b and a[:len(b) - 1] == b[:len(b) - 1] if versionish else left == right
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def marker_applies(marker: str) -> Optional[bool]:
    """Evaluate a PEP 508 marker for THIS interpreter: `packaging` when importable, otherwise a small evaluator of
    `and`/`or`/parentheses over the known variables. None = could not evaluate (unknown variable or syntax)."""
    marker = marker.strip()
    if not marker:
        return True
    try:
        from packaging.markers import Marker, UndefinedEnvironmentName, InvalidMarker  # type: ignore
        try:
            return bool(Marker(marker).evaluate())
        except (UndefinedEnvironmentName, InvalidMarker):
            return None
    except ImportError:
        pass
    expr = marker
    # innermost parentheses first
    while "(" in expr:
        m = re.search(r"\(([^()]*)\)", expr)
        if not m:
            return None
        inner = marker_applies(m.group(1))
        if inner is None:
            return None
        expr = expr[:m.start()] + ("1==1" if inner else "1==2") + expr[m.end():]
    for part in re.split(r"\s+or\s+", expr):
        vals = [_marker_atom(a) if a.strip() not in ("1==1", "1==2") else a.strip() == "1==1" for a in re.split(r"\s+and\s+", part)]
        if any(v is None for v in vals):
            return None
        if all(vals):
            return True
    return False


def _req_name(req: str) -> str:
    s = req.split(";")[0].strip()
    for sep in ("[", " ", "(", "<", ">", "=", "!", "~"):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
    return s.strip()


def installed_license(meta: Any) -> str:
    """PEP 639 `License-Expression` first (cryptography ships it since 46.0.0 with the legacy `License` field empty —
    measured on PyPI metadata 20/09/2026; cffi 2.0 and pycparser 3.0 likewise), then the legacy `License` field,
    then the first `License ::` trove classifier."""
    for key in ("License-Expression", "License"):
        v = (meta.get(key) or "").strip()
        if v and v.upper() != "UNKNOWN":
            return v[:80]
    for c in meta.get_all("Classifier") or []:
        if c.startswith("License ::"):
            return c.split("::")[-1].strip()[:80]
    return ""


def is_spdx_expression(value: str) -> bool:
    """A compound SPDX expression (`A OR B`, `A AND B`, `A WITH exc`) whose atoms are listed identifiers."""
    parts = re.split(r"\s+(?:OR|AND|WITH)\s+", value)
    return len(parts) > 1 and all(is_spdx_id(p.strip("() ")) or p.strip("() ").endswith("-exception") for p in parts)


def sbom_from_installed(product_id: str, product_version: str, top_level: List[str], transitive: bool = False) -> SBOMRecord:
    """Components resolved from THIS interpreter's installed distributions. A dependency that is declared but not
    installed is recorded with version 'NOT-INSTALLED' (the floor is honest, not padded)."""
    from importlib import metadata as md
    comps: Dict[str, SBOMComponent] = {}
    edges: List[List[str]] = []
    walked: List[str] = []                      # keys whose Requires-Dist was READ (only these may assert "no dependencies")
    unevaluated = 0
    todo = [("", n) for n in top_level]         # (parent key, name); "" = the product
    seen = set()
    while todo:
        parent, name = todo.pop(0)
        key = _norm_key(name)
        if [parent, key] not in edges and parent != key:
            edges.append([parent, key])
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = md.distribution(name)
            ver = dist.version
            lic = installed_license(dist.metadata)
            comps[key] = SBOMComponent(name=dist.metadata["Name"], version=ver, purl=pypi_purl(key, ver), license=lic)
            if transitive:
                walked.append(key)
                for r in dist.requires or []:
                    if _is_extra_requirement(r):
                        continue
                    marker = r.split(";", 1)[1] if ";" in r else ""
                    applies = marker_applies(marker)
                    if applies is False:
                        continue                # a dependency of ANOTHER environment (python_version, platform…) is not one here
                    if applies is None:
                        unevaluated += 1        # kept, conservatively, and counted
                    todo.append((key, _req_name(r)))
        except md.PackageNotFoundError:
            comps[key] = SBOMComponent(name=name, version="NOT-INSTALLED")
    source = {"format": "installed", "generator": "cra-evidence:importlib.metadata", "generator_version": sys.version.split()[0],
              "requires_dist_read": walked, "markers_unevaluated_kept": unevaluated, "dependency_edges": len(edges)}
    return SBOMRecord(product_id=product_id, product_version=product_version, components=list(comps.values()),
                      depth="transitive" if transitive else "top-level-only", edges=edges, source=source)


def _norm_key(name: str) -> str:
    """PEP 503 normalisation: the key under which a distribution is looked up and an edge is recorded."""
    return re.sub(r"[-_.]+", "-", name.lower())


def _load_document(path: str) -> Any:
    """A generator document is third-party input: a nesting that exhausts the parser (or a duplicate key, which two
    readers would resolve differently) is a malformed document (ValueError), never a crash."""
    from .ledger import parse_line
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        return parse_line(text)
    except RecursionError:
        raise ValueError("document malformed: JSON nested too deep") from None


def _cdx_generator(d: Dict[str, Any]) -> Tuple[str, str]:
    """metadata.tools as 1.5+ {components:[...]} or the legacy list of {vendor,name,version}: (name, version)."""
    try:
        tools = (d.get("metadata", {}) or {}).get("tools", {})
        comp = tools.get("components", []) if isinstance(tools, dict) else tools
        if isinstance(comp, list) and comp and isinstance(comp[0], dict):
            return str(comp[0].get("name", "")), str(comp[0].get("version", ""))
    except Exception:  # noqa: BLE001
        pass
    return "", ""


def sbom_from_cyclonedx(path: str, product_id: str, product_version: str) -> SBOMRecord:
    """Ingest a CycloneDX JSON (1.2 … 1.7) from ANY generator: components are walked recursively (a generator may
    nest `components[].components`), malformed components are skipped, a malformed document raises. The record's
    `source` says what the document declared (spec version, generator, total/nested component count, dependency
    edges, component types) and how many duplicates (same name+version+purl at two locations, as Syft emits for a
    workflow file referenced twice) the index merged — the count the auditor reads is the generator's, not ours."""
    d = _load_document(path)
    if not isinstance(d, dict) or d.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX malformed: not a JSON object with bomFormat 'CycloneDX'")
    gen, gen_ver = _cdx_generator(d)
    raw = d.get("components")
    if not isinstance(raw, list):
        raise ValueError("CycloneDX malformed: 'components' must be a list")
    comps: List[SBOMComponent] = []
    declared, nested, types = 0, 0, {}

    def walk(items: List[Any], level: int) -> None:
        nonlocal declared, nested
        for c in items:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            declared += 1
            if level:
                nested += 1
            typ = str(c.get("type", "") or "library")
            types[typ] = types.get(typ, 0) + 1
            sha = ""
            for h in (c.get("hashes") if isinstance(c.get("hashes"), list) else []):
                if isinstance(h, dict) and str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
                    sha = _sha256_or_empty(h.get("content", ""))
                    break
            lic = ""
            for le in (c.get("licenses") if isinstance(c.get("licenses"), list) else []):
                if isinstance(le, dict):
                    li = le.get("license") if isinstance(le.get("license"), dict) else {}
                    lic = li.get("id") or li.get("name") or le.get("expression") or ""
                    if lic:
                        break
            sup = c.get("supplier")
            comps.append(SBOMComponent(name=str(c["name"]), version=str(c.get("version", "") or ""),
                                       supplier=str(sup.get("name", "")) if isinstance(sup, dict) else "",
                                       purl=str(c.get("purl", "") or ""), sha256=sha, license=str(lic)[:80],
                                       type=typ if typ in CYCLONEDX_COMPONENT_TYPES else "library", cpe=str(c.get("cpe", "") or "")))
            if isinstance(c.get("components"), list):
                walk(c["components"], level + 1)
    try:
        walk(raw, 0)
    except RecursionError:
        raise ValueError("CycloneDX malformed: components nested too deep") from None
    deps = d.get("dependencies") if isinstance(d.get("dependencies"), list) else []
    source = {"format": "cyclonedx-json", "spec_version": str(d.get("specVersion", "")), "generator": gen, "generator_version": gen_ver,
              "serial_number": str(d.get("serialNumber", "") or ""), "components_declared": declared, "components_nested": nested,
              "duplicates_merged": declared - len(dedup(comps)), "dependency_edges": sum(len(x["dependsOn"]) for x in deps if isinstance(x, dict) and isinstance(x.get("dependsOn"), list)),
              "dependencies_declared": len(deps), "component_types": dict(sorted(types.items()))}
    source.update(source_fingerprint(path))
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps,
                      depth=f"external:cyclonedx:{gen or 'unknown'}", source=source)


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


# SPDX 2.3 primaryPackagePurpose → CycloneDX component type (purposes without a counterpart stay "library")
SPDX_PURPOSE_TO_TYPE = {"APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library", "CONTAINER": "container",
                        "OPERATING-SYSTEM": "operating-system", "DEVICE": "device", "FIRMWARE": "firmware", "FILE": "file"}


def _spdx2_components(d: Dict[str, Any]) -> Tuple[List[SBOMComponent], str]:
    rels = [r for r in (d.get("relationships") or []) if isinstance(r, dict)]
    roots = {r.get("relatedSpdxElement") for r in rels if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
    roots |= {r.get("spdxElementId") for r in rels if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == "SPDXRef-DOCUMENT"}
    roots |= set(d.get("documentDescribes") or [])
    comps = []
    for p in d.get("packages", []) or []:
        if not isinstance(p, dict) or not _clean(p.get("name")):
            continue                                     # counted by the caller as packages_unnamed
        if p.get("SPDXID") in roots:
            continue                                     # the product itself is metadata, not a dependency
        refs = [r for r in (p.get("externalRefs") or []) if isinstance(r, dict)]
        purl = next((r.get("referenceLocator", "") for r in refs if r.get("referenceType") == "purl"), "")
        cpe = next((r.get("referenceLocator", "") for r in refs if str(r.get("referenceType", "")).startswith("cpe2")), "")
        sha = next((c.get("checksumValue", "") for c in (p.get("checksums") or [])
                    if isinstance(c, dict) and str(c.get("algorithm", "")).upper() == "SHA256"), "")
        lic = _clean(p.get("licenseConcluded")) or _clean(p.get("licenseDeclared"))
        comps.append(SBOMComponent(name=_clean(p["name"]), version=_clean(p.get("versionInfo")) or "NOASSERTION",
                                   supplier=_agent_name(p.get("supplier")) or _agent_name(p.get("originator")),   # cleaned BEFORE the fallback
                                   purl=_clean(purl), sha256=_sha256_or_empty(sha), license=lic,
                                   type=SPDX_PURPOSE_TO_TYPE.get(str(p.get("primaryPackagePurpose", "")).upper(), "library"), cpe=_clean(cpe)))
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
        purpose = _ld_prop(e, "software_primaryPurpose", "primaryPurpose")
        purpose = str(purpose[0] if isinstance(purpose, list) and purpose else purpose or "").rsplit("/", 1)[-1].upper().replace("OPERATINGSYSTEM", "OPERATING-SYSTEM")
        ext = _ld_prop(e, "externalIdentifier") or []
        cpe = next((str(x.get("identifier", "")) for x in ext if isinstance(x, dict) and str(_ld_prop(x, "externalIdentifierType") or "").rsplit("/", 1)[-1] in ("cpe22", "cpe23")), "")
        comps.append(SBOMComponent(name=_clean(e["name"]), version=_clean(_ld_prop(e, "software_packageVersion", "packageVersion")) or "NOASSERTION",
                                   supplier=supplier, purl=_clean(_ld_prop(e, "software_packageUrl", "packageUrl")), sha256=_sha256_or_empty(sha),
                                   license=lic_of.get(_ld_id(e), ""), type=SPDX_PURPOSE_TO_TYPE.get(purpose, "library"), cpe=_clean(cpe)))
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
    d = _load_document(path)
    if not isinstance(d, dict):
        raise ValueError("SPDX document is not a JSON object")
    if str(d.get("spdxVersion", "")).startswith("SPDX-2"):
        comps, depth = _spdx2_components(d)
        pk = [x for x in (d.get("packages") or []) if isinstance(x, dict)]
        rels = [r for r in (d.get("relationships") or []) if isinstance(r, dict)]
        source = {"format": "spdx-json", "spec_version": _clean(d.get("spdxVersion")), "packages_declared": len(pk),
                  "packages_unnamed": sum(1 for x in pk if not _clean(x.get("name"))), "relationships_declared": len(rels),
                  "dependency_edges": sum(1 for r in rels if str(r.get("relationshipType", "")).upper() in ("DEPENDS_ON", "DEPENDENCY_OF"))}
    elif "@graph" in d:
        comps, depth = _spdx3_components(d)
        g = [e for e in (d.get("@graph") or []) if isinstance(e, dict)]
        source = {"format": "spdx-jsonld", "spec_version": "SPDX-3.0",
                  "packages_declared": sum(1 for e in g if _ld_type(e) in ("software_Package", "Package")),
                  "packages_unnamed": sum(1 for e in g if _ld_type(e) in ("software_Package", "Package") and not _clean(e.get("name"))),
                  "relationships_declared": sum(1 for e in g if _ld_type(e) in ("Relationship", "LifecycleScopedRelationship")),
                  "dependency_edges": sum(1 for e in g if _ld_type(e) in ("Relationship", "LifecycleScopedRelationship") and _ld_prop(e, "relationshipType") == "dependsOn")}
    else:
        raise ValueError("not an SPDX 2.x JSON (spdxVersion) nor an SPDX 3.0 JSON-LD (@graph) document")
    parts = depth.split(":")
    source.update({"generator": parts[2] if len(parts) > 2 else "", "generator_version": "",
                   "roots_excluded": source["packages_declared"] - source["packages_unnamed"] - len(comps),
                   "duplicates_merged": len(comps) - len(dedup(comps))})
    gv = re.match(r"^(.*?)[-\s]?(\d+\.\d+[\w.\-]*)$", source["generator"])
    if gv:   # "syft-1.52.0" / "trivy-0.74.0" → name + version
        source["generator"], source["generator_version"] = gv.group(1).rstrip("-"), gv.group(2)
    source.update(source_fingerprint(path))
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps, depth=depth, source=source)
