# SPDX-License-Identifier: AGPL-3.0-or-later
"""Known-vulnerability and exploitation signals from public sources, with positive controls.

- OSV.dev  POST https://api.osv.dev/v1/querybatch  (package name + ecosystem + version → vulnerability ids)
- CISA KEV https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (exploited in the wild)
- ENISA EUVD https://euvdservices.enisa.europa.eu/api/kev/dump (EU consolidated known-exploited list, daily 07:00 UTC;
  community-documented endpoint, no auth) — Art. 14 obligations arise for ACTIVELY EXPLOITED vulnerabilities, so a
  KEV/EUVD hit is the signal that starts the 24 h clock; absence of a hit is NOT proof of non-exploitation.
Network is optional: every function degrades to an explicit {"error": ...}, never to a silent empty result, and the
positive control (a version with a known CVE) must light up before any "no vulnerabilities" is believed.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Dict, List, Optional

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH_MAX = 1000   # queries per request (server-side cap of the OSV API implementation); larger inputs are chunked
OSV_VULN = "https://api.osv.dev/v1/vulns/"   # querybatch answers are CONDENSED (id + modified only): aliases come from here
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_KEV_DUMP = "https://euvdservices.enisa.europa.eu/api/kev/dump"
POSITIVE_CONTROL = ("cryptography", "3.2", "PyPI")   # has public CVEs: if this returns nothing, the feed is broken


def _post_json(url: str, body: Dict[str, Any], timeout: int) -> Any:
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 — fixed https URLs
        return json.loads(r.read().decode() or "{}")


def _get_json(url: str, timeout: int) -> Any:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "cra-evidence/0.1"}), timeout=timeout) as r:  # nosec B310
        return json.loads(r.read().decode() or "{}")


def osv_query_batch(components: List[Dict[str, str]], timeout: int = 30) -> Dict[str, Any]:
    """components: [{name, version, ecosystem}] → {"results": [ids-or-None per INPUT component], "by_component":
    {"name@version": ids}, "error": None|str}. `results` is aligned with the INPUT list (None = not queried: no
    version, NOT-INSTALLED, or no OSV ecosystem), so an id can never be attributed to the wrong component.
    Every vulnerability contributes its id AND its aliases (GHSA ↔ CVE), so KEV/EUVD matching on CVE works."""
    idx = [i for i, c in enumerate(components) if c.get("version") and c["version"] != "NOT-INSTALLED" and c.get("ecosystem", "PyPI")]
    qs = [{"package": {"name": components[i]["name"], "ecosystem": components[i].get("ecosystem", "PyPI")}, "version": components[i]["version"]} for i in idx]
    aligned: List[Optional[List[str]]] = [None] * len(components)
    if not qs:
        return {"results": aligned, "by_component": {}, "queried": 0, "error": None}
    res: List[List[str]] = []
    cache: Dict[str, List[str]] = {}
    try:
        for start in range(0, len(qs), OSV_BATCH_MAX):
            chunk = qs[start:start + OSV_BATCH_MAX]
            out = _post_json(OSV_BATCH, {"queries": chunk}, timeout)
            batch = out.get("results", [])
            if len(batch) != len(chunk):
                raise ValueError(f"OSV returned {len(batch)} results for {len(chunk)} queries")
            for q, r in zip(chunk, batch):
                ids = _ids_with_aliases(r.get("vulns") or [], timeout, cache)
                token = r.get("next_page_token")
                pages = 0
                while token:   # documented pagination (google.github.io/osv.dev/post-v1-querybatch): follow it or under-report
                    pages += 1
                    if pages > 50:
                        raise ValueError("OSV pagination did not terminate")
                    more = _post_json(OSV_QUERY, {**q, "page_token": token}, timeout)
                    ids += _ids_with_aliases(more.get("vulns") or [], timeout, cache)
                    token = more.get("next_page_token")
                res.append(sorted(set(ids)))
    except Exception as e:  # noqa: BLE001 — network/shape: declared, not hidden; NEVER a partial list passed off as complete
        return {"results": [], "by_component": {}, "queried": len(qs), "error": f"{type(e).__name__}: {str(e)[:120]}"}
    by = {}
    for i, ids in zip(idx, res):
        aligned[i] = ids
        by[f"{components[i]['name']}@{components[i]['version']}"] = ids
    return {"results": aligned, "by_component": by, "queried": len(qs), "error": None}


def _ids_with_aliases(vulns: List[Dict[str, Any]], timeout: int = 30, cache: Optional[Dict[str, List[str]]] = None) -> List[str]:
    """Each id plus its aliases (GHSA ↔ CVE ↔ PYSEC). The batch endpoint returns only {id, modified} (verified
    live 15/09/2026), so aliases are fetched per id from /v1/vulns/{id} (cached); a failed lookup raises — a list
    without aliases would silently miss the CVE that KEV/EUVD key on."""
    out: List[str] = []
    cache = cache if cache is not None else {}
    for v in vulns:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        vid = str(v["id"])
        aliases = v.get("aliases")
        if aliases is None:
            if vid not in cache:
                full = _get_json(OSV_VULN + vid, timeout)
                cache[vid] = [str(a) for a in (full.get("aliases") or []) if a]
            aliases = cache[vid]
        out.append(vid)
        out += [str(a) for a in aliases if a]
    return out


KEV_POSITIVE_CONTROL = "CVE-2021-44228"   # Log4Shell: in CISA KEV since 2021-12-10 and in the EUVD exploited list


def osv_positive_control(timeout: int = 30) -> Dict[str, Any]:
    """The control passes only if the known-vulnerable version returns ids AND at least one CVE alias was resolved
    (the alias path is what KEV/EUVD matching depends on)."""
    r = osv_query_batch([{"name": POSITIVE_CONTROL[0], "version": POSITIVE_CONTROL[1], "ecosystem": POSITIVE_CONTROL[2]}], timeout)
    hits = r["results"][0] if r["results"] and r["results"][0] else []
    ok = r["error"] is None and bool(hits) and any(h.upper().startswith("CVE-") for h in hits)
    return {"ok": ok, "control": POSITIVE_CONTROL, "hits": hits, "error": r["error"]}


def cisa_kev_ids(timeout: int = 60) -> Dict[str, Any]:
    try:
        d = _get_json(KEV_URL, timeout)
        ids = {v.get("cveID") for v in d.get("vulnerabilities", []) if v.get("cveID")}
        ids = {i.upper() for i in ids}
        if KEV_POSITIVE_CONTROL not in ids:
            raise ValueError(f"positive control {KEV_POSITIVE_CONTROL} absent: feed shape changed or truncated ({len(ids)} ids)")
        return {"ids": ids, "count": len(ids), "catalog_version": d.get("catalogVersion"), "error": None}
    except Exception as e:  # noqa: BLE001
        return {"ids": set(), "count": 0, "catalog_version": None, "error": f"{type(e).__name__}: {str(e)[:120]}"}


def euvd_kev_ids(timeout: int = 60) -> Dict[str, Any]:
    try:
        d = _get_json(EUVD_KEV_DUMP, timeout)
        items = d if isinstance(d, list) else d.get("items", d.get("vulnerabilities")) if isinstance(d, dict) else None
        if not isinstance(items, list):
            raise ValueError("EUVD payload shape not recognised (expected a list or {items|vulnerabilities: [...]})")
        ids = set()
        for v in items:
            if isinstance(v, dict):
                for k in ("id", "aliases", "cveId", "cve"):
                    val = v.get(k)
                    if isinstance(val, str):
                        ids.update(x.strip() for x in re.split(r"[,\s]+", val) if x.strip())   # EUVD joins aliases with newlines
                    elif isinstance(val, list):
                        ids.update(str(x) for x in val)
        ids = {i.upper() for i in ids}
        if KEV_POSITIVE_CONTROL not in ids:
            raise ValueError(f"positive control {KEV_POSITIVE_CONTROL} absent: feed shape changed or truncated ({len(ids)} ids)")
        return {"ids": ids, "count": len(ids), "error": None}
    except Exception as e:  # noqa: BLE001
        return {"ids": set(), "count": 0, "error": f"{type(e).__name__}: {str(e)[:120]}"}


def exploitation_signal(vuln_ids: List[str], kev: Optional[Dict[str, Any]] = None, euvd: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Which of the given ids are known-exploited according to the loaded feeds (sources declared)."""
    kev = kev or {"ids": set(), "error": "not loaded"}
    euvd = euvd or {"ids": set(), "error": "not loaded"}
    hits = {}
    kev_ids = {str(i).upper() for i in kev["ids"]}
    eu_ids = {str(i).upper() for i in euvd["ids"]}
    for vid in vuln_ids:
        src = []
        if str(vid).upper() in kev_ids:
            src.append("cisa_kev")
        if str(vid).upper() in eu_ids:
            src.append("enisa_euvd")
        if src:
            hits[vid] = src
    return {"actively_exploited": hits, "sources_loaded": {"cisa_kev": kev.get("error") is None, "enisa_euvd": euvd.get("error") is None},
            "note": "absence from KEV/EUVD is not proof of non-exploitation; a vendor advisory or own telemetry also starts the Art. 14 clock"}
