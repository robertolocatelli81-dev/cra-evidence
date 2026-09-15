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
import urllib.request
from typing import Any, Dict, List, Optional

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH_MAX = 1000   # queries per request (server-side cap of the OSV API implementation); larger inputs are chunked
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
    """components: [{name, version, ecosystem}] → {"results": [[vuln ids]…], "error": None|str}."""
    qs = [{"package": {"name": c["name"], "ecosystem": c.get("ecosystem", "PyPI")}, "version": c["version"]}
          for c in components if c.get("version") and c["version"] != "NOT-INSTALLED"]
    if not qs:
        return {"results": [], "queried": 0, "error": None}
    res: List[List[str]] = []
    try:
        for start in range(0, len(qs), OSV_BATCH_MAX):
            chunk = qs[start:start + OSV_BATCH_MAX]
            out = _post_json(OSV_BATCH, {"queries": chunk}, timeout)
            batch = out.get("results", [])
            if len(batch) != len(chunk):
                raise ValueError(f"OSV returned {len(batch)} results for {len(chunk)} queries")
            for q, r in zip(chunk, batch):
                ids = [v.get("id") for v in (r.get("vulns") or [])]
                token = r.get("next_page_token")
                pages = 0
                while token:   # documented pagination (google.github.io/osv.dev/post-v1-querybatch): follow it or under-report
                    pages += 1
                    if pages > 50:
                        raise ValueError("OSV pagination did not terminate")
                    more = _post_json(OSV_QUERY, {**q, "page_token": token}, timeout)
                    ids += [v.get("id") for v in (more.get("vulns") or [])]
                    token = more.get("next_page_token")
                res.append(ids)
    except Exception as e:  # noqa: BLE001 — network/shape: declared, not hidden; NEVER a partial list passed off as complete
        return {"results": [], "queried": len(qs), "error": f"{type(e).__name__}: {str(e)[:120]}"}
    return {"results": res, "queried": len(qs), "error": None}


def osv_positive_control(timeout: int = 30) -> Dict[str, Any]:
    r = osv_query_batch([{"name": POSITIVE_CONTROL[0], "version": POSITIVE_CONTROL[1], "ecosystem": POSITIVE_CONTROL[2]}], timeout)
    ok = r["error"] is None and bool(r["results"]) and bool(r["results"][0])
    return {"ok": ok, "control": POSITIVE_CONTROL, "hits": r["results"][0] if r["results"] else [], "error": r["error"]}


def cisa_kev_ids(timeout: int = 60) -> Dict[str, Any]:
    try:
        d = _get_json(KEV_URL, timeout)
        ids = {v.get("cveID") for v in d.get("vulnerabilities", []) if v.get("cveID")}
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
                        ids.update(x.strip() for x in val.split(",") if x.strip())
                    elif isinstance(val, list):
                        ids.update(str(x) for x in val)
        return {"ids": ids, "count": len(ids), "error": None}
    except Exception as e:  # noqa: BLE001
        return {"ids": set(), "count": 0, "error": f"{type(e).__name__}: {str(e)[:120]}"}


def exploitation_signal(vuln_ids: List[str], kev: Optional[Dict[str, Any]] = None, euvd: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Which of the given ids are known-exploited according to the loaded feeds (sources declared)."""
    kev = kev or {"ids": set(), "error": "not loaded"}
    euvd = euvd or {"ids": set(), "error": "not loaded"}
    hits = {}
    for vid in vuln_ids:
        src = []
        if vid in kev["ids"]:
            src.append("cisa_kev")
        if vid in euvd["ids"]:
            src.append("enisa_euvd")
        if src:
            hits[vid] = src
    return {"actively_exploited": hits, "sources_loaded": {"cisa_kev": kev.get("error") is None, "enisa_euvd": euvd.get("error") is None},
            "note": "absence from KEV/EUVD is not proof of non-exploitation; a vendor advisory or own telemetry also starts the Art. 14 clock"}
