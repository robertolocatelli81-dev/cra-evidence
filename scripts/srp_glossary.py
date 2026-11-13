#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The ENISA CRA SRP glossary, as a dated snapshot, and the drift check against the live page. Python standard library only.

  extract HTML_FILE                 print the snapshot JSON of a saved page (the format of spec/sources/*.json)
  check [--html FILE] [--url URL] [--snapshot FILE]
                                    extract the live page (or a saved one) and compare it with the newest snapshot in
                                    spec/sources/, and the page's version line and the notes after the table with the
                                    ones recorded for that snapshot (PAGE): exit 0 = identical, 1 = something differs (a
                                    readable diff is printed), 2 = the page could not be fetched or holds no glossary
                                    table, or a local file could not be read

Extraction (the method of the snapshots of 15/09/2026 and 29/09/2026, which it reproduces byte for byte from their raw
pages): html.parser, one text string per <td>/<th>, entities unescaped, NBSP read as a space, <br>/<p>/<li> as a space,
whitespace collapsed and stripped; header = the first <tr>, rows = every other <tr> of the table, in document order,
cells as they appear (rowspan continuation rows have fewer cells). Serialisation: json indent=0, ensure_ascii=False,
no final newline."""
from __future__ import annotations

import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

URL = "https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = os.path.join(ROOT, "spec", "sources")
HEADER = ["Nr.", "Field", "Applies to AEV or SI", "What this field means", "How you may complete it", "Example",
          "Expected format", "Early Warning (EW) 24h", "72h", "Final Report (FR)"]
MAX_PAGE = 8 * 1024 * 1024


class _Table(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_table = 0
        self.tables = 0
        self.rows: List[List[str]] = []
        self.row: Optional[List[str]] = None
        self.cell: Optional[List[str]] = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.in_table += 1
            self.tables += 1
        if not self.in_table:
            return
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th"):
            self.cell = []
        elif tag in ("br", "p", "li") and self.cell is not None:
            self.cell.append(" ")

    def handle_endtag(self, tag):
        if not self.in_table:
            return
        if tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append(re.sub(r"\s+", " ", "".join(self.cell).replace("\xa0", " ")).strip())
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None
        elif tag == "table":
            self.in_table -= 1

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)


def extract(html: str) -> Dict[str, Any]:
    """The glossary table of the page. ValueError when the page holds no single table with the glossary header."""
    p = _Table()
    p.feed(html)
    p.close()
    if p.tables != 1:
        raise ValueError(f"expected one table in the page, found {p.tables}")
    if not p.rows or p.rows[0] != HEADER:
        raise ValueError(f"the table header is not the glossary header: {p.rows[0] if p.rows else None!r}")
    return {"header": p.rows[0], "rows": p.rows[1:]}


def serialise(snapshot: Dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=0, ensure_ascii=False)


def page_version(html: str) -> Optional[str]:
    m = re.search(r"Version\s+[0-9.]+\.\s+Last update:\s+[0-9]{1,2} [A-Za-z]+ [0-9]{4}", html.replace("&nbsp;", " ").replace("\xa0", " "))
    return m.group(0) if m else None


_FOOTNOTES_13 = ("[1] This field will be available in the next release of the Platform. [2] In the current release this field is "
                 "named: \u201cDate and time when the incident was detected (UTC time)\u201d.")
# What the page says OUTSIDE the table, per snapshot: the version line, and the notes after the table (pages 1.3 and 1.4 had
# two footnotes on v26/i37 that qualified those fields; the page 1.6 has none). A change here is drift too.
PAGE = {"enisa_srp_glossary_20260915.json": ("Version 1.3. Last update: 10 September 2026", _FOOTNOTES_13),
        "enisa_srp_glossary_20260929.json": ("Version 1.3. Last update: 25 September 2026", _FOOTNOTES_13),
        "enisa_srp_glossary_20261010.json": ("Version 1.4. Last update: 01 October 2026", _FOOTNOTES_13),
        "enisa_srp_glossary_20261112.json": ("Version 1.6. Last update: 21 October 2026", "")}


def page_notes(html: str) -> Optional[str]:
    """The text between the end of the glossary table and the page footer ("Subscribe"), whitespace collapsed; None when
    the page has no such region (layout changed)."""
    import html as _h
    end = html.rfind("</table>")
    if end < 0:
        return None
    rest = re.sub(r"<(script|style)\b.*?</\1>", " ", html[end + 8:], flags=re.S | re.I)
    text = re.sub(r"\s+", " ", _h.unescape(re.sub(r"<[^>]+>", " ", rest)).replace("\xa0", " ")).strip()
    i = text.find("Subscribe")
    return text[:i].strip() if i >= 0 else None


def newest_snapshot(directory: str = SOURCES) -> str:
    files = sorted(glob.glob(os.path.join(directory, "enisa_srp_glossary_*.json")))
    files = [f for f in files if re.fullmatch(r"enisa_srp_glossary_\d{8}\.json", os.path.basename(f))]
    if not files:
        raise FileNotFoundError(f"no enisa_srp_glossary_YYYYMMDD.json in {directory}")
    return files[-1]


def _key(row: List[str]) -> Optional[str]:
    return re.sub(r"\s", "", row[0]) if len(row) >= 10 else None


def diff(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """Readable differences, row by row (numbered rows by their number, the others by position)."""
    out: List[str] = []
    if old.get("header") != new.get("header"):
        out.append(f"header: {old.get('header')!r} -> {new.get('header')!r}")
    o = {_key(r): r for r in old["rows"] if _key(r)}
    n = {_key(r): r for r in new["rows"] if _key(r)}
    for k in n:
        if k not in o:
            out.append(f"row {k} added: {n[k][1]!r} ({n[k][2]}; EW {n[k][7]!r}, 72h {n[k][8]!r}, FR {n[k][9]!r})")
    for k in o:
        if k not in n:
            out.append(f"row {k} removed: {o[k][1]!r}")
    hdr = new.get("header") or HEADER
    for k in n:
        if k in o:
            for c in range(10):
                if o[k][c] != n[k][c]:
                    name = hdr[c] if c < len(hdr) else str(c)
                    out.append(f"row {k} [{name}]: {o[k][c]!r} -> {n[k][c]!r}")
    if [k for k in o if k in n] != [k for k in n if k in o]:
        out.append("order of the numbered rows changed")
    ou = [r for r in old["rows"] if not _key(r)]
    nu = [r for r in new["rows"] if not _key(r)]
    if ou != nu:
        out.append(f"unnumbered rows (sections, continuation lines): {ou!r} -> {nu!r}")
    if not out and old != new:
        out.append("the snapshots differ (whitespace or cell count)")
    return out


def fetch(url: str = URL, timeout: float = 60.0, attempts: int = 3, wait: float = 30.0) -> str:
    """The page, or the last error. HTTP 429 and 5xx and network errors are retried (`attempts` in all, `wait` x attempt
    seconds apart): ENISA's site answered 429 to repeated fetches on 12/11/2026 (measured on its FAQ page)."""
    import time
    req = urllib.request.Request(url, headers={"User-Agent": "omega-cra-evol glossary drift check (+https://github.com/robertolocatelli81-dev/omega-cra-evol)"})
    for i in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:   # nosec: a fixed https URL, read-only
                body = r.read(MAX_PAGE + 1)
            break
        except urllib.error.HTTPError as e:
            if i == attempts or not (e.code == 429 or e.code >= 500):
                raise
        except (urllib.error.URLError, OSError):
            if i == attempts:
                raise
        time.sleep(wait * i)
    if len(body) > MAX_PAGE:
        raise ValueError(f"page larger than {MAX_PAGE} bytes")
    return body.decode("utf-8")


def check(html: Optional[str], snapshot_path: str, out=sys.stdout) -> int:
    try:
        with open(snapshot_path, encoding="utf-8") as f:
            ref = json.load(f)
    except (OSError, ValueError) as e:       # never exit 1 ("the glossary differs") for a local error
        print(f"REFERENCE UNREADABLE: {snapshot_path}: {e}", file=out)
        return 2
    name = os.path.basename(snapshot_path)
    if name not in PAGE:
        print(f"NO PAGE RECORD for {name}: the version line and the notes cannot be compared", file=out)
        return 2
    try:
        live = extract(html or "")
    except ValueError as e:
        print(f"NO GLOSSARY: {e}", file=out)
        return 2
    version, notes = page_version(html or ""), page_notes(html or "")
    print(f"page: {version or 'version line not found'}", file=out)
    print(f"reference: {name}", file=out)
    d = [] if serialise(live) == serialise(ref) else diff(ref, live)
    if version != PAGE[name][0]:
        d.append(f"version line: {PAGE[name][0]!r} -> {version!r}")
    if notes != PAGE[name][1]:
        d.append(f"notes outside the table: {PAGE[name][1]!r} -> {notes!r}")
    if not d:
        print(f"identical: {len(live['rows'])} rows, {sum(1 for r in live['rows'] if _key(r))} numbered fields, same version line and notes", file=out)
        return 0
    print(f"DRIFT: the ENISA glossary differs from {os.path.basename(snapshot_path)} in {len(d)} place(s):", file=out)
    for line in d:
        print("  " + line, file=out)
    print("Next: save the page, write spec/sources/enisa_srp_glossary_YYYYMMDD.json with `extract`, update "
          "spec/SRP_FIELDS.md, then omega_cra_evol/srp_notice.py and the tests.", file=out)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="srp_glossary.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("html")
    c = sub.add_parser("check")
    c.add_argument("--html", help="a saved page instead of the live one (offline)")
    c.add_argument("--url", default=URL)
    c.add_argument("--snapshot", help="reference snapshot (default: the newest in spec/sources/)")
    c.add_argument("--attempts", type=int, default=3, help="fetch attempts on HTTP 429/5xx or a network error (default 3, 30 s, 60 s apart)")
    a = ap.parse_args(argv)
    if a.cmd == "extract":
        try:
            with open(a.html, encoding="utf-8") as f:
                sys.stdout.write(serialise(extract(f.read())))
        except (OSError, ValueError) as ex:   # UnicodeDecodeError is a ValueError
            print(f"NO GLOSSARY: {ex}", file=sys.stderr)
            return 2
        return 0
    try:
        snap = a.snapshot or newest_snapshot()
        if a.html:
            with open(a.html, encoding="utf-8") as f:
                html = f.read()
    except (OSError, ValueError) as ex:      # a local error is 2, never 1 ("the glossary differs")
        print(f"LOCAL INPUT FAILED: {ex}")
        return 2
    if not a.html:
        try:
            html = fetch(a.url, attempts=max(1, a.attempts))
        except (urllib.error.URLError, OSError, ValueError, UnicodeDecodeError) as ex:
            print(f"FETCH FAILED: {a.url}: {ex}")
            return 2
    return check(html, snap)


if __name__ == "__main__":
    sys.exit(main())
