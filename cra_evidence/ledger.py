# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only hash-chained JSONL ledger in the cryptovalid profile.

Entry: {"idx": n, "ts": "YYYY-MM-DDTHH:MM:SSZ", "prev_hash": <64 hex>, "data": {...}, "self_hash": <64 hex>} where
self_hash = SHA-256 of the canonical JSON of the entry without self_hash, and genesis prev_hash = 64 zeros.
Because the profile is the same, an evidence ledger written here is verified by the independent cryptovalid
checkers (verifier.py, cvverify.mjs, Go cvverify, Rust) and by cryptovalid's signed chain tip.

Writer discipline (lessons paid for on 15/09/2026, in the open): one descriptor, exclusive flock BEFORE reading the
tail, write under the same lock (two processes reading the tail outside the lock forked the chain); a last line
that is complete but lost its newline is closed before the next record (never two records on one line); a tail
that does not parse is never continued from (refused, recovery is a human decision); an empty ledger is FAIL
(nothing verified), never a third verdict.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .canonical import canonical_bytes, sha256_hex

GENESIS = "0" * 64
_log = logging.getLogger("cra_evidence.ledger")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lock(f) -> bool:
    try:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return True
    except (ImportError, OSError) as e:  # non-POSIX or a filesystem without flock: SAY it
        _log.warning("ledger: no exclusive lock on %s (%s): concurrent appends are not serialised", getattr(f, "name", "?"), e)
        return False


def _refuse_constant(name: str):
    raise ValueError(f"non-JSON constant {name} in ledger line")


def _no_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} in ledger line (the profile forbids it: readers disagree on which wins)")
        d[k] = v
    return d


def parse_line(line: str):
    return json.loads(line, parse_constant=_refuse_constant, object_pairs_hook=_no_dup_keys)


def entry_hash(entry: Dict[str, Any]) -> str:
    return sha256_hex({k: v for k, v in entry.items() if k != "self_hash"})


def _tail_state(f) -> Tuple[int, str, str, bool]:
    """(next idx, last self_hash, first self_hash, file ends without newline). Fail-closed on a bad line."""
    f.seek(0)
    n, last, first, unterminated = 0, GENESIS, GENESIS, False
    for lineno, raw in enumerate(f, 1):
        unterminated = not raw.endswith(b"\n")
        line = raw.strip()
        if not line:
            continue
        try:
            e = parse_line(line)
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"ledger line {lineno} unparsable ({type(e).__name__}): chain not continuable — verify, repair, record the incident")
        if not isinstance(e, dict) or not isinstance(e.get("self_hash"), str) or len(e["self_hash"]) != 64:
            raise ValueError(f"ledger line {lineno} is not a chained entry")
        n += 1
        last = e["self_hash"]
        if n == 1:
            first = last
    return n, last, first, unterminated


class Ledger:
    """A single JSONL file. `append(data)` is O(n) (reads the tail under the lock) — fine for evidence lockers,
    where a product records dozens to thousands of events, not millions per second."""

    def __init__(self, path: str, tip_key: Optional[object] = None, allow_unlocked: bool = False):
        # allow_unlocked=True is the ONLY way to append on a filesystem without flock, and it is the caller's
        # declared acceptance that concurrent appends may fork the chain (fail-closed by default)
        self.allow_unlocked = allow_unlocked
        self.path = path
        self._tip_key = tip_key   # (sk, pk_hex) from cra_evidence.signing.load_key(): signed chain tip after each append
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    # ── write ──────────────────────────────────────────────────────────────
    def append(self, data: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        canonical_bytes(data)   # refuse floats / NaN EARLY (never store what the verifiers reject)
        with open(self.path, "ab+") as f:
            if not _lock(f) and not self.allow_unlocked:
                raise RuntimeError("ledger: exclusive lock unavailable on this filesystem; refusing to append "
                                   "(pass allow_unlocked=True to accept unserialised appends explicitly)")
            idx, prev, first, unterminated = _tail_state(f)
            entry = {"idx": idx, "ts": ts or _now_ts(), "prev_hash": prev, "data": data}
            entry["self_hash"] = entry_hash(entry)
            f.seek(0, os.SEEK_END)
            if unterminated:
                _log.warning("ledger %s ended without newline (crash or truncation): line closed before the new record", self.path)
                f.write(b"\n")
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n")
            f.flush()
            os.fsync(f.fileno())
            if self._tip_key is not None:
                from .signing import write_tip
                write_tip(self.path + ".tip.json", self._tip_key, idx + 1, first if idx > 0 else entry["self_hash"], entry["self_hash"])
        return entry

    # ── read / verify ──────────────────────────────────────────────────────
    def entries(self) -> Iterator[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return iter(())
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield parse_line(line)   # NaN/Infinity are not JSON: fail

    def verify(self) -> Dict[str, Any]:
        """Snapshot verification: every self_hash recomputes, every prev_hash links, idx contiguous, non-empty.
        Does NOT see a truncated tail (a shorter prefix is a valid chain): use the signed tip / cryptovalid."""
        failures: List[str] = []
        prev, n = GENESIS, 0
        try:
            for e in self.entries():
                if not isinstance(e, dict):
                    failures.append(f"entry {n}: not an object (JSON {type(e).__name__})")
                    break
                if type(e.get("idx")) is not int or e.get("idx") != n:   # `true` == 1 in Python: refuse the type, not just the value
                    failures.append(f"entry {n}: idx {e.get('idx')!r} not sequential")
                if e.get("prev_hash") != prev:
                    failures.append(f"entry {n}: prev_hash does not link")
                if entry_hash(e) != e.get("self_hash"):
                    failures.append(f"entry {n}: self_hash mismatch")
                prev = e.get("self_hash", prev) if isinstance(e.get("self_hash"), str) else prev
                n += 1
        except (ValueError, TypeError, RecursionError) as ex:
            failures.append(f"unparsable line: {type(ex).__name__}: {str(ex)[:120]}")
        if n == 0:
            failures.append("empty_ledger: zero entries, nothing to verify")
        return {"chain_ok": not failures, "entries": n, "failures": failures[:10], "last_self_hash": prev}
