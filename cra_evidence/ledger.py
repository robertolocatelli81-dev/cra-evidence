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

from .canonical import MAX_DEPTH, canonical_bytes, deep_recursion, nesting_depth, sha256_hex

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


MAX_LINE_BYTES = 64 << 20   # same bound as cryptovalid's Go verifier (MaxLineBytes): the four cra verifiers agree on it


def _no_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} in ledger line (the profile forbids it: readers disagree on which wins)")
        d[k] = v
    return d


def line_content(raw: bytes) -> bytes:
    """One JSONL line without its terminator: exactly one trailing \\n, then at most one \\r (the same rule in the four
    verifiers — a run of \\r bytes is content, not a terminator, and counts against the bound)."""
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw


def is_blank_line(content: bytes) -> bool:
    """Blank = only ASCII space / tab. Unicode spaces (U+00A0, U+2028, U+0085, U+FEFF…) are NOT blank: they are an
    unparsable line, in all four verifiers."""
    return content.strip(b" \t") == b""


def _refuse_int(tok: str):
    n = int(tok)
    if abs(n) > 2 ** 53 - 1:
        raise ValueError(f"integer {tok} outside ±(2^53-1) (the profile forbids it: a JavaScript reader would round it)")
    return n


def _refuse_float(tok: str):
    raise ValueError(f"floating-point number {tok} (the profile forbids floats: `10.0` and `10` would hash alike in one reader and not in another)")


def parse_line(line: str, allow_floats: bool = False):
    """The profile's strict JSON: no NaN/Infinity, no duplicate keys, no floats (not even integral ones such as 10.0 —
    JSON.parse would silently turn them into 10), no integer outside ±(2^53-1). allow_floats=True only for third-party
    generator documents, which are stored as bytes, never canonicalised (numbers are then read as JSON allows)."""
    if nesting_depth(line) > MAX_DEPTH:       # linear pre-scan, before the recursive parser: exactly the verifiers' bound
        raise ValueError(f"json_too_deep: nesting exceeds the acceptance-profile bound {MAX_DEPTH}")
    try:
        with deep_recursion():                 # depth ≤ 512 must PARSE in the reference too (hooks cost frames per level)
            v = json.loads(line, parse_constant=_refuse_constant, object_pairs_hook=_no_dup_keys,
                           parse_float=(float if allow_floats else _refuse_float), parse_int=(int if allow_floats else _refuse_int))
    except RecursionError:
        raise ValueError("json_too_deep: the parser could not hold this nesting") from None
    if not allow_floats and _has_lone_surrogate(v):
        raise ValueError("lone surrogate in a JSON string (the profile forbids it: it has no UTF-8 encoding)")
    return v


def _has_lone_surrogate(v) -> bool:
    """Iterative walk (a 512-deep document must not cost interpreter frames here)."""
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                return True
        elif isinstance(x, dict):
            stack.extend(x.keys())
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return False


def load_trust_store(text: str) -> Dict[str, str]:
    """{signer_id: public_key_hex}: strict JSON, an object, string values — anything else is unreadable (exit 2 in
    every verifier), never a partial trust store."""
    try:
        d = parse_line(text)
    except (ValueError, RecursionError) as e:
        raise ValueError(f"trust store unreadable: {str(e)[:100]}") from None
    if not isinstance(d, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in d.items()):
        raise ValueError("trust store unreadable: must be a JSON object of signer_id -> public_key_hex strings")
    return d


def entry_hash(entry: Dict[str, Any]) -> str:
    return sha256_hex({k: v for k, v in entry.items() if k != "self_hash"})


def _tail_state(f) -> Tuple[int, str, str, bool]:
    """(next idx, last self_hash, first self_hash, file ends without newline). Fail-closed on a bad line."""
    f.seek(0)
    n, last, first, unterminated, lineno = 0, GENESIS, GENESIS, False, 0
    while True:                                           # the writer reads with the VERIFIERS' rules: bounded, one terminator, ASCII blank
        raw = f.readline(MAX_LINE_BYTES + 2)
        if not raw:
            break
        lineno += 1
        if not raw.endswith(b"\n") and len(raw) == MAX_LINE_BYTES + 2:
            raise ValueError(f"ledger line {lineno} exceeds {MAX_LINE_BYTES} bytes: chain not continuable — verify, repair, record the incident")
        unterminated = not raw.endswith(b"\n")
        line = line_content(raw)
        if is_blank_line(line):
            continue
        if len(line) > MAX_LINE_BYTES:
            raise ValueError(f"ledger line {lineno} exceeds {MAX_LINE_BYTES} bytes: chain not continuable — verify, repair, record the incident")
        try:
            e = parse_line(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as e:
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
            line = canonical_bytes(entry) + b"\n"
            if len(line) - 1 > MAX_LINE_BYTES:   # content without the terminator
                raise ValueError(f"record would exceed {MAX_LINE_BYTES} bytes on one line: the verifiers refuse it, so it is not written")
            if nesting_depth(line.decode("utf-8")) > MAX_DEPTH:   # the LINE's depth (entry adds a level over data): what every reader bounds
                raise ValueError(f"record would nest deeper than {MAX_DEPTH} on its ledger line: the verifiers refuse it, so it is not written")
            f.seek(0, os.SEEK_END)
            if unterminated:
                _log.warning("ledger %s ended without newline (crash or truncation): line closed before the new record", self.path)
                f.write(b"\n")
            f.write(line)
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
        with open(self.path, "rb") as f:
            while True:
                raw = f.readline(MAX_LINE_BYTES + 2)          # bounded read: a hostile line is never buffered whole
                if not raw:
                    break
                if not raw.endswith(b"\n") and len(raw) == MAX_LINE_BYTES + 2:
                    raise ValueError(f"ledger line exceeds {MAX_LINE_BYTES} bytes (cryptovalid profile: refused, never truncated)")
                content = line_content(raw)
                if is_blank_line(content):
                    continue
                if len(content) > MAX_LINE_BYTES:             # the bound is on the content, terminator excluded, in all four verifiers
                    raise ValueError(f"ledger line exceeds {MAX_LINE_BYTES} bytes (cryptovalid profile: refused, never truncated)")
                yield parse_line(content.decode("utf-8"))   # NaN/Infinity are not JSON: fail; invalid UTF-8: fail

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
        except (ValueError, TypeError, RecursionError, OSError) as ex:
            failures.append(f"unparsable line: {type(ex).__name__}: {str(ex)[:120]}")
        if n == 0:
            failures.append("empty_ledger: zero entries, nothing to verify")
        return {"chain_ok": not failures, "entries": n, "failures": failures[:10], "last_self_hash": prev}
