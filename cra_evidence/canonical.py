# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canonical JSON and digests shared by every record in this package.

Profile (identical to the cryptovalid acceptance profile, so ledgers written here verify with the independent
cryptovalid checkers in Python, JS, Go and Rust): keys sorted, separators (",", ":"), ASCII-escaped, NaN/Infinity
refused, and NO floats inside hashed content — encoders disagree on floats (Go `1` vs Python `1.0`), so a float is a
bug in the caller, not something to normalise silently. `floatfree()` is the explicit conversion for values that
legitimately arrive as floats (an epoch time, a score): they become exact strings before hashing.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def floatfree(obj: Any) -> Any:
    """Recursively turn every float into its shortest exact repr string (bool/int untouched)."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return repr(obj)
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):   # {"1": a, 1: b} would collapse to one key: refuse, never alter evidence silently
                raise TypeError(f"canonical: non-string key {k!r} — JSON object keys must be strings")
        return {k: floatfree(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [floatfree(v) for v in obj]
    return obj


def _refuse_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise TypeError(f"canonical: float at {path} — hashed content must be float-free (use floatfree())")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"canonical: non-string key {k!r} at {path}")
            _refuse_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _refuse_floats(v, f"{path}[{i}]")


def canonical_bytes(obj: Any) -> bytes:
    _refuse_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha3_hex(obj: Any) -> str:
    return hashlib.sha3_256(canonical_bytes(obj)).hexdigest()
