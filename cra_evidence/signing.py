# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ed25519 signing: file key (hex seed, 0600), signed chain tip (cryptovalid_tip/1, byte-identical payload so
cryptovalid's Python/JS/Go checkers verify it), and the evidence-pack signature sidecar (`<pack>.sig.json`).

Honest scope: a file key proves WHICH key signed, not WHO holds it; for attribution to an organisation put the key
in an HSM/KMS (out of scope here) and pin the public key out of band. Requires the optional `cryptography` package.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import re

from .ledger import parse_line, read_regular

HEX64_RE = re.compile(r"[0-9a-f]{64}")
HEX128_RE = re.compile(r"[0-9a-f]{128}")



# small-order / non-canonical Ed25519 keys: R=identity, S=0 verifies on every message and OpenSSL accepts it (measured 25/09/2026); same list in the JS/Go/Rust verifiers
WEAK_ED25519_KEYS = frozenset((
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
))


def weak_ed25519_key(pub_hex: str) -> bool:
    """True for a small-order key or a non-canonical encoding (y >= p). `pub_hex` is lower-case hex of 64 characters."""
    if pub_hex in WEAK_ED25519_KEYS:
        return True
    return (int.from_bytes(bytes.fromhex(pub_hex), "little") & ((1 << 255) - 1)) >= 2 ** 255 - 19

def _hex_ok(v: Any, n: int) -> bool:
    """Signature/key hex as the profile writes it: lower-case, exactly n hex characters — `bytes.fromhex` would also
    take spaces, JS `Buffer.from` would truncate at the first non-hex, Rust `from_str_radix` would take '+': one rule."""
    return isinstance(v, str) and (HEX64_RE if n == 64 else HEX128_RE).fullmatch(v) is not None
INSTANT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")
from .canonical import canonical_bytes, sha3_hex

TIP_KIND = "cryptovalid_tip/1"


def _ed():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def keygen(path: str) -> Dict[str, str]:
    Ed25519PrivateKey, _, ser = _ed()
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    # O_EXCL: an existing key is never overwritten (a second keygen on the same path would orphan every
    # signature made with the first key — council finding, 15/09/2026)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(seed.hex())
    return {"keyfile": path, "public_key_hex": sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()}


def load_key(path: str) -> Tuple[Any, str]:
    """(private key object, public key hex). Load ONCE and keep it — never re-read in a hot path."""
    Ed25519PrivateKey, _, ser = _ed()
    with open(path, encoding="utf-8") as f:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    return sk, sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


# ── signed chain tip (cryptovalid_tip/1) ──────────────────────────────────────
def tip_payload(entries: int, ledger_id: str, tip_sha256: str, ts: str) -> bytes:
    return json.dumps({"entries": entries, "kind": TIP_KIND, "ledger_id": ledger_id, "tip_sha256": tip_sha256, "ts": ts},
                      sort_keys=True, separators=(",", ":")).encode()


def write_tip(out: str, key: Tuple[Any, str], entries: int, ledger_id: str, tip_sha256: str, ts: Optional[str] = None) -> Dict[str, Any]:
    sk, pk = key
    ts = ts or datetime.now(timezone.utc).isoformat(timespec="seconds")
    tip = {"kind": TIP_KIND, "entries": entries, "ledger_id": ledger_id, "tip_sha256": tip_sha256, "ts": ts,
           "log_pubkey_hex": pk, "signature_hex": sk.sign(tip_payload(entries, ledger_id, tip_sha256, ts)).hex()}
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tip, f, separators=(",", ":"), sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    return tip


def verify_tip(tip: Dict[str, Any], trusted_pubkey_hex: str, entries: int, ledger_id: str, tip_sha256: str) -> Dict[str, Any]:
    """Minimal checker (the full profile lives in cryptovalid ≥ 0.11.3; this one is for self-tests)."""
    if not trusted_pubkey_hex:
        return {"ok": False, "error": "tip_untrusted: no trusted log key given"}
    try:
        _, Ed25519PublicKey, _ = _ed()
    except ImportError:
        return {"ok": False, "error": "tip_unchecked: a signed tip is present but cannot be checked here (cryptography not installed: pip install 'cra-evidence[sign]', or use the JS/Go/Rust verifier)"}
    if not isinstance(tip, dict) or tip.get("kind") != TIP_KIND:
        return {"ok": False, "error": "tip_invalid: not a cryptovalid_tip/1 document"}
    # field TYPES as the three independent verifiers require them (a string "3" is not an entry count, a bool is not an int)
    n = tip.get("entries")
    if isinstance(n, bool) or not isinstance(n, int) or n < 0 or not all(isinstance(tip.get(k), str) for k in ("ledger_id", "tip_sha256", "ts", "signature_hex")):
        return {"ok": False, "error": "tip_invalid: bad field types"}
    if not (HEX64_RE.fullmatch(tip["ledger_id"]) and HEX64_RE.fullmatch(tip["tip_sha256"]) and INSTANT_RE.fullmatch(tip["ts"])
            and _hex_ok(tip["signature_hex"], 128) and _hex_ok(trusted_pubkey_hex, 64)):
        return {"ok": False, "error": "tip_invalid: bad fields"}
    lk = tip.get("log_pubkey_hex")
    if lk not in (None, "") and lk != trusted_pubkey_hex:   # "" = absent (cryptovalid profile, as Go/JS); a non-string never equals the key
        return {"ok": False, "error": "tip_invalid: tip log key differs from the trusted log key"}
    if weak_ed25519_key(trusted_pubkey_hex):
        return {"ok": False, "error": "tip_invalid: weak log key (small order or non-canonical)"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_pubkey_hex)).verify(
            bytes.fromhex(tip["signature_hex"]), tip_payload(n, tip["ledger_id"], tip["tip_sha256"], tip["ts"]))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"tip_invalid: {type(e).__name__}"}
    if n != entries:
        return {"ok": False, "error": "tail_truncated" if entries < n else "unsealed_tail"}
    if tip["ledger_id"] != ledger_id:
        return {"ok": False, "error": "tip_of_another_ledger"}
    if tip["tip_sha256"] != tip_sha256:
        return {"ok": False, "error": "tail_rewritten"}
    return {"ok": True}


# ── evidence-pack signature sidecar ───────────────────────────────────────────
def sidecar_path(pack_path: str) -> str:
    """`<pack path>.sig.json` — the string as given, no normalisation (the three verifiers append the suffix to the argument as is)."""
    return str(pack_path) + ".sig.json"


def pack_digest(pack: Dict[str, Any]) -> str:
    """pack_sha3 recomputed FROM CONTENT (never trusted from the field)."""
    return sha3_hex({k: v for k, v in pack.items() if k != "pack_sha3"})


SIG_KIND = "cra_pack_sig/1"


def sidecar_fields_ok(side: Dict[str, Any]) -> bool:
    return (all(isinstance(side.get(k), str) and side.get(k) for k in ("signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "signature_hex"))
            and INSTANT_RE.fullmatch(side["signed_utc"]) is not None and ("alg" not in side or isinstance(side["alg"], str)))


def signed_payload(side: Dict[str, Any]) -> bytes:
    """Domain-separated, canonical bytes that the sidecar signature covers."""
    return canonical_bytes({"kind": SIG_KIND, "signed_pack_sha3": side["signed_pack_sha3"], "signer_id": side["signer_id"],
                            "signed_utc": side["signed_utc"], "public_key_hex": side["public_key_hex"], "alg": side.get("alg", "Ed25519")})


def sign_pack(pack_path: str, key: Tuple[Any, str], signer_id: str) -> Dict[str, Any]:
    sk, pk = key
    if not isinstance(signer_id, str) or not signer_id:
        raise ValueError("signer_id must be a non-empty string")
    with open(pack_path, "rb") as f:
        pack = parse_line(f.read().decode("utf-8"))
    digest = pack_digest(pack)
    if pack.get("pack_sha3") != digest:
        raise ValueError("pack_sha3 does not match the pack content: refusing to sign a broken pack")
    side = {"signer_id": signer_id, "public_key_hex": pk, "alg": "Ed25519",
            "fingerprint": hashlib.sha256(bytes.fromhex(pk)).hexdigest()[:16],
            "signed_pack_sha3": digest, "signed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    # the signature covers WHO signed and WHEN, not only the digest (a sidecar with a rewritten signer_id must fail)
    side["signature_hex"] = sk.sign(signed_payload(side)).hex()
    with open(sidecar_path(pack_path), "w", encoding="utf-8") as f:
        f.write(json.dumps(side, indent=1, sort_keys=True))
    return {"signed": True, "sidecar": str(sidecar_path(pack_path)), "fingerprint": side["fingerprint"]}


def verify_pack_signature(pack_path: str, trust_store: Optional[Dict[str, str]] = None, pack: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """PASS / FAIL / SKIP. Content-binding first (digest recomputed), then signature-binding, then the optional
    trust store {signer_id: public_key_hex} — a valid signature from an unknown signer is 'signed', not 'trusted'."""
    sp = sidecar_path(pack_path)
    try:                                                # one rule in the four: lstat ENOENT/ENOTDIR = no sidecar; any other error = a sidecar path that cannot be used
        os.lstat(sp)
    except (FileNotFoundError, NotADirectoryError):
        return {"status": "SKIP", "detail": "pack not signed"}
    except OSError as e:
        return {"status": "FAIL", "detail": f"sidecar path unusable ({e.errno}: {e.strerror})"}
    try:                                                # a regular file within MAX_DOC_BYTES (a FIFO / device is a FAIL, never a hang)
        side = parse_line(read_regular(sp).decode("utf-8"))              # strict: duplicate keys / NaN / UTF-8 refused like the verifiers
        if pack is None:
            pack = parse_line(read_regular(pack_path).decode("utf-8"))   # the verifier passes the pack it already read (read once)
    except (OSError, ValueError, RecursionError) as e:
        return {"status": "FAIL", "detail": f"unreadable: {str(e)[:120]}"}
    if not isinstance(side, dict) or not isinstance(pack, dict):
        return {"status": "FAIL", "detail": "sidecar or pack is not a JSON object"}
    try:
        digest = pack_digest(pack)
    except TypeError as e:
        return {"status": "FAIL", "detail": f"pack not canonicalisable: {e}"}
    if pack.get("pack_sha3") != digest:
        return {"status": "FAIL", "detail": "content does not match pack_sha3 (modified after signing)"}
    if side.get("signed_pack_sha3") != digest:
        return {"status": "FAIL", "detail": "pack changed after signature (digest differs from the signed one)"}
    try:
        _, Ed25519PublicKey, _ = _ed()
    except ImportError:
        # Fail-closed, and now SAID so in the verdict: this host could not run the check, so it is an absence rather
        # than a finding about the pack. Measured 24/09/2026 while building the 0.3.1 release: a pack signed minutes
        # earlier with the KMS key verified as authenticity=FAIL in a venv without `cryptography` — our own missing
        # library reported with the value of a bad signature, on our own release artifact.
        return {"status": "FAIL", "assessed": False,
                "detail": "signature present but NOT checkable here (cryptography not installed: pip install 'cra-evidence[sign]', or use the JS/Go/Rust verifier)"}
    if not sidecar_fields_ok(side):   # the signed fields must exist as strings (a missing field is never signed "as null")
        return {"status": "FAIL", "detail": "sidecar field missing or not a string (signed_pack_sha3, signer_id, signed_utc instant, public_key_hex, signature_hex; alg if present)"}
    if not (_hex_ok(side.get("public_key_hex"), 64) and _hex_ok(side.get("signature_hex"), 128)):
        return {"status": "FAIL", "detail": "signature invalid for the declared key (key/signature must be lower-case hex of exact length)"}
    if weak_ed25519_key(side["public_key_hex"]):
        return {"status": "FAIL", "detail": "signature invalid for the declared key (weak key: small order or non-canonical)"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(side["public_key_hex"])).verify(bytes.fromhex(side["signature_hex"]), signed_payload(side))
    except Exception as e:  # noqa: BLE001
        return {"status": "FAIL", "detail": f"signature invalid for the declared key ({type(e).__name__})"}
    fp = hashlib.sha256(bytes.fromhex(side["public_key_hex"])).hexdigest()[:16]   # recomputed, never echoed
    # absent = not declared; PRESENT must be the key's fingerprint — `null` is a malformed value like any other non-match
    # (the signer always writes the 16-hex string). Measured 25/09/2026: `fingerprint: null` passed in the five while an
    # int / list / object failed: absent != null.
    if "fingerprint" in side and side["fingerprint"] != fp:
        return {"status": "FAIL", "detail": "declared fingerprint does not match the signing key"}
    if not isinstance(side.get("signer_id"), str):
        return {"status": "FAIL", "detail": "signer_id must be a string"}
    out = {"status": "PASS", "signer_id": side.get("signer_id"), "fingerprint": fp, "trusted": False}
    if trust_store is not None:
        expected = trust_store.get(side.get("signer_id", ""))
        out["trusted"] = bool(expected) and expected == side.get("public_key_hex")
        out["detail"] = "trusted-signed" if out["trusted"] else "signed by a key NOT in the trust store"
    else:
        out["detail"] = "signed (signer not compared with a trust store)"
    return out
