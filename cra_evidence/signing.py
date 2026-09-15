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
    _, Ed25519PublicKey, _ = _ed()
    if not trusted_pubkey_hex:
        return {"ok": False, "error": "tip_untrusted: no trusted log key given"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_pubkey_hex)).verify(
            bytes.fromhex(tip["signature_hex"]), tip_payload(int(tip["entries"]), tip["ledger_id"], tip["tip_sha256"], tip["ts"]))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"tip_invalid: {type(e).__name__}"}
    if int(tip["entries"]) != entries:
        return {"ok": False, "error": "tail_truncated" if entries < int(tip["entries"]) else "unsealed_tail"}
    if tip["ledger_id"] != ledger_id:
        return {"ok": False, "error": "tip_of_another_ledger"}
    if tip["tip_sha256"] != tip_sha256:
        return {"ok": False, "error": "tail_rewritten"}
    return {"ok": True}


# ── evidence-pack signature sidecar ───────────────────────────────────────────
def sidecar_path(pack_path: str) -> Path:
    return Path(pack_path).with_suffix(Path(pack_path).suffix + ".sig.json")


def pack_digest(pack: Dict[str, Any]) -> str:
    """pack_sha3 recomputed FROM CONTENT (never trusted from the field)."""
    return sha3_hex({k: v for k, v in pack.items() if k != "pack_sha3"})


SIG_KIND = "cra_pack_sig/1"


def signed_payload(side: Dict[str, Any]) -> bytes:
    """Domain-separated, canonical bytes that the sidecar signature covers."""
    return canonical_bytes({"kind": SIG_KIND, "signed_pack_sha3": side["signed_pack_sha3"], "signer_id": side["signer_id"],
                            "signed_utc": side["signed_utc"], "public_key_hex": side["public_key_hex"], "alg": side.get("alg", "Ed25519")})


def sign_pack(pack_path: str, key: Tuple[Any, str], signer_id: str) -> Dict[str, Any]:
    sk, pk = key
    pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    digest = pack_digest(pack)
    if pack.get("pack_sha3") != digest:
        raise ValueError("pack_sha3 does not match the pack content: refusing to sign a broken pack")
    side = {"signer_id": signer_id, "public_key_hex": pk, "alg": "Ed25519",
            "fingerprint": hashlib.sha256(bytes.fromhex(pk)).hexdigest()[:16],
            "signed_pack_sha3": digest, "signed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    # the signature covers WHO signed and WHEN, not only the digest (a sidecar with a rewritten signer_id must fail)
    side["signature_hex"] = sk.sign(signed_payload(side)).hex()
    sidecar_path(pack_path).write_text(json.dumps(side, indent=1, sort_keys=True), encoding="utf-8")
    return {"signed": True, "sidecar": str(sidecar_path(pack_path)), "fingerprint": side["fingerprint"]}


def verify_pack_signature(pack_path: str, trust_store: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """PASS / FAIL / SKIP. Content-binding first (digest recomputed), then signature-binding, then the optional
    trust store {signer_id: public_key_hex} — a valid signature from an unknown signer is 'signed', not 'trusted'."""
    sp = sidecar_path(pack_path)
    if not sp.exists():
        return {"status": "SKIP", "detail": "pack not signed"}
    try:
        side = json.loads(sp.read_text(encoding="utf-8"))
        pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {"status": "FAIL", "detail": f"unreadable: {e}"}
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
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(side["public_key_hex"])).verify(bytes.fromhex(side["signature_hex"]), signed_payload(side))
    except Exception as e:  # noqa: BLE001
        return {"status": "FAIL", "detail": f"signature invalid for the declared key ({type(e).__name__})"}
    out = {"status": "PASS", "signer_id": side.get("signer_id"), "fingerprint": side.get("fingerprint"), "trusted": False}
    if trust_store is not None:
        expected = trust_store.get(side.get("signer_id", ""))
        out["trusted"] = bool(expected) and expected == side.get("public_key_hex")
        out["detail"] = "trusted-signed" if out["trusted"] else "signed by a key NOT in the trust store"
    else:
        out["detail"] = "signed (signer not compared with a trust store)"
    return out
