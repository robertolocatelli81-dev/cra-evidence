# SPDX-License-Identifier: AGPL-3.0-or-later
"""Long-term evidence seal for the 10-year CRA retention: a chain of archive timestamps in the spirit of RFC 4998
(Evidence Record Syntax) / eIDAS LTA, crypto-agile.

Each record signs the evidence digest + the WHOLE previous chain (+ an optional stronger re-hash), so a renewal
cannot be grafted, reordered or applied to a different digest without breaking every later signature. The
algorithm registry starts with Ed25519 (the optional `cryptography` dependency); a hybrid ML-DSA-65 + Ed25519 signer can be
registered by the caller (see `register_algorithm`) — NIST IR 8547 (an initial public DRAFT, not a final standard)
proposes deprecating the quantum-vulnerable signatures after 2030 and disallowing them after 2035, inside the
retention window that starts today, so the seal MUST be renewable.

Honest scope: with ts_source="asserted" the time is the prover's claim, NOT an objective anchor; pass
ts_source="rfc3161" (or "ots") only after obtaining a third-party timestamp, and inject `timestamp_trust_fn`
at verification time. The verdict says whether temporal trust was VERIFIED or ASSUMED.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


HASHES: Dict[str, Callable[[bytes], "hashlib._Hash"]] = {"sha3-256": hashlib.sha3_256, "sha2-512": hashlib.sha512}
DEFAULT_HASH = "sha3-256"


def register_hash(name: str, ctor: Callable) -> None:
    """Hash agility for the seal chain (the signature is not the only primitive that ages over 10 years)."""
    HASHES[name] = ctor


def _digest(hash_alg: str, b: bytes) -> str:
    if hash_alg not in HASHES:
        raise ValueError(f"unknown hash: {hash_alg}")
    return HASHES[hash_alg](b).hexdigest()


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _ed_gen():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw().hex()


# NIST IR 8547 (initial public draft, Nov 2024): quantum-vulnerable digital signatures (Ed25519 included) deprecated
# after 2030 and disallowed after 2035. Used as the DEFAULT policy so that "always valid" is never the silent default.
NIST_IR_8547_DISALLOWED_AFTER = 2051222400.0   # 2035-01-01T00:00:00Z
NIST_IR_8547_DEPRECATED_AFTER = 1893456000.0   # 2030-01-01T00:00:00Z


def _ed_sign(sk, msg: bytes) -> str:
    return sk.sign(msg).hex()


def _ed_verify(pub_hex: str, sig_hex: str, msg: bytes) -> bool:
    from .signing import weak_ed25519_key
    try:
        if len(pub_hex) != 64 or weak_ed25519_key(pub_hex.lower()):
            return False
        from cryptography.hazmat.primitives.asymmetric import ed25519
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except Exception:  # noqa: BLE001 — any failure is one verdict
        return False


REGISTRY: Dict[str, Dict[str, Callable]] = {"ed25519": {"gen": _ed_gen, "sign": _ed_sign, "verify": _ed_verify}}


def register_algorithm(name: str, gen: Callable, sign: Callable, verify: Callable) -> None:
    """Crypto-agility hook: e.g. a hybrid Ed25519+ML-DSA-65 signer for the post-quantum renewal."""
    REGISTRY[name] = {"gen": gen, "sign": sign, "verify": verify}


class Signer:
    def __init__(self, alg: str, key: Optional[tuple] = None):
        """key = (private, public_hex) of an EXISTING identity (pinned by the verifier); None = ephemeral key, which
        proves integrity of the chain but NOT who sealed it (declared by `ephemeral`)."""
        if alg not in REGISTRY:
            raise ValueError(f"unknown algorithm: {alg}")
        self.alg = alg
        self.ephemeral = key is None
        self._sk, self.pub = key if key is not None else REGISTRY[alg]["gen"]()

    def sign(self, msg: bytes) -> str:
        return REGISTRY[self.alg]["sign"](self._sk, msg)


@dataclass
class AlgorithmPolicy:
    """alg (signature OR hash name) -> epoch instant after which it is considered broken (None = not broken)."""
    broken_after: Dict[str, Optional[float]] = field(default_factory=dict)

    def trusted_at(self, alg: str, t: float) -> bool:
        b = self.broken_after.get(alg)
        return b is None or t < b

    @classmethod
    def nist_ir_8547(cls) -> "AlgorithmPolicy":
        return cls({"ed25519": NIST_IR_8547_DISALLOWED_AFTER})


@dataclass
class LongTermEvidence:
    evidence_digest: str
    records: List[Dict] = field(default_factory=list)

    def _msg(self, prefix_len: int, current: Dict, hash_alg: str = DEFAULT_HASH) -> bytes:
        """Signed message of record `prefix_len`: the digest, EVERY previous record, and the current record's own
        fields (t, ts_source, token, pub, alg, hash, rehash…) minus its signature — like an ERS archive timestamp
        covering its own time. Without that, the outer seal's time and time-source could be rewritten freely
        (council round 3, four minds)."""
        own = {k: v for k, v in current.items() if k != "sig"}
        return bytes.fromhex(_digest(hash_alg, _canon([self.evidence_digest, self.records[:prefix_len], own]).encode()))

    def seal(self, signer: Signer, t: float, ts_source: str = "asserted", stronger_digest: Optional[str] = None,
             hash_alg: str = DEFAULT_HASH, token_b64: Optional[str] = None) -> Dict:
        """ts_source != "asserted" REQUIRES the third-party token (RFC 3161 / OTS) so that the label can never be a
        bare claim; the token is stored (and digested) with the record and verified by `timestamp_trust_fn`."""
        if ts_source != "asserted" and not token_b64:
            raise ValueError(f"ts_source={ts_source!r} needs the timestamp token (token_b64); without it the time is 'asserted'")
        rehash = stronger_digest or ""
        # t is stored as repr(float): Python's repr is the shortest round-trip string, float(repr(x)) == x exactly
        rec = {"alg": signer.alg, "hash": hash_alg, "t": repr(float(t)), "pub": signer.pub, "ts_source": ts_source,
               "rehash": rehash, "ephemeral_key": signer.ephemeral}
        if token_b64:
            rec["token_b64"] = token_b64
            rec["token_sha3"] = hashlib.sha3_256(token_b64.encode()).hexdigest()
        rec["sig"] = signer.sign(self._msg(len(self.records), rec, hash_alg))
        self.records.append(rec)
        return rec

    def verify(self, now: float, policy: Optional[AlgorithmPolicy] = None, timestamp_trust_fn: Optional[Callable[[Dict], bool]] = None,
               trusted_pubs: Optional[set] = None) -> Dict:
        """policy None → NIST IR 8547 dates; trusted_pubs pins the FIRST signer (identity is external to the chain:
        a chain over a known digest can be re-created by anyone with a fresh key — the pin is what says who sealed)."""
        reasons: List[str] = []
        policy = policy or AlgorithmPolicy.nist_ir_8547()
        if not self.records:
            return {"ok": False, "reasons": ["empty chain (no archive timestamp)"], "temporal_trust": "n/a"}
        for i, rec in enumerate(self.records):   # shape first: a malformed record is a reason, never a KeyError
            if not isinstance(rec, dict) or not all(isinstance(rec.get(k), str) for k in ("alg", "pub", "sig", "t")):
                return {"ok": False, "reasons": [f"record {i}: malformed (alg/pub/sig/t must be strings)"], "temporal_trust": "n/a",
                        "chain_len": len(self.records)}
            try:
                float(rec["t"])
            except ValueError:
                return {"ok": False, "reasons": [f"record {i}: time {rec['t']!r} is not numeric"], "temporal_trust": "n/a",
                        "chain_len": len(self.records)}
        if trusted_pubs is not None and self.records[0].get("pub") not in trusted_pubs:
            reasons.append("record 0: sealing key not in trusted_pubs (identity NOT established)")
        if any(r.get("ephemeral_key") for r in self.records):
            if trusted_pubs is not None:
                reasons.append("a seal used an EPHEMERAL key: integrity only, identity not provable")
        for i, rec in enumerate(self.records):
            if rec["alg"] not in REGISTRY:
                reasons.append(f"record {i}: unknown algorithm {rec['alg']}")
                continue
            if rec.get("hash", DEFAULT_HASH) not in HASHES:
                reasons.append(f"record {i}: unknown hash {rec.get('hash')}")
                continue
            if not REGISTRY[rec["alg"]]["verify"](rec["pub"], rec["sig"], self._msg(i, rec, rec.get("hash", DEFAULT_HASH))):
                reasons.append(f"record {i}: invalid signature (chain tampered)")
        if timestamp_trust_fn is not None:
            attested = True
            for i, rec in enumerate(self.records):
                if not timestamp_trust_fn(rec):
                    reasons.append(f"record {i}: time t={rec['t']} NOT attested by a trusted source (ts_source={rec.get('ts_source')})")
                    attested = False
            temporal = "verified" if attested else "NOT verified — the temporal oracle refused one or more timestamps"
        else:
            temporal = "ASSUMED — timestamps not verified: inject timestamp_trust_fn (RFC 3161 / OTS) in production"
            if len(self.records) > 1:
                reasons.append("renewal chain: 'renewed before the algorithm broke' rests on UNVERIFIED timestamps (inject timestamp_trust_fn)")
        times = [float(r["t"]) for r in self.records]
        for i in range(1, len(times)):
            if times[i] < times[i - 1]:
                reasons.append(f"record {i}: timestamp not monotonic")
        last = len(self.records) - 1
        if not policy.trusted_at(self.records[last]["alg"], now):
            reasons.append(f"outer seal (record {last}, {self.records[last]['alg']}) uses an algorithm broken at now={now}")
        if not policy.trusted_at(self.records[last].get("hash", DEFAULT_HASH), now):
            reasons.append(f"outer seal (record {last}) uses a hash ({self.records[last].get('hash')}) broken at now={now}")
        for i in range(last):
            if not policy.trusted_at(self.records[i]["alg"], times[i + 1]):
                reasons.append(f"record {i} ({self.records[i]['alg']}) renewed too late (algorithm already broken)")
            if not policy.trusted_at(self.records[i].get("hash", DEFAULT_HASH), times[i + 1]):
                reasons.append(f"record {i} (hash {self.records[i].get('hash', DEFAULT_HASH)}) renewed too late (hash already broken)")
        unpoliced = sorted({r["alg"] for r in self.records if r["alg"] not in policy.broken_after} |
                           {r.get("hash", DEFAULT_HASH) for r in self.records if r.get("hash", DEFAULT_HASH) not in policy.broken_after})
        return {"ok": not reasons, "reasons": reasons, "chain_len": len(self.records),
                "algorithms": [r["alg"] for r in self.records], "temporal_trust": temporal,
                "policy_note": ("every algorithm has an expiry in the policy" if not unpoliced else
                                f"no expiry in the policy for {unpoliced}: their trust is NOT bounded in time")}

    def renewal_due(self, now: float, policy: Optional[AlgorithmPolicy] = None, margin: float = 0.0) -> Dict:
        policy = policy or AlgorithmPolicy.nist_ir_8547()
        outer = self.records[-1]["alg"] if self.records else None
        outer_hash = self.records[-1].get("hash", DEFAULT_HASH) if self.records else None
        bs = [b for b in (policy.broken_after.get(outer) if outer else None, policy.broken_after.get(outer_hash) if outer_hash else None) if b is not None]
        if not bs:
            return {"due": False, "outer_alg": outer, "outer_hash": outer_hash, "reason": "neither the outer signature nor its hash has an expiry in the policy: renewal horizon UNKNOWN"}
        b = min(bs)
        return {"due": bool((now + margin) >= b), "outer_alg": outer, "outer_hash": outer_hash, "breaks_at": b}

    def to_dict(self) -> Dict:
        return {"evidence_digest": self.evidence_digest, "records": self.records, "format": "CRA-LTA-1",
                "spec_ref": "RFC 4998 ERS / eIDAS LTA (open implementation, not a certified ERS)"}

    @classmethod
    def from_dict(cls, d: Dict) -> "LongTermEvidence":
        return cls(evidence_digest=d["evidence_digest"], records=list(d.get("records", [])))
