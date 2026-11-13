# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shape of a time token given to `cra seal` (no signature, no certificate, no time is VERIFIED here).

`ts_source="rfc3161"`: the token (standard base64) must be the DER of an RFC 3161 TimeStampResp whose status is granted
(0) or granted with mods (1), or of the TimeStampToken itself (a CMS ContentInfo, signedData), whose encapsulated
content type is id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4) and whose TSTInfo messageImprint is SHA3-256
(2.16.840.1.101.3.4.2.8) over the 32 bytes of the sealed digest (the pack_sha3). Anything else is refused with the
reason. `ts_source="ots"`: the token must start with the OpenTimestamps file header (it is not parsed further).

What this does NOT do: verify the CMS signature, the TSA certificate, its EKU or its chain, nor read the genTime as
a trusted time. A seal with a well-formed token is still `temporal_trust: ASSUMED` until a `timestamp_trust_fn` is
injected at verification."""
from __future__ import annotations

import base64
import binascii
from typing import List, Tuple

TS_SOURCES = ("asserted", "rfc3161", "ots")
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA3_256 = "2.16.840.1.101.3.4.2.8"
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


class TokenRefused(ValueError):
    pass


def _tlv(b: bytes, i: int) -> Tuple[int, int, int]:
    """(tag, start of value, end of value) of the DER element at i: one-byte tags, definite minimal lengths"""
    if i + 2 > len(b):
        raise TokenRefused("truncated DER")
    tag, n = b[i], b[i + 1]
    if tag & 0x1F == 0x1F:
        raise TokenRefused("multi-byte DER tag")
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(b) or b[i] == 0:
            raise TokenRefused("DER length not definite and minimal")
        n = int.from_bytes(b[i:i + k], "big")
        if n < 0x80:
            raise TokenRefused("DER length not minimal")
        i += k
    if i + n > len(b):
        raise TokenRefused("truncated DER")
    return tag, i, i + n


def _children(b: bytes, s: int, e: int) -> List[Tuple[int, int, int]]:
    out = []
    while s < e:
        t = _tlv(b, s)
        if t[2] > e:
            raise TokenRefused("DER element beyond its parent")
        out.append(t)
        s = t[2]
    return out


def _oid(b: bytes, t: Tuple[int, int, int]) -> str:
    tag, s, e = t
    if tag != 0x06 or s == e:
        raise TokenRefused("OBJECT IDENTIFIER expected")
    arcs, v = [], 0
    for x in b[s:e]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            arcs.append(v)
            v = 0
    if b[e - 1] & 0x80:
        raise TokenRefused("OBJECT IDENTIFIER truncated")
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


def _int(b: bytes, t: Tuple[int, int, int]) -> int:
    if t[0] != 0x02 or t[1] == t[2]:
        raise TokenRefused("INTEGER expected")
    return int.from_bytes(b[t[1]:t[2]], "big", signed=True)


def _whole(b: bytes) -> Tuple[int, int, int]:
    t = _tlv(b, 0)
    if t[2] != len(b):
        raise TokenRefused("bytes after the DER element")
    return t


def rfc3161_imprint(der: bytes) -> Tuple[str, bytes]:
    """(hash algorithm OID, hashedMessage) of the TSTInfo inside a TimeStampResp or a TimeStampToken"""
    tag, s, e = _whole(der)
    if tag != 0x30:
        raise TokenRefused("not a DER SEQUENCE")
    kids = _children(der, s, e)
    if kids and kids[0][0] == 0x30:              # TimeStampResp: status, then the token
        st = _children(der, kids[0][1], kids[0][2])
        if not st or _int(der, st[0]) not in (0, 1):
            raise TokenRefused("TimeStampResp status is not granted (0) or grantedWithMods (1)")
        if len(kids) != 2:
            raise TokenRefused("TimeStampResp without a timeStampToken")
        kids = _children(der, kids[1][1], kids[1][2]) if kids[1][0] == 0x30 else []
    if len(kids) != 2 or _oid(der, kids[0]) != OID_SIGNED_DATA or kids[1][0] != 0xA0:
        raise TokenRefused("not a CMS ContentInfo with signedData")
    sd = _children(der, kids[1][1], kids[1][2])
    if len(sd) != 1 or sd[0][0] != 0x30:
        raise TokenRefused("signedData is not a SEQUENCE")
    sd = _children(der, sd[0][1], sd[0][2])
    if len(sd) < 4 or sd[2][0] != 0x30:
        raise TokenRefused("SignedData without encapContentInfo")
    eci = _children(der, sd[2][1], sd[2][2])
    if len(eci) != 2 or _oid(der, eci[0]) != OID_TSTINFO or eci[1][0] != 0xA0:
        raise TokenRefused("the encapsulated content is not id-ct-TSTInfo")
    oc = _children(der, eci[1][1], eci[1][2])
    if len(oc) != 1 or oc[0][0] != 0x04:
        raise TokenRefused("eContent is not an OCTET STRING")
    tst = der[oc[0][1]:oc[0][2]]
    t = _whole(tst)
    if t[0] != 0x30:
        raise TokenRefused("TSTInfo is not a SEQUENCE")
    f = _children(tst, t[1], t[2])
    if len(f) < 5 or _int(tst, f[0]) != 1:
        raise TokenRefused("TSTInfo version is not 1")
    _oid(tst, f[1])                                   # policy
    if f[2][0] != 0x30:
        raise TokenRefused("messageImprint is not a SEQUENCE")
    mi = _children(tst, f[2][1], f[2][2])
    if len(mi) != 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
        raise TokenRefused("messageImprint malformed")
    alg = _children(tst, mi[0][1], mi[0][2])
    if not alg:
        raise TokenRefused("messageImprint hashAlgorithm malformed")
    return _oid(tst, alg[0]), tst[mi[1][1]:mi[1][2]]


def check_token(ts_source: str, token_b64: str, evidence_digest: str) -> None:
    """refuse (TokenRefused, with the reason) a token that is not of the shape its ts_source names"""
    if ts_source not in TS_SOURCES:
        raise TokenRefused(f"ts_source {ts_source!r}: one of {list(TS_SOURCES)}")
    if ts_source == "asserted":
        if token_b64 is not None:
            raise TokenRefused("ts_source 'asserted' takes no token (a token names its source: rfc3161 or ots)")
        return
    if not isinstance(token_b64, str) or not token_b64:
        raise TokenRefused(f"ts_source {ts_source!r} needs the timestamp token (token_b64)")
    try:
        raw = base64.b64decode(token_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise TokenRefused("token_b64 is not standard base64") from None
    if ts_source == "ots":
        if not raw.startswith(OTS_MAGIC):
            raise TokenRefused("the token does not start with the OpenTimestamps file header")
        return
    try:
        alg, h = rfc3161_imprint(raw)
    except TokenRefused as e:
        raise TokenRefused(f"the token is not an RFC 3161 TimeStampResp / TimeStampToken: {e}") from None
    except (IndexError, ValueError) as e:
        raise TokenRefused(f"the token is not an RFC 3161 TimeStampResp / TimeStampToken: {type(e).__name__}") from None
    if alg != OID_SHA3_256 or h != bytes.fromhex(evidence_digest):
        raise TokenRefused(f"the token's messageImprint ({alg}, {h.hex()[:64]}) is not SHA3-256 over the sealed digest "
                           f"{evidence_digest}")
