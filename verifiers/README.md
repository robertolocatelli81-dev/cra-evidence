# Independent verifiers

Three re-implementations of `cra verify`, written from the profile (not from each other), so that an auditor can
check a pack without running the producer's code:

| language | file | dependencies | signature layers |
|---|---|---|---|
| JavaScript | `js/cra-verify.mjs` | none (Node ≥ 18: `node:crypto` SHA3-256 + Ed25519) | yes |
| Go | `go/` (`go build`) | standard library only (`crypto/sha3` since Go 1.24, `crypto/ed25519`) | yes |
| Rust | `rust/` (`cargo build --release`) | `ed25519-dalek` for Ed25519; JSON parser, canonical encoder, SHA-256 and SHA3-256 are pure Rust | yes |

Canonical JSON = Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`; the strict parser
refuses duplicate keys, NaN/Infinity, floats, lone surrogates and nesting deeper than 512 (the cryptovalid acceptance
profile — the parser/encoder modules are cryptovalid's, same author, AGPL). Same command line and the same JSON
verdict shape as the Python reference:

```
node verifiers/js/cra-verify.mjs pack.json [--ledger l.jsonl] [--trust-store trust.json] [--log-pubkey <hex>]
./cra-verify pack.json …                      # Go / Rust binaries
```

`verifiers/differential.py` builds 26 fixtures with the Python library — intact (unsigned, signed, trusted, with a
signed tip, ledger elsewhere) and tampered (pack field, re-hashed pack, broken record digest, re-linked chain,
sidecar signer/fingerprint rewritten, wrong trust store, truncated / unsealed tail under a trusted log key, wrong log
key, ledger required but missing, NaN and duplicate-key lines, empty ledger, non-object pack, path traversal in
`ledger_file`) — and requires every verifier to return the same `(ok, authenticity, anchored)`. CI runs it with all
three present; a missing verifier is a failure, not a skip. Measured on 15/09/2026: 26 cases, 0 divergences.
