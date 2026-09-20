# Independent verifiers

Three re-implementations of `cra verify`, written from the profile (not from each other), so that an auditor can
check a pack without running the producer's code:

| language | file | dependencies | signature layers |
|---|---|---|---|
| JavaScript | `js/cra-verify.mjs` | none (Node ≥ 18: `node:crypto` SHA3-256 + Ed25519) | yes |
| Go | `go/` (`go build`) | standard library only (`crypto/sha3` since Go 1.24, `crypto/ed25519`) | yes |
| Rust | `rust/` (`cargo build --release`) | `ed25519-dalek` for Ed25519; JSON parser, canonical encoder, SHA-256 and SHA3-256 are pure Rust | yes |

Canonical JSON = Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`; the strict parser
refuses duplicate keys, NaN/Infinity, floats (integral ones such as `10.0` included: `JSON.parse` would silently make them `10`), integers outside ±(2^53-1), `+10` / `010`, raw control characters in strings, lone surrogates, a BOM, invalid UTF-8, nesting deeper than 512 and a ledger line whose content (exactly one terminator excluded — `\n` or `\r\n`; a blank line is ASCII space/tab only) exceeds 64 MiB
(the cryptovalid acceptance profile — `MaxLineBytes` in its Go verifier; the producer refuses to write such a line — the parser/encoder modules are cryptovalid's, same author, AGPL). Same command line and the same JSON
verdict shape as the Python reference:

```
node verifiers/js/cra-verify.mjs pack.json [--ledger l.jsonl] [--trust-store trust.json] [--log-pubkey <hex>] [--require-sources]
./cra-verify pack.json …                      # Go / Rust binaries
```

`verifiers/differential.py` builds 99 fixtures with the Python library — intact (unsigned, signed, trusted, with a
signed tip, ledger elsewhere, an ingested SBOM with its generator document stored) and tampered (pack field, re-hashed
pack, broken record digest, re-linked chain, sidecar signer/fingerprint rewritten, wrong trust store, truncated /
unsealed tail under a trusted log key, wrong log key, ledger required but missing, NaN and duplicate-key lines, empty
ledger, non-object pack, path traversal in `ledger_file`, one byte appended to a stored SBOM source document, a
source document absent with and without `--require-sources`, hostile `source.sha256` values — int, object, null, empty, upper-case hex, path traversal, non-ASCII — `--require-sources` with the ledger missing, a stored document made unreadable, duplicate keys in the pack / sidecar / tip, a tip whose `kind` or `log_pubkey_hex` was rewritten, integral floats in pack / ledger / tip, a non-string sidecar fingerprint, a non-UTF-8 pack, a relocated ledger with and without its `.sources/`, and three unreadable trust stores — duplicate key, not an object, non-string value — on which every verifier must exit 2 without a verdict; tip `entries` as a string or a bool, `log_pubkey_hex` empty / null / non-string, non-ASCII hex or instant strings in sidecar and tip, a non-string `signer_id` signed by the real key, a pack without `pack_sha3` next to an anchor without a hash, a CRLF ledger, Unicode-space "blank" lines, `\r` padding, integers beyond 2^53-1 in pack / sidecar / tip, non-UTF-8 bytes in sidecar / tip / trust store / ledger, a sidecar that is a directory or unreadable, `ledger_file` non-string or with a slash, `honest_scope` as a list, `+10` / `010` / a raw control character / a BOM / a lone surrogate escape in the pack, a sidecar missing a signed field, a `\r\r\n` line, a dangling-symlink sidecar, nesting at exactly 512 (accepted) and 513 (refused) in a ledger line and in a pack) — and requires every verifier to return the same
`(ok, authenticity, anchored)` **and the same set of failing layers** (since 0.3.0: a FAIL for the wrong reason is a
divergence). CI runs it with all three present; a missing verifier is a failure, not a skip. Measured on 20/09/2026:
99 cases, 0 divergences (104 with `CRA_ORACLE_BIG=1`, which adds five big-line ledgers: exactly 64 MiB of content accepted, one byte more refused, two 65 MiB lines, 66 MiB of `\r` padding); ablations: a JS verifier that accepts any stored bytes → 1 divergence, the pre-fix Go verifier that skipped a non-string hash → 2 divergences, both caught.

**`source-documents` layer (0.3.0).** For every `cra_sbom` record whose `source.sha256` is set, the file
`<ledger>.sources/<sha256>.json` next to the ledger is re-hashed (SHA-256 of the raw bytes — no JSON re-parsing, so a
generator document with floats is checked byte-exact): a mismatch is a FAIL; an absent file is a SKIP that says how
many documents are hash-only, or a FAIL with `--require-sources`. A `sha256` that is present and not a lower-case 64-hex string is a FAIL, never a path (null or empty = no hash recorded);
`--require-sources` with no ledger next to the pack is a FAIL, like `--log-pubkey`. A stored document above 256 MiB is refused unread.
The trust store (`--trust-store`) is parsed with the same strict rules and must be an object of strings; otherwise every verifier
exits 2 with no verdict (a lax reader would take the last of two duplicate `signer_id` entries and answer `trusted-signed`).
