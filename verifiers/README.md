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

`verifiers/differential.py` builds 160 fixtures with the Python library — intact (unsigned, signed, trusted, with a
signed tip, ledger elsewhere, an ingested SBOM with its generator document stored) and tampered (pack field, re-hashed
pack, broken record digest, re-linked chain, sidecar signer/fingerprint rewritten, wrong trust store, truncated /
unsealed tail under a trusted log key, wrong log key, ledger required but missing, NaN and duplicate-key lines, empty
ledger, non-object pack, path traversal in `ledger_file`, one byte appended to a stored SBOM source document, a
source document absent with and without `--require-sources`, hostile `source.sha256` values — int, object, null, empty, upper-case hex, path traversal, non-ASCII — `--require-sources` with the ledger missing, a stored document made unreadable, duplicate keys in the pack / sidecar / tip, a tip whose `kind` or `log_pubkey_hex` was rewritten, integral floats in pack / ledger / tip, a non-string sidecar fingerprint, a non-UTF-8 pack, a relocated ledger with and without its `.sources/`, and three unreadable trust stores — duplicate key, not an object, non-string value — on which every verifier must exit 2 without a verdict; tip `entries` as a string or a bool, `log_pubkey_hex` empty / null / non-string, non-ASCII hex or instant strings in sidecar and tip, a non-string `signer_id` signed by the real key, a pack without `pack_sha3` next to an anchor without a hash, a CRLF ledger, Unicode-space "blank" lines, `\r` padding, integers beyond 2^53-1 in pack / sidecar / tip, non-UTF-8 bytes in sidecar / tip / trust store / ledger, a sidecar that is a directory or unreadable, `ledger_file` non-string or with a slash, `honest_scope` as a list, `+10` / `010` / a raw control character / a BOM / a lone surrogate escape in the pack, a sidecar missing a signed field, a `\r\r\n` line, a dangling-symlink sidecar, nesting at exactly 512 (accepted) and 513 (refused) in a ledger line and in a pack, keys named `__proto__` with the digest recomputed and untouched, signature hex with a space / a `+` / a trailing character / upper case, a sidecar signed by the real key over a missing or null or non-instant `signed_utc`, an ingested-format record without a hash under `--require-sources`, an unreadable ledger, and six CLI boundary cases — empty or missing values of `--ledger` / `--trust-store` / `--log-pubkey` — on which the Python CLI too must exit 2, a pack whose name makes the sidecar name exceed NAME_MAX, a blank line at exactly 64 MiB and one byte more, an unknown flag / an abbreviated flag / a second positional (exit 2 in all four, the Python CLI included), `--log-pubkey=<hex>` with the right and the wrong key, a pack reached through a symlink and `..`, a pack path with a trailing slash or `/.`, a record re-chained coherently with a stale `record_sha3` (the binding layer and the declared ledger state see it, the chain itself does not), a value flag followed by a flag, a pack named `-`, a stored source path that is a directory / a symlink to one / a dangling symlink, an explicit `--ledger` reached through a symlink and `..` with the real copy tampered and an intact copy where a lexical join would look, and — since 25/09/2026 — the twenty-one cases of the next paragraph) — and requires every verifier to return the same
`(ok, authenticity, anchored)`, the same `assessed` (since 25/09/2026) **and the same set of failing layers** (since 0.3.0: a FAIL for the wrong reason is a
divergence). CI runs it with all three present; a missing verifier is a failure, not a skip. Measured on 25/09/2026: 160 cases, 0 divergences (the 139-case set of 21/09/2026 measured 0 divergences again on HEAD `51ecbb3` on 25/09/2026, before this change; `CRA_ORACLE_BIG=1`: 171 cases, 0 divergences, measured 25/09/2026 — BIG mode adds four documents at exactly the 64 MiB bound (pack, sidecar, tip, trust store: `trusted-signed` in the five rows) and seven big-line ledgers: a record line of exactly 64 MiB of content accepted and one byte more refused, a blank line of exactly 64 MiB accepted and one byte more refused, two 65 MiB lines, 66 MiB of `\r` padding); ablations: a JS verifier that accepts any stored bytes → 1 divergence, the pre-fix Go verifier that skipped a non-string hash → 2 divergences, both caught.

**`source-documents` layer (0.3.0).** For every `cra_sbom` record whose `source.sha256` is set, the file
`<ledger>.sources/<sha256>.json` next to the ledger is re-hashed (SHA-256 of the raw bytes — no JSON re-parsing, so a
generator document with floats is checked byte-exact): a mismatch is a FAIL; an absent file is a SKIP that says how
many documents are hash-only, or a FAIL with `--require-sources`. A `sha256` that is present and not a lower-case 64-hex string is a FAIL, never a path (null or empty = no hash recorded);
`--require-sources` with no ledger next to the pack is a FAIL, like `--log-pubkey`. A stored document above 256 MiB is refused unread.

**Files a verifier reads (25/09/2026, Unreleased).** Every file — pack, sidecar, ledger, tip, trust store, stored source
document — is opened without blocking (`O_NONBLOCK | O_NOCTTY`) and read only if the open descriptor is a regular file
(`fstat`); a FIFO, a device (`/dev/zero`, directly or through a symlink), a socket or a directory is `not a regular
file`, with the outcome an unreadable file has in that position (`pack-json` / `producer-signature` / `ledger-chain` /
`signed-tip` FAIL, exit 2 with no verdict for the trust store). Presence is one rule in the four: `lstat` ENOENT/ENOTDIR
= absent, anything else is present and must read as a regular file — so a `ledger_file` that names a FIFO or a directory
is a `ledger-chain` FAIL, not a SKIP. Every JSON document — a ledger line, the pack, the sidecar, the tip, the trust
store — is bounded by the same `MAX_DOC_BYTES` = 64 MiB (67108864 bytes, the ledger-line bound of the cryptovalid profile):
a larger file is refused unread (`larger than 67108864 bytes`), on the `fstat` size and again if more can be read. The
bound caps what is READ, not what parsing costs: a 64 MiB document of tiny values (`[{},…]`, `[0,…]`) reached, measured on 25/09/2026, 1.8 GB (Python), 2.6 GB (Node, V8 abort), 2.9 GB (Go), 4.0 GB (Rust), and under RLIMIT_DATA 1.5 GB it ends in a crash in JS / Go / Rust and a `verifier-exception` in Python — the same holds for a ledger line (same parsers, read in the code, not measured); closing it needs a change to the acceptance profile (a lower bound or a bound on the number of values), left to the author. Above the bound and on `/dev/zero` the peak is 10–48 MB and the outcome identical in the four. Measured before the change (HEAD `51ecbb3`,
RLIMIT_DATA 1.5 GB): a FIFO blocked all five rows (library, CLI, JS, Go, Rust) on the pack, the sidecar and the trust
store; `/dev/zero` ended in MemoryError / abort / exit 2 / "out of memory". An internal error is a single
`verifier-exception` layer with `assessed: false` in the four (Go `recover`, JS `catch`, Rust `catch_unwind`; measured
before: JS and Go gave a plain FAIL without `assessed`, Rust exited 101 without a verdict); `CRA_VERIFY_INJECT_FAULT=1`
raises one inside the guarded verification (a test hook: it can only ever produce that inconclusive FAIL). Twenty-one oracle
cases carry a DECLARED outcome checked on every row, the Python CLI included (reason included: agreeing with the reference is not enough), so a rule is red even when the five are wrong
alike: FIFO and `/dev/zero` for pack, sidecar, ledger (with `--log-pubkey` and implicit), tip and trust store, a stored
source document on `/dev/zero`, one byte over the bound for pack / sidecar / tip / trust store, `fingerprint: null`
(FAIL: the signer never writes it; absent = not declared) and absent (verifies), an injected internal error on an intact
pack, a `ledger_file` with a NUL (malformed in the four). Hazard rows run with a 20 s timeout and RLIMIT_DATA 1.5 GB per child. Ablation (25/09/2026, each control removed alone, in each verifier): regular-file check (pre-open `stat` + `fstat`, removed together) → 13 cases red; `O_NONBLOCK` with the `stat` → 6; size bound → 4; presence rule → 6; fingerprint → 1; `assessed` → 1; NUL rule → 1. Removing only the `stat` or only the `fstat`, or only `O_NONBLOCK`, turns nothing red: they back each other up against a swap between check and open, which no case reproduces.
The trust store (`--trust-store`) is parsed with the same strict rules and must be an object of strings; otherwise every verifier
exits 2 with no verdict (a lax reader would take the last of two duplicate `signer_id` entries and answer `trusted-signed`).
