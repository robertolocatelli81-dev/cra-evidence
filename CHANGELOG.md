# Changelog

## 0.3.0 — 2026-09-20
The generator's SBOM document is the evidence. Measured with the real generators (Syft 1.52.0, Trivy 0.74.0, cdxgen
12.8.4 — all emitting CycloneDX 1.7 by default) and sbomqs 2.1.2 on a 419-component npm tree: 0.2.0 stored only its
own re-encoding of an ingested SBOM, which scored below every original (5.3→4.2, 6.6→4.4, 4.8→3.7). Now `cra sbom
--from-cyclonedx/--from-spdx` hashes the document's exact bytes (SHA-256) into the record, copies it to
`<ledger>.sources/<sha256>.json` (`--no-store-source` keeps the hash only; the store never overwrites different bytes;
a file changed between ingest and record is refused), and every verifier — Python, JS, Go, Rust — re-hashes it
(`source-documents` layer: mismatch FAIL, absent SKIP, `--require-sources` makes absence a FAIL). The record's index
now carries component type, CPE and what the document declared (generator + version, spec version, components incl.
nested, duplicates merged, dependency edges, component types); nested `components[].components` are walked; a
malformed hash is dropped as in the SPDX path; SPDX `primaryPackagePurpose` maps to the type and `cpe23Type` refs are
read. Export: CycloneDX 1.6 or 1.7 (official 1.7 schema vendored), with serialNumber, `metadata.tools`, bom-refs
(unique), component types, CPEs, SPDX licence *expressions* (`Apache-2.0 OR BSD-3-Clause`), and `dependencies` only
from edges the producer knows — the installed floor's Requires-Dist graph as walked, with PEP 508 markers evaluated for this interpreter (`packaging` when importable, else a small evaluator; an unevaluable marker keeps the edge and is counted): `dependsOn: []` is emitted only for a component whose metadata was read, everything else is declared an `unknown` composition (CycloneDX's own value for "inconclusive") — never re-invented for an ingested graph; the installed floor reads PEP 639
`License-Expression` (cryptography ships it since 46.0.0 with the legacy `License` field empty, measured on PyPI metadata 20/09/2026 — with such a distribution 0.2.0 recorded no licence).
Validated with the official CycloneDX CLI 0.33.1 and pyspdxtools 0.8.5 (CI steps with positive controls; run green on the v0.3.0 tag) and with jsonschema in the tests.
Six unmodified generator documents vendored as fixtures. Differential oracle: 137 cases (incl. hostile `source.sha256` values: int, object, null, empty, upper-case, traversal, non-ASCII; `--require-sources` with the ledger missing; a stored document made unreadable), and the failing layers must
agree too (ablation caught; before the fix Go/Rust skipped a non-string hash while Python/JS failed — found by self-review and by Haiku in round 1). Interop re-measured against cryptovalid 0.15.0. Found by the round-1 review (Opus) and fixed: the Python reference parsed pack, sidecar, tip and trust store with plain `json.loads` (duplicate keys accepted, first-wins for a reader, last-wins for the verifier — JS/Go/Rust refuse them) → strict parser everywhere; Python `verify_tip` did not check `kind` / `log_pubkey_hex` (the three did); the Go verifier ignored the scanner error (a line above 64 MiB ended the scan silently and the prefix verified); a `source_path` could be bound to an index not read from it; an ingested SBOM recorded without `source_path` carried a hash nothing re-verified (Sonnet) — now refused; a generator document nested too deep crashed the ingest instead of raising (Sonnet) — malformed now; the JS verifier built a 65 M-node string on a 65 MiB pad and died (fast path added); all four verifiers and the producer now share cryptovalid's 64 MiB line bound. Round 2 (Opus, Sonnet): the JS verifier accepted integral floats (`10.0` parses to 10 and hashes alike) while the other
three refused them → number tokens with `.`/`e` refused in JS and in the Python parser (generator documents excepted: they are
bytes, never canonicalised); the trust store was read laxly by JS and Go (a duplicate `signer_id` gave `trusted-signed` there and
a refusal in Python/Rust) → strict object of strings in all four, unreadable = exit 2 everywhere, the oracle's reference now
loads it as the CLI does; Rust ignored a non-string sidecar `fingerprint`; the export said `compositions: incomplete` for
components nothing was read about (that asserts more exist) → `unknown`; the ingest read the file twice (index of one version,
hash of another) → read once; `record_sbom` re-derives the index from the bytes it stores and refuses one that differs (a
mutated index next to the right document verified PASS); the SBOM must belong to the locker's product; stored documents above
256 MiB are refused unread; a non-UTF-8 pack is `pack-json` in all four; CI gained a job with NO optional dependency (the
"three configurations" were measured by hand before; round 3 added the third job, cryptography only — all three enforced now). Oracle cases for each.
Round 3 (Opus, Sonnet, Haiku): the Rust verifier could still panic on non-ASCII hex / instant strings in the sidecar and the
tip (byte slices) → ASCII guards; tip field types were not the same in the four (Python `int("3")`, `log_pubkey_hex` empty or
non-string read four ways) → one rule: `entries` a JSON integer ≥ 0, `ledger_id`/`tip_sha256` 64-hex, `ts` an instant,
`log_pubkey_hex` absent/null/"" = not checked (cryptovalid's rule), anything else must equal the trusted key; a non-string
`signer_id` reached `trusted-signed` in JS only → must be a string in all four and in `sign_pack`; the 64 MiB line bound was
off by one across the four (with/without the terminator) → content bytes, terminator excluded, boundary cases at exactly
64 MiB (accepted) and +1 (refused); the re-derivation in `record_sbom` did not cover `edges`/`depth` (a forged dependency
graph and profile label rode through with the right document) → covered; generator documents are bounded (256 MiB) before
being read at ingest and at record time; an anchor is matched only against a 64-hex `pack_sha3` (a pack without one matched
an anchor without one in three verifiers); a stale `__pycache__` had stamped the day's scored exports as 0.2.0 → cache
cleared, exports regenerated and re-scored (Syft 5.3, cdxgen 5.5, Trivy 4.8, installed floor 4.5); 39 fields vs 44 glossary
rows reconciled in the texts; CI runs three dependency configurations. Oracle after round 3: 66 cases, 70 with
`CRA_ORACLE_BIG=1`, 0 divergences.
Round 4 (Opus, Sonnet, Haiku) — input hygiene was still four rules, not one: a blank ledger line was ASCII-whitespace in
Python and Unicode-whitespace in the three (a U+00A0 line broke the chain in the reference and passed elsewhere) → blank =
ASCII space/tab only; the line terminator was "any run of `\r`/`\n`" in Python (66 MiB of `\r` padding verified there and
was refused by the three) → exactly one `\n`, then at most one `\r`, and the reference reads lines bounded (never buffers a
hostile line whole); integers outside ±(2^53-1) were refused at parse in Go/Rust and only at hashing in Python/JS (a signed
sidecar or tip with such a field was `trusted-signed` in two verifiers) → refused at parse in all four; the JS verifier
decoded every input but the pack lossily (one invalid byte in a sidecar read as `signed`/`trusted-signed`) and dropped a
UTF-8 BOM (a pack with a BOM verified in JS only) → strict decoding, BOM kept, on every input; Go and Rust treated a sidecar
that exists but cannot be read (directory, mode 0, not UTF-8) as "not signed" → SKIP only when there is no sidecar; the Rust
JSON module accepted `+10`, `010` and raw control characters in strings (canonical form unchanged, so a byte-tampered pack
verified `signed` in Rust alone) → RFC 8259 grammar (the same module is cryptovalid's: to be fixed there too); `ledger_file`
was resolved four ways (a non-string, an array, a trailing slash) → must be a plain file name in all four, else FAIL;
`honest_scope` must be a string; a lone surrogate escape in a pack failed at different layers → refused at parse
everywhere; a sidecar missing `signed_utc` (or with a non-string field) threw past the JS signature check → an invalid
signature; the tip `ts` is checked by shape in all four (JS validated the calendar alone). A public sentence "Round 4: no
material issues" had been written before round 4 ran — removed; this paragraph is what round 4 found. Oracle after round 4:
93 cases, 98 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 5 (Opus, Sonnet, Haiku): the Python reference could not parse the profile's own nesting bound — with the strict hooks
CPython's JSON scanner stopped at depth 332 (the three verifiers accept 512), so a record the producer had written (a
verbatim CSAF/VEX attachment, a deep `details`) verified in JS/Go/Rust and failed in the reference, and the next append
crashed → linear depth pre-scan (exactly the verifiers' rule) before parsing, recursion limit raised locally while
(de)serialising, the LINE's depth bounded at append, `RecursionError` never escapes; an aborted record scan was reported as
"a digest does not match" → stated as an aborted scan; Go's `bufio.ScanLines` already drops one `\r`, the manual strip
removed a second (a `\r\r\n` line was blank in Go alone) → removed; a sidecar that is a dangling symlink was "not signed"
in Python/JS and unreadable in Go/Rust → `lstat` rule everywhere; SPDX documents with a list where an id string is expected
crashed the ingest (`TypeError`) → type guards on every SPDX field; the writer's own tail reader now uses the verifiers'
line rules (bounded, one terminator, ASCII blank); without `cryptography` a valid signature was reported "invalid"
(`ModuleNotFoundError` caught as an invalid signature) → "present but NOT checkable here", with a vendored signed fixture
(its tests were hidden from CI by a misplaced `__main__` block until round 7 — CI now runs `unittest discover` and asserts that every TestCase class ran); `--ledger ""` is a usage error in all four; `WITH` exceptions carrying a version
(`Classpath-exception-2.0`) are recognised as SPDX expressions. Oracle after round 5: 99 cases, 104 with
`CRA_ORACLE_BIG=1`, 0 divergences.
Round 6 (Opus, Fable 5.1 — Sonnet and Haiku found nothing; the two found the same three and one more each): the JS
verifier's key-dropping copy lost an own `__proto__` key (a pack or entry with such a key verified in JS alone — and a
`__proto__` added with the digest untouched verified as bound in JS alone) → `Object.fromEntries`, cases with a `zz_extra`
control (cryptovalid's `cvverify.mjs` has the same function: to be fixed there); hex decoding of signatures was four rules
(`bytes.fromhex` skips spaces, `Buffer.from(…, "hex")` truncates at the first non-hex, Rust takes `+`) → lower-case hex of
exact length before decoding, in sidecar, tip and `--log-pubkey`, in all four; a CLI flag with an empty value or no value
(`--trust-store ""`, `--log-pubkey "$KEY"` with the variable unset, a trailing `--ledger`) was silently dropped by one
verifier or another → usage error (exit 2) in all four, and the Python CLI is now a row of the oracle for these; the Go
and Rust payload builders signed a MISSING `signed_utc` as `null` (a sidecar without the time verified there) → every
signed field must be a non-empty string and `signed_utc` an instant, in all four and in `sign_pack`; SPDX `SPDXID` as a
list crashed the ingest and hostile non-string fields (`name: ["a"]`) were stringified into data → never coerced; an
ingested-format record without a hash passed `--require-sources` → malformed; the writer's tail reader bounds the
content length; the store compares sizes before bytes; an unreadable ledger is `ledger-chain` in the reference too;
the README sentence "until a round found nothing material" was not true of the record → replaced by the dated outcome.
Oracle after round 6: 122 cases, 127 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 7 (Opus, Fable 5.1; Sonnet and Haiku found nothing): "is there a sidecar?" was four rules (a legal 250-byte pack name
makes the sidecar name exceed NAME_MAX: `verifier-exception` in Python, "not signed" in JS/Rust, unreadable in Go) → one rule,
lstat ENOENT/ENOTDIR = no sidecar, any other error = FAIL, with a case; a run of spaces above 64 MiB was a blank line in JS/Rust
and a refusal in Python/Go → the bound comes before the blank test everywhere (two gated cases); the two tests of the vendored
signed fixture had never run in CI (a `__main__` block above the class) → moved, CI runs `unittest discover` and asserts that
every TestCase class ran; two README sentences were false of the code ("four processes appending at once — is a named FAIL":
they produce one valid chain; the seal policy "defaults to the NIST IR 8547 dates for both the signature and the hash": the
default bounds Ed25519 only and the verdict says the hash is not bounded) → rewritten; `version` is bounded to the schema's
maxLength (1024) at ingest and the product version refused above it (an 1100-character version made a schema-invalid
export); the index's `metadata.component.type` is the generator's (Syft declares the scanned directory as `file`; the SPDX branch
followed in round 10), not a default; an SPDX 3.0 `identifier` list was still stringified into `cpe` → never; a lone surrogate escape in a generator
document was a `TypeError` at record time → malformed at ingest; the verifier reads the ledger once (chain, binding, anchor,
sources and tip judge one snapshot); the example pack is now signed (an ephemeral key, its public key in `trust.json`) as
its README already said; oracle hygiene: a stale Rust binary is refused like a stale Go one, the Python-CLI rows run from the
repo root. Oracle after round 7: 123 cases, 130 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 8 (Opus, Fable 5.1; Sonnet and Haiku found nothing): the CI guard "every TestCase class ran" could not match the
`unittest -v` line format of Python 3.11/3.12 (the first push would have gone red on two of three rows) → matches both
formats, with a fake-class positive control; an unknown flag, an abbreviation (`--require-source`, `--log`) or a second
positional was silently taken as the pack by the three verifiers (a typo verified PASS on an absent source document) and
abbreviations were expanded by the reference → usage error in all four (`allow_abbrev=False` on every subparser), and
`--flag=value` is one grammar in the four; the ledger next to a pack reached through a symlink and `..` was found by Rust
alone → the pack's directory is resolved through the filesystem (`realpath`) in all four (Node's JS `realpathSync` resolved
`..` before the symlink: its `.native` variant does not); a component the generator declared without a version exported
`version: ""` → omitted; a `kind` that is not a string crashed `evidence_pack` → ignored in the counts; verifiers/README
listed five gated big-line cases for seven; `SECURITY.md` pointed at a file that does not exist; the README claim "no wall
clock in tests" was broader than the tests → "the deadline arithmetic never reads the wall clock". Oracle after round 8:
129 cases, 136 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 9 (Opus, Sonnet; Haiku found nothing; 21/09/2026): the full-dependency CI job piped `unittest` into `tee` without
`pipefail` — it could not go red → `shell: bash`, `set -o pipefail`, and the guard asserts the suite ended `OK`; the
reference read the pack through `pathlib`, which normalises `p.json/` to `p.json` (the three answer ENOTDIR) → OS path
semantics in the reference, sidecar = the argument + `.sig.json`, two cases; a declared-but-NOT-INSTALLED name was exported
as a component with the fabricated version `NOT-INSTALLED` (and inflated `component_count`) → named in a
`cra-evidence:declared_not_installed` property, never a component; the installed floor's version is bounded like the two
ingest paths; a record tampered with its `record_sha3` left stale and the whole chain re-linked coherently was caught by
the four but exercised by no test or case (the test that claimed to test the binding was caught by the chain) → oracle
case and unit test on the binding layer alone; a value flag followed by a flag, and a pack named `-`, are usage errors in
all four; a stored copy is removed if the append that records it fails; the README's "five models in three rounds"
now says it is 0.1.0's history. Oracle after round 9: 134 cases, 141 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 10 (Opus, Sonnet; Haiku found nothing): after round 9 a parent whose declared child is not installed kept a
positive `dependsOn` list with the child silently dropped (the product's own list read "no dependencies" while one was
declared) → such a parent is left out of the graph and declared `unknown`; the SPDX ingest never set the product's type
(the same Syft scan gave `file` from CycloneDX and the default `application` from SPDX) → the root's
`primaryPackagePurpose` / `software_primaryPurpose` maps to `metadata.component.type`, a purpose without a CycloneDX
counterpart is kept as declared in `source.root_purpose_declared`; a stored source path that exists but is not a
regular file (a directory, a symlink to one, a dangling symlink) was reported as honest absence in all four → FAIL, three
cases; `record_id` must be a UUID (it becomes the schema-patterned `serialNumber`); the texts said "measured 20/09" and
"in CI" of cases that exist since 21/09 and of a workflow not yet run on 0.3.0 → dated 21/09/2026, and "in CI" is stated
only where this release's CI run is green on the tag. Oracle: 137 cases, 144 with `CRA_ORACLE_BIG=1`, 0 divergences. Legal basis re-read 20/09/2026 (ENISA
FAQ: no API at initial release; glossary unchanged; Digital Omnibus 2025/0360(COD) still a proposal).

## 0.2.0 — 2026-09-15
SPDX ingest: `sbom_from_spdx()` / `cra sbom --from-spdx` read SPDX 2.2/2.3 JSON (`packages`, purl external refs,
SHA-256 checksums, supplier/originator, concluded→declared licence) and SPDX 3.0 JSON-LD (`software_Package`,
`software_packageUrl`, `verifiedUsing` Hash, `suppliedBy` resolved to the agent, licences via hasConcludedLicense /
hasDeclaredLicense relationships); the product described by the document is not a component; `NOASSERTION` versions
are not resolved and never meet the Annex I floor. Field names checked on the official spdx/spdx-examples documents,
vendored as fixtures. Suggested by the Gemini Pro competitor review of 15/09/2026 (Yocto and other industrial
generators emit SPDX natively).

## 0.1.1 — 2026-09-15
Independent verifiers in JavaScript (Node, no dependencies), Go (standard library) and Rust (pure-Rust JSON/SHA-256/
SHA3-256 + ed25519-dalek) with the same CLI and verdict as `cra verify`; differential oracle on 26 intact/tampered
fixtures (0 divergences), required in CI. `cra sign --aws-kms-key-id`: Ed25519 signing in AWS KMS (SigV4, standard
library; derivation validated on the official AWS vector). Release packs signed with the author's KMS key; trust
store published with each release. Clean-clone bench: 5 passes, 7/7 suites (67 tests) each.

## 0.1.0 — 2026-09-15
First public release. SBOM records (schema-valid CycloneDX 1.6 subset; ingest of any CycloneDX; VEX/CSAF documents
embedded content-bound), Art. 14 clock on recorded submission instants (vulnerabilities and severe incidents; calendar
month per Art. 14(4)(c)), SRP-aligned notices (39-field ENISA glossary derived from a vendored dated snapshot, per-stage
R/O/A/C rules, PEC options), hash-chained ledger in the cryptovalid profile (flock fail-closed, torn tail refused,
floats/NaN/unportable ints/lone surrogates refused, signed chain tip), evidence pack anchored + Ed25519 sidecar whose
signature covers signer and time, crypto-agile seal (renewable chain, pinned key, hash named per record, NIST IR 8547
dates as default policy, time token stored when given), offline verifier with layers and authenticity levels (tip
checked with a trusted log key), OSV (chunked, paginated, aliases, aligned to input) / CISA KEV / ENISA EUVD feeds with
positive controls (OSV aliases resolved per id, since the batch endpoint is condensed). Seal signs its own fields;
hash policy applied to every record; carried-forward SRP fields copied from the previous stage or counted missing;
incident final-report deadline never invented in a notice; licences exported as SPDX id or free-text name; pack
written atomically after its anchor; a required ledger that is missing is a FAIL. Interop measured against
cryptovalid v0.11.4. Three council rounds (five models, two providers): 44 findings → tests.
