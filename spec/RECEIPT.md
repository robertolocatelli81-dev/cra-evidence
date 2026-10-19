# The receipt of `cra verify` — admission, states, policy (states vocabulary `cra-evidence/states-1`, since 0.6.0)

Status: normative for the Python reference verifier (`cra_evidence.verify_pack.verify_pack`, `cra verify`) from 0.6.0.
Written before the code (19/10/2026). The Go, JS and Rust verifiers do NOT carry these fields in 0.6.0 (§7).

The fields of 0.5.1 — `ok`, `assessed`, `authenticity`, `anchored`, `layers`, `pack_sha3` — keep their meaning and
their values on every input (§6 lists the one case whose `assessed` changes). 0.6.0 adds, on every receipt, one closed
field per question a relying party asks, so that it reads one value per subject instead of combining layers.

## 1. `admission`

`"admitted"`, `"refused"` or `"not_evaluated"`.

- `"refused"`: the pack is not one this verifier evaluates. `refusal_class` is one of, checked in this order (the first
  that applies is the class):
  1. `malformed` — the pack file cannot be read as one JSON object (absent, unreadable, not a regular file, above the
     64 MiB bound, invalid UTF-8, invalid or duplicate-key JSON, not an object);
  2. `format_unsupported` — `kind` is not `"cra_evidence_pack/1"` (also absent or not a string);
  3. `unknown_member` — a top-level key outside the closed list (`PACK_KEYS`, as since 0.4.1);
  4. `malformed` — a field this format requires is unusable: `honest_scope` not a string holding the declared-limit
     mark, a pack that cannot be canonicalised (no digest can be computed), a `ledger_file` that is present and not a
     plain file name.
  A refused pack receives no states: `states` and `policy` are `null`. Its 0.5.1 fields are unchanged: every refusal
  above is already a `FAIL` layer, so `ok` is false and `authenticity` is `"FAIL"` on every refused receipt.
- `"admitted"`: every other pack; `refusal_class` is `null` and `states` / `policy` are objects (§2, §4).
- `"not_evaluated"`: the verifier itself raised (the `verifier-exception` layer, `assessed: false`, exit 77). Nothing is
  known about the pack: `refusal_class`, `states` and `policy` are `null`. ap2-evidence-pack has no such receipt; this
  third value is this format's own.

The 0.5.1 layers are still all reported on a refused pack (the layers after a refusal are not cut).

## 2. `states_vocabulary` and `states`

`states_vocabulary` is `"cra-evidence/states-1"`, the identifier of the vocabulary this text defines; an identifier
never changes meaning (a change of a state or of a reason is a new identifier). It is aligned with
draft-krausz-verification-state-03 §3.1, §3.3, §5.4.2 (an individual Internet-Draft, work in progress) and with
ap2-evidence-pack 1.6.0 SPEC §6.9; neither is the identifier.

`states` (admitted packs) is a closed object with exactly five subjects. Each is `{"state": S, "reasons": [R, ...]}`
with an optional `detail` (free text, informative, never compared). S is one of `verified`, `contradicted`,
`indeterminate`, `not_evaluated`. `indeterminate` is reserved: no check of this revision produces it.

**Elements and precedence** (as ap2-evidence-pack 1.6.0 §6.9). A subject is stated from its elements and takes the
state of its highest element under `contradicted` > `not_evaluated` with `instrument_failure` > any other
`not_evaluated` > `verified`. The two `not_evaluated` ranks give the same state (no receipt can show
the difference); an `instrument_failure` element is never hidden, because `reasons` lists every element that is not
`verified`. `verified` only when every element is. `reasons` lists one reason per element that is not
`verified`, in element order. A subject with no element is `not_evaluated` with `not_present`.

| subject | elements | `verified` | `contradicted` (reason) | `not_evaluated` (reason) |
|---|---|---|---|---|
| `sealed_content` | the digest (`pack_sha3` recomputed from content); the pack's own verification snapshot | both | `digest_mismatch`; `self_verification_failed` (the snapshot does not say `chain_ok` and `record_digests_bound` true) | — |
| `ledger_anchor` | the ledger (read, entry schema, chain, record binding, anchor of THIS pack); the declared ledger state | the chain verifies, every record is bound, the pack is anchored, the declared state is the ledger's | `ledger_malformed` (the file at the ledger path is not a regular file within the bound, or a line does not parse); `entry_unknown_member` (an entry key outside the closed list); `chain_broken`; `record_unbound`; `not_anchored`; `state_mismatch` | `not_present` (no ledger given or next to the pack; with `--ledger`, `--log-pubkey` or `--require-sources` also `policy.unmet: ledger_required`); `unreadable` (the ledger exists and the host could not read it: permissions, I/O) |
| `signed_tip` | the tip next to the ledger | the tip verifies under the trusted log key and names this ledger's last entry | `tip_invalid` (unparsable, malformed, or the signature does not verify under the trusted key); `tail_mismatch` (it verifies and names another state: a truncated tail, entries after it, another ledger, a rewritten tail) | `key_not_given` (a tip is present, no trusted log key: not checked); `not_present` (no tip; with `--log-pubkey` also `policy.unmet: tip_required`); `ledger_not_verified` (the ledger is absent or did not verify: the tip is not looked at); `instrument_failure` (no `cryptography` here); `unreadable` |
| `source_documents` | each SBOM source document the ledger records by SHA-256; a record whose hash is malformed | the stored document hashes to the recorded value | `source_mismatch` (stored bytes hash to another value, or the stored path holds something that is not a regular file within 256 MiB); `record_malformed` (a recorded hash that is not 64 lower-case hex, or an ingested document recorded without one) | `hash_only` (no stored copy; with `--require-sources` also `policy.unmet: sources_required`); `not_present` (no document recorded by hash); `ledger_not_verified`; `unreadable` |
| `producer_signature` | the signature sidecar | it verifies and its key is the trust store's key for its `signer_id` | `sidecar_malformed` (unparsable, not an object, a key outside its closed list, a required field missing or mistyped, not a regular file within the bound); `digest_mismatch` (the pack changed after signing: content or signed digest); `signature_invalid` (the signature, key or fingerprint does not verify) | `self_asserted` (it verifies, no trust store: the key is the one the sidecar carries — `signed` is a verdict of this format, never a trust statement); `key_unresolved` (it verifies, a trust store is given and does not hold this key for this `signer_id`; `policy.unmet: trusted_signer`); `not_present` (no sidecar); `instrument_failure` (no `cryptography` here); `unreadable` |

`instrument_failure` (krausz §3.1): the verifier's instrument failed, never a result about the input. In this revision
it is the absence of the `cryptography` library on a check that needs it, and it is exactly the case where a layer
carries `assessed: false`. `unreadable`: a file that exists and that this host could not read (an `OSError` other than
"not a regular file" or "too large", e.g. `EACCES`, `EIO`): fail-closed (`ok` false), stated as not evaluated.

## 3. `policy`

`{"met": bool, "unmet": [...]}`, `unmet` in this order: `trusted_signer` (a trust store is given and
`producer_signature` is not `verified`), `ledger_required` (`--ledger`, `--log-pubkey` or `--require-sources` is given
and no ledger is there), `tip_required` (`--log-pubkey` is given and no tip is there), `sources_required`
(`--require-sources` and a document is recorded by hash only), `authenticity_basis` (neither a producer signature that
verifies nor the pack anchored in a chain that verifies: the 0.5.1 verdict `FAIL` with no finding against the pack).
`met` is true iff `unmet` is empty. A policy is a disposition of the relying party (or, for `authenticity_basis`, of
this verifier), not a state of the pack.

## 4. `ok` and the states (an equation, proved, not a derivation)

`ok` is computed as in 0.5.1. On every admitted receipt it equals: no subject is `contradicted`, AND no element has the
reason `instrument_failure` or `unreadable`, AND `policy.met`. On every refused or not-evaluated receipt `ok` is false.
On every admitted receipt `assessed: false` implies no subject `contradicted` and at least one `instrument_failure`; a
not-evaluated receipt (§1) has `assessed: false` and no states. Measured by
`verifiers/states_bench.py` (§8 of the 0.6.0 CHANGELOG entry gives the numbers).

## 5. Exit codes (meanings unchanged; §6 lists the cases whose code changes): 0 `ok`; 1 a finding (refused included — read `admission`); 77 not assessed; 2 usage; 74 the receipt was not written

The giro-unico design (ap2-evidence-pack 1.6.0 §6.10) gives exit 74 WITH a complete receipt to a check that could not
run. That point does not fit this format and is not applied: since 0.3.3 cra-evidence exits 77 for exactly that case,
with the complete receipt on stdout, and since 0.5.1 74 means "the receipt was not written". Moving the case to 74
would change the exit code of four verifiers and merge two documented meanings; 77 already lets a reader tell the two
cases apart without reading stdout.

## 6. Not additive

- On a host without `cryptography`, `cra verify --log-pubkey` on a ledger with a signed tip: the `signed-tip` layer was
  `FAIL` with `assessed` true ("tip_unchecked", exit 1: a finding against the pack that is not one); it now carries
  `assessed: false` like the producer-signature layer since 0.3.2, so the receipt is `assessed: false` and the exit 77
  when no other layer judged against the pack. `ok` and `authenticity` do not change. This covers a tip that is a
  well-formed `cryptovalid_tip/1` with only its signature left to check; a tip that is not one (not an object, another
  `kind`, a field of the wrong type or form, a log key other than the trusted one) is `contradicted/tip_invalid` on
  every host, exit 1 as in 0.5.1.
- On a host without `cryptography`, a producer-signature sidecar with a field missing, mistyped or malformed (a
  required field absent, key or signature not lower-case hex of the exact length, a weak key) was `assessed: false`,
  exit 77 when nothing else judged ("not checkable here"); it is now judged as on a host with the library
  (`sidecar_malformed` or `signature_invalid`, `assessed` true, exit 1). Only a well-formed sidecar whose signature is
  left to check is `instrument_failure`. `ok` and `authenticity` do not change.
- Every other 0.5.1 field keeps its value on every input (measured on the bench, §4).

## 7. Where it does not apply in 0.6.0

The Go, JS and Rust verifiers and the differential oracle are unchanged: their receipts carry no `admission`, `states`
or `policy`. Carrying them means three more implementations of the table above and an oracle that compares them; not
done in this revision.

## 8. What no state can say

A sidecar that was removed and one that was never written give `producer_signature: not_evaluated/not_present`; only a
trust store (`policy.unmet: trusted_signer`) or a hash of the sidecar kept elsewhere tells them apart. A ledger whose
tail was cut after the anchor reads `ledger_anchor: verified`; only `signed_tip` (with the trusted log key) sees it.
