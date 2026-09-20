#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// cra-verify — independent JavaScript verifier of a cra-evidence pack (Node ≥ 18, no dependencies).
// Same layers and the same authenticity verdict as cra_evidence/verify_pack.py, re-implemented from the profile:
// canonical JSON = Python json.dumps(sort_keys, separators=(",",":"), ensure_ascii) (canon/pyEscape are the
// functions of cryptovalid's cvverify.mjs); SHA-256 chain; SHA3-256 pack/record digests; Ed25519 sidecar over
// {"alg","kind":"cra_pack_sig/1","public_key_hex","signed_pack_sha3","signed_utc","signer_id"}; cryptovalid_tip/1.
// Usage: node cra-verify.mjs <pack.json> [--ledger path] [--trust-store file.json] [--log-pubkey hex] [--require-sources] ; exit 0 only if ok.
// source-documents layer: every cra_sbom record with source.sha256 names <ledger>.sources/<sha256>.json, whose bytes must
// hash (SHA-256) to that value when the file is present (mismatch = FAIL; absence = SKIP, or FAIL with --require-sources).
import { createHash, verify as edVerify, createPublicKey } from "node:crypto";
import { readFileSync, existsSync, statSync } from "node:fs";
import { basename, dirname, join } from "node:path";

const PACK_KIND = "cra_evidence_pack/1", SCOPE_MARK = "NOT a conformity assessment", GENESIS = "0".repeat(64);
const RECORD_KINDS = new Set(["cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor"]);
const TIP_KIND = "cryptovalid_tip/1", SPKI = Buffer.from("302a300506032b6570032100", "hex"), HEX64 = /^[0-9a-f]{64}$/;

const MAX_LINE_BYTES = 64 << 20;   // cryptovalid profile: a longer JSONL line is a failure, never a silent truncation
function pyEscape(s) {
  if (!/[^\x20-\x7e]|["\\]/.test(s)) return '"' + s + '"';   // fast path: nothing to escape (a 65 MB pad must not build a 65 M-node rope)
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i), ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}
const cmp = (a, b) => { const A = [...a], B = [...b]; for (let i = 0; i < Math.min(A.length, B.length); i++) { const d = A[i].codePointAt(0) - B[i].codePointAt(0); if (d) return d; } return A.length - B.length; };
function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") { if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-portable number (float or |int|>2^53-1)"); return String(v); }
  if (typeof v === "string") return pyEscape(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort(cmp).map((k) => pyEscape(k) + ":" + canon(v[k])).join(",") + "}";
  throw new Error("unserialisable " + typeof v);
}
function hasDuplicateKeys(text) {
  const seen = []; let inStr = false, esc = false, expectKey = false, i = 0, curKey = null, readingKey = false;
  while (i < text.length) {
    const c = text[i++];
    if (inStr) {
      if (esc) {
        esc = false;
        if (readingKey) {
          if (c === "u") { const hex = text.substr(i, 4); i += 4; curKey += String.fromCharCode(parseInt(hex, 16)); }
          else curKey += ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", "/": "/", '"': '"' }[c] ?? c);
        }
      }
      else if (c === String.fromCharCode(92)) { esc = true; }
      else if (c === '"') { inStr = false; readingKey = false; }
      else if (readingKey) curKey += c;
      continue;
    }
    if (c === '"') { inStr = true; if (expectKey) { readingKey = true; curKey = ''; } continue; }
    if (c === '{') { seen.push(new Set()); expectKey = true; }
    else if (c === '}') { seen.pop(); expectKey = false; }
    else if (c === '[') { seen.push(null); expectKey = false; }
    else if (c === ']') { seen.pop(); expectKey = false; }
    else if (c === ':') {
      const set = seen.length ? seen[seen.length - 1] : null;
      if (curKey !== null && set) { if (set.has(curKey)) return true; set.add(curKey); }
      curKey = null; expectKey = false;
    } else if (c === ',') { expectKey = seen.length > 0 && seen[seen.length - 1] instanceof Set; }
  }
  return false;
}
function jsonNestingDepth(text) {
  let depth = 0, max = 0, inStr = false, esc = false;
  for (const ch of text) {
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; }
    else if (ch === '"') inStr = true;
    else if (ch === "[" || ch === "{") { depth++; if (depth > max) max = depth; }
    else if (ch === "]" || ch === "}") depth--;
  }
  return max;
}
function hasLoneSurrogate(text) {
  let i = 0; const n = text.length, hex = (s) => (/^[0-9a-fA-F]{4}$/.test(s) ? parseInt(s, 16) : NaN);
  while (i < n) {
    if (text[i] !== "\\") { i++; continue; }
    if (text[i + 1] === "u" && i + 5 < n) {
      const cp = hex(text.slice(i + 2, i + 6));
      if (Number.isNaN(cp)) { i += 2; continue; }   // malformed escape: the parser refuses it, not this rule
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (text.slice(i + 6, i + 8) !== "\\u") return true;
        const lo = hex(text.slice(i + 8, i + 12));
        if (!(lo >= 0xdc00 && lo <= 0xdfff)) return true;
        i += 12; continue;
      }
      if (cp >= 0xdc00 && cp <= 0xdfff) return true;
      i += 6; continue;
    }
    i += 2;
  }
  return false;
}
function tipPayload(entries, ledgerId, tipSha256, ts) {
  return Buffer.from(`{"entries":${entries},"kind":"${TIP_KIND}","ledger_id":"${ledgerId}","tip_sha256":"${tipSha256}","ts":"${ts}"}`, "utf-8");
}
function parseInstant(s) {
  if (typeof s !== "string") return null;
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  if (y < 1 || y > 9999 || mo < 1 || mo > 12 || h > 23 || mi > 59 || sec > 59) return null;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (d < 1 || d > dim) return null;
  let offSec = 0;
  if (m[8] !== "Z") { const oh = Number(m[8].slice(1, 3)), om = Number(m[8].slice(4, 6)); if (oh > 23 || om > 59) return null; offSec = (oh * 3600 + om * 60) * (m[8][0] === "-" ? -1 : 1); }
  const dt = new Date(0); dt.setUTCFullYear(y, mo - 1, d); dt.setUTCHours(h, mi, sec, 0);   // year-safe, no Date.UTC quirk
  const nanos = Number(((m[7] || "0") + "000000000").slice(0, 9));
  return [Math.floor(dt.getTime() / 1000) - offSec, nanos];
}

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const sha3 = (b) => createHash("sha3-256").update(b).digest("hex");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const without = (o, k) => { const c = {}; for (const x of Object.keys(o)) if (x !== k) c[x] = o[x]; return c; };
function strictParse(text) {   // JSON.parse alone hides what the profile forbids
  if (/\b(NaN|Infinity)\b/.test(text) && !/"[^"]*\b(NaN|Infinity)\b[^"]*"/.test(text)) throw new Error("non-JSON constant");
  if (hasDuplicateKeys(text)) throw new Error("duplicate key");
  if (hasLoneSurrogate(text)) throw new Error("lone surrogate");
  if (jsonNestingDepth(text) > 512) throw new Error("nesting deeper than 512");
  return JSON.parse(text);
}
function edOk(pubHex, msg, sigHex) {
  try { return edVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pubHex, "hex")]), format: "der", type: "spki" }), Buffer.from(sigHex, "hex")); }
  catch { return false; }
}
function signedPayload(side) {
  return Buffer.from(canon({ kind: "cra_pack_sig/1", signed_pack_sha3: side.signed_pack_sha3, signer_id: side.signer_id, signed_utc: side.signed_utc,
                             public_key_hex: side.public_key_hex, alg: side.alg === undefined ? "Ed25519" : side.alg }), "utf-8");
}
const L = (layer, status, detail = "") => ({ layer, status, detail });

export function verifyPack(packPath, { ledgerPath = null, trustStore = null, logPubkeyHex = null, requireSources = false } = {}) {
  try { return verify(packPath, ledgerPath, trustStore, logPubkeyHex, requireSources); }
  catch (e) { return { ok: false, authenticity: "FAIL", anchored: false, layers: [L("verifier-exception", "FAIL", String(e.message || e).slice(0, 160))], pack_sha3: null }; }
}

function verify(packPath, ledgerPath, trustStore, logPubkeyHex, requireSources = false) {
  const layers = [];
  let pack;
  try { pack = strictParse(readFileSync(packPath, "utf-8")); layers.push(L("pack-json", "PASS")); }
  catch (e) { return { ok: false, authenticity: "FAIL", anchored: false, layers: [L("pack-json", "FAIL", String(e.message))], pack_sha3: null }; }
  if (!isObj(pack)) return { ok: false, authenticity: "FAIL", anchored: false, layers: [L("pack-json", "FAIL", "pack is not a JSON object")], pack_sha3: null };
  layers.push(L("pack-kind", pack.kind === PACK_KIND ? "PASS" : "FAIL", String(pack.kind)));
  const scope = String(pack.honest_scope ?? "");
  layers.push(L("honest-scope", scope.includes(SCOPE_MARK) ? "PASS" : "FAIL", scope.includes(SCOPE_MARK) ? "declared limits present" : `missing the declared limit '${SCOPE_MARK}'`));
  let computed = null;
  try { computed = sha3(Buffer.from(canon(without(pack, "pack_sha3")), "utf-8")); }
  catch (e) { layers.push(L("pack-sha3", "FAIL", "pack not canonicalisable: " + e.message)); }
  if (computed !== null) layers.push(L("pack-sha3", pack.pack_sha3 === computed ? "PASS" : "FAIL", `declared ${String(pack.pack_sha3).slice(0, 16)}… computed ${computed.slice(0, 16)}…`));
  const pv = isObj(pack.verification) ? pack.verification : {};
  layers.push(L("pack-self-verification", pv.chain_ok === true && pv.record_digests_bound === true ? "PASS" : "FAIL", `chain_ok=${pv.chain_ok} record_digests_bound=${pv.record_digests_bound}`));
  const lp = ledgerPath || (pack.ledger_file ? join(dirname(packPath), basename(String(pack.ledger_file))) : null);
  let anchored = false;
  const isFile = (p) => { try { return statSync(p).isFile(); } catch { return false; } };
  if ((ledgerPath || logPubkeyHex || requireSources) && !(lp && isFile(lp))) {
    layers.push(L("ledger-chain", "FAIL", "ledger explicitly required (ledger_path / log key / require_sources given) but not found"));
  } else if (lp && isFile(lp)) {
    const entries = [], failures = [];
    let prev = GENESIS, n = 0;
    for (const line of readFileSync(lp, "utf-8").split("\n")) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line, "utf-8") > MAX_LINE_BYTES) { failures.push(`entry ${n}: line exceeds ${MAX_LINE_BYTES} bytes`); break; }
      let e;
      try { e = strictParse(line); } catch (err) { failures.push(`unparsable line: ${err.message}`); break; }
      if (!isObj(e)) { failures.push(`entry ${n}: not an object`); break; }
      if (!Number.isInteger(e.idx) || e.idx !== n) failures.push(`entry ${n}: idx not sequential`);
      if (e.prev_hash !== prev) failures.push(`entry ${n}: prev_hash does not link`);
      let h = null; try { h = sha256(Buffer.from(canon(without(e, "self_hash")), "utf-8")); } catch (err) { failures.push(`entry ${n}: ${err.message}`); }
      if (h !== e.self_hash) failures.push(`entry ${n}: self_hash mismatch`);
      if (typeof e.self_hash === "string") prev = e.self_hash;
      entries.push(e); n++;
    }
    if (n === 0) failures.push("empty_ledger: zero entries, nothing to verify");
    if (failures.length) layers.push(L("ledger-chain", "FAIL", failures.slice(0, 3).join("; ")));
    else {
      let bound = true, anchorIdx = null;
      for (const e of entries) {
        const d = isObj(e.data) ? e.data : {};
        if (RECORD_KINDS.has(d.kind)) {
          let rh = null; try { rh = sha3(Buffer.from(canon(without(d, "record_sha3")), "utf-8")); } catch { rh = null; }
          if (rh !== d.record_sha3) bound = false;
          if (d.kind === "cra_pack_anchor" && d.anchored_pack_sha3 === pack.pack_sha3) anchorIdx = e.idx;
        }
      }
      if (!bound) layers.push(L("ledger-chain", "FAIL", "a record's record_sha3 does not match its content"));
      else if (anchorIdx === null) layers.push(L("ledger-chain", "FAIL", "chain valid but THIS pack is not anchored (no cra_pack_anchor entry with its pack_sha3)"));
      else { anchored = true; layers.push(L("ledger-chain", "PASS", `${n} entries, records bound, pack anchored at idx ${anchorIdx}`)); }
      const ne = pack.ledger_entries;
      const okState = Number.isInteger(ne) && ne > 0 && ne <= entries.length && entries[ne - 1].self_hash === pack.ledger_last_self_hash && (anchorIdx === null || anchorIdx >= ne);
      layers.push(L("pack-ledger-state", okState ? "PASS" : "FAIL", `declared entries=${ne} last=${String(pack.ledger_last_self_hash).slice(0, 12)}…; anchor idx=${anchorIdx}`));
      layers.push(sourceDocuments(lp, entries, requireSources, isFile));
      const tipPath = lp + ".tip.json";
      if (!entries.length) layers.push(L("signed-tip", "FAIL", "ledger has no entries"));
      else if (logPubkeyHex) {
        if (!existsSync(tipPath)) layers.push(L("signed-tip", "FAIL", "trusted log key given but no tip file next to the ledger"));
        else {
          const r = checkTip(entries.length, entries[0].self_hash, entries[entries.length - 1].self_hash, tipPath, logPubkeyHex);
          layers.push(L("signed-tip", r.ok ? "PASS" : "FAIL", r.ok ? "tip verified: no tail truncation" : r.error));
        }
      } else if (existsSync(tipPath)) layers.push(L("signed-tip", "SKIP", "tip present but NOT checked: pass the trusted log key (tail truncation undetected)"));
      else layers.push(L("signed-tip", "SKIP", "no tip: tail truncation undetectable offline (use a tip key / cryptovalid monitor)"));
    }
  } else layers.push(L("ledger-chain", "SKIP", "ledger not next to the pack (honest: integrity of the chain not checked)"));
  const sig = verifySidecar(packPath, pack, trustStore);
  layers.push(L("producer-signature", sig.status, sig.detail || ""));
  let auth;
  if (sig.status === "FAIL") auth = "FAIL";
  else if (trustStore !== null && sig.status === "SKIP") { auth = "FAIL"; layers.push(L("trusted-signer", "FAIL", "a trust store was required but the pack is not signed")); }
  else if (sig.status === "PASS" && trustStore !== null && !sig.trusted) { auth = "FAIL"; layers.push(L("trusted-signer", "FAIL", "valid signature but signer not in the trust store")); }
  else if (sig.status === "PASS" && sig.trusted) auth = "trusted-signed";
  else if (sig.status === "PASS") auth = "signed";
  else if (anchored) auth = "anchored";
  else auth = "FAIL";
  const ok = auth !== "FAIL" && !layers.some((l) => l.status === "FAIL");
  return { ok, authenticity: ok ? auth : "FAIL", anchored, layers, pack_sha3: pack.pack_sha3 ?? null };
}

function checkTip(count, first, last, tipPath, pubHex) {
  let tip; try { tip = strictParse(readFileSync(tipPath, "utf-8")); } catch (e) { return { ok: false, error: "tip_unreadable: " + e.message }; }
  if (!isObj(tip) || tip.kind !== TIP_KIND) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  for (const k of ["entries", "ledger_id", "tip_sha256", "ts", "signature_hex"]) if (!(k in tip)) return { ok: false, error: `tip_invalid: tip missing field ${k}` };
  if (!Number.isInteger(tip.entries) || tip.entries < 0 || !["ledger_id", "tip_sha256", "ts", "signature_hex"].every((k) => typeof tip[k] === "string")) return { ok: false, error: "tip_invalid: bad field types" };
  if (!HEX64.test(tip.ledger_id) || !HEX64.test(tip.tip_sha256) || parseInstant(tip.ts) === null) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  if (tip.log_pubkey_hex && tip.log_pubkey_hex !== pubHex) return { ok: false, error: "tip_invalid: tip log key differs from the trusted log key" };
  if (!edOk(pubHex, tipPayload(tip.entries, tip.ledger_id, tip.tip_sha256, tip.ts), tip.signature_hex)) return { ok: false, error: "tip_invalid: tip signature invalid" };
  if (tip.ledger_id !== first) return { ok: false, error: "tip_of_another_ledger" };
  if (count < tip.entries) return { ok: false, error: `tail_truncated: file has ${count} entries, the signed tip commits to ${tip.entries}` };
  if (count > tip.entries) return { ok: false, error: `unsealed_tail: file has ${count} entries, the signed tip commits to ${tip.entries}` };
  if (last !== tip.tip_sha256) return { ok: false, error: "tail_rewritten" };
  return { ok: true };
}

function verifySidecar(packPath, pack, trustStore) {
  const sp = packPath + ".sig.json";
  if (!existsSync(sp)) return { status: "SKIP", detail: "pack not signed" };
  let side; try { side = strictParse(readFileSync(sp, "utf-8")); } catch (e) { return { status: "FAIL", detail: "unreadable: " + e.message }; }
  if (!isObj(side)) return { status: "FAIL", detail: "sidecar is not a JSON object" };
  let digest; try { digest = sha3(Buffer.from(canon(without(pack, "pack_sha3")), "utf-8")); } catch (e) { return { status: "FAIL", detail: "pack not canonicalisable" }; }
  if (pack.pack_sha3 !== digest) return { status: "FAIL", detail: "content does not match pack_sha3 (modified after signing)" };
  if (side.signed_pack_sha3 !== digest) return { status: "FAIL", detail: "pack changed after signature (digest differs from the signed one)" };
  if (typeof side.public_key_hex !== "string" || !edOk(side.public_key_hex, signedPayload(side), String(side.signature_hex))) return { status: "FAIL", detail: "signature invalid for the declared key" };
  const fp = sha256(Buffer.from(side.public_key_hex, "hex")).slice(0, 16);
  if (side.fingerprint !== undefined && side.fingerprint !== null && side.fingerprint !== fp) return { status: "FAIL", detail: "declared fingerprint does not match the signing key" };
  const out = { status: "PASS", signer_id: side.signer_id, fingerprint: fp, trusted: false };
  if (trustStore !== null) { const exp = trustStore[String(side.signer_id ?? "")]; out.trusted = Boolean(exp) && exp === side.public_key_hex; out.detail = out.trusted ? "trusted-signed" : "signed by a key NOT in the trust store"; }
  else out.detail = "signed (signer not compared with a trust store)";
  return out;
}

function sourceDocuments(lp, entries, require, isFile) {
  const wanted = new Set(); let malformed = 0;
  for (const e of entries) {
    const d = isObj(e.data) ? e.data : {};
    if (d.kind !== "cra_sbom" || !isObj(d.source)) continue;
    const v = d.source.sha256;
    if (v === undefined || v === null || v === "") continue;            // absent / null / empty: no hash recorded
    if (typeof v !== "string" || !HEX64.test(v)) { malformed++; continue; }  // present but not a SHA-256: FAIL, never a path
    wanted.add(v);
  }
  if (!wanted.size && !malformed) return L("source-documents", "SKIP", "no SBOM source document recorded by hash");
  let present = 0, absent = 0; const bad = malformed ? [`${malformed} record(s) with a malformed source hash`] : [];
  for (const h of [...wanted].sort()) {
    const fp = join(lp + ".sources", h + ".json");
    if (!isFile(fp)) { absent++; continue; }
    let got;
    try { got = sha256(readFileSync(fp)); } catch (e) { bad.push(`${h.slice(0, 16)}… unreadable (${e.code || e.name})`); continue; }
    if (got === h) present++; else bad.push(`${h.slice(0, 16)}… stored bytes hash to ${got.slice(0, 16)}…`);
  }
  if (bad.length) return L("source-documents", "FAIL", `${bad.length} source document(s) do not match their recorded SHA-256: ` + bad.slice(0, 3).join("; "));
  if (absent) return L("source-documents", require ? "FAIL" : "SKIP", `${present} of ${wanted.size} source document(s) present and verified; ${absent} recorded by hash only` + (require ? " (required)" : ""));
  return L("source-documents", "PASS", `${present} source document(s) present, bytes hash to the recorded SHA-256`);
}

function main(argv) {
  const args = argv.slice(2); let pack = null, ledger = null, trust = null, key = null, requireSources = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--ledger") ledger = args[++i]; else if (args[i] === "--trust-store") trust = JSON.parse(readFileSync(args[++i], "utf-8"));
    else if (args[i] === "--log-pubkey") key = args[++i]; else if (args[i] === "--require-sources") requireSources = true; else pack = args[i];
  }
  if (!pack) { console.error("usage: cra-verify.mjs <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]"); return 2; }
  const r = verifyPack(pack, { ledgerPath: ledger, trustStore: trust, logPubkeyHex: key, requireSources });
  console.log(JSON.stringify(r, null, 1));
  return r.ok ? 0 : 1;
}
if (process.argv[1] && /cra-verify\.mjs$/.test(process.argv[1])) process.exit(main(process.argv));
