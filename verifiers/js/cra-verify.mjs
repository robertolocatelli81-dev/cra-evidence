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
import { readFileSync, existsSync, statSync, lstatSync } from "node:fs";
import { basename, dirname, join } from "node:path";

const PACK_KIND = "cra_evidence_pack/1", SCOPE_MARK = "NOT a conformity assessment", GENESIS = "0".repeat(64);
const RECORD_KINDS = new Set(["cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor"]);
const INSTANT_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$/;
const ledgerFileNameOk = (v) => typeof v === "string" && v !== "" && v !== "." && v !== ".." && !v.includes("/") && !v.includes("\\");
const TIP_KIND = "cryptovalid_tip/1", SPKI = Buffer.from("302a300506032b6570032100", "hex"), HEX64 = /^[0-9a-f]{64}$/;

const MAX_LINE_BYTES = 64 << 20, MAX_SOURCE_BYTES = 256 << 20;   // cryptovalid profile: a longer JSONL line is a failure, never a silent truncation
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

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const sha3 = (b) => createHash("sha3-256").update(b).digest("hex");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const without = (o, k) => Object.fromEntries(Object.entries(o).filter(([x]) => x !== k));   // keeps an own "__proto__" key (c[x] = … would invoke the setter and drop it)
function badNumberToken(text) {   // outside strings: a token with '.', 'e', 'E' (10.0 would JSON.parse to 10 and hash alike) or an integer outside ±(2^53-1)
  let inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; continue; }
    if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i; while (j < text.length && /[-+0-9.eE]/.test(text[j])) j++;
      const tok = text.slice(i, j);
      if (/[.eE]/.test(tok)) return "floating-point number (the profile forbids floats)";
      if (tok.replace("-", "").length > 15 && (BigInt(tok) > 9007199254740991n || BigInt(tok) < -9007199254740991n)) return "integer outside ±(2^53-1) (the profile forbids it)";
      i = j - 1;
    }
  }
  return null;
}
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });   // strict: one invalid byte is unreadable, never U+FFFD; a BOM stays in the text (JSON.parse refuses it, as the other three)
const readText = (p) => UTF8.decode(readFileSync(p));
function strictParse(text) {   // JSON.parse alone hides what the profile forbids
  if (/\b(NaN|Infinity)\b/.test(text) && !/"[^"]*\b(NaN|Infinity)\b[^"]*"/.test(text)) throw new Error("non-JSON constant");
  const bad = badNumberToken(text); if (bad) throw new Error(bad);
  if (hasDuplicateKeys(text)) throw new Error("duplicate key");
  if (hasLoneSurrogate(text)) throw new Error("lone surrogate");
  if (jsonNestingDepth(text) > 512) throw new Error("nesting deeper than 512");
  return JSON.parse(text);
}
const HEX128 = /^[0-9a-f]{128}$/, EXTERNAL_FORMATS = new Set(["cyclonedx-json", "spdx-json", "spdx-jsonld"]);
function edOk(pubHex, msg, sigHex) {   // lower-case hex of exact length, as the profile writes it (Buffer.from(…, "hex") would truncate at the first non-hex char)
  if (typeof pubHex !== "string" || !HEX64.test(pubHex) || typeof sigHex !== "string" || !HEX128.test(sigHex)) return false;
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
  try { pack = strictParse(readText(packPath)); layers.push(L("pack-json", "PASS")); }
  catch (e) { return { ok: false, authenticity: "FAIL", anchored: false, layers: [L("pack-json", "FAIL", String(e.message))], pack_sha3: null }; }
  if (!isObj(pack)) return { ok: false, authenticity: "FAIL", anchored: false, layers: [L("pack-json", "FAIL", "pack is not a JSON object")], pack_sha3: null };
  layers.push(L("pack-kind", pack.kind === PACK_KIND ? "PASS" : "FAIL", String(pack.kind)));
  const scopeOk = typeof pack.honest_scope === "string" && pack.honest_scope.includes(SCOPE_MARK);   // a string, not a list that contains the mark
  layers.push(L("honest-scope", scopeOk ? "PASS" : "FAIL", scopeOk ? "declared limits present" : `missing the declared limit '${SCOPE_MARK}' (honest_scope must be a string containing it)`));
  let computed = null;
  try { computed = sha3(Buffer.from(canon(without(pack, "pack_sha3")), "utf-8")); }
  catch (e) { layers.push(L("pack-sha3", "FAIL", "pack not canonicalisable: " + e.message)); }
  if (computed !== null) layers.push(L("pack-sha3", pack.pack_sha3 === computed ? "PASS" : "FAIL", `declared ${String(pack.pack_sha3).slice(0, 16)}… computed ${computed.slice(0, 16)}…`));
  const pv = isObj(pack.verification) ? pack.verification : {};
  layers.push(L("pack-self-verification", pv.chain_ok === true && pv.record_digests_bound === true ? "PASS" : "FAIL", `chain_ok=${pv.chain_ok} record_digests_bound=${pv.record_digests_bound}`));
  const lf = pack.ledger_file;
  const lfBad = lf !== undefined && lf !== null && !ledgerFileNameOk(lf);
  const lp = ledgerPath || (lf !== undefined && lf !== null && !lfBad ? join(dirname(packPath), lf) : null);
  let anchored = false;
  const isFile = (p) => { try { return statSync(p).isFile(); } catch { return false; } };
  if (lfBad) {
    layers.push(L("ledger-chain", "FAIL", "ledger_file malformed: must be a plain file name (string, no path separators)"));
  } else if ((ledgerPath || logPubkeyHex || requireSources) && !(lp && isFile(lp))) {
    layers.push(L("ledger-chain", "FAIL", "ledger explicitly required (ledger_path / log key / require_sources given) but not found"));
  } else if (lp && isFile(lp)) {
    const entries = [], failures = [];
    let prev = GENESIS, n = 0;
    let ledgerText;
    try { ledgerText = readText(lp); } catch (e) { ledgerText = null; failures.push("ledger not UTF-8: " + e.message); }
    for (let line of ledgerText === null ? [] : ledgerText.split("\n")) {
      if (line.endsWith("\r")) line = line.slice(0, -1);   // exactly one terminator (\n or \r\n); a run of \r is content and counts
      if (/^[ \t]*$/.test(line)) continue;                  // blank = ASCII space/tab only (U+00A0, U+2028, U+0085, U+FEFF are unparsable lines)
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
          if (d.kind === "cra_pack_anchor" && typeof pack.pack_sha3 === "string" && HEX64.test(pack.pack_sha3) && d.anchored_pack_sha3 === pack.pack_sha3) anchorIdx = e.idx;
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
      if (logPubkeyHex) {
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
  let tip; try { tip = strictParse(readText(tipPath)); } catch (e) { return { ok: false, error: "tip_unreadable: " + e.message }; }
  if (!isObj(tip) || tip.kind !== TIP_KIND) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };
  for (const k of ["entries", "ledger_id", "tip_sha256", "ts", "signature_hex"]) if (!(k in tip)) return { ok: false, error: `tip_invalid: tip missing field ${k}` };
  if (!Number.isInteger(tip.entries) || tip.entries < 0 || !["ledger_id", "tip_sha256", "ts", "signature_hex"].every((k) => typeof tip[k] === "string")) return { ok: false, error: "tip_invalid: bad field types" };
  if (!HEX64.test(tip.ledger_id) || !HEX64.test(tip.tip_sha256) || !INSTANT_RE.test(tip.ts)) return { ok: false, error: "tip_invalid: not a cryptovalid_tip/1 document" };   // shape, as the other three (values are the writer's)
  if (tip.log_pubkey_hex !== undefined && tip.log_pubkey_hex !== null && tip.log_pubkey_hex !== "" && tip.log_pubkey_hex !== pubHex) return { ok: false, error: "tip_invalid: tip log key differs from the trusted log key" };   // "" = absent (cryptovalid profile); a non-string never equals the key
  if (!edOk(pubHex, tipPayload(tip.entries, tip.ledger_id, tip.tip_sha256, tip.ts), tip.signature_hex)) return { ok: false, error: "tip_invalid: tip signature invalid" };
  if (tip.ledger_id !== first) return { ok: false, error: "tip_of_another_ledger" };
  if (count < tip.entries) return { ok: false, error: `tail_truncated: file has ${count} entries, the signed tip commits to ${tip.entries}` };
  if (count > tip.entries) return { ok: false, error: `unsealed_tail: file has ${count} entries, the signed tip commits to ${tip.entries}` };
  if (last !== tip.tip_sha256) return { ok: false, error: "tail_rewritten" };
  return { ok: true };
}

function verifySidecar(packPath, pack, trustStore) {
  const sp = packPath + ".sig.json";
  try { lstatSync(sp); } catch { return { status: "SKIP", detail: "pack not signed" }; }   // SKIP only when there is NO sidecar entry (a dangling symlink is one that cannot be read)
  let side; try { side = strictParse(readText(sp)); } catch (e) { return { status: "FAIL", detail: "unreadable: " + e.message }; }
  if (!isObj(side)) return { status: "FAIL", detail: "sidecar is not a JSON object" };
  let digest; try { digest = sha3(Buffer.from(canon(without(pack, "pack_sha3")), "utf-8")); } catch (e) { return { status: "FAIL", detail: "pack not canonicalisable" }; }
  if (pack.pack_sha3 !== digest) return { status: "FAIL", detail: "content does not match pack_sha3 (modified after signing)" };
  if (side.signed_pack_sha3 !== digest) return { status: "FAIL", detail: "pack changed after signature (digest differs from the signed one)" };
  if (!["signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "signature_hex"].every((k) => typeof side[k] === "string" && side[k] !== "") || !INSTANT_RE.test(side.signed_utc) || ("alg" in side && typeof side.alg !== "string"))
    return { status: "FAIL", detail: "sidecar field missing or not a string (a missing field is never signed as null)" };
  let sigOk = false;
  try { sigOk = typeof side.public_key_hex === "string" && typeof side.signature_hex === "string" && edOk(side.public_key_hex, signedPayload(side), side.signature_hex); } catch { sigOk = false; }   // a payload that cannot be canonicalised (missing/odd fields) is an invalid signature, never an exception
  if (!sigOk) return { status: "FAIL", detail: "signature invalid for the declared key" };
  const fp = sha256(Buffer.from(side.public_key_hex, "hex")).slice(0, 16);
  if (side.fingerprint !== undefined && side.fingerprint !== null && side.fingerprint !== fp) return { status: "FAIL", detail: "declared fingerprint does not match the signing key" };
  const out = { status: "PASS", signer_id: side.signer_id, fingerprint: fp, trusted: false };
  if (typeof side.signer_id !== "string") return { status: "FAIL", detail: "signer_id must be a string" };
  if (trustStore !== null) { const exp = trustStore[side.signer_id]; out.trusted = Boolean(exp) && exp === side.public_key_hex; out.detail = out.trusted ? "trusted-signed" : "signed by a key NOT in the trust store"; }
  else out.detail = "signed (signer not compared with a trust store)";
  return out;
}

function sourceDocuments(lp, entries, require, isFile) {
  const wanted = new Set(); let malformed = 0;
  for (const e of entries) {
    const d = isObj(e.data) ? e.data : {};
    if (d.kind !== "cra_sbom" || !isObj(d.source)) continue;
    const v = d.source.sha256;
    if (v === undefined || v === null || v === "") { if (EXTERNAL_FORMATS.has(d.source.format)) malformed++; continue; }   // an ingested document is always recorded WITH its hash
    if (typeof v !== "string" || !HEX64.test(v)) { malformed++; continue; }  // present but not a SHA-256: FAIL, never a path
    wanted.add(v);
  }
  if (!wanted.size && !malformed) return L("source-documents", "SKIP", "no SBOM source document recorded by hash");
  let present = 0, absent = 0; const bad = malformed ? [`${malformed} record(s) with a malformed source hash`] : [];
  for (const h of [...wanted].sort()) {
    const fp = join(lp + ".sources", h + ".json");
    if (!isFile(fp)) { absent++; continue; }
    let got;
    try {
      if (statSync(fp).size > MAX_SOURCE_BYTES) { bad.push(`${h.slice(0, 16)}… stored file exceeds ${MAX_SOURCE_BYTES} bytes`); continue; }
      got = sha256(readFileSync(fp));
    } catch (e) { bad.push(`${h.slice(0, 16)}… unreadable (${e.code || e.name})`); continue; }
    if (got === h) present++; else bad.push(`${h.slice(0, 16)}… stored bytes hash to ${got.slice(0, 16)}…`);
  }
  if (bad.length) return L("source-documents", "FAIL", `${bad.length} source document(s) do not match their recorded SHA-256: ` + bad.slice(0, 3).join("; "));
  if (absent) return L("source-documents", require ? "FAIL" : "SKIP", `${present} of ${wanted.size} source document(s) present and verified; ${absent} recorded by hash only` + (require ? " (required)" : ""));
  return L("source-documents", "PASS", `${present} source document(s) present, bytes hash to the recorded SHA-256`);
}

function main(argv) {
  const args = argv.slice(2); let pack = null, ledger = null, trust = null, key = null, requireSources = false;
  const usage = () => { console.error("usage: cra-verify.mjs <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]"); return 2; };
  for (let i = 0; i < args.length; i++) {
    const val = () => { if (i + 1 >= args.length || args[i + 1] === "") return null; return args[++i]; };   // a flag without a value, or with "", is a usage error — never a silent default
    if (args[i] === "--ledger") { ledger = val(); if (ledger === null) return usage(); }
    else if (args[i] === "--trust-store") {
      const f = val(); if (f === null) return usage();
      try { trust = strictParse(readText(f)); if (!isObj(trust) || !Object.values(trust).every((v) => typeof v === "string")) throw new Error("not an object of strings"); }
      catch (e) { console.error("trust store unreadable: " + e.message); return 2; }
    }
    else if (args[i] === "--log-pubkey") { key = val(); if (key === null || !HEX64.test(key)) return usage(); }
    else if (args[i] === "--require-sources") requireSources = true; else pack = args[i];
  }
  if (!pack) return usage();
  const r = verifyPack(pack, { ledgerPath: ledger, trustStore: trust, logPubkeyHex: key, requireSources });
  console.log(JSON.stringify(r, null, 1));
  return r.ok ? 0 : 1;
}
if (process.argv[1] && /cra-verify\.mjs$/.test(process.argv[1])) process.exit(main(process.argv));
