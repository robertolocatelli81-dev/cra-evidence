// SPDX-License-Identifier: AGPL-3.0-or-later
//! cra-verify — independent Rust verifier of a cra-evidence pack. Same layers and authenticity verdict as
//! cra_evidence/verify_pack.py. json.rs / keccak.rs / sha256.rs are cryptovalid's pure-Rust modules (same profile).
//! Usage: cra-verify <pack.json> [--ledger path] [--trust-store file.json] [--log-pubkey hex] [--require-sources]; exit 0 only if ok.
//! source-documents layer: every cra_sbom record with source.sha256 names <ledger>.sources/<sha256>.json, whose bytes must
//! hash (SHA-256) to that value when present (mismatch = FAIL; absence = SKIP, or FAIL with --require-sources).
mod json;
mod keccak;
mod sha256;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use json::{canonical, Json, Parser};
use std::collections::BTreeMap;
use std::path::Path;

const PACK_KIND: &str = "cra_evidence_pack/1";
const SCOPE_MARK: &str = "NOT a conformity assessment";
const TIP_KIND: &str = "cryptovalid_tip/1";
const MAX_LINE_BYTES: usize = 64 << 20;
const MAX_SOURCE_BYTES: u64 = 256 << 20;
fn ledger_file_name_ok(v: &str) -> bool { !v.is_empty() && v != "." && v != ".." && !v.contains('/') && !v.contains('\\') }   // a stored generator document above this is refused unread   // cryptovalid profile: a longer JSONL line is a failure, never a silent truncation
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_KINDS: [&str; 5] = ["cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor"];

struct Layer(String, String, String);

fn has_float(v: &Json) -> bool {
    match v {
        Json::Float(_) => true,
        Json::Array(a) => a.iter().any(has_float),
        Json::Object(o) => o.values().any(has_float),
        _ => false,
    }
}
fn parse_obj(text: &str) -> Result<BTreeMap<String, Json>, String> {
    let v = Parser::parse(text)?;
    if has_float(&v) {
        return Err("float in JSON (profile forbids it)".into());
    }
    match v {
        Json::Object(o) => Ok(o),
        _ => Err("not a JSON object".into()),
    }
}
fn without(o: &BTreeMap<String, Json>, k: &str) -> Json {
    let mut c = o.clone();
    c.remove(k);
    Json::Object(c)
}
fn sha3_of(o: &BTreeMap<String, Json>, drop: &str) -> String {
    keccak::hex(canonical(&without(o, drop)).as_bytes())
}
fn sha256_of(o: &BTreeMap<String, Json>, drop: &str) -> String {
    sha256::hex(canonical(&without(o, drop)).as_bytes())
}
fn gs<'a>(o: &'a BTreeMap<String, Json>, k: &str) -> Option<&'a str> {
    match o.get(k) {
        Some(Json::Str(s)) => Some(s),
        _ => None,
    }
}
fn gi(o: &BTreeMap<String, Json>, k: &str) -> Option<i64> {
    match o.get(k) {
        Some(Json::Int(i)) => Some(*i),
        _ => None,
    }
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || s.len() % 2 != 0 {   // a byte slice of a non-ASCII string would panic: hostile input is a None, never a crash
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
fn ed_ok(pub_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let (Some(p), Some(s)) = (unhex(pub_hex), unhex(sig_hex)) else { return false };
    let (Ok(pb), Ok(sb)) = (<[u8; 32]>::try_from(p.as_slice()), <[u8; 64]>::try_from(s.as_slice())) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pb) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sb)).is_ok()
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn is_instant(s: &str) -> bool {
    if !s.is_ascii() { return false; }
    // YYYY-MM-DDThh:mm:ss[.f]{Z|±hh:mm} — same shape as the other verifiers (values validated by the writers)
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(|c| c.is_ascii_digit());
    if !(digits(0..4) && digits(5..7) && digits(8..10) && digits(11..13) && digits(14..16) && digits(17..19)) {
        return false;
    }
    let rest = &s[19..];
    let rest = if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > 9 { return false; }
        &r[n..]
    } else { rest };
    rest == "Z" || (rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) && rest[1..3].bytes().all(|c| c.is_ascii_digit()) && &rest[3..4] == ":" && rest[4..6].bytes().all(|c| c.is_ascii_digit()))
}

struct Out { ok: bool, auth: String, anchored: bool, layers: Vec<Layer>, pack_sha3: Option<String> }

fn source_documents(lp: &str, entries: &[BTreeMap<String, Json>], require: bool) -> Layer {
    let mut wanted: Vec<String> = Vec::new();
    let mut malformed = 0usize;
    let is_hex64 = |h: &str| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    for e in entries {
        if let Some(Json::Object(d)) = e.get("data") {
            if gs(d, "kind") != Some("cra_sbom") { continue; }
            if let Some(Json::Object(src)) = d.get("source") {
                match src.get("sha256") {
                    None | Some(Json::Null) => {}                                   // absent / null: no hash recorded
                    Some(Json::Str(h)) if h.is_empty() => {}                        // empty: no hash recorded
                    Some(Json::Str(h)) if is_hex64(h) => { if !wanted.iter().any(|w| w == h) { wanted.push(h.to_string()); } }
                    Some(_) => { malformed += 1; }                                  // present but not a SHA-256: FAIL, never a path
                }
            }
        }
    }
    if wanted.is_empty() && malformed == 0 { return Layer("source-documents".into(), "SKIP".into(), "no SBOM source document recorded by hash".into()); }
    wanted.sort();
    let (mut present, mut absent, mut bad): (usize, usize, Vec<String>) = (0, 0, Vec::new());
    if malformed > 0 { bad.push(format!("{malformed} record(s) with a malformed source hash")); }
    for h in &wanted {
        let fp = format!("{lp}.sources/{h}.json");
        if !Path::new(&fp).is_file() { absent += 1; continue; }
        if std::fs::metadata(&fp).map(|m| m.len()).unwrap_or(0) > MAX_SOURCE_BYTES { bad.push(format!("{}… stored file exceeds {MAX_SOURCE_BYTES} bytes", &h[..16])); continue; }
        match std::fs::read(&fp) {
            Ok(raw) => { let got = sha256::hex(&raw); if &got == h { present += 1; } else { bad.push(format!("{}… stored bytes hash to {}…", &h[..16], &got[..16])); } }
            Err(_) => bad.push(format!("{}… unreadable", &h[..16])),
        }
    }
    if !bad.is_empty() {
        let n = bad.len();
        bad.truncate(3);
        return Layer("source-documents".into(), "FAIL".into(), format!("{n} source document(s) do not match their recorded SHA-256: {}", bad.join("; ")));
    }
    if absent > 0 {
        return Layer("source-documents".into(), if require { "FAIL" } else { "SKIP" }.into(),
                     format!("{present} of {} source document(s) present and verified; {absent} recorded by hash only{}", wanted.len(), if require { " (required)" } else { "" }));
    }
    Layer("source-documents".into(), "PASS".into(), format!("{present} source document(s) present, bytes hash to the recorded SHA-256"))
}

fn verify(pack_path: &str, ledger_path: Option<&str>, trust: Option<&BTreeMap<String, Json>>, log_pub: Option<&str>, require_sources: bool) -> Out {
    let fail = |layer: &str, detail: String| Out { ok: false, auth: "FAIL".into(), anchored: false, layers: vec![Layer(layer.into(), "FAIL".into(), detail)], pack_sha3: None };
    let raw = match std::fs::read_to_string(pack_path) { Ok(t) => t, Err(e) => return fail("pack-json", e.to_string()) };
    let pack = match parse_obj(&raw) { Ok(o) => o, Err(e) => return fail("pack-json", e) };
    let mut layers = vec![Layer("pack-json".into(), "PASS".into(), String::new())];
    let l = |layers: &mut Vec<Layer>, name: &str, ok: bool, detail: String| layers.push(Layer(name.into(), if ok { "PASS" } else { "FAIL" }.into(), detail));
    let kind = gs(&pack, "kind").unwrap_or("");
    l(&mut layers, "pack-kind", kind == PACK_KIND, kind.into());
    let scope = gs(&pack, "honest_scope").unwrap_or("");
    l(&mut layers, "honest-scope", scope.contains(SCOPE_MARK), if scope.contains(SCOPE_MARK) { "declared limits present" } else { "missing the declared limit" }.into());
    let declared = gs(&pack, "pack_sha3").unwrap_or("").to_string();
    let computed = sha3_of(&pack, "pack_sha3");
    l(&mut layers, "pack-sha3", declared == computed, format!("declared {}… computed {}…", &declared.chars().take(16).collect::<String>(), &computed[..16]));
    let self_ok = match pack.get("verification") {
        Some(Json::Object(pv)) => matches!(pv.get("chain_ok"), Some(Json::Bool(true))) && matches!(pv.get("record_digests_bound"), Some(Json::Bool(true))),
        _ => false,
    };
    l(&mut layers, "pack-self-verification", self_ok, format!("snapshot ok={self_ok}"));
    // ledger_file must be a plain file name: a non-string, an empty string or anything with a path separator is a malformed field
    let lf_bad = match pack.get("ledger_file") { None | Some(Json::Null) => false, Some(Json::Str(v)) => !ledger_file_name_ok(v), Some(_) => true };
    let lp: Option<String> = match ledger_path {
        Some(p) => Some(p.to_string()),
        None => if lf_bad { None } else { gs(&pack, "ledger_file").map(|lf| Path::new(pack_path).parent().unwrap_or(Path::new(".")).join(lf).to_string_lossy().to_string()) },
    };
    let is_file = |p: &str| Path::new(p).is_file();
    let mut anchored = false;
    let required = ledger_path.is_some() || log_pub.is_some() || require_sources;
    if lf_bad {
        layers.push(Layer("ledger-chain".into(), "FAIL".into(), "ledger_file malformed: must be a plain file name (string, no path separators)".into()));
    } else if required && !lp.as_deref().map(is_file).unwrap_or(false) {
        layers.push(Layer("ledger-chain".into(), "FAIL".into(), "ledger explicitly required (ledger_path / log key / require_sources given) but not found".into()));
    } else if let Some(lp) = lp.filter(|p| is_file(p)) {
        let mut failures: Vec<String> = vec![];
        let text = match std::fs::read_to_string(&lp) { Ok(t) => t, Err(e) => { failures.push(format!("ledger unreadable or not UTF-8: {e}")); String::new() } };
        let mut entries: Vec<BTreeMap<String, Json>> = vec![];
        let (mut prev, mut n) = (GENESIS.to_string(), 0i64);
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);   // exactly one terminator; a run of \r is content and counts
            if line.trim_matches(|c| c == ' ' || c == '\t').is_empty() { continue; }   // blank = ASCII space/tab only
            if line.len() > MAX_LINE_BYTES { failures.push(format!("entry {n}: line exceeds {MAX_LINE_BYTES} bytes")); break; }
            let e = match parse_obj(line) { Ok(o) => o, Err(err) => { failures.push(format!("entry {n}: unparsable: {err}")); break; } };
            if gi(&e, "idx") != Some(n) { failures.push(format!("entry {n}: idx not sequential")); }
            if gs(&e, "prev_hash") != Some(prev.as_str()) { failures.push(format!("entry {n}: prev_hash does not link")); }
            let sh = gs(&e, "self_hash").unwrap_or("").to_string();
            if sha256_of(&e, "self_hash") != sh { failures.push(format!("entry {n}: self_hash mismatch")); }
            if !sh.is_empty() { prev = sh; }
            entries.push(e);
            n += 1;
        }
        if n == 0 { failures.push("empty_ledger: zero entries, nothing to verify".into()); }
        if !failures.is_empty() {
            failures.truncate(3);
            layers.push(Layer("ledger-chain".into(), "FAIL".into(), failures.join("; ")));
        } else {
            let (mut bound, mut anchor_idx): (bool, Option<i64>) = (true, None);
            for e in &entries {
                if let Some(Json::Object(d)) = e.get("data") {
                    let k = gs(d, "kind").unwrap_or("");
                    if !RECORD_KINDS.contains(&k) { continue; }
                    if sha3_of(d, "record_sha3") != gs(d, "record_sha3").unwrap_or("") { bound = false; }
                    if k == "cra_pack_anchor" && is_hex64(&declared) && gs(d, "anchored_pack_sha3") == Some(declared.as_str()) { anchor_idx = gi(e, "idx"); }
                }
            }
            if !bound { layers.push(Layer("ledger-chain".into(), "FAIL".into(), "a record's record_sha3 does not match its content".into())); }
            else if anchor_idx.is_none() { layers.push(Layer("ledger-chain".into(), "FAIL".into(), "chain valid but THIS pack is not anchored".into())); }
            else { anchored = true; layers.push(Layer("ledger-chain".into(), "PASS".into(), format!("{n} entries, records bound, pack anchored at idx {}", anchor_idx.unwrap()))); }
            let ne = gi(&pack, "ledger_entries");
            let ok_state = match ne {
                Some(ne) if ne > 0 && (ne as usize) <= entries.len() =>
                    gs(&entries[ne as usize - 1], "self_hash") == gs(&pack, "ledger_last_self_hash") && anchor_idx.map(|a| a >= ne).unwrap_or(true),
                _ => false,
            };
            l(&mut layers, "pack-ledger-state", ok_state, format!("declared entries={ne:?}; anchor idx={anchor_idx:?}"));
            layers.push(source_documents(&lp, &entries, require_sources));
            let tip_path = format!("{lp}.tip.json");
            let first = gs(&entries[0], "self_hash").unwrap_or("").to_string();
            let last = gs(&entries[entries.len() - 1], "self_hash").unwrap_or("").to_string();
            if let Some(pk) = log_pub {
                if !is_file(&tip_path) { layers.push(Layer("signed-tip".into(), "FAIL".into(), "trusted log key given but no tip file next to the ledger".into())); }
                else { match check_tip(entries.len() as i64, &first, &last, &tip_path, pk) {
                    Ok(()) => layers.push(Layer("signed-tip".into(), "PASS".into(), "tip verified: no tail truncation".into())),
                    Err(why) => layers.push(Layer("signed-tip".into(), "FAIL".into(), why)),
                } }
            } else if is_file(&tip_path) { layers.push(Layer("signed-tip".into(), "SKIP".into(), "tip present but NOT checked: pass the trusted log key (tail truncation undetected)".into())); }
            else { layers.push(Layer("signed-tip".into(), "SKIP".into(), "no tip: tail truncation undetectable offline".into())); }
        }
    } else {
        layers.push(Layer("ledger-chain".into(), "SKIP".into(), "ledger not next to the pack (honest: integrity of the chain not checked)".into()));
    }
    let (sig_status, sig_detail, trusted) = verify_sidecar(pack_path, &pack, &declared, trust);
    layers.push(Layer("producer-signature".into(), sig_status.clone(), sig_detail));
    let have_trust = trust.is_some();
    let mut auth = if sig_status == "FAIL" { "FAIL" }
        else if have_trust && sig_status == "SKIP" { layers.push(Layer("trusted-signer".into(), "FAIL".into(), "a trust store was required but the pack is not signed".into())); "FAIL" }
        else if sig_status == "PASS" && have_trust && !trusted { layers.push(Layer("trusted-signer".into(), "FAIL".into(), "valid signature but signer not in the trust store".into())); "FAIL" }
        else if sig_status == "PASS" && trusted { "trusted-signed" }
        else if sig_status == "PASS" { "signed" }
        else if anchored { "anchored" } else { "FAIL" }.to_string();
    let ok = auth != "FAIL" && !layers.iter().any(|l| l.1 == "FAIL");
    if !ok { auth = "FAIL".into(); }
    Out { ok, auth, anchored, layers, pack_sha3: if declared.is_empty() { None } else { Some(declared) } }
}

fn check_tip(count: i64, first: &str, last: &str, tip_path: &str, pub_hex: &str) -> Result<(), String> {
    let tip = parse_obj(&std::fs::read_to_string(tip_path).map_err(|e| format!("tip_unreadable: {e}"))?).map_err(|e| format!("tip_unreadable: {e}"))?;
    if gs(&tip, "kind") != Some(TIP_KIND) { return Err("tip_invalid: not a cryptovalid_tip/1 document".into()); }
    let n = gi(&tip, "entries").filter(|n| *n >= 0).ok_or("tip_invalid: bad fields")?;
    let (lid, th, ts, sig) = (gs(&tip, "ledger_id"), gs(&tip, "tip_sha256"), gs(&tip, "ts"), gs(&tip, "signature_hex"));
    let (Some(lid), Some(th), Some(ts), Some(sig)) = (lid, th, ts, sig) else { return Err("tip_invalid: bad fields".into()) };
    if !is_hex64(lid) || !is_hex64(th) || !is_instant(ts) { return Err("tip_invalid: bad fields".into()); }
    match tip.get("log_pubkey_hex") {   // "" = absent (cryptovalid profile); a non-string never equals the key
        None | Some(Json::Null) => {}
        Some(Json::Str(lk)) if lk.is_empty() || lk == pub_hex => {}
        Some(_) => return Err("tip_invalid: tip log key differs from the trusted log key".into()),
    }
    let payload = format!("{{\"entries\":{n},\"kind\":\"{TIP_KIND}\",\"ledger_id\":\"{lid}\",\"tip_sha256\":\"{th}\",\"ts\":\"{ts}\"}}");
    if !ed_ok(pub_hex, payload.as_bytes(), sig) { return Err("tip_invalid: tip signature invalid".into()); }
    if lid != first { return Err("tip_of_another_ledger".into()); }
    if count < n { return Err(format!("tail_truncated: file has {count} entries, the signed tip commits to {n}")); }
    if count > n { return Err(format!("unsealed_tail: file has {count} entries, the signed tip commits to {n}")); }
    if last != th { return Err("tail_rewritten".into()); }
    Ok(())
}

fn verify_sidecar(pack_path: &str, pack: &BTreeMap<String, Json>, declared: &str, trust: Option<&BTreeMap<String, Json>>) -> (String, String, bool) {
    let sp = format!("{pack_path}.sig.json");
    if !Path::new(&sp).exists() && std::fs::symlink_metadata(&sp).is_err() { return ("SKIP".into(), "pack not signed".into(), false); }   // SKIP only when there is NO sidecar
    let raw = match std::fs::read_to_string(&sp) { Ok(r) => r, Err(e) => return ("FAIL".into(), format!("unreadable: {e}"), false) };
    let side = match parse_obj(&raw) { Ok(o) => o, Err(e) => return ("FAIL".into(), format!("unreadable: {e}"), false) };
    let dg = sha3_of(pack, "pack_sha3");
    if declared != dg { return ("FAIL".into(), "content does not match pack_sha3 (modified after signing)".into(), false); }
    if gs(&side, "signed_pack_sha3") != Some(dg.as_str()) { return ("FAIL".into(), "pack changed after signature (digest differs from the signed one)".into(), false); }
    let pub_hex = gs(&side, "public_key_hex").unwrap_or("");
    let mut payload = BTreeMap::new();
    payload.insert("kind".to_string(), Json::Str("cra_pack_sig/1".into()));
    for k in ["signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex"] { payload.insert(k.to_string(), side.get(k).cloned().unwrap_or(Json::Null)); }
    payload.insert("alg".to_string(), side.get("alg").cloned().unwrap_or(Json::Str("Ed25519".into())));
    if !ed_ok(pub_hex, canonical(&Json::Object(payload)).as_bytes(), gs(&side, "signature_hex").unwrap_or("")) { return ("FAIL".into(), "signature invalid for the declared key".into(), false); }
    let fp = sha256::hex(&unhex(pub_hex).unwrap_or_default())[..16].to_string();
    match side.get("fingerprint") {
        None | Some(Json::Null) => {}
        Some(Json::Str(f)) if *f == fp => {}
        Some(_) => return ("FAIL".into(), "declared fingerprint does not match the signing key".into(), false),
    }
    if !matches!(side.get("signer_id"), Some(Json::Str(_))) { return ("FAIL".into(), "signer_id must be a string".into(), false); }
    if let Some(t) = trust {
        let sid = gs(&side, "signer_id").unwrap_or("");   // a non-string signer_id already failed above
        if let Some(Json::Str(exp)) = t.get(sid) { if !exp.is_empty() && exp == pub_hex { return ("PASS".into(), "trusted-signed".into(), true); } }
        return ("PASS".into(), "signed by a key NOT in the trust store".into(), false);
    }
    ("PASS".into(), "signed (signer not compared with a trust store)".into(), false)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut pack, mut ledger, mut trust_file, mut key): (Option<String>, Option<String>, Option<String>, Option<String>) = (None, None, None, None);
    let mut require_sources = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ledger" => { i += 1; ledger = args.get(i).cloned(); }
            "--trust-store" => { i += 1; trust_file = args.get(i).cloned(); }
            "--log-pubkey" => { i += 1; key = args.get(i).cloned(); }
            "--require-sources" => { require_sources = true; }
            a => pack = Some(a.to_string()),
        }
        i += 1;
    }
    let Some(pack) = pack else { eprintln!("usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]"); std::process::exit(2) };
    let trust = trust_file.map(|f| {
        let o = parse_obj(&std::fs::read_to_string(f).unwrap_or_default()).unwrap_or_else(|_| { eprintln!("trust store unreadable"); std::process::exit(2) });
        if !o.values().all(|v| matches!(v, Json::Str(_))) { eprintln!("trust store unreadable: values must be strings"); std::process::exit(2); }
        o
    });
    let out = verify(&pack, ledger.as_deref(), trust.as_ref(), key.as_deref(), require_sources);
    let layers: Vec<Json> = out.layers.iter().map(|l| { let mut m = BTreeMap::new(); m.insert("layer".into(), Json::Str(l.0.clone())); m.insert("status".into(), Json::Str(l.1.clone())); m.insert("detail".into(), Json::Str(l.2.clone())); Json::Object(m) }).collect();
    let mut m = BTreeMap::new();
    m.insert("ok".into(), Json::Bool(out.ok)); m.insert("authenticity".into(), Json::Str(out.auth.clone())); m.insert("anchored".into(), Json::Bool(out.anchored));
    m.insert("layers".into(), Json::Array(layers)); m.insert("pack_sha3".into(), out.pack_sha3.map(Json::Str).unwrap_or(Json::Null));
    println!("{}", canonical(&Json::Object(m)));
    std::process::exit(if out.ok { 0 } else { 1 });
}
