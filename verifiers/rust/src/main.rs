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

use std::io::Read;
use std::path::Path;

const PACK_KIND: &str = "cra_evidence_pack/1";
const SCOPE_MARK: &str = "NOT a conformity assessment";
const TIP_KIND: &str = "cryptovalid_tip/1";
const MAX_LINE_BYTES: usize = 64 << 20;
const MAX_SOURCE_BYTES: u64 = 256 << 20;
const MAX_DOC_BYTES: u64 = MAX_LINE_BYTES as u64;   // ONE bound for every JSON document read: a ledger line, the pack, the sidecar, the tip, the trust store
const FAULT_ENV: &str = "CRA_VERIFY_INJECT_FAULT";  // test hook: "1" panics inside the guarded verification (only ever an inconclusive FAIL)
#[cfg(target_os = "linux")]
const OPEN_FLAGS: i32 = 0o4000 | 0o400;   // O_NONBLOCK | O_NOCTTY (Linux, x86_64 and aarch64)
#[cfg(target_os = "macos")]
const OPEN_FLAGS: i32 = 0x0004 | 0x20000; // O_NONBLOCK | O_NOCTTY (Darwin)
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const OPEN_FLAGS: i32 = 0;

enum ReadErr { NotRegular, TooLarge(u64), Io(String) }
impl std::fmt::Display for ReadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ReadErr::NotRegular => write!(f, "not a regular file"), ReadErr::TooLarge(c) => write!(f, "larger than {c} bytes"), ReadErr::Io(e) => write!(f, "{e}") }
    }
}
/// Open WITHOUT blocking (a FIFO with no writer, a device) and keep the handle only if the OPEN descriptor is a regular
/// file (fstat): a FIFO must not hang the verifier, a symlink to /dev/zero must not exhaust its memory — same rule in the four.
fn open_regular(p: &str) -> Result<(std::fs::File, u64), ReadErr> {
    // refused BEFORE it is opened (opening a device can act on it); the fstat on the open handle closes the race
    if !std::fs::metadata(p).map_err(|e| ReadErr::Io(e.to_string()))?.is_file() { return Err(ReadErr::NotRegular); }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; o.custom_flags(OPEN_FLAGS); }
    let f = o.open(p).map_err(|e| ReadErr::Io(e.to_string()))?;
    let md = f.metadata().map_err(|e| ReadErr::Io(e.to_string()))?;
    if !md.is_file() { return Err(ReadErr::NotRegular); }
    Ok((f, md.len()))
}
/// The bytes of a regular file of at most `cap` bytes (refused on the fstat size, and again if more can be read).
fn read_regular(p: &str, cap: u64) -> Result<Vec<u8>, ReadErr> {
    let (f, len) = open_regular(p)?;
    if len > cap { return Err(ReadErr::TooLarge(cap)); }
    let mut buf = Vec::new();
    f.take(cap + 1).read_to_end(&mut buf).map_err(|e| ReadErr::Io(e.to_string()))?;
    if buf.len() as u64 > cap { return Err(ReadErr::TooLarge(cap)); }
    Ok(buf)
}
fn read_text(p: &str) -> Result<String, String> {
    let b = read_regular(p, MAX_DOC_BYTES).map_err(|e| e.to_string())?;
    String::from_utf8(b).map_err(|_| "stream did not contain valid UTF-8".to_string())
}
/// lstat ENOENT / ENOTDIR = absent; anything else at the path (FIFO, device, directory, dangling symlink) is PRESENT and must read as a regular file.
fn present(p: &str) -> bool {
    match std::fs::symlink_metadata(p) { Ok(_) => true, Err(e) => !(e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(20)) }
}
fn is_hex_n(h: &str, n: usize) -> bool { h.len() == n && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) }
/// One line's CONTENT (exactly one terminator excluded: \n, then at most one \r), read in bounded pieces; Err = above the bound.
fn bounded_line<R: std::io::BufRead>(r: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let (consumed, done) = {
            let avail = match r.fill_buf() { Ok(a) => a, Err(e) => return Err(format!("unreadable: {e}")) };
            if avail.is_empty() { (0, true) } else {
                match avail.iter().position(|&b| b == b'\n') {
                    Some(i) => { buf.extend_from_slice(&avail[..i]); (i + 1, true) }
                    None => { buf.extend_from_slice(avail); (avail.len(), false) }
                }
            }
        };
        r.consume(consumed);
        if buf.len() > MAX_LINE_BYTES + 1 { return Err(format!("line exceeds {MAX_LINE_BYTES} bytes")); }   // content + one possible \r
        if done {
            if consumed == 0 && buf.is_empty() { return Ok(None); }   // EOF
            if buf.last() == Some(&b'\r') { buf.pop(); }
            if buf.len() > MAX_LINE_BYTES { return Err(format!("line exceeds {MAX_LINE_BYTES} bytes")); }
            return Ok(Some(buf));
        }
    }
}
fn ledger_file_name_ok(v: &str) -> bool { !v.is_empty() && v != "." && v != ".." && !v.contains('/') && !v.contains('\\') && !v.contains('\0') }   // NUL: never a file name   // a stored generator document above this is refused unread   // cryptovalid profile: a longer JSONL line is a failure, never a silent truncation
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_KINDS: [&str; 5] = ["cra_sbom", "cra_vuln", "cra_srp_notice", "cra_longterm_seal", "cra_pack_anchor"];

struct Layer(String, String, String);
static PANIC_MSG: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

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
    if !is_hex64(pub_hex) || !is_hex_n(sig_hex, 128) { return false; }   // lower-case hex of exact length, as the profile writes it
    let (Some(p), Some(s)) = (unhex(pub_hex), unhex(sig_hex)) else { return false };
    let (Ok(pb), Ok(sb)) = (<[u8; 32]>::try_from(p.as_slice()), <[u8; 64]>::try_from(s.as_slice())) else { return false };
    if weak_ed25519(&pb) { return false; }
    let Ok(vk) = VerifyingKey::from_bytes(&pb) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sb)).is_ok()
}
// small-order / non-canonical Ed25519 keys: with the identity key R=identity, S=0 verifies on every message and OpenSSL accepts it (measured 25/09/2026; other small-order points: a share of messages); same list in the JS/Go/Rust verifiers
const WEAK_ED25519: [&str; 10] = ["0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"];
fn weak_ed25519(pk: &[u8; 32]) -> bool {
    let h: String = pk.iter().map(|b| format!("{:02x}", b)).collect();
    if WEAK_ED25519.contains(&h.as_str()) { return true; }
    if pk[31] & 0x7f != 0x7f || pk[0] < 0xed { return false; }
    pk[1..31].iter().all(|&b| b == 0xff)
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
    let shape = rest == "Z" || (rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) && rest[1..3].bytes().all(|c| c.is_ascii_digit()) && &rest[3..4] == ":" && rest[4..6].bytes().all(|c| c.is_ascii_digit()));
    if !shape { return false; }
    // an instant that EXISTS (26/09/2026: the shape alone let a signature dated 2026-02-30 or 25:61:61 verify in all
    // four verifiers): month, day of that month and year, hour, minute, second, offset
    let n = |r: std::ops::Range<usize>| b[r].iter().fold(0u32, |v, c| v * 10 + (c - b'0') as u32);
    let (y, mo, d) = (n(0..4), n(5..7), n(8..10));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > dim[(mo - 1) as usize] || n(11..13) > 23 || n(14..16) > 59 || n(17..19) > 59 {
        return false;
    }
    let rb = rest.as_bytes();
    rest == "Z" || (rb[1..3].iter().fold(0u32, |v, c| v * 10 + (c - b'0') as u32) <= 23 && rb[4..6].iter().fold(0u32, |v, c| v * 10 + (c - b'0') as u32) <= 59)
}

struct Out { ok: bool, assessed: bool, auth: String, anchored: bool, layers: Vec<Layer>, pack_sha3: Option<String> }

fn source_documents(lp: &str, entries: &[BTreeMap<String, Json>], require: bool) -> Layer {
    let mut wanted: Vec<String> = Vec::new();
    let mut malformed = 0usize;
    let is_hex64 = |h: &str| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    for e in entries {
        if let Some(Json::Object(d)) = e.get("data") {
            if gs(d, "kind") != Some("cra_sbom") { continue; }
            if let Some(Json::Object(src)) = d.get("source") {
                let external = matches!(gs(src, "format"), Some("cyclonedx-json") | Some("spdx-json") | Some("spdx-jsonld"));
                match src.get("sha256") {
                    None | Some(Json::Null) => { if external { malformed += 1; } }   // an ingested document is always recorded WITH its hash
                    Some(Json::Str(h)) if h.is_empty() => { if external { malformed += 1; } }
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
        match std::fs::symlink_metadata(&fp) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => { absent += 1; continue; }   // genuinely absent
            Err(e) => { bad.push(format!("{}… stored path unusable ({e})", &h[..16])); continue; }
            Ok(_) => {}
        }
        match read_regular(&fp, MAX_SOURCE_BYTES) {   // opened without blocking, judged on the open descriptor, bounded
            Ok(raw) => { let got = sha256::hex(&raw); if &got == h { present += 1; } else { bad.push(format!("{}… stored bytes hash to {}…", &h[..16], &got[..16])); } }
            Err(ReadErr::NotRegular) => bad.push(format!("{}… stored path is not a regular file", &h[..16])),   // something IS there: never "absent"
            Err(ReadErr::TooLarge(_)) => bad.push(format!("{}… stored file exceeds {MAX_SOURCE_BYTES} bytes", &h[..16])),
            Err(ReadErr::Io(_)) => bad.push(format!("{}… unreadable", &h[..16])),
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
    if std::env::var(FAULT_ENV).as_deref() == Ok("1") { panic!("injected internal error ({FAULT_ENV}=1)"); }
    let fail = |layer: &str, detail: String| Out { ok: false, assessed: true, auth: "FAIL".into(), anchored: false, layers: vec![Layer(layer.into(), "FAIL".into(), detail)], pack_sha3: None };
    let raw = match read_text(pack_path) { Ok(t) => t, Err(e) => return fail("pack-json", e) };
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
        None => if lf_bad { None } else { gs(&pack, "ledger_file").map(|lf| {
            let real = std::fs::canonicalize(pack_path).unwrap_or_else(|_| Path::new(pack_path).to_path_buf());   // the pack's REAL directory, the same in all four
            real.parent().unwrap_or(Path::new(".")).join(lf).to_string_lossy().to_string()
        }) },
    };
    let mut anchored = false;
    let required = ledger_path.is_some() || log_pub.is_some() || require_sources;
    if lf_bad {
        layers.push(Layer("ledger-chain".into(), "FAIL".into(), "ledger_file malformed: must be a plain file name (string, no path separators)".into()));
    } else if required && !lp.as_deref().map(present).unwrap_or(false) {
        layers.push(Layer("ledger-chain".into(), "FAIL".into(), "ledger explicitly required (ledger_path / log key / require_sources given) but not found".into()));
    } else if let Some(lp) = lp.filter(|p| present(p)) {
        let mut failures: Vec<String> = vec![];
        let mut entries: Vec<BTreeMap<String, Json>> = vec![];
        let (mut prev, mut n) = (GENESIS.to_string(), 0i64);
        let mut reader = match open_regular(&lp) { Ok((f, _)) => Some(std::io::BufReader::with_capacity(1 << 20, f)), Err(e) => { failures.push(format!("ledger unreadable: {e}")); None } };   // something is there: it must open as a regular file
        loop {   // streamed, bounded: a hostile line is never buffered whole (a line above the content bound stops the read)
            let Some(r) = reader.as_mut() else { break };
            let raw = match bounded_line(r) { Ok(Some(b)) => b, Ok(None) => break, Err(msg) => { failures.push(format!("entry {n}: {msg}")); break; } };
            let line = match std::str::from_utf8(&raw) { Ok(t) => t, Err(_) => { failures.push(format!("entry {n}: not UTF-8")); break; } };
            if line.trim_matches(|c| c == ' ' || c == '\t').is_empty() { continue; }   // blank = ASCII space/tab only (the bound was applied before)
            let e = match parse_obj(line) { Ok(o) => o, Err(err) => { failures.push(format!("entry {n}: unparsable: {err}")); break; } };
            if gi(&e, "idx") != Some(n) { failures.push(format!("entry {n}: idx not sequential")); }
            if gs(&e, "prev_hash") != Some(prev.as_str()) { failures.push(format!("entry {n}: prev_hash does not link")); }
            let sh = gs(&e, "self_hash").unwrap_or("").to_string();
            if sha256_of(&e, "self_hash") != sh { failures.push(format!("entry {n}: self_hash mismatch")); }
            if !sh.is_empty() { prev = sh; }
            entries.push(e);
            n += 1;
        }
        if n == 0 && reader.is_some() { failures.push("empty_ledger: zero entries, nothing to verify".into()); }
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
                if !present(&tip_path) { layers.push(Layer("signed-tip".into(), "FAIL".into(), "trusted log key given but no tip file next to the ledger".into())); }
                else { match check_tip(entries.len() as i64, &first, &last, &tip_path, pk) {
                    Ok(()) => layers.push(Layer("signed-tip".into(), "PASS".into(), "tip verified: no tail truncation".into())),
                    Err(why) => layers.push(Layer("signed-tip".into(), "FAIL".into(), why)),
                } }
            } else if present(&tip_path) { layers.push(Layer("signed-tip".into(), "SKIP".into(), "tip present but NOT checked: pass the trusted log key (tail not sealed: truncation, rewrite or additions undetected)".into())); }
            else { layers.push(Layer("signed-tip".into(), "SKIP".into(), "no tip: tail not sealed — truncation, rewrite or additions undetectable offline".into())); }
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
    Out { ok, assessed: true, auth, anchored, layers, pack_sha3: if declared.is_empty() { None } else { Some(declared) } }
}

fn check_tip(count: i64, first: &str, last: &str, tip_path: &str, pub_hex: &str) -> Result<(), String> {
    let tip = parse_obj(&read_text(tip_path).map_err(|e| format!("tip_unreadable: {e}"))?).map_err(|e| format!("tip_unreadable: {e}"))?;
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
    if let Err(e) = std::fs::symlink_metadata(&sp) {   // one rule in the four: ENOENT/ENOTDIR = no sidecar; any other lstat error is never "not signed"
        if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(20) { return ("SKIP".into(), "pack not signed".into(), false); }
        return ("FAIL".into(), format!("sidecar path unusable ({e})"), false);
    }
    let raw = match read_text(&sp) { Ok(r) => r, Err(e) => return ("FAIL".into(), format!("unreadable: {e}"), false) };
    let side = match parse_obj(&raw) { Ok(o) => o, Err(e) => return ("FAIL".into(), format!("unreadable: {e}"), false) };
    let dg = sha3_of(pack, "pack_sha3");
    if declared != dg { return ("FAIL".into(), "content does not match pack_sha3 (modified after signing)".into(), false); }
    if gs(&side, "signed_pack_sha3") != Some(dg.as_str()) { return ("FAIL".into(), "pack changed after signature (digest differs from the signed one)".into(), false); }
    for k in ["signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "signature_hex"] {   // a missing field is never signed "as null"
        if !matches!(side.get(k), Some(Json::Str(v)) if !v.is_empty()) { return ("FAIL".into(), format!("sidecar field missing or not a string: {k}"), false); }
    }
    if !is_instant(gs(&side, "signed_utc").unwrap_or("")) { return ("FAIL".into(), "sidecar signed_utc is not an instant".into(), false); }
    if let Some(a) = side.get("alg") { if !matches!(a, Json::Str(_)) { return ("FAIL".into(), "sidecar alg is not a string".into(), false); } }
    let pub_hex = gs(&side, "public_key_hex").unwrap_or("");
    let mut payload = BTreeMap::new();
    payload.insert("kind".to_string(), Json::Str("cra_pack_sig/1".into()));
    for k in ["signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex"] { payload.insert(k.to_string(), side.get(k).cloned().unwrap_or(Json::Null)); }
    payload.insert("alg".to_string(), side.get("alg").cloned().unwrap_or(Json::Str("Ed25519".into())));
    if !ed_ok(pub_hex, canonical(&Json::Object(payload)).as_bytes(), gs(&side, "signature_hex").unwrap_or("")) { return ("FAIL".into(), "signature invalid for the declared key".into(), false); }
    let fp = sha256::hex(&unhex(pub_hex).unwrap_or_default())[..16].to_string();
    match side.get("fingerprint") {
        None => {}   // absent = not declared; present (null included) must be the key's fingerprint
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

fn flag_value(args: &[String], i: usize, flag: &str) -> String {   // a flag without a value, or with "", is a usage error — never a silent default
    match args.get(i) { Some(v) if !v.is_empty() && !v.starts_with('-') => v.clone(), _ => { eprintln!("usage: {flag} needs a value"); std::process::exit(2) } }
}

fn main() {
    let mut args: Vec<String> = Vec::new();   // --flag=value is the same as --flag value
    for a in std::env::args().skip(1) {
        match ["--ledger", "--trust-store", "--log-pubkey"].iter().find(|f| a.starts_with(&format!("{f}="))) {
            Some(f) => { args.push(f.to_string()); args.push(a[f.len() + 1..].to_string()); }
            None => args.push(a),
        }
    }
    let (mut pack, mut ledger, mut trust_file, mut key): (Option<String>, Option<String>, Option<String>, Option<String>) = (None, None, None, None);
    let mut require_sources = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ledger" => { i += 1; ledger = Some(flag_value(&args, i, "--ledger")); }
            "--trust-store" => { i += 1; trust_file = Some(flag_value(&args, i, "--trust-store")); }
            "--log-pubkey" => { i += 1; let k = flag_value(&args, i, "--log-pubkey"); if !is_hex64(&k) { eprintln!("usage: --log-pubkey must be 64 lower-case hex characters"); std::process::exit(2); } key = Some(k); }
            "--require-sources" => { require_sources = true; }
            a => { if a.starts_with('-') || pack.is_some() { eprintln!("usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]"); std::process::exit(2); } pack = Some(a.to_string()); }
        }
        i += 1;
    }
    let Some(pack) = pack else { eprintln!("usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]"); std::process::exit(2) };
    let trust = trust_file.map(|f| {
        let text = read_text(&f).unwrap_or_else(|e| { eprintln!("trust store unreadable: {e}"); std::process::exit(2) });   // a regular file within the bound: a FIFO / device is unreadable, never a hang
        let o = parse_obj(&text).unwrap_or_else(|_| { eprintln!("trust store unreadable"); std::process::exit(2) });
        if !o.values().all(|v| matches!(v, Json::Str(_))) { eprintln!("trust store unreadable: values must be strings"); std::process::exit(2); }
        o
    });
    // a panic inside verify is the VERIFIER's defect, not a finding about the pack: fail-closed (ok false, FAIL) but
    // assessed=false, the same layer and shape as the Python reference (the hook keeps the message, prints nothing)
    std::panic::set_hook(Box::new(|info| {
        let p = info.payload();
        let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".into());
        if let Ok(mut m) = PANIC_MSG.lock() { *m = msg; }
    }));
    let out = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify(&pack, ledger.as_deref(), trust.as_ref(), key.as_deref(), require_sources))) {
        Ok(o) => o,
        Err(_) => {
            let msg: String = PANIC_MSG.lock().map(|m| m.clone()).unwrap_or_default().chars().take(160).collect();
            Out { ok: false, assessed: false, auth: "FAIL".into(), anchored: false, layers: vec![Layer("verifier-exception".into(), "FAIL".into(), format!("panic: {msg}"))], pack_sha3: None }
        }
    };
    let layers: Vec<Json> = out.layers.iter().map(|l| { let mut m = BTreeMap::new(); m.insert("layer".into(), Json::Str(l.0.clone())); m.insert("status".into(), Json::Str(l.1.clone())); m.insert("detail".into(), Json::Str(l.2.clone())); Json::Object(m) }).collect();
    let mut m = BTreeMap::new();
    m.insert("ok".into(), Json::Bool(out.ok)); m.insert("assessed".into(), Json::Bool(out.assessed)); m.insert("authenticity".into(), Json::Str(out.auth.clone())); m.insert("anchored".into(), Json::Bool(out.anchored));
    m.insert("layers".into(), Json::Array(layers)); m.insert("pack_sha3".into(), out.pack_sha3.map(Json::Str).unwrap_or(Json::Null));
    println!("{}", canonical(&Json::Object(m)));
    std::process::exit(if out.ok { 0 } else { 1 });
}
