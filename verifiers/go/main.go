// SPDX-License-Identifier: AGPL-3.0-or-later
// cra-verify — independent Go verifier of a cra-evidence pack (standard library only: crypto/sha256, crypto/sha3,
// crypto/ed25519). Same layers and authenticity verdict as cra_evidence/verify_pack.py; canonical.go/prescan.go are
// the strict parser + canonical encoder of cryptovalid's Go verifier (same profile, same author).
// Usage: cra-verify <pack.json> [--ledger path] [--trust-store file.json] [--log-pubkey hex] [--require-sources]; exit 0 only if ok.
// source-documents layer: every cra_sbom record with source.sha256 names <ledger>.sources/<sha256>.json, whose bytes must
// hash (SHA-256) to that value when present (mismatch = FAIL; absence = SKIP, or FAIL with --require-sources).
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	packKind  = "cra_evidence_pack/1"
	scopeMark = "NOT a conformity assessment"
	tipKind   = "cryptovalid_tip/1"
	genesis   = "0000000000000000000000000000000000000000000000000000000000000000"
)

var recordKinds = map[string]bool{"cra_sbom": true, "cra_vuln": true, "cra_srp_notice": true, "cra_longterm_seal": true, "cra_pack_anchor": true}
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var instantRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)

type layer struct {
	Layer, Status, Detail string
}
type result struct {
	Ok           bool    `json:"ok"`
	Assessed     bool    `json:"assessed"` // false only when the verifier itself failed (verifier-exception): inconclusive, not adverse
	Authenticity string  `json:"authenticity"`
	Anchored     bool    `json:"anchored"`
	Layers       []layer `json:"layers"`
	PackSHA3     any     `json:"pack_sha3"`
}

func (l layer) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"layer": l.Layer, "status": l.Status, "detail": l.Detail})
}

func getS(o *Object, k string) (string, bool) {
	v, ok := o.Vals[k].(string)
	return v, ok
}
func getInt(o *Object, k string) (int, bool) {
	n, ok := o.Vals[k].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0, false
	}
	return int(i), true
}
func without(o *Object, k string) *Object {
	cp := &Object{Vals: map[string]any{}}
	for _, key := range o.Keys {
		if key != k {
			cp.Keys = append(cp.Keys, key)
			cp.Vals[key] = o.Vals[key]
		}
	}
	return cp
}
func digest(algo string, o *Object, drop string) (string, error) {
	b, err := Canonical(without(o, drop))
	if err != nil {
		return "", err
	}
	return Hash(algo, b)
}
func parseObject(b []byte) (*Object, error) {
	v, err := Parse(b)
	if err != nil {
		return nil, err
	}
	o, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return o, nil
}

var hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)

func edOK(pubHex string, msg []byte, sigHex string) bool {
	if !hex64.MatchString(pubHex) || !hex128.MatchString(sigHex) { // lower-case hex of exact length, as the profile writes it
		return false
	}
	pub, e1 := hex.DecodeString(pubHex)
	sig, e2 := hex.DecodeString(sigHex)
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if weakEd25519(pub) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// small-order / non-canonical Ed25519 keys: R=identity, S=0 verifies on every message and OpenSSL accepts it (measured 25/09/2026); same list in the JS/Go/Rust verifiers
var weakEd25519Keys = map[string]bool{"0100000000000000000000000000000000000000000000000000000000000000": true, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true, "0000000000000000000000000000000000000000000000000000000000000000": true, "0000000000000000000000000000000000000000000000000000000000000080": true, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": true, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": true, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": true, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": true, "0100000000000000000000000000000000000000000000000000000000000080": true, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": true}

func weakEd25519(pk []byte) bool {
	if len(pk) != 32 || weakEd25519Keys[hex.EncodeToString(pk)] {
		return true
	}
	if pk[31]&0x7f != 0x7f || pk[0] < 0xed {
		return false
	}
	for i := 1; i < 31; i++ {
		if pk[i] != 0xff {
			return false
		}
	}
	return true
}
func short(s any, n int) string {
	t := fmt.Sprint(s)
	if len(t) > n {
		return t[:n] + "…"
	}
	return t
}

func verifyPack(packPath, ledgerPath string, trust map[string]string, haveTrust bool, logPub string, requireSources bool) (r result) {
	defer func() {
		if e := recover(); e != nil {
			// a panic is the VERIFIER's defect, not a finding about the pack: fail-closed (ok false, FAIL) but assessed=false,
			// the same layer and shape as the Python reference — a tool fault must never read as a tampered pack
			r = result{Ok: false, Assessed: false, Authenticity: "FAIL", Layers: []layer{{"verifier-exception", "FAIL", short("panic: "+fmt.Sprint(e), 160)}}}
			return
		}
		r.Assessed = true
	}()
	if os.Getenv(faultEnv) == "1" {
		panic("injected internal error (" + faultEnv + "=1)")
	}
	var layers []layer
	raw, err := readRegular(packPath, maxDocBytes)
	if err != nil {
		return result{Authenticity: "FAIL", Layers: []layer{{"pack-json", "FAIL", err.Error()}}}
	}
	pack, err := parseObject(raw)
	if err != nil {
		return result{Authenticity: "FAIL", Layers: []layer{{"pack-json", "FAIL", err.Error()}}}
	}
	layers = append(layers, layer{"pack-json", "PASS", ""})
	kind, _ := getS(pack, "kind")
	layers = append(layers, layer{"pack-kind", ifs(kind == packKind, "PASS", "FAIL"), kind})
	scope, _ := getS(pack, "honest_scope") // getS: a non-string honest_scope is "" → FAIL (a list containing the mark is not a declaration)
	layers = append(layers, layer{"honest-scope", ifs(strings.Contains(scope, scopeMark), "PASS", "FAIL"), ifs(strings.Contains(scope, scopeMark), "declared limits present", "missing the declared limit")})
	declared, _ := getS(pack, "pack_sha3")
	computed, err := digest("sha3_256", pack, "pack_sha3")
	if err != nil {
		layers = append(layers, layer{"pack-sha3", "FAIL", "pack not canonicalisable: " + err.Error()})
	} else {
		layers = append(layers, layer{"pack-sha3", ifs(declared == computed, "PASS", "FAIL"), "declared " + short(declared, 16) + " computed " + short(computed, 16)})
	}
	selfOK := false
	if pv, ok := pack.Vals["verification"].(*Object); ok {
		a, _ := pv.Vals["chain_ok"].(bool)
		b, _ := pv.Vals["record_digests_bound"].(bool)
		selfOK = a && b
	}
	layers = append(layers, layer{"pack-self-verification", ifs(selfOK, "PASS", "FAIL"), fmt.Sprintf("snapshot ok=%v", selfOK)})
	lp := ledgerPath
	lfBad := false
	if v, has := pack.Vals["ledger_file"]; has && v != nil {
		lf, isStr := v.(string)
		if !isStr || !ledgerFileNameOK(lf) {
			lfBad = true // a non-string, an empty string or anything with a path separator: malformed pack field, never a path
		} else if lp == "" {
			realPack := packPath
			if r, e := filepath.EvalSymlinks(packPath); e == nil {
				realPack = r // the pack's REAL directory (symlinks resolved), the same in all four
			}
			lp = filepath.Join(filepath.Dir(realPack), lf)
		}
	}
	anchored := false
	if lfBad {
		layers = append(layers, layer{"ledger-chain", "FAIL", "ledger_file malformed: must be a plain file name (string, no path separators)"})
	} else if (ledgerPath != "" || logPub != "" || requireSources) && !(lp != "" && present(lp)) {
		layers = append(layers, layer{"ledger-chain", "FAIL", "ledger explicitly required (ledger_path / log key / require_sources given) but not found"})
	} else if lp != "" && present(lp) {
		var entries []*Object
		var failures []string
		prev, n := genesis, 0
		var src io.Reader = strings.NewReader("") // an unreadable ledger is an empty stream plus a failure
		f, _, oerr := openRegular(lp)             // something is there: it must open as a regular file (never "absent", never a hang)
		if oerr != nil {
			failures = append(failures, "ledger unreadable: "+oerr.Error())
		} else {
			src = f
		}
		sc := bufio.NewScanner(src)
		sc.Buffer(make([]byte, 1<<20), maxLineBytes+2) // content up to the bound plus "\r\n": exactly 64 MiB of content is accepted
		for sc.Scan() {
			line := sc.Bytes()
			// bufio.ScanLines already drops exactly one trailing \r (dropCR): no second strip here — a run of \r is content
			if len(line) > maxLineBytes { // bound BEFORE the blank test
				failures = append(failures, fmt.Sprintf("entry %d: line exceeds %d bytes", n, maxLineBytes))
				break
			}
			if len(strings.Trim(string(line), " \t")) == 0 { // blank = ASCII space/tab only (Unicode spaces are an unparsable line)
				continue
			}
			e, err := parseObject(line)
			if err != nil {
				failures = append(failures, fmt.Sprintf("entry %d: unparsable: %v", n, err))
				break
			}
			if idx, ok := getInt(e, "idx"); !ok || idx != n {
				failures = append(failures, fmt.Sprintf("entry %d: idx not sequential", n))
			}
			if ph, _ := getS(e, "prev_hash"); ph != prev {
				failures = append(failures, fmt.Sprintf("entry %d: prev_hash does not link", n))
			}
			sh, _ := getS(e, "self_hash")
			if h, err := digest("sha256", e, "self_hash"); err != nil || h != sh {
				failures = append(failures, fmt.Sprintf("entry %d: self_hash mismatch", n))
			}
			if sh != "" {
				prev = sh
			}
			entries = append(entries, e)
			n++
		}
		if err := sc.Err(); err != nil { // a line above 64 MiB (cryptovalid MaxLineBytes) or an I/O error ends the scan: the prefix is NOT the ledger
			failures = append(failures, fmt.Sprintf("entry %d: line exceeds 64 MiB or unreadable: %v", n, err))
		}
		if f != nil {
			f.Close()
		}
		if n == 0 && oerr == nil {
			failures = append(failures, "empty_ledger: zero entries, nothing to verify")
		}
		if len(failures) > 0 {
			if len(failures) > 3 {
				failures = failures[:3]
			}
			layers = append(layers, layer{"ledger-chain", "FAIL", strings.Join(failures, "; ")})
		} else {
			bound, anchorIdx := true, -1
			for _, e := range entries {
				d, ok := e.Vals["data"].(*Object)
				if !ok {
					continue
				}
				k, _ := getS(d, "kind")
				if !recordKinds[k] {
					continue
				}
				rs, _ := getS(d, "record_sha3")
				if h, err := digest("sha3_256", d, "record_sha3"); err != nil || h != rs {
					bound = false
				}
				if ap, _ := getS(d, "anchored_pack_sha3"); k == "cra_pack_anchor" && hex64.MatchString(declared) && ap == declared {
					anchorIdx, _ = getInt(e, "idx")
				}
			}
			if !bound {
				layers = append(layers, layer{"ledger-chain", "FAIL", "a record's record_sha3 does not match its content"})
			} else if anchorIdx < 0 {
				layers = append(layers, layer{"ledger-chain", "FAIL", "chain valid but THIS pack is not anchored"})
			} else {
				anchored = true
				layers = append(layers, layer{"ledger-chain", "PASS", fmt.Sprintf("%d entries, records bound, pack anchored at idx %d", n, anchorIdx)})
			}
			ne, okN := getInt(pack, "ledger_entries")
			last, _ := getS(pack, "ledger_last_self_hash")
			okState := okN && ne > 0 && ne <= len(entries)
			if okState {
				sh, _ := getS(entries[ne-1], "self_hash")
				okState = sh == last && (anchorIdx < 0 || anchorIdx >= ne)
			}
			layers = append(layers, layer{"pack-ledger-state", ifs(okState, "PASS", "FAIL"), fmt.Sprintf("declared entries=%v; anchor idx=%d", pack.Vals["ledger_entries"], anchorIdx)})
			layers = append(layers, sourceDocuments(lp, entries, requireSources))
			tipPath := lp + ".tip.json"
			first, _ := getS(entries[0], "self_hash")
			lastHash, _ := getS(entries[len(entries)-1], "self_hash")
			if logPub != "" {
				if !present(tipPath) {
					layers = append(layers, layer{"signed-tip", "FAIL", "trusted log key given but no tip file next to the ledger"})
				} else {
					ok, why := checkTip(len(entries), first, lastHash, tipPath, logPub)
					layers = append(layers, layer{"signed-tip", ifs(ok, "PASS", "FAIL"), ifs(ok, "tip verified: no tail truncation", why)})
				}
			} else if present(tipPath) {
				layers = append(layers, layer{"signed-tip", "SKIP", "tip present but NOT checked: pass the trusted log key (tail not sealed: truncation, rewrite or additions undetected)"})
			} else {
				layers = append(layers, layer{"signed-tip", "SKIP", "no tip: tail not sealed — truncation, rewrite or additions undetectable offline"})
			}
		}
	} else {
		layers = append(layers, layer{"ledger-chain", "SKIP", "ledger not next to the pack (honest: integrity of the chain not checked)"})
	}
	sigStatus, sigDetail, trusted := verifySidecar(packPath, pack, declared, trust, haveTrust)
	layers = append(layers, layer{"producer-signature", sigStatus, sigDetail})
	var auth string
	switch {
	case sigStatus == "FAIL":
		auth = "FAIL"
	case haveTrust && sigStatus == "SKIP":
		auth = "FAIL"
		layers = append(layers, layer{"trusted-signer", "FAIL", "a trust store was required but the pack is not signed"})
	case sigStatus == "PASS" && haveTrust && !trusted:
		auth = "FAIL"
		layers = append(layers, layer{"trusted-signer", "FAIL", "valid signature but signer not in the trust store"})
	case sigStatus == "PASS" && trusted:
		auth = "trusted-signed"
	case sigStatus == "PASS":
		auth = "signed"
	case anchored:
		auth = "anchored"
	default:
		auth = "FAIL"
	}
	ok := auth != "FAIL"
	for _, l := range layers {
		if l.Status == "FAIL" {
			ok = false
		}
	}
	if !ok {
		auth = "FAIL"
	}
	var ps any
	if declared != "" {
		ps = declared
	}
	return result{Ok: ok, Authenticity: auth, Anchored: anchored, Layers: layers, PackSHA3: ps}
}

func checkTip(count int, first, last, tipPath, pubHex string) (bool, string) {
	raw, err := readRegular(tipPath, maxDocBytes)
	if err != nil {
		return false, "tip_unreadable: " + err.Error()
	}
	tip, err := parseObject(raw)
	if err != nil {
		return false, "tip_unreadable: " + err.Error()
	}
	if k, _ := getS(tip, "kind"); k != tipKind {
		return false, "tip_invalid: not a cryptovalid_tip/1 document"
	}
	n, okN := getInt(tip, "entries")
	lid, ok1 := getS(tip, "ledger_id")
	th, ok2 := getS(tip, "tip_sha256")
	ts, ok3 := getS(tip, "ts")
	sig, ok4 := getS(tip, "signature_hex")
	if !okN || n < 0 || !ok1 || !ok2 || !ok3 || !ok4 || !hex64.MatchString(lid) || !hex64.MatchString(th) || !instantRe.MatchString(ts) {
		return false, "tip_invalid: bad fields"
	}
	if v, has := tip.Vals["log_pubkey_hex"]; has && v != nil { // "" = absent (cryptovalid profile); a non-string never equals the key
		if lk, ok := v.(string); !(ok && (lk == "" || lk == pubHex)) {
			return false, "tip_invalid: tip log key differs from the trusted log key"
		}
	}
	payload := []byte(fmt.Sprintf(`{"entries":%d,"kind":"%s","ledger_id":"%s","tip_sha256":"%s","ts":"%s"}`, n, tipKind, lid, th, ts))
	if !edOK(pubHex, payload, sig) {
		return false, "tip_invalid: tip signature invalid"
	}
	if lid != first {
		return false, "tip_of_another_ledger"
	}
	if count < n {
		return false, fmt.Sprintf("tail_truncated: file has %d entries, the signed tip commits to %d", count, n)
	}
	if count > n {
		return false, fmt.Sprintf("unsealed_tail: file has %d entries, the signed tip commits to %d", count, n)
	}
	if last != th {
		return false, "tail_rewritten"
	}
	return true, ""
}

func verifySidecar(packPath string, pack *Object, declared string, trust map[string]string, haveTrust bool) (string, string, bool) {
	sp := packPath + ".sig.json"
	if _, err := os.Lstat(sp); err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			return "SKIP", "pack not signed", false // one rule in the four: ENOENT/ENOTDIR = no sidecar
		}
		return "FAIL", "sidecar path unusable: " + err.Error(), false // any other lstat error (ENAMETOOLONG, EACCES…) is never "not signed"
	}
	raw, err := readRegular(sp, maxDocBytes)
	if err != nil {
		return "FAIL", "unreadable: " + err.Error(), false
	}
	side, err := parseObject(raw)
	if err != nil {
		return "FAIL", "unreadable: " + err.Error(), false
	}
	dg, err := digest("sha3_256", pack, "pack_sha3")
	if err != nil {
		return "FAIL", "pack not canonicalisable", false
	}
	if declared != dg {
		return "FAIL", "content does not match pack_sha3 (modified after signing)", false
	}
	if s, _ := getS(side, "signed_pack_sha3"); s != dg {
		return "FAIL", "pack changed after signature (digest differs from the signed one)", false
	}
	for _, k := range []string{"signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "signature_hex"} {
		if v, ok := getS(side, k); !ok || v == "" { // the signed fields must exist as strings: a missing field is never signed "as null"
			return "FAIL", "sidecar field missing or not a string: " + k, false
		}
	}
	if su, _ := getS(side, "signed_utc"); !instantRe.MatchString(su) {
		return "FAIL", "sidecar signed_utc is not an instant", false
	}
	pub, _ := getS(side, "public_key_hex")
	sigHex, _ := getS(side, "signature_hex")
	alg, okAlg := side.Vals["alg"]
	if !okAlg {
		alg = "Ed25519"
	} else if _, isStr := alg.(string); !isStr {
		return "FAIL", "sidecar alg is not a string", false
	}
	payloadObj := &Object{Keys: []string{"kind", "signed_pack_sha3", "signer_id", "signed_utc", "public_key_hex", "alg"},
		Vals: map[string]any{"kind": "cra_pack_sig/1", "signed_pack_sha3": side.Vals["signed_pack_sha3"], "signer_id": side.Vals["signer_id"],
			"signed_utc": side.Vals["signed_utc"], "public_key_hex": side.Vals["public_key_hex"], "alg": alg}}
	payload, err := Canonical(payloadObj)
	if err != nil || !edOK(pub, payload, sigHex) {
		return "FAIL", "signature invalid for the declared key", false
	}
	pb, _ := hex.DecodeString(pub)
	fp := sha256.Sum256(pb)
	fpHex := hex.EncodeToString(fp[:])[:16]
	if f, ok := side.Vals["fingerprint"]; ok && f != fpHex { // absent = not declared; present (null included) must be the key's fingerprint
		return "FAIL", "declared fingerprint does not match the signing key", false
	}
	if _, isStr := side.Vals["signer_id"].(string); !isStr {
		return "FAIL", "signer_id must be a string", false
	}
	if haveTrust {
		sid, _ := getS(side, "signer_id")
		exp, ok := trust[sid]
		if ok && exp != "" && exp == pub {
			return "PASS", "trusted-signed", true
		}
		return "PASS", "signed by a key NOT in the trust store", false
	}
	return "PASS", "signed (signer not compared with a trust store)", false
}

func ifs(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func ledgerFileNameOK(v string) bool {
	return v != "" && v != "." && v != ".." && !strings.ContainsAny(v, "/\\\x00") // NUL: never a file name
}

const maxLineBytes = 64 << 20              // cryptovalid MaxLineBytes: content of one JSONL line, terminator excluded
const maxDocBytes = maxLineBytes           // ONE bound for every JSON document read: a ledger line, the pack, the sidecar, the tip, the trust store
const maxSourceBytes = 256 << 20           // a stored generator document above this is refused unread
const faultEnv = "CRA_VERIFY_INJECT_FAULT" // test hook: "1" panics inside the guarded verification (only ever an inconclusive FAIL)

var errNotRegular = errors.New("not a regular file")

type tooLarge struct{ cap int64 }

func (e tooLarge) Error() string { return fmt.Sprintf("larger than %d bytes", e.cap) }

// openRegular opens WITHOUT blocking (a FIFO with no writer, a device) and keeps the descriptor only if it is a regular
// file, decided on the open descriptor (fstat): a FIFO must not hang the verifier, a symlink to /dev/zero must not
// exhaust its memory — the same rule in the four verifiers.
func openRegular(p string) (*os.File, os.FileInfo, error) {
	if pre, err := os.Stat(p); err != nil { // refused BEFORE it is opened (opening a device can act on it); the fstat below closes the race
		return nil, nil, err
	} else if !pre.Mode().IsRegular() {
		return nil, nil, errNotRegular
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, errNotRegular
	}
	return f, st, nil
}

// readRegular: the bytes of a regular file of at most max bytes (refused on the fstat size, and again if more can be read).
func readRegular(p string, max int64) ([]byte, error) {
	f, st, err := openRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > max {
		return nil, tooLarge{max}
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, tooLarge{max}
	}
	return b, nil
}

// present: lstat ENOENT / ENOTDIR = absent; anything else at the path (FIFO, device, directory, dangling symlink) is
// present and must then read as a regular file or be a FAIL — never a silent "absent".
func present(p string) bool {
	_, err := os.Lstat(p)
	return err == nil || !(os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR))
}

// sourceDocuments: the SBOM source documents recorded by hash must, when present next to the ledger, hash to it.
func sourceDocuments(lp string, entries []*Object, require bool) layer {
	wanted := map[string]bool{}
	malformed := 0
	for _, e := range entries {
		d, ok := e.Vals["data"].(*Object)
		if !ok {
			continue
		}
		if k, _ := getS(d, "kind"); k != "cra_sbom" {
			continue
		}
		src, ok := d.Vals["source"].(*Object)
		if !ok {
			continue
		}
		v, has := src.Vals["sha256"]
		h, isStr := v.(string)
		if !has || v == nil || (isStr && h == "") {
			if f, _ := getS(src, "format"); f == "cyclonedx-json" || f == "spdx-json" || f == "spdx-jsonld" {
				malformed++ // an ingested document is always recorded WITH its hash: a record without it is malformed
			}
			continue // otherwise absent / null / empty: no hash recorded (installed floor)
		}
		if !isStr || !hex64.MatchString(h) {
			malformed++ // present but not a SHA-256: a FAIL, never a path
			continue
		}
		wanted[h] = true
	}
	if len(wanted) == 0 && malformed == 0 {
		return layer{"source-documents", "SKIP", "no SBOM source document recorded by hash"}
	}
	keys := make([]string, 0, len(wanted))
	for h := range wanted {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	present, absent, bad := 0, 0, []string{}
	if malformed > 0 {
		bad = append(bad, fmt.Sprintf("%d record(s) with a malformed source hash", malformed))
	}
	for _, h := range keys {
		fp := lp + ".sources/" + h + ".json" // concatenation, never filepath.Join (Clean would resolve ".." lexically before a symlink)
		if _, e := os.Lstat(fp); e != nil {
			if os.IsNotExist(e) {
				absent++ // genuinely absent (hash-only evidence)
				continue
			}
			bad = append(bad, h[:16]+"… stored path unusable: "+e.Error())
			continue
		}
		raw, err := readRegular(fp, maxSourceBytes) // opened without blocking, judged on the open descriptor, bounded
		var tl tooLarge
		if errors.Is(err, errNotRegular) { // something IS there but it is not a regular file: never "absent"
			bad = append(bad, h[:16]+"… stored path is not a regular file")
			continue
		} else if errors.As(err, &tl) {
			bad = append(bad, fmt.Sprintf("%s… stored file exceeds %d bytes", h[:16], maxSourceBytes))
			continue
		} else if err != nil {
			bad = append(bad, h[:16]+"… unreadable")
			continue
		}
		got := hex.EncodeToString(func() []byte { s := sha256.Sum256(raw); return s[:] }())
		if got == h {
			present++
		} else {
			bad = append(bad, fmt.Sprintf("%s… stored bytes hash to %s…", h[:16], got[:16]))
		}
	}
	if len(bad) > 0 {
		total := len(bad)
		if len(bad) > 3 {
			bad = bad[:3]
		}
		return layer{"source-documents", "FAIL", fmt.Sprintf("%d source document(s) do not match their recorded SHA-256: %s", total, strings.Join(bad, "; "))}
	}
	if absent > 0 {
		return layer{"source-documents", ifs(require, "FAIL", "SKIP"), fmt.Sprintf("%d of %d source document(s) present and verified; %d recorded by hash only%s", present, len(wanted), absent, ifs(require, " (required)", ""))}
	}
	return layer{"source-documents", "PASS", fmt.Sprintf("%d source document(s) present, bytes hash to the recorded SHA-256", present)}
}

func main() {
	var pack, ledger, trustFile, key string
	requireSources := false
	args := os.Args[1:]
	next := func(i int) string { // a flag without its value (or whose "value" is a flag) is a usage error, never a panic
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			fmt.Fprintln(os.Stderr, "usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]")
			os.Exit(2)
		}
		return args[i+1]
	}
	for i := 0; i < len(args); i++ {
		for _, f := range []string{"--ledger", "--trust-store", "--log-pubkey"} { // --flag=value is the same as --flag value
			if strings.HasPrefix(args[i], f+"=") {
				args = append(args[:i], append([]string{f, strings.TrimPrefix(args[i], f+"=")}, args[i+1:]...)...)
				break
			}
		}
		switch args[i] {
		case "--ledger":
			ledger = next(i)
			if ledger == "" {
				fmt.Fprintln(os.Stderr, "usage: --ledger needs a path (empty string given)")
				os.Exit(2)
			}
			i++
		case "--trust-store":
			trustFile = next(i)
			if trustFile == "" {
				fmt.Fprintln(os.Stderr, "usage: --trust-store needs a path (empty string given)")
				os.Exit(2)
			}
			i++
		case "--log-pubkey":
			key = next(i)
			if !hex64.MatchString(key) {
				fmt.Fprintln(os.Stderr, "usage: --log-pubkey must be 64 lower-case hex characters")
				os.Exit(2)
			}
			i++
		case "--require-sources":
			requireSources = true
		default:
			if strings.HasPrefix(args[i], "-") || pack != "" { // an unknown flag, a --flag=value form or a second positional is never silently "the pack"
				fmt.Fprintln(os.Stderr, "usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]")
				os.Exit(2)
			}
			pack = args[i]
		}
	}
	if pack == "" {
		fmt.Fprintln(os.Stderr, "usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex] [--require-sources]")
		os.Exit(2)
	}
	trust := map[string]string{}
	haveTrust := false
	if trustFile != "" {
		raw, err := readRegular(trustFile, maxDocBytes) // a regular file within the bound (a FIFO / device is unreadable, never a hang)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trust store unreadable: "+err.Error())
			os.Exit(2)
		}
		obj, perr := parseObject(raw) // the profile's strict parser: duplicate keys / floats / NaN refused, like every other input
		if perr != nil {
			fmt.Fprintln(os.Stderr, "trust store unreadable")
			os.Exit(2)
		}
		for k, v := range obj.Vals {
			sv, ok := v.(string)
			if !ok {
				fmt.Fprintln(os.Stderr, "trust store unreadable: values must be strings")
				os.Exit(2)
			}
			trust[k] = sv
		}
		haveTrust = true
	}
	r := verifyPack(pack, ledger, trust, haveTrust, key, requireSources)
	out, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(out))
	if !r.Ok {
		os.Exit(1)
	}
}
