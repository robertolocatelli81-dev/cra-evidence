// SPDX-License-Identifier: AGPL-3.0-or-later
// cra-verify — independent Go verifier of a cra-evidence pack (standard library only: crypto/sha256, crypto/sha3,
// crypto/ed25519). Same layers and authenticity verdict as cra_evidence/verify_pack.py; canonical.go/prescan.go are
// the strict parser + canonical encoder of cryptovalid's Go verifier (same profile, same author).
// Usage: cra-verify <pack.json> [--ledger path] [--trust-store file.json] [--log-pubkey hex]; exit 0 only if ok.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
func edOK(pubHex string, msg []byte, sigHex string) bool {
	pub, e1 := hex.DecodeString(pubHex)
	sig, e2 := hex.DecodeString(sigHex)
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
func short(s any, n int) string {
	t := fmt.Sprint(s)
	if len(t) > n {
		return t[:n] + "…"
	}
	return t
}

func verifyPack(packPath, ledgerPath string, trust map[string]string, haveTrust bool, logPub string) (r result) {
	defer func() {
		if e := recover(); e != nil {
			r = result{Ok: false, Authenticity: "FAIL", Layers: []layer{{"verifier-exception", "FAIL", fmt.Sprint(e)}}}
		}
	}()
	var layers []layer
	raw, err := os.ReadFile(packPath)
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
	scope, _ := getS(pack, "honest_scope")
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
	if lp == "" {
		if lf, ok := getS(pack, "ledger_file"); ok && lf != "" {
			lp = filepath.Join(filepath.Dir(packPath), filepath.Base(lf))
		}
	}
	isFile := func(p string) bool { st, e := os.Stat(p); return e == nil && st.Mode().IsRegular() }
	anchored := false
	if (ledgerPath != "" || logPub != "") && !(lp != "" && isFile(lp)) {
		layers = append(layers, layer{"ledger-chain", "FAIL", "ledger explicitly required (ledger_path / log key given) but not found"})
	} else if lp != "" && isFile(lp) {
		f, _ := os.Open(lp)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		var entries []*Object
		var failures []string
		prev, n := genesis, 0
		for sc.Scan() {
			line := sc.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
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
		f.Close()
		if n == 0 {
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
				if ap, _ := getS(d, "anchored_pack_sha3"); k == "cra_pack_anchor" && ap == declared {
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
			tipPath := lp + ".tip.json"
			first, _ := getS(entries[0], "self_hash")
			lastHash, _ := getS(entries[len(entries)-1], "self_hash")
			if logPub != "" {
				if !isFile(tipPath) {
					layers = append(layers, layer{"signed-tip", "FAIL", "trusted log key given but no tip file next to the ledger"})
				} else {
					ok, why := checkTip(len(entries), first, lastHash, tipPath, logPub)
					layers = append(layers, layer{"signed-tip", ifs(ok, "PASS", "FAIL"), ifs(ok, "tip verified: no tail truncation", why)})
				}
			} else if isFile(tipPath) {
				layers = append(layers, layer{"signed-tip", "SKIP", "tip present but NOT checked: pass the trusted log key (tail truncation undetected)"})
			} else {
				layers = append(layers, layer{"signed-tip", "SKIP", "no tip: tail truncation undetectable offline"})
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
	raw, err := os.ReadFile(tipPath)
	if err != nil {
		return false, "tip_unreadable"
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
	if lk, _ := getS(tip, "log_pubkey_hex"); lk != "" && lk != pubHex {
		return false, "tip_invalid: tip log key differs from the trusted log key"
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
	raw, err := os.ReadFile(sp)
	if err != nil {
		return "SKIP", "pack not signed", false
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
	pub, _ := getS(side, "public_key_hex")
	sigHex, _ := getS(side, "signature_hex")
	alg, okAlg := side.Vals["alg"]
	if !okAlg {
		alg = "Ed25519"
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
	if f, ok := side.Vals["fingerprint"]; ok && f != nil && f != fpHex {
		return "FAIL", "declared fingerprint does not match the signing key", false
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

func main() {
	var pack, ledger, trustFile, key string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ledger":
			i++
			ledger = args[i]
		case "--trust-store":
			i++
			trustFile = args[i]
		case "--log-pubkey":
			i++
			key = args[i]
		default:
			pack = args[i]
		}
	}
	if pack == "" {
		fmt.Fprintln(os.Stderr, "usage: cra-verify <pack.json> [--ledger path] [--trust-store file] [--log-pubkey hex]")
		os.Exit(2)
	}
	trust := map[string]string{}
	haveTrust := false
	if trustFile != "" {
		raw, err := os.ReadFile(trustFile)
		if err != nil || json.Unmarshal(raw, &trust) != nil {
			fmt.Fprintln(os.Stderr, "trust store unreadable")
			os.Exit(2)
		}
		haveTrust = true
	}
	r := verifyPack(pack, ledger, trust, haveTrust, key)
	out, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(out))
	if !r.Ok {
		os.Exit(1)
	}
}
