# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra` command line. Exit 0 only on a verified positive outcome: `vuln` exits 1 when an applicable deadline is
overdue, `seal` when the seal does not verify, `notice` when required fields are missing, `verify` when authenticity
is FAIL (77 when it could not judge), `obligations` when a support period is below the five-year minimum with no
declared shorter expected use (under one reading of the day, at least) for a product the requirements reach (Art. 69(2)). Exit 74 when the JSON outcome (also the text of `--help` and `--version`) could
not be written whole to stdout (full disk, closed pipe, closed or read-only stdout, a file size limit, also under -u /
PYTHONUNBUFFERED), or what the subcommand promises could not be written: its ledger line, the copy of an ingested
SBOM document, a file (`pack --out`, the `sign` sidecar, the `notice` drop file, the `keygen` seed, the ledger's
signed tip) — whatever the outcome was, with a `receipt not written: <reason>` line on stderr. A stdout that is
non-blocking and full is waited for, as a blocking one (measured on Linux; not on macOS or Windows). Usage errors exit 2 and
refusals keep their code (`keygen` on an existing seed: 1, one line, no traceback) even when stderr cannot take
their line. What a subcommand records in the ledger is recorded before its outcome is printed. Nothing is ever sent
anywhere except the OSV/KEV/EUVD read-only queries (`feeds`, and `vuln --source cisa_kev|enisa_euvd` unless
--assert-source)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List

from . import __version__
from .applicability import ROLES, STREAMS
from .locker import CRAEvidenceLocker
from .sbom import resolved_components, sbom_from_cyclonedx, sbom_from_installed, sbom_from_spdx
from .signing import keygen, load_key, sign_pack
from .srp_notice import DryRunDrop, SRPNotice, schema
from .verify_pack import verify_pack
from .vuln import STATUSES, VulnerabilityRecord
from .longterm import LongTermEvidence
from .outputs import OutputNotWritten
from datetime import datetime, timezone


EX_IOERR = 74   # sysexits: the outcome was computed but its receipt could not be written


class ReceiptNotWritten(Exception):
    """stdout refused the receipt (ENOSPC, EPIPE, EBADF, a closed or absent stdout): the exit code becomes 74"""


def _p(obj: Any) -> None:
    """print the JSON outcome: every byte to stdout and flushed HERE, before the exit code is chosen, or
    ReceiptNotWritten (exit 74)"""
    try:
        _write_all(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    except OSError as e:
        raise ReceiptNotWritten(str(e) or type(e).__name__) from None


def _text_layer_bytes(out: Any, buf: Any, text: str) -> bytes:
    """The bytes Python's own stdout text layer writes for `text` as the first thing written: its encoding and error
    handler, "\\n" as os.linesep where the platform translates it (not Linux; not measured here), and a byte order mark
    only where that layer puts one — utf-16 / utf-32 only on a stdout seekable at offset 0 (a file), utf-8-sig on a
    pipe too, none on a seekable stdout past offset 0 (str.encode would put one on a pipe too)."""
    import codecs
    if os.linesep != "\n":
        text = text.replace("\n", os.linesep)
    encoding = out.encoding or "utf-8"
    enc = codecs.getincrementalencoder(encoding)(out.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")):
        enc.setstate(0)   # no byte order mark
    return enc.encode(text, final=True)


def _wait_writable(buf: Any) -> None:
    """stdout is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow, not
    gone; one that goes away makes the next write EPIPE). `select` sleeps in the kernel and Python retries it after a
    signal (PEP 475). The descriptor is asked for only here: a byte stream with no descriptor (an io.BytesIO under a
    TextIOWrapper, as pytest's capsys) never blocks. POSIX only: on Windows `select` waits on sockets only, so a full
    non-blocking pipe there would be reported as 74 (not measured)."""
    import select
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:   # no descriptor, or one select cannot wait on
        raise OSError(f"stdout is non-blocking and cannot be waited for: {e}")


def _write_all(text: str) -> None:
    """Write the whole text to stdout and flush it; OSError when it did not all get there. The bytes go to
    `sys.stdout.buffer` in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw FileIO whose write()
    can take part of the data (a file size limit, a disk nearly full) and return the count without raising, or return
    None (a full non-blocking pipe) — the text layer above dropped the rest in silence (measured on 0.5.1's first
    commits, 13/10/2026: the verdict's code with the receipt cut). A full non-blocking stdout is waited for, never
    given up on."""
    out = sys.stdout
    if out is None:   # started with fd 1 closed: print() would drop the receipt and say nothing
        raise OSError("stdout is closed")
    try:
        buf = getattr(out, "buffer", None)
        while True:   # whatever the text layer still holds goes first: text the caller wrote and left unflushed, on a full
            try:      # non-blocking stdout, is waited for like the receipt (at e25795e that was exit 74 with nothing written)
                out.flush()
                break
            except BlockingIOError:
                if buf is None:
                    raise
                _wait_writable(buf)
        if buf is None:   # an in-process text stream (io.StringIO): no bytes below it
            out.write(text)
            out.flush()
            return
        data = memoryview(_text_layer_bytes(out, buf, text))
        while data:
            try:
                n = buf.write(data)
                waited = False
            except BlockingIOError as e:   # buffered stdout on a full non-blocking pipe: part of it taken
                n, waited = e.characters_written, True
            if n is None:   # raw stdout on a full non-blocking pipe: nothing taken
                n, waited = 0, True
            if n < 0 or n > len(data) or (n == 0 and not waited):
                raise OSError(f"short write: {len(data)} bytes not written")
            data = data[n:]
            if data and waited:
                _wait_writable(buf)
        while True:   # flushed HERE, before the exit code is chosen, not by the interpreter at exit
            try:
                buf.flush()
                return
            except BlockingIOError:
                _wait_writable(buf)
    except ValueError as e:   # I/O operation on a closed file, or text the stream cannot encode
        raise OSError(str(e))


def _say(text: str) -> bool:
    """Write `text` to stderr without ever raising; True when it was written. If stderr is full, closed or its reader
    gone, its descriptor is pointed at the null device (so the interpreter's last flush cannot fail again and turn the
    exit code into 120) and the caller's exit code stands."""
    err = sys.stderr
    if err is None:   # started with fd 2 closed
        return False
    try:
        err.write(text)
        err.flush()
        return True
    except (OSError, ValueError):
        _silence(err)
        return False


def _silence(stream: Any) -> None:
    """point the descriptor BEHIND `stream` at /dev/null so the interpreter's own flush at exit does not fail again on
    what is still buffered (it would print "Exception ignored" and exit 120 instead of 74). The descriptor is the
    stream's own, never a fixed number: with fd 1 closed at start, a file this run opened may hold descriptor 1."""
    try:
        if stream is None:
            return
        fd = stream.fileno()
    except (OSError, ValueError, AttributeError):
        return
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except OSError:
        pass


def _receipt_lost(reason: str, stdout_failed: bool = True) -> int:
    if stdout_failed:
        _silence(sys.stdout)
    _say(f"receipt not written: {reason}\n")   # stderr refused too: the exit code alone says it
    return EX_IOERR


class _Version(argparse.Action):
    """`--version` prints through the receipt writer: not written whole, the exit is 74 (argparse's own print exited
    120 on a full stdout, "Exception ignored")"""

    def __init__(self, option_strings, version=None, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help="show program's version number and exit", **kw):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help, **kw)
        self.version = version

    def __call__(self, parser, namespace, values, option_string=None):
        formatter = parser._get_formatter()
        formatter.add_text(self.version)
        parser._print_outcome(formatter.format_help())
        parser.exit()


class _Parser(argparse.ArgumentParser):
    """argparse with its output through the writers above. Every message argparse prints (the usage and error lines
    of a usage error, exit 2) goes through `_print_message` to stderr with a write that never raises (argparse's own:
    with stderr full or its reader gone the interpreter's last flush exited 120; with stderr closed the usage went to
    STDOUT, exit 1). `--help` and `--version` print the command's output: not written whole, the exit is 74."""

    def _print_outcome(self, text: str) -> None:
        try:
            _write_all(text)
        except OSError as e:
            raise SystemExit(_receipt_lost(str(e) or type(e).__name__))

    def print_help(self, file=None):
        if file is not None:
            return super().print_help(file)
        self._print_outcome(self.format_help())

    def _print_message(self, message, file=None):   # argparse's only writer: error() and exit() print through it
        if not message:
            return
        if file is not None and file is not sys.stdout and file is not sys.stderr:   # a file a caller passed itself
            file.write(message)
        else:
            _say(message)


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _locker(a) -> CRAEvidenceLocker:
    key = load_key(a.tip_key) if getattr(a, "tip_key", None) else None
    return CRAEvidenceLocker(a.ledger, a.product, a.version, tip_key=key, support_period_end=getattr(a, "support_period_end", None))


def main(argv: List[str] = None) -> int:
    try:
        return _main(argv)
    except ReceiptNotWritten as e:
        return _receipt_lost(str(e))
    except OutputNotWritten as e:   # a promised file (pack, sidecar, drop file, seed) could not be written whole
        return _receipt_lost(str(e), stdout_failed=False)
    except Exception:   # a refusal still printed as a traceback (exit 1, as before): through the writer that never raises,
        import traceback   # so a full stderr or one whose reader has gone keeps exit 1 (the interpreter's own print exited 120)
        _say(traceback.format_exc())
        return 1


def _main(argv: List[str] = None) -> int:
    p = _Parser(prog="cra", description="CRA evidence locker (SBOM, Art. 14 clock, SRP notices, 10-year seal) — offline-verifiable",
                                allow_abbrev=False)   # `--require-source` is not `--require-sources`: the three independent verifiers refuse it, so does the reference
    p.add_argument("--version", action=_Version, version=f"cra-evidence {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(s):
        s.add_argument("--ledger", required=True); s.add_argument("--product", required=True); s.add_argument("--version", dest="version", required=True)
        s.add_argument("--tip-key", help="Ed25519 seed file: sign the chain tip after each append (cryptovalid_tip/1)")
        s.add_argument("--support-period-end", help="ISO-8601 end of the product's support period (retention = 10 years or this, whichever is longer)")

    s = sub.add_parser("keygen", help="generate an Ed25519 seed file (0600)"); s.add_argument("path")
    s = sub.add_parser("sbom", help="record an SBOM"); common(s)
    s.add_argument("--from-cyclonedx", help="ingest a CycloneDX JSON (Syft, Trivy, cdxgen…)")
    s.add_argument("--from-spdx", help="ingest an SPDX 2.2/2.3 JSON or SPDX 3.0 JSON-LD document (Syft, Yocto, Parlay…)")
    s.add_argument("--installed", nargs="*", help="top-level PyPI names resolved from this environment"); s.add_argument("--transitive", action="store_true")
    s.add_argument("--no-store-source", action="store_true", help="do not copy the ingested document to <ledger>.sources/ (its SHA-256 is still recorded)")
    s.add_argument("--spec-version", default="1.6", choices=["1.6", "1.7"], help="CycloneDX version of the index export written into the record (default 1.6)")
    s = sub.add_parser("vuln", help="record a vulnerability-handling event"); common(s)
    s.add_argument("--id", required=True); s.add_argument("--aware", required=True, help="awareness instant, ISO-8601 UTC: with --exploited, awareness of the ACTIVE EXPLOITATION (the Art. 14 trigger); with --incident, of the severe incident")
    s.add_argument("--exploited", action="store_true"); s.add_argument("--source", default="manual", choices=["manual", "cisa_kev", "enisa_euvd", "vendor_advisory"])
    s.add_argument("--incident", action="store_true", help="severe incident (Art. 14(3)): final report one month after the 72 h notification")
    s.add_argument("--status", default="aware", choices=list(STATUSES)); s.add_argument("--fix-available", help="ISO-8601 UTC when the corrective measure became available")
    s.add_argument("--ew-sent", help="instant the early warning was submitted (ISO-8601 with zone)")
    s.add_argument("--notified", help="instant the 72 h notification was submitted (ISO-8601 with zone)")
    s.add_argument("--final-sent", help="instant the final report was submitted (ISO-8601 with zone)")
    s.add_argument("--assert-source", action="store_true", help="skip the live KEV/EUVD check for --source cisa_kev/enisa_euvd (recorded as 'asserted:…')")
    s.add_argument("--allow-overdue", action="store_true", help="exit 0 even if an applicable deadline is overdue (default: exit 1)")
    s = sub.add_parser("notice", help="build an SRP-aligned Art. 14 notice (dry-run drop file, never submitted)"); common(s)
    s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"]); s.add_argument("--stage", required=True, choices=["early_warning", "notification", "final_report"])
    s.add_argument("--fields", required=True, help="JSON file with the SRP fields (see `cra schema --template`)"); s.add_argument("--drop", required=True, help="drop folder")
    s.add_argument("--previous", help="JSON file with the previous stage's fields: carried-forward fields are copied from it")
    s.add_argument("--divergence-reason", help="why this notice's awareness differs from the recorded vulnerability event")
    s = sub.add_parser("schema", help="print the SRP field schema for a stream, or a fillable template for a stage"); s.add_argument("--stream", default="vulnerability", choices=["vulnerability", "incident"])
    s.add_argument("--template", choices=["early_warning", "notification", "final_report"], help="print {field: \"\"} for the fields of this stage (R/C/O/A), ready for `cra notice --fields`")
    s = sub.add_parser("pack", help="write the evidence pack and anchor it in the ledger"); common(s); s.add_argument("--out", required=True)
    s = sub.add_parser("sign", help="sign a pack (Ed25519 sidecar) with a seed file or an AWS KMS Ed25519 key (the key never leaves the HSM)"); s.add_argument("pack")
    s.add_argument("--key", help="Ed25519 seed file"); s.add_argument("--signer-id", required=True)
    s.add_argument("--aws-kms-key-id", help="KMS key id/ARN (key spec ECC_NIST_EDWARDS25519); credentials from AWS_* env or --aws-creds-file")
    s.add_argument("--aws-region"); s.add_argument("--aws-creds-file", help="KEY=VALUE file with AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY [/ AWS_SESSION_TOKEN]")
    s = sub.add_parser("seal", help="long-term seal of a pack digest (crypto-agile archive timestamp); --tip-key = the sealing identity"); common(s)
    s.add_argument("--pack-sha3", required=True); s.add_argument("--ts-source", default="asserted"); s.add_argument("--token-b64", help="RFC 3161 / OTS token (required when --ts-source is not 'asserted')")
    s.add_argument("--renew", help="JSON file with the previous seal (lte dict) to extend the chain")
    s = sub.add_parser("verify", help="verify a pack offline (exit 0 only if authenticity is not FAIL)"); s.add_argument("pack")
    s.add_argument("--ledger"); s.add_argument("--trust-store", help="JSON {signer_id: public_key_hex}")
    s.add_argument("--log-pubkey", help="trusted public key (hex) of the ledger's signed tip: detects a truncated tail")
    s.add_argument("--require-sources", action="store_true", help="every SBOM source document recorded by hash must be present next to the ledger and match (absence = FAIL)")
    s = sub.add_parser("feeds", help="read-only network checks: OSV positive control, KEV/EUVD exploitation signal for ids"); s.add_argument("ids", nargs="*")
    s = sub.add_parser("obligations", help="which CRA obligations are in force for a role at an instant, and the horizons counted in years "
                                           "(Art. 13(8), 13(9), 13(13), 14, 24(3), 69, 71); never reads the clock, records nothing")
    s.add_argument("--role", default="manufacturer", choices=list(ROLES)); s.add_argument("--stream", default="vulnerability", choices=list(STREAMS))
    s.add_argument("--at", help="the instant evaluated: is the reporting obligation in force then? (ISO-8601 with zone)")
    s.add_argument("--exploitation-aware", help="instant the reporter became aware of the ACTIVE EXPLOITATION (or, with --stream incident, of the "
                                                "severe incident): does the Art. 14 obligation arise? (guidance C(2026) 5252 §217, non-binding)")
    s.add_argument("--vulnerability-aware", help="instant the vulnerability itself became known (recorded; it never decides: §217)")
    s.add_argument("--placed-on-market", help="instant the product was placed on the market (the latest placing you know of)")
    s.add_argument("--substantially-modified", help="instant of a substantial modification (Art. 69(2)); whether it is substantial is yours to decide")
    s.add_argument("--support-period-end", help="ISO-8601 end of the support period")
    s.add_argument("--shorter-use-reason", help="why the support period is shorter than five years (Art. 13(8)): recorded, not assessed")
    s.add_argument("--update-issued", help="instant a security update was issued: how long it must stay available (Art. 13(9))")
    for sp_ in sub.choices.values():
        sp_.allow_abbrev = False          # subparsers do not inherit it: `--require-source` must not become `--require-sources`
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        try:
            r = keygen(a.path)
        except FileExistsError:   # the refusal (O_EXCL): an existing key is never overwritten — one line, no traceback
            _say(f"keygen refused: {a.path} already exists (an existing key is never overwritten)\n")
            return 1
        _p(r); return 0
    if a.cmd == "schema":
        if a.template:
            sch = schema(a.stream)
            _p({k: ("" if spec["format"] not in ("list", "enum-list") else []) for k, spec in sch.items() if spec["stages"][a.template] != "-"}); return 0
        _p({"stream": a.stream, "fields": schema(a.stream)}); return 0
    if a.cmd == "sbom":
        lk = _locker(a)
        if sum(1 for x in (a.from_cyclonedx, a.from_spdx, a.installed is not None) if x) > 1:
            p.error("sbom: --from-cyclonedx, --from-spdx and --installed are mutually exclusive")
        if a.from_cyclonedx:
            rec = sbom_from_cyclonedx(a.from_cyclonedx, a.product, a.version)
        elif a.from_spdx:
            rec = sbom_from_spdx(a.from_spdx, a.product, a.version)
        elif a.installed is not None:
            rec = sbom_from_installed(a.product, a.version, a.installed, transitive=a.transitive)
        else:
            p.error("sbom: give --from-cyclonedx, --from-spdx or --installed")
        src = a.from_cyclonedx or a.from_spdx
        e = lk.record_sbom(rec, source_path=src, store=not a.no_store_source, spec_version=a.spec_version); n = len(resolved_components(rec))
        _p({"recorded": e["idx"], "components": len(rec.components), "resolved": n, "depth": rec.depth, "floor_met": e["data"]["sbom_floor_met"],
            "source": e["data"].get("source")})
        return 0 if e["data"]["sbom_floor_met"] else 1
    if a.cmd == "vuln":
        lk = _locker(a)
        source, exploited = a.source, a.exploited
        if a.source in ("cisa_kev", "enisa_euvd"):
            if a.assert_source:
                source = f"asserted:{a.source}"
            else:   # the provenance label is only stored as such when the feed confirms it now
                from .feeds import cisa_kev_ids, euvd_kev_ids, exploitation_signal
                feed = cisa_kev_ids() if a.source == "cisa_kev" else euvd_kev_ids()
                if feed["error"]:
                    _say(f"feed {a.source} unavailable ({feed['error']}): use --assert-source to record an unverified provenance\n"); return 1
                sig = exploitation_signal([a.id], feed if a.source == "cisa_kev" else None, feed if a.source == "enisa_euvd" else None)
                if a.id.upper() not in {k.upper() for k in sig["actively_exploited"]}:
                    _say(f"{a.id} is NOT in {a.source} today: refusing to record that provenance (use --assert-source)\n"); return 1
                exploited = True     # confirmed in a known-exploited catalogue: the clock and the provenance cannot diverge
        rec = VulnerabilityRecord(product_id=a.product, vuln_id=a.id, actively_exploited=exploited, awareness_utc=a.aware,
                                  status=a.status, exploitation_source=source, corrective_available_utc=a.fix_available,
                                  kind=("incident" if a.incident else "vulnerability"), early_warning_sent_utc=a.ew_sent,
                                  notification_sent_utc=a.notified, final_report_sent_utc=a.final_sent)
        e = lk.record_vulnerability(rec); od = rec.overdue(); _p({"recorded": e["idx"], "deadlines": rec.deadlines(), "overdue": od})
        return 0 if (not od["any_overdue"] or a.allow_overdue) else 1
    if a.cmd == "notice":
        lk = _locker(a)
        with open(a.fields, encoding="utf-8") as f:
            fields = json.load(f)
        prev = _load_json(a.previous) if a.previous else None
        n = SRPNotice(stream=a.stream, stage=a.stage, fields=fields, previous_fields=prev)
        r = DryRunDrop(a.drop).prepare(n); lk.record_notice(n, r, divergence_reason=a.divergence_reason); _p(r)
        return 0 if r["complete"] else 1
    if a.cmd == "pack":
        lk = _locker(a); pk = lk.evidence_pack(a.out); _p({"pack": a.out, "pack_sha3": pk["pack_sha3"], "verification": pk["verification"]})
        return 0 if pk["verification"]["chain_ok"] else 1
    if a.cmd == "sign":
        if a.aws_kms_key_id:
            from .kms import KMSSigner, load_creds_file
            if not a.aws_region:
                p.error("sign: --aws-region is required with --aws-kms-key-id")
            creds = load_creds_file(a.aws_creds_file) if a.aws_creds_file else {}
            signer = KMSSigner(a.aws_kms_key_id, a.aws_region, creds.get("AWS_ACCESS_KEY_ID"), creds.get("AWS_SECRET_ACCESS_KEY"), creds.get("AWS_SESSION_TOKEN"))
            r = sign_pack(a.pack, signer.as_key(), a.signer_id); r["public_key_hex"] = signer.public_key_hex; r["backend"] = "aws-kms"; _p(r); return 0
        if not a.key:
            p.error("sign: give --key or --aws-kms-key-id")
        _p(sign_pack(a.pack, load_key(a.key), a.signer_id)); return 0
    if a.cmd == "seal":
        lk = _locker(a)
        prev = _load_json(a.renew) if a.renew else None
        d = lk.seal_longterm(a.pack_sha3, ts_source=a.ts_source, previous=prev, token_b64=a.token_b64)
        v = LongTermEvidence.from_dict(d).verify(now=datetime.now(timezone.utc).timestamp())
        _p({"seal": d, "verify": v})
        return 0 if v["ok"] else 1
    if a.cmd == "verify":
        for flag, val in (("--ledger", a.ledger), ("--trust-store", a.trust_store), ("--log-pubkey", a.log_pubkey)):
            if val is not None and (val == "" or val.startswith("-")):
                p.error(f"verify: {flag} needs a value (got {val!r})")
        if a.pack.startswith("-"):
            p.error("verify: the pack must be a file path (got a flag-like argument)")
        if a.log_pubkey is not None and not re.fullmatch(r"[0-9a-f]{64}", a.log_pubkey):
            p.error("verify: --log-pubkey must be 64 lower-case hex characters")
        ts = None
        if a.trust_store:
            from .ledger import load_trust_store
            from .ledger import read_regular
            try:   # a regular file within MAX_DOC_BYTES (a FIFO / device is unreadable, never a hang); strict JSON: a duplicate signer_id would make two readers disagree
                ts = load_trust_store(read_regular(a.trust_store).decode("utf-8"))
            except (OSError, ValueError) as e:
                _say(f"trust store unreadable: {e}\n"); return 2
        r = verify_pack(a.pack, a.ledger, ts, a.log_pubkey, require_sources=a.require_sources); _p(r)
        # 0 = verified; 77 = NOT ASSESSED (assessed=false: this host or the verifier itself could not judge, and no layer
        # judged against the pack); 1 = a finding against the pack. Since 27/09/2026, as omega-evidence: before, both
        # "the pack is bad" and "the tool is broken" exited 1.
        return 0 if r["ok"] else (77 if r.get("assessed") is False else 1)
    if a.cmd == "feeds":
        from .feeds import cisa_kev_ids, euvd_kev_ids, exploitation_signal, osv_positive_control
        pc = osv_positive_control(); kev = cisa_kev_ids(); eu = euvd_kev_ids()
        out: Dict[str, Any] = {"osv_positive_control": pc, "cisa_kev": {"count": kev["count"], "error": kev["error"]},
                               "enisa_euvd": {"count": eu["count"], "error": eu["error"]}}
        if a.ids:
            out["signal"] = exploitation_signal(a.ids, kev, eu)
        _p(out)
        return 0 if (pc["ok"] and not kev["error"] and not eu["error"]) else 1
    if a.cmd == "obligations":
        from .applicability import (art14_obligation, legacy_product_scope, reporting_in_force, retention_until,
                                    support_period, update_available_until)
        if not (a.at or a.exploitation_aware or a.placed_on_market or a.update_issued):
            p.error("obligations: give at least one of --at, --exploitation-aware, --placed-on-market, --update-issued")
        if a.vulnerability_aware and not a.exploitation_aware:
            p.error("obligations: --vulnerability-aware needs --exploitation-aware")
        if (a.substantially_modified or a.shorter_use_reason) and not a.placed_on_market:
            p.error("obligations: --substantially-modified and --shorter-use-reason need --placed-on-market")
        if a.support_period_end and not (a.placed_on_market or a.update_issued):
            p.error("obligations: --support-period-end needs --placed-on-market or --update-issued")
        if a.shorter_use_reason and not a.support_period_end:
            p.error("obligations: --shorter-use-reason needs --support-period-end")
        ob: Dict[str, Any] = {}
        try:   # an instant without a zone, inconsistent instants, a reason for a period that needs none: usage (exit 2, nothing printed)
            if a.at:
                ob["reporting"] = reporting_in_force(a.role, a.at, a.stream)
            if a.exploitation_aware:
                ob["art14_obligation"] = art14_obligation(a.exploitation_aware, a.role, a.stream, a.vulnerability_aware)
            if a.placed_on_market:
                ob["legacy_scope"] = legacy_product_scope(a.placed_on_market, a.substantially_modified)
                ob["retention"] = retention_until(a.placed_on_market, a.support_period_end)
                if a.support_period_end:
                    ob["support_period"] = support_period(a.placed_on_market, a.support_period_end, a.shorter_use_reason)
            if a.update_issued:
                ob["update_availability"] = update_available_until(a.update_issued, a.support_period_end)
            # Art. 69(2): a product placed before 11 December 2027 and not substantially modified from that date is not
            # subject to the requirements (Art. 13 included): its horizons are computed, marked, and never a finding
            lg = ob.get("legacy_scope")
            for k in ("retention", "support_period", "update_availability"):
                if k in ob:
                    ob[k]["requirements_apply"] = lg["requirements_apply"] if lg else None
                    ob[k]["requirements_apply_basis"] = ("Art. 69(2): see legacy_scope" if lg else
                                                         "not known: give --placed-on-market (Art. 69(2))")
        except ValueError as e:
            p.error(f"obligations: {e}")
        _p(ob)
        sp_ = ob.get("support_period", {})
        lg_r = ob.get("legacy_scope", {}).get("readings", {})
        # below the minimum under one reading WHERE THE REQUIREMENTS REACH THE PRODUCT (Art. 69(2)) is a finding: exit 1
        below = any(x["status"] == "below_minimum" and lg_r.get(r, {}).get("requirements_apply") for r, x in sp_.get("readings", {}).items())
        return 1 if below else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
