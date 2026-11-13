# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/11/2026 — `cra import sbomify` loses no field (spec/SRP_FIELDS.md, "Importing from sbomify"; rule 10 of the
amendment of 13/11/2026). Written before the importer, on the real responses of sbomify's API at commit 4ef6128
(tests/fixtures/sbomify_4ef6128/, 3 reports, 9 filings, all five stages):

1. every non-empty (field, value) pair of a filing's snapshot, date columns included, is accounted for in exactly one
   of fields / previous_fields / later_stage / readings, and the list of unmapped pairs is empty;
2. reverse: from each drop file written by the CLI (fields, previous_fields and its `source` block) the snapshot's pairs
   are rebuilt equal, after the normalisations the drop file declares (each one checked against the closed conversion
   it names);
3. positive control: removing one entry of the mapping table makes the accounting fail — `title` on every one of the 9
   filings, and every one of the 39 entries on each filing where its field is valued;
4. every one of the 39 sbomify fields is valued in at least one fixture snapshot (the fixtures exercise the whole table).
The reverse reconstruction is written here, not taken from the importer."""
import contextlib, glob, hashlib, io, json, os, shutil, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "sbomify_4ef6128")
DATE_IDS = ("aware_at", "occurred_at", "measure_available_at")
PRODUCT_TYPES = {"Default": "Default", "Important Product with Digital Elements": "Important",
                 "Critical Product with Digital Elements": "Critical"}


def _strict(raw):
    def hook(pairs):
        d = {}
        for k, v in pairs:
            assert k not in d, f"duplicate key {k}"
            d[k] = v
        return d
    return json.loads(raw.decode("utf-8"), object_pairs_hook=hook)


def fixtures():
    """[(report path, report, filing path, filing)] for the 9 filings, each with its own report"""
    out = []
    for rp in sorted(glob.glob(os.path.join(FIX, "report_*.json"))):
        with open(rp, "rb") as f:
            rep = _strict(f.read())
        for fp in sorted(glob.glob(os.path.join(FIX, f"filing_{rep['id']}_*.json"))):
            with open(fp, "rb") as f:
                out.append((rp, rep, fp, _strict(f.read())))
    return out


def snapshot_pairs(filing):
    """{sbomify id: value} of every non-empty pair of the snapshot (srp_fields and the date columns)"""
    s = filing["snapshot"]
    pairs = {k: v for k, v in s["srp_fields"].items() if v not in (None, "")}
    pairs.update({k: s[k] for k in DATE_IDS if s.get(k) not in (None, "")})
    return pairs


class _Fixtures:
    """Mixin, not a TestCase: the CI check wants every TestCase class to have run."""
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures()

    def test_fixture_bytes_are_the_measured_ones(self):
        with open(os.path.join(FIX, "SHA256SUMS"), encoding="utf-8") as f:
            sums = dict(reversed(l.split("  ", 1)) for l in f.read().splitlines())
        names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(FIX, "*.json")))
        self.assertEqual(len(names), 12)                     # 3 reports + 9 filings
        for n in names + ["GENERATED.md"]:
            with open(os.path.join(FIX, n), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sums[n], n)
        self.assertEqual(len(self.fx), 9)
        self.assertEqual({f["stage"] for *_, f in self.fx},
                         {"early_warning", "notification", "intermediate", "final_report", "users_informed"})


def _si():
    from cra_evidence import sbomify_import
    return sbomify_import


def _field_to_id(si, kind):
    inv = {}
    for (scope, sid), field in si.MAPPING.items():
        if scope in ("both", kind):
            assert field not in inv, f"two sbomify ids map to {field} for {kind}"
            inv[field] = sid
    return inv


def accounted(si, placed, kind):
    """[(sbomify id, place)] for every pair the placement accounts for"""
    inv = _field_to_id(si, kind)
    out = [(inv[k], "fields") for k in placed["fields"]]
    out += [(inv[k], "previous_fields") for k in (placed["previous_fields"] or {})]
    out += [(e["sbomify_id"], "later_stage") for e in placed["later_stage"]]
    out += [(e["sbomify_id"], "readings") for e in placed["readings"]]
    return out


class TestEveryPairAccountedOnce(_Fixtures, unittest.TestCase):
    def test_every_pair_in_exactly_one_place_and_nothing_unmapped(self):
        si = _si()
        for rp, rep, fp, filing in self.fx:
            with self.subTest(filing=os.path.basename(fp)):
                placed = si.place_filing(filing, rep["kind"])
                self.assertEqual(placed["unmapped"], [])
                acc = accounted(si, placed, rep["kind"])
                ids = [sid for sid, _ in acc]
                self.assertEqual(len(ids), len(set(ids)), f"a pair in two places: {acc}")
                self.assertEqual(set(ids), set(snapshot_pairs(filing)))

    def test_mapping_has_the_39_rows_of_the_spec(self):
        si = _si()
        self.assertEqual(len(si.MAPPING), 39)
        self.assertEqual(sum(1 for s, _ in si.MAPPING if s == "both"), 17)
        self.assertEqual(sum(1 for s, _ in si.MAPPING if s == "vulnerability"), 13)
        self.assertEqual(sum(1 for s, _ in si.MAPPING if s == "incident"), 9)

    def test_every_one_of_the_39_fields_is_valued_in_a_fixture(self):
        si = _si()
        valued = set()
        for _, rep, _, filing in self.fx:
            for sid in snapshot_pairs(filing):
                valued.add(("both", sid) if ("both", sid) in si.MAPPING else (rep["kind"], sid))
        self.assertEqual(sorted(set(si.MAPPING) - valued), [])


class TestPositiveControl(_Fixtures, unittest.TestCase):
    def failing_filings(self, si, key):
        table = {k: v for k, v in si.MAPPING.items() if k != key}
        bad = []
        with mock.patch.object(si, "MAPPING", table):
            for _, rep, fp, filing in self.fx:
                try:
                    placed = si.place_filing(filing, rep["kind"])
                except ValueError:
                    bad.append(fp)
                    continue
                if placed["unmapped"] or set(sid for sid, _ in accounted(si, placed, rep["kind"])) != set(snapshot_pairs(filing)):
                    bad.append(fp)
        return bad

    def test_removing_title_fails_on_every_filing(self):
        self.assertEqual(len(self.failing_filings(_si(), ("both", "title"))), 9)

    def test_removing_any_entry_fails_where_the_field_is_valued(self):
        si = _si()
        for key in list(si.MAPPING):
            scope, sid = key
            where = [fp for _, rep, fp, f in self.fx if scope in ("both", rep["kind"]) and sid in snapshot_pairs(f)]
            with self.subTest(entry=key):
                self.assertTrue(where)
                self.assertEqual(sorted(self.failing_filings(si, key)), sorted(where))


def _forward(conversion, value):
    """the closed conversions of the spec, written here independently of the importer"""
    if conversion == "product_type":
        return PRODUCT_TYPES[value]
    if conversion == "member_states":
        return [p.strip() for p in value.split(",")]
    if conversion == "utc_offset":
        from datetime import datetime, timezone
        d = datetime.fromisoformat(value)
        assert d.tzinfo is not None
        return d.astimezone(timezone.utc)
    if conversion == "pec_option":
        from cra_evidence.srp_notice import PEC_OPTIONS
        return [k for k, t in PEC_OPTIONS.items() if t == value]
    raise AssertionError(f"conversion {conversion!r} not in the spec")


class TestReverseFromDropFiles(_Fixtures, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def cli(self, *argv):
        from cra_evidence.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_drop_files_rebuild_every_snapshot_pair(self):
        si = _si()
        by_report = {}
        for rp, rep, fp, filing in self.fx:
            by_report.setdefault(rp, (rep, []))[1].append((fp, filing))
        n = 0
        for rp, (rep, filings) in by_report.items():
            led, drop = os.path.join(self.d, rep["id"] + ".jsonl"), os.path.join(self.d, "drop_" + rep["id"])
            argv = ["import", "sbomify", "--report", rp, "--ledger", led, "--product", "p-" + rep["id"], "--version", "1",
                    "--drop-dir", drop, "--source-version", "4ef61281e69d693e3560185bf81ec5474179ea98"]
            for fp, _ in filings:
                argv += ["--filing", fp]
            rc, out, err = self.cli(*argv)
            self.assertEqual(rc, 0, err)
            drops = {}
            for p in glob.glob(os.path.join(drop, "*.json")):
                with open(p, "rb") as f:
                    d = _strict(f.read())
                if d.get("schema") == "cra-srp/3":
                    drops[d["source"]["document_sha256"]] = d
            inv = _field_to_id(si, rep["kind"])
            for fp, filing in filings:
                with open(fp, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
                d = drops[sha]
                with self.subTest(filing=os.path.basename(fp)):
                    self.assertEqual(d["stage"], filing["stage"])
                    self.assertEqual(d["filing"], {"declared_by": "sbomify", "srp_reference": filing["srp_reference"],
                                                   "filed_at": filing["filed_at"], "filed_by": filing["filed_by"]})
                    got = {}
                    for k, v in list(d["fields"].items()) + list((d["previous_fields"] or {}).items()):
                        self.assertNotIn(inv[k], got)
                        got[inv[k]] = v
                    for e in d["source"]["later_stage"] + d["source"]["readings"]:
                        self.assertNotIn(e["sbomify_id"], got)
                        got[e["sbomify_id"]] = e["value"]
                    for nm in d["source"]["normalisations"]:
                        sid = nm["sbomify_id"]
                        fwd = _forward(nm["conversion"], nm["from"])
                        if nm["conversion"] == "utc_offset":
                            self.assertEqual(_forward("utc_offset", nm["to"]), fwd)
                        else:
                            self.assertEqual(nm["to"], fwd)
                        self.assertEqual(got[sid], nm["to"])
                        got[sid] = nm["from"]                 # undo the declared normalisation
                    self.assertEqual(got, snapshot_pairs(filing))
                    with open(os.path.join(led + ".sources", sha + ".json"), "rb") as f:
                        self.assertEqual(hashlib.sha256(f.read()).hexdigest(), sha)   # the source kept byte for byte
                    n += 1
        self.assertEqual(n, 9)


if __name__ == "__main__":
    unittest.main()
