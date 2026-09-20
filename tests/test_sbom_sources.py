# SPDX-License-Identifier: AGPL-3.0-or-later
"""0.3.0 — the generator's document is the evidence, the record is its index.

Fixtures in tests/fixtures/real_tools/ are the UNMODIFIED output of the real generators run on 20/09/2026 on a
one-dependency npm project (`tiny-cra-sample` → base64-js 1.5.1): Syft 1.52.0 (CycloneDX 1.7, SPDX 2.3),
Trivy 0.74.0 (CycloneDX 1.7, SPDX 2.3), cdxgen 12.8.4 (CycloneDX 1.6 and 1.7). Every test on them is a
cross-generator measurement, not an assumption about a format.
"""
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.canonical import canonical_bytes  # noqa: E402
from cra_evidence.locker import CRAEvidenceLocker, source_file, sources_dir  # noqa: E402
from cra_evidence.sbom import (SBOMComponent, SBOMRecord, installed_license, is_spdx_expression,  # noqa: E402
                               sbom_from_cyclonedx, sbom_from_installed, sbom_from_spdx, source_fingerprint)
from cra_evidence.verify_pack import verify_pack  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = sorted(glob.glob(os.path.join(HERE, "fixtures", "real_tools", "*.json")))
SCHEMAS = os.path.join(os.path.dirname(HERE), "spec", "schemas")


def ingest(path):
    return (sbom_from_spdx if "spdx" in os.path.basename(path) else sbom_from_cyclonedx)(path, "tiny-cra-sample", "1.0.0")


def layer(result, name):
    return next(l for l in result["layers"] if l["layer"] == name)


class TestRealGenerators(unittest.TestCase):
    def test_six_fixtures_present(self):
        names = [os.path.basename(p) for p in REAL]
        self.assertEqual(names, ["cdxgen-12.8.4_cyclonedx-1.6.json", "cdxgen-12.8.4_cyclonedx-1.7.json", "syft-1.52.0_cyclonedx-1.7.json",
                                 "syft-1.52.0_spdx-2.3.json", "trivy-0.74.0_cyclonedx-1.7.json", "trivy-0.74.0_spdx-2.3.json"])

    def test_every_generator_agrees_on_the_dependency(self):
        """the same purl, version and licence from six documents of three generators in two formats"""
        for p in REAL:
            r = ingest(p)
            dep = [c for c in r.components if c.purl == "pkg:npm/base64-js@1.5.1"]
            self.assertEqual(len(dep), 1, p)
            self.assertEqual((dep[0].name, dep[0].version, dep[0].license, dep[0].type), ("base64-js", "1.5.1", "MIT", "library"), p)

    def test_counts_reconcile_with_what_the_generator_declared(self):
        """independent count in the fixture JSON (not the module's own fields) vs what the record declares"""
        def count_cdx(items):
            return sum(1 + count_cdx(c.get("components") or []) for c in items if isinstance(c, dict) and c.get("name"))
        for p in REAL:
            r = ingest(p)
            s = r.source
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
            if s["format"] == "cyclonedx-json":
                self.assertEqual(s["components_declared"], count_cdx(doc["components"]), p)
                self.assertEqual(s["dependency_edges"], sum(len(x.get("dependsOn") or []) for x in doc.get("dependencies") or []), p)
                keys = set()
                def walk(items):
                    for c in items:
                        if isinstance(c, dict) and c.get("name"):
                            keys.add((c["name"], str(c.get("version", "") or ""), str(c.get("purl", "") or ""))); walk(c.get("components") or [])
                walk(doc["components"])
                self.assertEqual(len(r.components), len(keys), p)                                        # independent de-duplication
                self.assertEqual(s["duplicates_merged"], count_cdx(doc["components"]) - len(keys), p)
            else:
                self.assertEqual(s["packages_declared"], len(doc["packages"]), p)
                self.assertEqual(s["relationships_declared"], len(doc["relationships"]), p)
                roots = {x["relatedSpdxElement"] for x in doc["relationships"] if x["relationshipType"] == "DESCRIBES"}
                self.assertEqual(s["roots_excluded"], len(roots), p)
                self.assertEqual(len(r.components), s["packages_declared"] - s["packages_unnamed"] - s["roots_excluded"] - s["duplicates_merged"], p)
            with open(p, "rb") as f:
                self.assertEqual(s["sha256"], hashlib.sha256(f.read()).hexdigest())
            self.assertEqual(s["size_bytes"], os.path.getsize(p))

    def test_generator_name_and_version_are_read(self):
        got = {os.path.basename(p): (ingest(p).source["generator"], ingest(p).source["generator_version"], ingest(p).source["spec_version"]) for p in REAL}
        self.assertEqual(got["syft-1.52.0_cyclonedx-1.7.json"], ("syft", "1.52.0", "1.7"))
        self.assertEqual(got["syft-1.52.0_spdx-2.3.json"], ("syft", "1.52.0", "SPDX-2.3"))
        self.assertEqual(got["trivy-0.74.0_cyclonedx-1.7.json"], ("trivy", "0.74.0", "1.7"))
        self.assertEqual(got["trivy-0.74.0_spdx-2.3.json"], ("trivy", "0.74.0", "SPDX-2.3"))
        self.assertEqual(got["cdxgen-12.8.4_cyclonedx-1.7.json"], ("cdxgen", "12.8.4", "1.7"))
        self.assertEqual(got["cdxgen-12.8.4_cyclonedx-1.6.json"], ("cdxgen", "12.8.4", "1.6"))

    def test_component_types_and_cpes_pass_through(self):
        syft = ingest(os.path.join(HERE, "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json"))
        self.assertEqual(syft.source["component_types"], {"file": 1, "library": 2})
        self.assertTrue(any(c.cpe.startswith("cpe:2.3:a:base64-js:") for c in syft.components))
        trivy = ingest(os.path.join(HERE, "fixtures", "real_tools", "trivy-0.74.0_spdx-2.3.json"))
        self.assertIn(("package-lock.json", "application"), [(c.name, c.type) for c in trivy.components])   # primaryPackagePurpose
        self.assertEqual(ingest(os.path.join(HERE, "fixtures", "real_tools", "trivy-0.74.0_cyclonedx-1.7.json")).source["dependency_edges"], 2)

    def test_cyclonedx_1_7_is_ingested_like_1_6(self):
        a = ingest(os.path.join(HERE, "fixtures", "real_tools", "cdxgen-12.8.4_cyclonedx-1.6.json"))
        b = ingest(os.path.join(HERE, "fixtures", "real_tools", "cdxgen-12.8.4_cyclonedx-1.7.json"))
        self.assertEqual(a.components, b.components)
        self.assertEqual({k: v for k, v in a.source.items() if k not in ("spec_version", "sha256", "size_bytes", "file", "serial_number")},
                         {k: v for k, v in b.source.items() if k not in ("spec_version", "sha256", "size_bytes", "file", "serial_number")})


class TestIngestRules(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _doc(self, name, doc):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return p

    def test_nested_components_are_walked_and_counted(self):
        p = self._doc("n.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "container", "name": "img", "version": "1", "components": [
                {"type": "library", "name": "zlib", "version": "1.3", "purl": "pkg:deb/debian/zlib@1.3", "components": [
                    {"type": "file", "name": "libz.so"}]}]}]})
        r = sbom_from_cyclonedx(p, "x", "1")
        self.assertEqual([c.name for c in r.components], ["img", "libz.so", "zlib"])
        self.assertEqual((r.source["components_declared"], r.source["components_nested"]), (3, 2))
        self.assertEqual(r.source["component_types"], {"container": 1, "file": 1, "library": 1})

    def test_duplicates_merged_are_counted_not_hidden(self):
        c = {"type": "library", "name": "actions/checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4"}
        p = self._doc("d.json", {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [c, dict(c), dict(c)]})
        r = sbom_from_cyclonedx(p, "x", "1")
        self.assertEqual((len(r.components), r.source["components_declared"], r.source["duplicates_merged"]), (1, 3, 2))

    def test_unknown_type_and_malformed_hash_are_not_trusted(self):
        p = self._doc("u.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "thing", "name": "a", "version": "1", "hashes": [{"alg": "SHA-256", "content": "zz"}]}]})
        c = sbom_from_cyclonedx(p, "x", "1").components[0]
        self.assertEqual((c.type, c.sha256), ("library", ""))

    def test_not_cyclonedx_raises(self):
        p = self._doc("x.json", {"components": []})
        with self.assertRaises(ValueError):
            sbom_from_cyclonedx(p, "x", "1")

    def test_legacy_tools_list_still_names_the_generator(self):
        p = self._doc("l.json", {"bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {"tools": [{"vendor": "anchore", "name": "syft", "version": "0.90.0"}]},
                                 "components": [{"type": "library", "name": "a", "version": "1"}]})
        self.assertEqual((sbom_from_cyclonedx(p, "x", "1").source["generator"], sbom_from_cyclonedx(p, "x", "1").source["generator_version"]), ("syft", "0.90.0"))


class TestSourceStore(unittest.TestCase):
    """the stored document is what the verifiers re-hash: intact → PASS, one byte → FAIL, absent → SKIP / FAIL if required"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.src = os.path.join(self.d, "syft.cdx.json")
        shutil.copy(os.path.join(HERE, "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json"), self.src)
        self.led = os.path.join(self.d, "l.jsonl")
        self.lk = CRAEvidenceLocker(self.led, "tiny-cra-sample", "1.0.0")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _record_and_pack(self, **kw):
        rec = self.lk.record_sbom(sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0"), source_path=self.src, **kw)
        pack = os.path.join(self.d, "p.json")
        self.lk.evidence_pack(pack)
        return rec, pack

    def test_stored_bytes_are_the_source_bytes_and_verify_passes(self):
        rec, pack = self._record_and_pack()
        h = rec["data"]["source"]["sha256"]
        stored = source_file(self.led, h)
        with open(stored, "rb") as a, open(self.src, "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertEqual(rec["data"]["source"]["stored_as"], h + ".json")
        r = verify_pack(pack)
        self.assertTrue(r["ok"])
        self.assertEqual(layer(r, "source-documents")["status"], "PASS")

    def test_one_byte_more_is_a_named_fail(self):
        rec, pack = self._record_and_pack()
        with open(source_file(self.led, rec["data"]["source"]["sha256"]), "ab") as f:
            f.write(b"\n")
        r = verify_pack(pack)
        self.assertFalse(r["ok"])
        self.assertEqual(layer(r, "source-documents")["status"], "FAIL")
        self.assertIn("do not match their recorded SHA-256", layer(r, "source-documents")["detail"])

    def test_absent_is_skip_unless_required(self):
        rec, pack = self._record_and_pack()
        os.remove(source_file(self.led, rec["data"]["source"]["sha256"]))
        r = verify_pack(pack)
        self.assertTrue(r["ok"])
        self.assertEqual(layer(r, "source-documents")["status"], "SKIP")
        self.assertIn("1 recorded by hash only", layer(r, "source-documents")["detail"])
        r = verify_pack(pack, require_sources=True)
        self.assertFalse(r["ok"])
        self.assertEqual(layer(r, "source-documents")["status"], "FAIL")

    def test_no_store_keeps_the_hash(self):
        rec, pack = self._record_and_pack(store=False)
        self.assertEqual(len(rec["data"]["source"]["sha256"]), 64)
        self.assertNotIn("stored_as", rec["data"]["source"])
        self.assertFalse(os.path.exists(sources_dir(self.led)))
        self.assertEqual(layer(verify_pack(pack), "source-documents")["status"], "SKIP")

    def test_file_changed_between_ingest_and_record_is_refused(self):
        sb = sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0")
        with open(self.src, "a") as f:
            f.write(" ")
        with self.assertRaises(ValueError) as cm:
            self.lk.record_sbom(sb, source_path=self.src)
        self.assertIn("changed since it was ingested", str(cm.exception))

    def test_a_document_cannot_be_bound_to_an_index_not_read_from_it(self):
        """found by Opus in round 1: an installed-floor (or hand-built) record accepted ANY source_path and verified PASS"""
        for sb in (sbom_from_installed("tiny-cra-sample", "1.0.0", ["cryptography"]), SBOMRecord("tiny-cra-sample", "1.0.0", [SBOMComponent("left-pad", "9.9.9")])):
            with self.assertRaises(ValueError) as cm:
                self.lk.record_sbom(sb, source_path=self.src)
            self.assertIn("not ingested from a document", str(cm.exception))
        self.assertFalse(os.path.exists(sources_dir(self.led)))

    def test_an_ingested_sbom_without_source_path_is_refused(self):
        """found by Sonnet in round 1: the record carried the ingest-time hash with nothing re-verified or stored"""
        with self.assertRaises(ValueError) as cm:
            self.lk.record_sbom(sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0"))
        self.assertIn("pass source_path", str(cm.exception))
        self.lk.record_sbom(sbom_from_installed("tiny-cra-sample", "1.0.0", ["cryptography"]))     # not ingested: fine without

    def test_spdx_origin_round_trip(self):
        src = os.path.join(HERE, "fixtures", "real_tools", "trivy-0.74.0_spdx-2.3.json")
        rec = self.lk.record_sbom(sbom_from_spdx(src, "tiny-cra-sample", "1.0.0"), source_path=src)
        pack = os.path.join(self.d, "p2.json"); self.lk.evidence_pack(pack)
        r = verify_pack(pack, require_sources=True)
        self.assertTrue(r["ok"], r["layers"])
        self.assertEqual(rec["data"]["source"]["format"], "spdx-json")
        with open(source_file(self.led, rec["data"]["source"]["sha256"]), "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), rec["data"]["source"]["sha256"])

    def test_an_oversized_document_is_refused_unread(self):
        from cra_evidence.sbom import MAX_SOURCE_BYTES
        big = os.path.join(self.d, "big.json")
        with open(big, "wb") as f:
            f.truncate(MAX_SOURCE_BYTES + 1)                                                  # sparse: nothing is read if the guard holds
        with self.assertRaises(ValueError) as cm:
            sbom_from_cyclonedx(big, "tiny-cra-sample", "1.0.0")
        self.assertIn("refused unread", str(cm.exception))
        sb = sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0")
        from dataclasses import replace
        import cra_evidence.locker as lm
        opened = []
        real_open = open
        lm.open = lambda path, *a, **k: (opened.append(str(path)), real_open(path, *a, **k))[1]
        try:
            with self.assertRaises(ValueError) as cm:                                         # and at record time, BEFORE any read
                self.lk.record_sbom(replace(sb, source={**sb.source, "sha256": "0" * 64}), source_path=big)
        finally:
            del lm.open
        self.assertIn("refused unread", str(cm.exception))
        self.assertNotIn(big, opened)

    def test_schema_bounds_and_product_type_from_the_document(self):
        from cra_evidence.sbom import SCHEMA_TEXT_MAX
        p = os.path.join(self.d, "long.json")
        with open(p, "w") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.7", "metadata": {"component": {"type": "firmware", "name": "fw", "version": "1"}},
                       "components": [{"type": "library", "name": "a", "version": "9" * 1100}]}, f)
        r = sbom_from_cyclonedx(p, "tiny-cra-sample", "1.0.0")
        self.assertEqual(len(r.components[0].version), SCHEMA_TEXT_MAX)                      # bounded to the schema's maxLength, never exported invalid
        self.assertEqual(r.product_type, "firmware")                                          # the generator's metadata.component.type, not a default
        self.assertEqual(r.to_cyclonedx_min("1.7")["metadata"]["component"]["type"], "firmware")
        with self.assertRaises(ValueError):
            SBOMRecord("p", "v" * 1100, [SBOMComponent("a", "1")]).to_cyclonedx_min()
        syft = ingest(os.path.join(HERE, "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json"))
        self.assertEqual(syft.product_type, "file")                                           # Syft declares the scanned directory as `file`

    def test_deeply_nested_and_duplicate_key_documents_are_malformed_not_crashes(self):
        deep = os.path.join(self.d, "deep.json")
        with open(deep, "w") as f:
            f.write('{"bomFormat":"CycloneDX","specVersion":"1.6","components":' + '[{"name":"a","components":' * 3000 + "[]" + "}]" * 3000 + "}")
        with self.assertRaises(ValueError):
            sbom_from_cyclonedx(deep, "p", "1")
        dup = os.path.join(self.d, "dup.json")
        with open(dup, "w") as f:
            f.write('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"components":[{"name":"x","version":"1"}]}')
        with self.assertRaises(ValueError):
            sbom_from_cyclonedx(dup, "p", "1")
        with self.assertRaises(ValueError):
            sbom_from_spdx(deep, "p", "1")
        sur = os.path.join(self.d, "sur.json")
        with open(sur, "w") as f:                                                              # a lone surrogate escape has no UTF-8 encoding: malformed, not a TypeError at record time
            f.write('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a\\ud800","version":"1"}]}')
        with self.assertRaises(ValueError):
            sbom_from_cyclonedx(sur, "p", "1")

    def test_a_mutated_index_is_refused_even_with_the_right_document(self):
        """found by Sonnet in round 2: the index was only co-located with the bytes, not a function of them"""
        from dataclasses import replace
        sb = sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0")
        for bad in (replace(sb, components=[SBOMComponent("left-pad", "9.9.9")]),
                    replace(sb, components=sb.components[:-1]),
                    replace(sb, source={**sb.source, "generator": "forged"}),
                    replace(sb, edges=[["", "base64-js"]]),                                          # round 3 (Opus/Sonnet): a forged graph rode through
                    replace(sb, depth="external:cyclonedx:trusted-tool")):
            with self.assertRaises(ValueError) as cm:
                self.lk.record_sbom(bad, source_path=self.src)
            self.assertIn("does not match the document", str(cm.exception))
        with self.assertRaises(ValueError):                                                   # another product's SBOM in this locker
            self.lk.record_sbom(replace(sb, product_version="2.0"), source_path=self.src)
        self.assertEqual(self.lk.verify()["entries"], 0)

    def test_ingest_reads_the_file_once(self):
        """found by Sonnet in round 2: two reads of a file still being written = index of A, hash of B"""
        import cra_evidence.sbom as m
        opened = []
        real_open = open
        def spy(path, *a, **k):
            if str(path) == self.src:
                opened.append(a[0] if a else k.get("mode", "r"))
            return real_open(path, *a, **k)
        m.open = spy
        try:
            sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0")
        finally:
            del m.open
        self.assertEqual(opened, ["rb"])

    def test_spdx_type_confusion_never_crashes(self):
        """round 5 (Sonnet/Opus): a list where a string id is expected raised TypeError instead of being ignored"""
        docs = [{"spdxVersion": "SPDX-2.3", "documentDescribes": [["x"]], "packages": [{"name": "a", "SPDXID": "S-a", "versionInfo": "1"}],
                 "relationships": [{"spdxElementId": ["S-a"], "relatedSpdxElement": {"x": 1}, "relationshipType": "DESCRIBES"}]},
                {"spdxVersion": "SPDX-2.3", "packages": 5, "relationships": "x", "documentDescribes": [{"a": 1}]},
                {"spdxVersion": "SPDX-2.3", "packages": [{"name": "a", "SPDXID": ["S-a"], "versionInfo": ["1"]}, {"name": ["b"], "SPDXID": {"x": 1}}],
                 "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "S-a", "relationshipType": "DESCRIBES"}]},
                {"spdxVersion": "SPDX-2.3", "packages": [{"name": "a", "externalRefs": 3, "checksums": {"a": 1}, "versionInfo": "1"}]},
                {"@graph": [{"type": "software_Package", "spdxId": ["p1"], "name": "a"}, {"type": "SpdxDocument", "rootElement": [["r"]]},
                            {"type": "Relationship", "relationshipType": "describes", "from": ["x"], "to": [{"a": 1}]},
                            {"type": "software_Package", "spdxId": "p2", "name": "b", "verifiedUsing": 7, "externalIdentifier": [{"externalIdentifierType": "cpe23", "identifier": ["cpe:2.3:a:x"]}]}]}]
        for i, doc in enumerate(docs):
            p = os.path.join(self.d, f"tc{i}.json")
            with open(p, "w") as f:
                json.dump(doc, f)
            r = sbom_from_spdx(p, "tiny-cra-sample", "1.0.0")            # a record, or ValueError — never TypeError
            self.assertIsInstance(r.components, list)
            for c in r.components:                                        # a hostile non-string field is never stringified into data
                for v in (c.name, c.version, c.purl, c.license, c.supplier, c.cpe):
                    self.assertNotIn("[", v); self.assertNotIn("{", v)
        cdx = os.path.join(self.d, "tc_cdx.json")
        with open(cdx, "w") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": {"x": 1}, "version": "1"}, {"name": "ok", "version": [1], "purl": {"p": 1}, "type": 3}]}, f)
        r = sbom_from_cyclonedx(cdx, "tiny-cra-sample", "1.0.0")
        self.assertEqual([(c.name, c.version, c.purl, c.type) for c in r.components], [("ok", "", "", "library")])

    def test_store_never_overwrites_different_bytes(self):
        sb = sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0")
        os.makedirs(sources_dir(self.led))
        with open(source_file(self.led, sb.source["sha256"]), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(ValueError) as cm:
            self.lk.record_sbom(sb, source_path=self.src)
        self.assertIn("refusing to overwrite", str(cm.exception))
        with open(source_file(self.led, sb.source["sha256"]), "rb") as f:
            self.assertEqual(f.read(), b"{}")

    def test_same_document_twice_is_one_stored_copy(self):
        self._record_and_pack()
        self.lk.record_sbom(sbom_from_cyclonedx(self.src, "tiny-cra-sample", "1.0.0"), source_path=self.src)
        self.assertEqual(len(os.listdir(sources_dir(self.led))), 1)

    def test_a_document_with_floats_is_stored_byte_exact_and_the_ledger_stays_float_free(self):
        """cdxgen 12.x emits evidence.identity[].confidence = 0.8 (measured 20/09/2026 on a 294-component tree);
        the profile forbids floats in hashed content — the bytes are stored, the index never carries the float"""
        p = os.path.join(self.d, "cdxgen_like.json")
        with open(p, "w") as f:
            f.write('{"bomFormat":"CycloneDX","specVersion":"1.7","metadata":{"tools":{"components":[{"type":"application","name":"cdxgen","version":"12.8.4"}]}},'
                    '"components":[{"type":"library","name":"a","version":"1","purl":"pkg:npm/a@1","evidence":{"identity":[{"field":"purl","confidence":0.8}]}}]}')
        sb = sbom_from_cyclonedx(p, "tiny-cra-sample", "1.0.0")
        from dataclasses import asdict
        canonical_bytes(asdict(sb))                       # the INDEX carries no float (this raises on one; `_bind` would stringify it later)
        rec = self.lk.record_sbom(sb, source_path=p)
        def leaves(o):
            if isinstance(o, dict):
                for v in o.values():
                    yield from leaves(v)
            elif isinstance(o, list):
                for v in o:
                    yield from leaves(v)
            else:
                yield o
        self.assertFalse(any(isinstance(x, float) or x == "0.8" for x in leaves(rec["data"])))   # neither as a number nor as its string
        with open(source_file(self.led, rec["data"]["source"]["sha256"]), "rb") as a, open(p, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_malformed_hash_in_a_record_is_a_fail_not_a_path(self):
        from cra_evidence.verify_pack import _source_documents
        entries = [{"data": {"kind": "cra_sbom", "source": {"sha256": "../../etc/passwd"}}}]
        lay = _source_documents(self.led, entries, False)
        self.assertEqual(lay["status"], "FAIL")
        self.assertIn("malformed source hash", lay["detail"])
        with self.assertRaises(ValueError):
            source_file(self.led, "../../etc/passwd")
        # the same semantics in all four verifiers (differential oracle cases sbom_source_hash_is_*): null / "" = no hash
        # recorded; any other non-64-hex value (int, object, upper-case hex, traversal) = FAIL
        for v, status in ((None, "SKIP"), ("", "SKIP"), (123, "FAIL"), ({"x": 1}, "FAIL"), ("A" * 64, "FAIL")):
            self.assertEqual(_source_documents(self.led, [{"data": {"kind": "cra_sbom", "source": {"sha256": v}}}], False)["status"], status, v)


class TestExport(unittest.TestCase):
    def _validators(self):
        try:
            import jsonschema
            from referencing import Registry, Resource
        except ImportError:
            self.skipTest("jsonschema/referencing not installed")
        jsf = json.load(open(os.path.join(SCHEMAS, "jsf-0.82.schema.json"))); spdx = json.load(open(os.path.join(SCHEMAS, "spdx.schema.json")))
        reg = Registry().with_resources([(jsf["$id"], Resource.from_contents(jsf)), (spdx["$id"], Resource.from_contents(spdx)),
                                         ("jsf-0.82.schema.json", Resource.from_contents(jsf)), ("spdx.schema.json", Resource.from_contents(spdx))])
        return {v: jsonschema.Draft7Validator(json.load(open(os.path.join(SCHEMAS, f"bom-{v}.schema.json"))), registry=reg) for v in ("1.6", "1.7")}

    def test_exports_validate_against_the_official_1_6_and_1_7_schemas(self):
        vs = self._validators()
        records = [ingest(p) for p in REAL] + [sbom_from_installed("cra-evidence", "0.3.0", ["cryptography"], transitive=True),
                                                SBOMRecord("p", "1", [SBOMComponent("a", "1", license="Apache-2.0 OR BSD-3-Clause"), SBOMComponent("b", "2", license="Proprietary")])]
        for r in records:
            for v, val in vs.items():
                errs = [e.message for e in val.iter_errors(r.to_cyclonedx_min(v))]
                self.assertEqual(errs, [], (r.depth, v))
        # positive control: the validator sees a broken document
        bad = records[0].to_cyclonedx_min("1.7"); bad["components"][0]["type"] = "not-a-type"
        self.assertTrue(list(vs["1.7"].iter_errors(bad)))

    def test_spec_version_is_declared_and_bounded(self):
        r = SBOMRecord("p", "1", [SBOMComponent("a", "1")])
        self.assertEqual(r.to_cyclonedx_min("1.7")["specVersion"], "1.7")
        self.assertEqual(r.to_cyclonedx_min()["specVersion"], "1.6")
        with self.assertRaises(ValueError):
            r.to_cyclonedx_min("1.5")

    def test_bom_refs_are_unique_and_dependencies_only_where_known(self):
        r = SBOMRecord("p", "1", [SBOMComponent("a", "1", purl="pkg:npm/x@1"), SBOMComponent("b", "1", purl="pkg:npm/x@1"), SBOMComponent("p", "1")])
        out = r.to_cyclonedx_min()
        refs = [c["bom-ref"] for c in out["components"]] + [out["metadata"]["component"]["bom-ref"]]
        self.assertEqual(len(refs), len(set(refs)), refs)
        self.assertNotIn("dependencies", out)                                                          # no edges known → none invented
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography not installed (the installed-floor part of this test needs it)")
        inst = sbom_from_installed("p", "1", ["cryptography", "no-such-dist-xyz"]).to_cyclonedx_min()   # top-level floor: all direct…
        self.assertEqual(inst["dependencies"], [{"ref": inst["metadata"]["component"]["bom-ref"], "dependsOn": [c["bom-ref"] for c in inst["components"]]}])
        # …and NOTHING else: `dependsOn: []` would assert "no dependencies" for a component whose Requires-Dist was never read
        self.assertEqual(inst["compositions"], [{"aggregate": "unknown", "dependencies": [c["bom-ref"] for c in inst["components"]]}])   # not "incomplete": that would assert more exist
        tr = sbom_from_installed("p", "1", ["cryptography", "no-such-dist-xyz"], transitive=True)
        deps = {d["ref"]: d["dependsOn"] for d in tr.to_cyclonedx_min("1.7")["dependencies"]}
        self.assertNotIn("no-such-dist-xyz@NOT-INSTALLED", deps)                                        # not read → not in the graph
        self.assertEqual(sorted(tr.to_cyclonedx_min("1.7")["compositions"][0]["dependencies"]), ["no-such-dist-xyz@NOT-INSTALLED"])
        cry = next(c for c in tr.components if c.name == "cryptography")
        self.assertEqual(deps["p@1"], ["pkg:pypi/cryptography@" + cry.version, "no-such-dist-xyz@NOT-INSTALLED"])
        self.assertIn("cryptography", tr.source["requires_dist_read"])
        self.assertNotIn("no-such-dist-xyz", tr.source["requires_dist_read"])
        for key in tr.source["requires_dist_read"]:                                                    # every walked component IS in the graph
            self.assertTrue(any(r.startswith(f"pkg:pypi/{key}@") for r in deps), key)
        comp = tr.to_cyclonedx_min("1.7")["compositions"][0]
        self.assertEqual(comp["aggregate"], "unknown")
        self.assertFalse(set(comp["dependencies"]) & set(deps), "a walked component is never in the unknown composition")
        rec = ingest(REAL[0]); ing = rec.to_cyclonedx_min()
        self.assertNotIn("dependencies", ing)                                                          # never re-invented for an ingested graph
        self.assertIn({"name": "cra-evidence:source_sha256", "value": rec.source["sha256"]}, ing["metadata"]["properties"])
        self.assertEqual(ing["serialNumber"], "urn:uuid:" + rec.record_id)
        self.assertEqual(ing["metadata"]["tools"]["components"][0]["name"], "cra-evidence")

    def test_licence_expression_and_pep639(self):
        self.assertTrue(is_spdx_expression("Apache-2.0 OR BSD-3-Clause"))
        self.assertFalse(is_spdx_expression("MIT"))
        self.assertFalse(is_spdx_expression("Foo OR Bar"))
        out = SBOMRecord("p", "1", [SBOMComponent("a", "1", license="Apache-2.0 OR BSD-3-Clause"), SBOMComponent("b", "1", license="MIT"),
                                    SBOMComponent("c", "1", license="Custom")]).to_cyclonedx_min("1.7")
        self.assertEqual([c["licenses"] for c in out["components"]],
                         [[{"expression": "Apache-2.0 OR BSD-3-Clause"}], [{"license": {"id": "MIT"}}], [{"license": {"name": "Custom"}}]])

        class Meta(dict):
            def get_all(self, k):
                return self.get(k)
        self.assertEqual(installed_license(Meta({"License-Expression": "Apache-2.0 OR BSD-3-Clause", "License": ""})), "Apache-2.0 OR BSD-3-Clause")
        self.assertEqual(installed_license(Meta({"License": "MIT"})), "MIT")
        self.assertEqual(installed_license(Meta({"License": "UNKNOWN", "Classifier": ["License :: OSI Approved :: MIT License"]})), "MIT License")
        self.assertEqual(installed_license(Meta({})), "")
        try:                                                                                  # the real distribution, not a synthetic object
            from importlib import metadata as md
            ver = md.version("cryptography")
        except md.PackageNotFoundError:
            return
        if tuple(int(x) for x in ver.split(".")[:2]) >= (46, 0):
            self.assertEqual(installed_license(md.metadata("cryptography")), "Apache-2.0 OR BSD-3-Clause")
            self.assertEqual((md.metadata("cryptography").get("License") or "").strip(), "")

    def test_pep508_markers_decide_the_edges_of_this_interpreter(self):
        from cra_evidence.sbom import marker_applies
        self.assertTrue(marker_applies(""))
        self.assertEqual(marker_applies("python_version < '2.0'"), False)                         # cryptography's typing-extensions marker shape
        self.assertEqual(marker_applies("python_version >= '3.0' and os_name == 'posix'"), os.name == "posix")
        self.assertEqual(marker_applies("(python_version < '2.0' or python_version >= '3.0') and python_version >= '3.0'"), True)
        self.assertIsNone(marker_applies("no_such_variable == 'x'"))                              # unknown → kept and counted, never dropped
        tr = sbom_from_installed("p", "1", ["cryptography"], transitive=True)
        self.assertIsInstance(tr.source["markers_unevaluated_kept"], int)
        # cryptography 50 declares typing-extensions only for python_full_version < '3.11': absent on newer interpreters
        if sys.version_info >= (3, 11) and any(c.name == "cryptography" and c.version.startswith("5") for c in tr.components):
            self.assertNotIn("typing-extensions", [c.name.replace("_", "-") for c in tr.components])

    def test_fingerprint_is_the_raw_bytes(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "x.json")
            with open(p, "wb") as f:
                f.write(b'{"a": 1.0}\n')
            self.assertEqual(source_fingerprint(p), {"sha256": hashlib.sha256(b'{"a": 1.0}\n').hexdigest(), "size_bytes": 11, "file": "x.json"})
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
