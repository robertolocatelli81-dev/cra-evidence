"""SPDX ingest on the OFFICIAL spdx/spdx-examples documents (vendored in tests/fixtures/spdx): 2.3 JSON with purl
and checksums, 2.3 enriched (NOASSERTION licences, no versions), 3.0 JSON-LD with packageUrl and licence relationships,
3.0 enriched with suppliedBy/verifiedUsing. The described product is never a component."""
import json, os, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from cra_evidence.sbom import sbom_from_spdx, resolved_components
from cra_evidence.locker import CRAEvidenceLocker

FX = os.path.join(ROOT, "tests", "fixtures", "spdx")


class TestSPDX(unittest.TestCase):
    def test_spdx23_with_purl_and_dependency(self):
        r = sbom_from_spdx(os.path.join(FX, "spdx-2.3-dependency.spdx.json"), "p", "1")
        names = {c.name: c for c in r.components}
        self.assertNotIn("tools-java", names)                 # DESCRIBES target = the product, not a dependency
        self.assertIn("xlsx", names)
        self.assertEqual(names["xlsx"].purl, "pkg:maven/org.webjars.npm/xlsx@0.16.6")
        self.assertEqual(names["xlsx"].version, "0.16.6"); self.assertEqual(names["xlsx"].supplier, "Webjar")
        self.assertEqual(names["xlsx"].sha256, "")            # only SHA1 in the document: no SHA-256 is invented
        self.assertTrue(r.depth.startswith("external:SPDX-2.3:"))

    def test_spdx23_enriched_noassertion(self):
        r = sbom_from_spdx(os.path.join(FX, "spdx-2.3-enriched.spdx.json"), "p", "1")
        junit = next(c for c in r.components if c.name == "JUnit")
        self.assertEqual(junit.license, "CPL-1.0")            # concluded NOASSERTION → declared
        self.assertTrue(any(c.version == "NOASSERTION" for c in r.components))
        self.assertLess(len(resolved_components(r)), len(r.components))   # NOASSERTION versions are not resolved

    def test_spdx30_jsonld(self):
        r = sbom_from_spdx(os.path.join(FX, "spdx-3.0-sbom.spdx3.json"), "p", "1")
        self.assertTrue(r.depth.startswith("external:SPDX-3.0:"))
        purls = {c.purl for c in r.components}
        self.assertIn("pkg:cargo/tokio@1.19.2", purls)
        self.assertNotIn("hello-server-src", {c.name for c in r.components})   # `describes` target = the product
        self.assertEqual(next(c for c in r.components if c.name == "tokio").license, "MIT")   # via hasConcludedLicense

    def test_spdx30_enriched_supplier(self):
        r = sbom_from_spdx(os.path.join(FX, "spdx-3.0-enriched.spdx3.json"), "p", "1")
        self.assertTrue(r.components)
        sups = {c.supplier for c in r.components}
        self.assertTrue(any(s for s in sups), sups)           # suppliedBy resolved to the Organization's name

    def test_rejects_other_shapes_and_records_floor(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.json"); json.dump({"bomFormat": "CycloneDX"}, open(p, "w"))
        with self.assertRaises(ValueError):
            sbom_from_spdx(p, "p", "1")
        lk = CRAEvidenceLocker(os.path.join(d, "l.jsonl"), "p", "1")
        e = lk.record_sbom(sbom_from_spdx(os.path.join(FX, "spdx-2.3-dependency.spdx.json"), "p", "1"))
        self.assertTrue(e["data"]["sbom_floor_met"])
        self.assertEqual(e["data"]["sbom"]["specVersion"], "1.6")   # exported as schema-valid CycloneDX



class TestSPDXCouncil(unittest.TestCase):
    """Council 15/09 (five models) on the SPDX ingest: rootElement roots, expanded JSON-LD, DESCRIBED_BY, licence IRIs,
    supplier fallback after cleaning, malformed checksums, floor on NOASSERTION, non-SPDX @graph refused."""
    def _w(self, obj):
        d = tempfile.mkdtemp(); p = os.path.join(d, "x.json"); json.dump(obj, open(p, "w")); return p

    def test_rootelement_and_expanded_form_and_license_iri(self):
        doc = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [
            {"@type": "software_Sbom", "@id": "urn:sbom", "rootElement": ["urn:pkg:app"]},
            {"@type": "https://spdx.org/rdf/3.0.1/terms/Software/Package", "@id": "urn:pkg:app", "name": "app", "software_packageVersion": "1.0"},
            {"@type": "software_Package", "@id": "urn:pkg:dep", "name": "dep", "software_packageVersion": "2.0",
             "software_packageUrl": "pkg:npm/dep@2.0", "verifiedUsing": [{"@type": "Hash", "algorithm": "sha256", "hashValue": "ab" * 32}]},
            {"@type": "Relationship", "@id": "urn:r1", "relationshipType": "hasConcludedLicense", "from": "urn:pkg:dep", "to": ["https://spdx.org/licenses/MIT"]}]}
        r = sbom_from_spdx(self._w(doc), "p", "1")
        self.assertEqual([c.name for c in r.components], ["dep"])           # the rootElement product is not a component
        self.assertEqual(r.components[0].license, "MIT"); self.assertEqual(r.components[0].sha256, "ab" * 32)

    def test_no_root_declared_is_said_and_non_spdx_graph_refused(self):
        doc = {"@graph": [{"type": "software_Package", "spdxId": "urn:a", "name": "a", "software_packageVersion": "1"}]}
        self.assertIn(":no-root-declared", sbom_from_spdx(self._w(doc), "p", "1").depth)
        with self.assertRaises(ValueError):
            sbom_from_spdx(self._w({"@graph": [{"@id": "item1", "name": "Example"}]}), "p", "1")

    def test_spdx2_described_by_supplier_fallback_and_bad_checksum(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "prod", "SPDXID": "SPDXRef-P", "versionInfo": "1"},
            {"name": "lib", "SPDXID": "SPDXRef-L", "versionInfo": "2", "supplier": "NOASSERTION", "originator": "Organization: Acme (Bar) Ltd (x@y.z)",
             "checksums": [{"algorithm": "SHA256", "checksumValue": "ZZ" * 32}]}],
            "relationships": [{"spdxElementId": "SPDXRef-P", "relationshipType": "DESCRIBED_BY", "relatedSpdxElement": "SPDXRef-DOCUMENT"}]}
        r = sbom_from_spdx(self._w(doc), "p", "1")
        self.assertEqual([c.name for c in r.components], ["lib"])
        self.assertEqual(r.components[0].supplier, "Acme (Bar) Ltd"); self.assertEqual(r.components[0].sha256, "")

    def test_floor_not_met_by_noassertion_versions(self):
        lk = CRAEvidenceLocker(os.path.join(tempfile.mkdtemp(), "l.jsonl"), "p", "1")
        doc = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "lib", "SPDXID": "SPDXRef-L"}], "documentDescribes": []}
        e = lk.record_sbom(sbom_from_spdx(self._w(doc), "p", "1"))
        self.assertFalse(e["data"]["sbom_floor_met"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
