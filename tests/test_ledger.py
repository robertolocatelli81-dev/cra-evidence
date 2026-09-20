import json, os, shutil, sys, tempfile, unittest
from multiprocessing import Process
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cra_evidence.ledger import Ledger, GENESIS
from cra_evidence.canonical import sha256_hex


def _worker(path, n, tag):
    led = Ledger(path)
    for i in range(n):
        led.append({"w": tag, "i": i})


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.p = os.path.join(self.d, "l.jsonl")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_chain_and_profile(self):
        led = Ledger(self.p)
        for i in range(3):
            led.append({"i": i}, ts="2026-09-15T10:00:0%dZ" % i)
        es = list(led.entries())
        self.assertEqual([e["idx"] for e in es], [0, 1, 2]); self.assertEqual(es[0]["prev_hash"], GENESIS)
        self.assertEqual(es[1]["prev_hash"], es[0]["self_hash"])
        self.assertEqual(es[2]["self_hash"], sha256_hex({k: v for k, v in es[2].items() if k != "self_hash"}))
        self.assertTrue(led.verify()["chain_ok"])

    def test_empty_is_fail_and_tamper_detected(self):
        led = Ledger(self.p); open(self.p, "w").close()
        self.assertFalse(led.verify()["chain_ok"])
        for i in range(4):
            led.append({"i": i})
        lines = open(self.p).read().split("\n")
        e = json.loads(lines[1]); e["data"]["i"] = 99; lines[1] = json.dumps(e, sort_keys=True, separators=(",", ":"))
        open(self.p, "w").write("\n".join(lines))
        r = led.verify(); self.assertFalse(r["chain_ok"]); self.assertTrue(any("self_hash" in f for f in r["failures"]))

    def test_floats_refused_before_write(self):
        led = Ledger(self.p)
        with self.assertRaises(TypeError):
            led.append({"score": 1.5})
        self.assertFalse(os.path.exists(self.p) and os.path.getsize(self.p) > 0)

    def test_unterminated_tail_closed_and_torn_tail_refused(self):
        led = Ledger(self.p)
        led.append({"i": 0}); body = open(self.p, "rb").read(); open(self.p, "wb").write(body[:-1])
        led.append({"i": 1})
        self.assertEqual(len([l for l in open(self.p, "rb").read().split(b"\n") if l]), 2); self.assertTrue(led.verify()["chain_ok"])
        open(self.p, "ab").write(b'{"idx":2,"ts":"t","data":{"a":')
        with self.assertRaises(ValueError):
            led.append({"i": 2})

    def test_four_processes_one_chain(self):
        ps = [Process(target=_worker, args=(self.p, 60, t)) for t in range(4)]
        [x.start() for x in ps]; [x.join() for x in ps]
        es = list(Ledger(self.p).entries()); self.assertEqual(len(es), 240)
        self.assertEqual(sum(1 for a, b in zip(es, es[1:]) if b["prev_hash"] != a["self_hash"]), 0)
        self.assertTrue(Ledger(self.p).verify()["chain_ok"])




class TestLineCap(unittest.TestCase):
    def test_a_record_above_64_mib_is_refused_before_writing(self):
        from cra_evidence.ledger import MAX_LINE_BYTES
        import tempfile
        d = tempfile.mkdtemp(); p = os.path.join(d, "l.jsonl")
        led = Ledger(p)
        led.append({"k": "small"})
        with self.assertRaises(ValueError):
            led.append({"pad": "a" * MAX_LINE_BYTES})
        self.assertEqual(led.verify()["entries"], 1)          # nothing half-written
        shutil.rmtree(d, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
