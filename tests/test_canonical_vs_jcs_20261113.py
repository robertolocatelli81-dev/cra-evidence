# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure (13/11/2026): where does the canonical profile of this package (`canonical_bytes`: sorted keys, separators
(",", ":"), ASCII-escaped, no floats, integers within ±(2^53−1)) give the same bytes as RFC 8785 (JCS), and where not?

Why: the profile is cryptovalid's acceptance profile (omega_cra_evol/canonical.py), and RFC 8785 is the canonical form
other formats sign. If a ledger line is ever handed to a JCS verifier, the answer decides whether the hash matches. Answer, measured below: the same bytes if and only if every
character of every key and string is in U+0000..U+007E; U+007F and every non-ASCII character are escaped by the profile
and raw UTF-8 in JCS, and beyond the BMP the member order differs too (code points against UTF-16 code units).

No product code is changed by this file. Two JCS encoders, independent of each other, are compared with the profile:
  - `jcs()` below, written for the float-free domain from the rules of RFC 8785 §3.2.2.2 (strings: only `"`, `\\` and
    U+0000..U+001F escaped, everything else literal UTF-8) and §3.2.3 (members sorted by UTF-16 code units);
  - Node's own `JSON.stringify` with keys in `Array.prototype.sort` default order (UTF-16 code units) — the serializer
    RFC 8785 is defined on. Skipped when `node` is not installed.
`jcs()` has a known answer: the member-ordering test data of RFC 8785 §3.2.3, read on 13/11/2026 in
https://www.rfc-editor.org/rfc/rfc8785.txt (sha256 63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240).
Positive control (13/11/2026, three mutations on a copy, each turns this file red): the profile without ASCII escaping,
the JCS encoder sorting by code point, the JCS encoder escaping like the profile.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol.canonical import MAX_SAFE_INT, canonical_bytes


def jcs(obj) -> bytes:
    """RFC 8785 on the domain the profile accepts (null, bool, int within ±(2^53−1), str, list, dict of str)."""
    def enc(x):
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            assert abs(x) <= MAX_SAFE_INT
            return str(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, list):
            return "[" + ",".join(enc(v) for v in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in keys) + "}"
        raise TypeError(type(x).__name__)
    return enc(obj).encode("utf-8")


_NODE_JCS = r"""
const canon = (v) => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
};
let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
  const out = JSON.parse(s).map((doc) => Buffer.from(canon(doc), "utf8").toString("hex"));
  process.stdout.write(JSON.stringify(out));
});
"""


def node_jcs(docs):
    """JCS bytes of each document, computed by Node (None if node is absent)."""
    if not shutil.which("node"):
        return None
    p = subprocess.run(["node", "-e", _NODE_JCS], input=json.dumps(docs, ensure_ascii=True).encode(),
                       capture_output=True, timeout=120, check=True)
    return [bytes.fromhex(h) for h in json.loads(p.stdout)]


# (name, document, same bytes as JCS?)
CASES = [
    ("ascii", {"b": [1, "x", None, True], "a": {"k": "v"}}, True),
    ("ascii_escapes", {"q": "a\"b\\c/d<&>", "n": "line\nfeed\ttab"}, True),
    ("control_1f", {"c": "\x1f\x00\x08\x0c"}, True),
    ("int_limits", {"hi": MAX_SAFE_INT, "lo": -MAX_SAFE_INT, "z": 0}, True),
    ("empty", {"": "", "l": [], "o": {}}, True),
    ("del_7f", {"d": "\x7f"}, False),      # ASCII, and still different: the profile escapes U+007F, JCS does not
    ("value_e_grave", {"note": "è"}, False),
    ("key_e_grave", {"è": 1}, False),
    ("value_u0080", {"c1": "\u0080"}, False),
    ("value_u2028", {"ls": "\u2028"}, False),
    ("value_astral", {"emoji": "\U0001F600"}, False),
    ("key_order_astral_vs_e000", {"": 1, "\U00010000": 2}, False),
]


class TestProfileVersusJCS(unittest.TestCase):
    def test_jcs_known_answer_rfc8785_3_2_3(self):
        # RFC 8785 §3.2.3: the expected member order is CR, "1", U+0080, U+00F6, U+20AC, U+1F600, U+FB33
        doc = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control",
               "ö": "Latin Small Letter O With Diaeresis"}
        order = list(json.loads(jcs(doc).decode("utf-8")))
        self.assertEqual(order, ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"])

    def test_cases(self):
        for name, doc, same in CASES:
            with self.subTest(case=name):
                self.assertEqual(canonical_bytes(doc) == jcs(doc), same,
                                 f"{name}: profile={canonical_bytes(doc)!r} jcs={jcs(doc)!r}")
                # both are the same JSON value: the difference is in the bytes, never in the data
                self.assertEqual(json.loads(canonical_bytes(doc)), json.loads(jcs(doc).decode("utf-8")))

    def test_exact_bytes_of_the_smallest_divergence(self):
        self.assertEqual(canonical_bytes({"note": "è"}), b'{"note":"\\u00e8"}')
        self.assertEqual(jcs({"note": "è"}), b'{"note":"\xc3\xa8"}')

    def test_del_is_ascii_and_still_diverges(self):
        self.assertEqual(canonical_bytes({"d": "\x7f"}), b'{"d":"\\u007f"}')
        self.assertEqual(jcs({"d": "\x7f"}), b'{"d":"\x7f"}')

    def test_key_order_differs_beyond_the_bmp(self):
        doc = {"": 1, "\U00010000": 2}
        self.assertEqual(list(json.loads(canonical_bytes(doc))), ["", "\U00010000"])     # code points
        self.assertEqual(list(json.loads(jcs(doc).decode("utf-8"))), ["\U00010000", ""])   # UTF-16 code units

    def test_node_agrees_with_the_jcs_encoder_here(self):
        docs = [d for _, d, _ in CASES]
        got = node_jcs(docs)
        if got is None:
            self.skipTest("node not installed")
        for (name, doc, _), b in zip(CASES, got):
            with self.subTest(case=name):
                self.assertEqual(b, jcs(doc))

    def _random_doc(self, rng, alphabet, depth=0):
        def s():
            return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))
        r = rng.random()
        if depth > 3 or r < 0.35:
            return rng.choice([None, True, False, rng.randint(-MAX_SAFE_INT, MAX_SAFE_INT), rng.randint(-9, 9), s()])
        if r < 0.6:
            return [self._random_doc(rng, alphabet, depth + 1) for _ in range(rng.randint(0, 4))]
        return {s(): self._random_doc(rng, alphabet, depth + 1) for _ in range(rng.randint(0, 4))}

    @staticmethod
    def _strings(x):
        if isinstance(x, str):
            yield x
        elif isinstance(x, list):
            for v in x:
                yield from TestProfileVersusJCS._strings(v)
        elif isinstance(x, dict):
            for k, v in x.items():
                yield k
                yield from TestProfileVersusJCS._strings(v)

    def test_property_same_bytes_exactly_when_no_character_is_above_u007e(self):
        ascii_alpha = [chr(c) for c in range(0x00, 0x7f)]          # U+0000..U+007E
        mixed_alpha = ascii_alpha[0x20:] + ["\x7f"] + list("èöß€\u0080 דּ") + ["\U00010000", "\U0001F600"]
        rng = random.Random(20261113)
        ascii_docs = [self._random_doc(rng, ascii_alpha) for _ in range(2000)]
        mixed_docs = [self._random_doc(rng, mixed_alpha) for _ in range(2000)]
        n_equal = n_diff = 0
        for doc in ascii_docs + mixed_docs:
            is_ascii = all(ord(c) <= 0x7e for s in self._strings(doc) for c in s)
            self.assertEqual(canonical_bytes(doc) == jcs(doc), is_ascii, repr(doc))
            n_equal += is_ascii
            n_diff += not is_ascii
        self.assertGreaterEqual(n_equal, 2000)     # the equality side is not vacuous …
        self.assertGreaterEqual(n_diff, 500)       # … and neither is the divergence side
        got = node_jcs(ascii_docs + mixed_docs)
        if got is not None:                        # second, independent JCS: Node's JSON.stringify
            for doc, b in zip(ascii_docs + mixed_docs, got):
                self.assertEqual(b, jcs(doc), repr(doc))


if __name__ == "__main__":
    unittest.main()
