"""2026-10-05 — no shipped module leaves a file or URL handle to the garbage collector: every open()/urlopen() in
cra_evidence/ is a `with` item. `cra notice --previous` and `cra seal --renew` read their JSON through an unclosed
open(); this test was RED on that code (cli.py lines 135 and 155) and is GREEN after the fix."""
import ast, os, unittest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cra_evidence")


def unclosed(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    managed = {id(i.context_expr) for n in ast.walk(tree) if isinstance(n, (ast.With, ast.AsyncWith)) for i in n.items}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and id(n) not in managed:
            fn = n.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            is_os = isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "os"
            if name in ("open", "urlopen") and not is_os:
                out.append(f"{os.path.relpath(path, PKG)}:{n.lineno}")
    return out


class TestOpenHandles(unittest.TestCase):
    def test_every_open_is_a_with_item(self):
        files = [os.path.join(d, f) for d, _, fs in os.walk(PKG) for f in fs if f.endswith(".py")]
        self.assertGreater(len(files), 3)                 # the walk reached the package
        self.assertEqual([x for p in sorted(files) for x in unclosed(p)], [])


if __name__ == "__main__":
    unittest.main()
