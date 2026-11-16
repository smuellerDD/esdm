#!/usr/bin/env python3
"""Tests of typstdiff.py (python3 -m unittest test_typstdiff).

The merges are compiled with typst when it is in PATH; then every result
must compile without errors and warnings."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import typstdiff as T  # noqa: E402

TYPST = shutil.which("typst")


def tokens(src):
    return [(t.kind, src[t.start:t.end]) for t in T.Parser(src).parse()]


def blocks(src):
    p = T.Parser(src)
    return [(b.kind, src[b.start:b.end]) for b in
            T.Grouper(p).group(p.parse())]


class ParserTest(unittest.TestCase):
    def test_words_and_markup(self):
        toks = tokens("a *strong* _emph_ snake_case x*y `raw` $x^2$ @ref.")
        kinds = [k for k, _ in toks if k != "space"]
        self.assertEqual(kinds, ["text", "strong", "emph", "text", "text",
                                 "raw", "math", "ref", "text"])
        self.assertIn(("text", "snake_case"), toks)
        self.assertIn(("ref", "@ref"), toks)

    def test_code(self):
        src = '#figure(image("a.svg", width: 50%), caption: [A *b*]) <fig>'
        toks = T.Parser(src).parse()
        self.assertEqual(toks[0].kind, "code")
        self.assertEqual(T.callee_of(toks[0].a["expr"]), "figure")
        pos, named = T.call_args(toks[0].a["expr"])
        self.assertEqual(len(pos), 1)
        self.assertEqual(sorted(named), ["caption"])
        self.assertEqual(toks[-1].kind, "label")

    def test_raw_and_escapes(self):
        toks = tokens("````\n```inner```\n```` a\\_b \\ c // x\n/* y */")
        self.assertEqual(toks[0][0], "raw")
        self.assertIn(("text", "a\\_b"), toks)
        self.assertIn(("linebreak", "\\"), toks)
        self.assertEqual([k for k, _ in toks].count("comment"), 2)

    def test_statements(self):
        src = ('#import "t.typ": a, b as c\n#let f(x, y: none) = x\n'
               '#show heading: it => block(it.body)\n#set text(size: 9pt)\n'
               '#show: tmpl.with(title: [T])\n#if x [a] else [b]\n')
        kinds = [b[0] for b in blocks(src)]
        self.assertEqual(kinds, ["stmt"] * 5 + ["code"])

    def test_blocks(self):
        src = ("= Head <h>\n\nPara one\ncontinued #footnote[x]\n"
               "- item\n  continued\n  - nested\n- second\n\n"
               "+ enum\n/ Term: desc\n\n#figure(rect())\nText after.\n")
        got = blocks(src)
        self.assertEqual([k for k, _ in got],
                         ["heading", "par", "item", "item", "item", "item",
                          "call", "par"])
        self.assertEqual(got[2][1], "- item\n  continued\n  - nested")

    def test_url_and_label(self):
        toks = tokens("see https://example.com/a_(b). <lab> a < b")
        self.assertIn(("url", "https://example.com/a_(b)"), toks)
        self.assertIn(("label", "<lab>"), toks)


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="typstdiff-test-")
        self.old = os.path.join(self.tmp, "old")
        self.new = os.path.join(self.tmp, "new")
        self.out = os.path.join(self.tmp, "out")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, side, files):
        root = self.old if side == "old" else self.new
        for rel, text in files.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            mode = "wb" if isinstance(text, bytes) else "w"
            with open(p, mode) as f:
                f.write(text)

    def merge(self, *args, out=None, compile_=("main.typ",)):
        out = out or self.out
        rc = T.main(["--old", self.old, "--new", self.new, "--out", out,
                     "--label-old", "1.0", "--label-new", "2.0"]
                    + list(args))
        self.assertEqual(rc, 0)
        if TYPST:
            for rel in compile_:
                r = subprocess.run(
                    [TYPST, "compile", "--root", out,
                     os.path.join(out, rel),
                     os.path.join(self.tmp, "x.pdf")],
                    capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stderr.strip(), "", r.stderr)
        return out

    def read(self, rel, out=None):
        with open(os.path.join(out or self.out, rel)) as f:
            return f.read()

    def test_words_headings_lists(self):
        self.write("old", {"main.typ":
                           "#set heading(numbering: \"1.1\")\n#outline()\n"
                           "= Intro <intro>\n\nThe quick brown fox.\n\n"
                           "= Gone <gone>\n\nOld text, see @gone.\n\n"
                           "+ one\n+ two\n+ three\n"})
        self.write("new", {"main.typ":
                           "#set heading(numbering: \"1.1\")\n#outline()\n"
                           "= Introduction <intro>\n\nThe slow brown fox.\n\n"
                           "= Fresh <fresh>\n\nSee @fresh.\n\n"
                           "+ one\n+ three\n+ four\n"})
        self.merge("--diff", "main.typ")
        m = self.read("main.typ")
        self.assertIn("#tdel[quick] #tins[slow]", m)
        self.assertIn("= #tdel[Intro ]#tins[Introduction] <intro>", m)
        self.assertIn("#tdel-heading(level: 1)[Gone]", m)
        self.assertNotIn("<gone>", m)
        self.assertIn('#tdref("gone")', m)
        self.assertIn("+ #tdel[two]", m)
        self.assertIn("2. three", m)
        self.assertIn("#show: td-setup", m)

    def test_figures_labels_assets_bib(self):
        old = {"main.typ": "#include \"ch.typ\"\n#include \"gone.typ\"\n"
               "#bibliography(\"refs.bib\")\n",
               "ch.typ": "#figure(image(\"img/a.svg\"), caption: [A]) <fa>\n"
               "\n#figure(rect(), caption: [Old]) <fo>\n\n"
               "See @fo and @fa and @k1 and @k2.\n",
               "gone.typ": "= Removed chapter\n\nIts text @k1.\n",
               "refs.bib": "@misc{k1, title = {One}}\n\n"
               "@misc{k2, title = {Two}}\n",
               "img/a.svg": SVG % "red"}
        new = {"main.typ": "#include \"ch.typ\"\n"
               "#bibliography(\"refs.bib\")\n",
               "ch.typ": "#figure(image(\"img/a.svg\"), caption: [A]) <fa>\n"
               "\nSee @fa and @k1.\n",
               "refs.bib": "@misc{k1, title = {One}}\n",
               "img/a.svg": SVG % "blue"}
        self.write("old", old)
        self.write("new", new)
        self.merge("--diff", "*.typ")
        ch = self.read("ch.typ")
        # changed asset: old figure deleted (paths into .old), new inserted
        self.assertIn('#tdel-block[#figure(outlined: false, '
                      'image("/.old/img/a.svg")', ch)
        self.assertIn('#tins-block[#figure(image("img/a.svg")', ch)
        self.assertEqual(ch.count("<fa>"), 1)
        # deleted figure keeps its label (NEW lacks it), refs resolve
        self.assertIn("<fo>", ch)
        self.assertIn("@fo", ch)
        self.assertIn("@k2", ch)
        main = self.read("main.typ")
        self.assertIn('#include "/gone.typ"', main)
        self.assertIn("#tdel-heading(level: 1)[Removed chapter]",
                      self.read("gone.typ"))
        bib = self.read("refs.bib")
        self.assertIn("@misc{k2", bib)
        self.assertTrue(os.path.exists(os.path.join(self.out, ".old",
                                                    "img", "a.svg")))

    def test_slides_tables_pairs(self):
        tmpl = ("#let slide(n, title: none, items: (), extra: none) = {\n"
                "  [*#title*]\n  for it in items.flatten() [- #it\n]\n"
                "  if extra != none { extra }\n  pagebreak(weak: true)\n}\n")
        self.write("old", {
            "t.typ": tmpl,
            "old-only.typ": "#let shot = [old screenshot]\n",
            "deck-v1.typ": "#import \"t.typ\": *\n#import \"old-only.typ\": *\n"
            "#slide(1, title: [Goals], items: ([A], ([a1], [a2]), [B]))\n"
            "#slide(2, title: [Gone], items: ([X],), extra: shot)\n"
            "#slide(3, title: [Tab], items: ([T],), extra: table(columns: 2,"
            " [a], [b], [c], [d]))\n"})
        self.write("new", {
            "t.typ": tmpl,
            "deck.typ": "#import \"t.typ\": *\n"
            "#slide(1, title: [Goals], items: ([A], ([a1], [a3]), [C]))\n"
            "#slide(2, title: [Tab], items: ([T],), extra: table(columns: 2,"
            " [a], [B], [c], [d]))\n#slide(3, title: [New], items: ([N],))\n"})
        self.merge("--diff", "deck.typ", "--pair", "deck-v1.typ=deck.typ",
                   compile_=("deck.typ",))
        d = self.read("deck.typ")
        self.assertIn('#import "/.old/old-only.typ": shot', d)
        self.assertIn("([a1], [#tdel[a2] #tins[a3]])", d)
        self.assertIn("tdel[B]", d)
        self.assertIn("tins[C]", d)
        self.assertIn("#tslide-del[#slide(2, title: [Gone]", d)
        self.assertIn("[#tdel[b] #tins[B]]", d)
        self.assertIn("#tslide-ins[#slide(3, title: [New]", d)
        # slide numbers are layout only: the first slide is unchanged
        self.assertIn("#slide(1, title: [Goals]", d)

    def test_slides_pair_by_title(self):
        tmpl = ("#let slide(..n, title: none, items: (), x: 0pt, width: "
                "100%, extra: none) = {\n  [*#title*]\n"
                "  for it in items.flatten() [- #it\n]\n"
                "  if extra != none { extra }\n  pagebreak(weak: true)\n}\n")
        self.write("old", {
            "t.typ": tmpl, "f.svg": SVG % "red",
            "deck.typ": "#import \"t.typ\": *\n"
            "#slide(1, title: [ESDM Design], items: ([7 sources], [All ES "
            "treated equally]), extra: image(\"f.svg\"))\n"
            "#slide(2, title: [DRNG Output APIs], items: ([Blocking APIs],"
            " [Prediction Resistance API], ([RPC client API],)))\n"})
        self.write("new", {
            "t.typ": tmpl, "f.svg": SVG % "blue",
            "deck.typ": "#import \"t.typ\": *\n"
            "#slide(title: [ESDM \\ Design], x: 10pt, width: 50%, items: "
            "([12 sources], [All ES treated equally], [Uncredited ES as "
            "additional input]), extra: image(\"f.svg\"))\n"
            "#slide(title: [Prediction Resistance API], items: ([RPC client "
            "API], [Blocking APIs with flag]))\n"
            "#slide(title: [DRNG Output APIs], x: 5pt, items: ([Blocking "
            "APIs], [EGD reads]))\n"})
        self.merge("--diff", "deck.typ", compile_=("deck.typ",))
        d = self.read("deck.typ")
        self.assertNotIn("tslide-del", d)
        self.assertIn("#tslide-chg[#slide(title: [ESDM \\ Design]", d)
        self.assertIn("[#tdel[7] #tins[12] sources]", d)
        self.assertIn("#tslide-ins[#slide(title: [Prediction Resistance API]",
                      d)
        self.assertIn("#tslide-chg[#slide(title: [DRNG Output APIs]", d)

    def test_headings_pair_by_text(self):
        self.write("old", {"main.typ": "= Health Tests\n\nThe tests of "
                           "the scheduler source.\n"})
        self.write("new", {"main.typ": "= Overview\n\nAn overview.\n\n"
                           "= Health Tests\n\nThe tests of the interrupt "
                           "source.\n"})
        self.merge("--diff", "main.typ")
        m = self.read("main.typ")
        self.assertIn("\n= Health Tests\n", m)
        self.assertNotIn("tdel-heading", m)
        self.assertIn("#tdel[scheduler] #tins[interrupt]", m)

    def test_old_definition_fallback(self):
        self.write("old", {
            "t.typ": "#let note(body, color: red) = text(fill: color, body)\n",
            "main.typ": "#import \"t.typ\": *\n\nKept.\n\n"
            "#note(color: blue)[Old note]\n"})
        self.write("new", {
            "t.typ": "#let note(body) = emph(body)\n",
            "main.typ": "#import \"t.typ\": *\n\nKept.\n"})
        self.merge("--diff", "main.typ")
        m = self.read("main.typ")
        self.assertIn('#import "/.old/t.typ" as td-old-0', m)
        self.assertIn("td-old-0.note(color: blue)", m)

    def test_table_count_change_replaces(self):
        self.write("old", {"main.typ": "#table(columns: 2, [a], [b])\n"})
        self.write("new", {"main.typ":
                           "#table(columns: 2, [a], [b], [c], [d])\n"})
        self.merge("--diff", "main.typ")
        m = self.read("main.typ")
        self.assertIn("#tdel-block[#table(columns: 2, [a], [b])]", m)
        self.assertIn("#tins-block[#table(columns: 2, [a], [b], [c], [d])]",
                      m)

    def test_out_inside_new_and_exclude(self):
        self.write("old", {"main.typ": "Old.\n"})
        self.write("new", {"main.typ": "New.\n", "build/junk.pdf": b"x",
                           "keep.txt": "k"})
        out = os.path.join(self.new, "build", "diff")
        self.merge("--diff", "main.typ", "--exclude", "build", out=out)
        self.assertFalse(os.path.exists(os.path.join(out, "build")))
        self.assertTrue(os.path.exists(os.path.join(out, "keep.txt")))
        # a second run replaces its own output
        self.merge("--diff", "main.typ", "--exclude", "build", out=out)

    def test_new_and_old_only_files(self):
        self.write("old", {"main.typ": "#include \"a.typ\"\n",
                           "a.typ": "Only old.\n"})
        self.write("new", {"main.typ": "#include \"b.typ\"\n",
                           "b.typ": "Only *new*.\n"})
        self.merge("--diff", "*.typ")
        self.assertIn("#tins[Only *new*.]", self.read("b.typ"))
        self.assertIn("#tdel[Only old.]", self.read("a.typ"))
        self.assertIn('#include "/a.typ"', self.read("main.typ"))

    def test_deterministic(self):
        self.write("old", {"main.typ": "= A\n\nOne two three.\n"})
        self.write("new", {"main.typ": "= B\n\nOne three four.\n"})
        self.merge("--diff", "main.typ")
        first = self.read("main.typ")
        self.merge("--diff", "main.typ")
        self.assertEqual(first, self.read("main.typ"))

    def test_refuses_foreign_out(self):
        self.write("old", {"main.typ": "a\n"})
        self.write("new", {"main.typ": "b\n"})
        os.makedirs(self.out)
        with open(os.path.join(self.out, "precious"), "w") as f:
            f.write("x")
        rc = T.main(["--old", self.old, "--new", self.new, "--out", self.out,
                     "--diff", "main.typ"])
        self.assertEqual(rc, 1)
        self.assertTrue(os.path.exists(os.path.join(self.out, "precious")))


SVG = ('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
       '<rect width="10" height="10" fill="%s"/></svg>')


if __name__ == "__main__":
    unittest.main()
