#!/usr/bin/env python3
"""typstdiff - a latexdiff for Typst.

Takes two versions of a Typst document tree and writes a third tree whose
compiled document shows the changes: deleted text red and struck through,
inserted text green and underlined, deleted / inserted figures, tables and
code blocks in tinted boxes, change bars in the left page margin.

    typstdiff.py --old OLD --new NEW --out OUT --diff 'chapters/*.typ' ...

OUT becomes a copy of NEW in which every file matching a --diff pattern is
replaced by the merged markup of its OLD and NEW version. OLD is copied to
OUT/.old, so that deleted content can still use its figures and data files.
The merged files import the helper library typstdiff.typ (copied to OUT).
Compile the result with OUT as the root:

    typst compile --root OUT OUT/esdm.typ diff.pdf

How the files are merged:

- Markup is split into blocks (paragraphs, headings, list/enum/term items,
  standalone calls, statements, raw blocks, comments). The block sequences
  are aligned with difflib; within replaced ranges, blocks of the same kind
  are paired by similarity and diffed recursively, the others are deleted
  or inserted as a whole.
- Paragraphs, headings and item bodies get a word diff. Strong/emph spans,
  bracket groups and inline calls are units: kept, diffed recursively (same
  kind or callee) or replaced; raw text and math are atomic.
- Statements (#import, #set, #show, #let) are taken from NEW only; a
  removed #let is kept when NEW does not define its name, a removed
  #include of a file only in OLD shows that file as deleted. A changed
  "#show: tmpl.with(..)" gets its content arguments diffed.
- Calls of the same callee are diffed argument by argument: content
  blocks as markup, arrays of content element by element; other arguments
  take the NEW value and mark the element as changed unless the change is
  layout only (numbers, lengths, alignments). Changed assets (images, data
  files) replace the element: old one deleted, new one inserted. Table and
  grid cells pair one to one only if their number is unchanged.
- Deleted text: labels NEW defines are dropped, references to labels that
  no longer exist are shown as text, paths point into OUT/.old, names that
  only OLD had in scope are imported from OUT/.old, calls the NEW
  definition does not accept use the OLD one. Bibliography entries cited
  by OLD only are appended to the bibliography of OUT.
- Slides (calls of --slide-callee functions) get a badge when inserted,
  removed or changed.

Only the Python standard library is used.
"""

import argparse
import difflib
import fnmatch
import hashlib
import os
import re
import shutil
import sys

HELPER_NAME = "typstdiff.typ"
OLD_DIR = ".old"
MARKER_FILE = ".typstdiff-out"

# Functions whose first positional argument is the path of a file.
ASSET_FUNCS = {"image", "read", "csv", "json", "yaml", "toml", "xml", "cbor",
               "plugin"}
# Callees of standalone calls that are block elements and are shown in a
# tinted box when deleted or inserted as a whole.
BOX_CALLEES = {"figure", "table", "grid", "image", "block", "rect", "stack",
               "raw", "columns", "box", "square", "circle", "ellipse",
               "polygon", "path", "curve"}
# Callees that are block elements: a standalone call of them is a block of
# its own even when the text around it is not separated by blank lines.
BLOCK_CALLEES = BOX_CALLEES | {"par", "heading", "align", "pad", "place",
                               "v", "pagebreak", "colbreak", "bibliography",
                               "outline", "line", "quote", "list", "enum",
                               "terms", "move", "rotate", "scale"}
# Callees whose positional arguments are cells: they pair one to one only.
TABLE_CALLEES = {"table", "grid"}
# Callees whose arguments are compared as a whole (raw text is atomic).
ATOMIC_CALLEES = {"raw"}
# Literals and identifiers whose changes are layout only.
LAYOUT_IDENTS = {"left", "right", "top", "bottom", "center", "horizon",
                 "start", "end", "true", "false", "auto", "none", "ltr",
                 "rtl", "ttb", "btt"}
STATEMENT_KWS = {"let", "set", "show", "import", "include"}

IDENT_RE = re.compile(r"[^\W\d][\w\-]*")
LABEL_RE = re.compile(r"<([\w:.\-]+)>")
REF_RE = re.compile(r"@([\w:.\-]*[\w\-])")
NUM_RE = re.compile(
    r"(?:0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)"
    r"(?:pt|mm|cm|in|em|fr|deg|rad|%)?")
HEADING_RE = re.compile(r"=+(?=[ \t\r\n]|$)")
ENUM_RE = re.compile(r"\d+\.(?=[ \t\r\n]|$)")
WORD_RE = re.compile(r"\w+|[^\w\s]")
BINOPS = ("==", "!=", "<=", ">=", "=>", "+=", "-=", "*=", "/=", "<", ">",
          "+", "-", "*", "/", "=")
PUNCT = set(".,;:!?()\"'“”‘’«»")
WS = " \t\r\n"


class TypstDiffError(Exception):
    """An error of the input or of the tool itself."""


class ParseError(TypstDiffError):
    pass


def is_ident_start(c):
    return c.isalpha() or c == "_"


# --------------------------------------------------------------------------
# Syntax tree
# --------------------------------------------------------------------------

class Node:
    """A token of markup or a node of code, spanning src[start:end]."""

    __slots__ = ("kind", "start", "end", "a")

    def __init__(self, kind, start, end, **a):
        self.kind = kind
        self.start = start
        self.end = end
        self.a = a

    def __repr__(self):
        return "Node(%s, %d, %d)" % (self.kind, self.start, self.end)


class Item:
    """An item of a parenthesized group: argument, array or dict entry."""

    __slots__ = ("name", "spread", "value", "start", "end")

    def __init__(self, name, spread, value, start, end):
        self.name = name
        self.spread = spread
        self.value = value
        self.start = start
        self.end = end


def children(node):
    """The child nodes of a node (markup tokens and code nodes)."""
    k = node.kind
    a = node.a
    if k in ("strong", "emph", "bracket", "content"):
        return a["toks"]
    if k == "code":
        return [a["expr"]]
    if k == "ref":
        return [a["supp"]] if a.get("supp") is not None else []
    if k == "chain":
        out = [a["base"]]
        for op in a["ops"]:
            if op[0] != "field":
                out.append(op[1])
        return out
    if k == "paren":
        return [it.value for it in a["items"] if it.value is not None]
    if k == "codeblock":
        return a["stmts"]
    if k == "expr":
        return [p for p in a["parts"] if p.kind != "op"]
    if k == "kw":
        return [v for v in a.get("subs", ()) if v is not None]
    if k == "math":
        return a.get("code", [])
    return []


def walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(children(n)))


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

class Parser:
    """A tokenizer/parser for Typst markup and code.

    It is no full Typst parser: it finds the boundaries of the elements the
    diff works on (blocks, inline units, calls and their arguments)."""

    def __init__(self, src, name="<input>"):
        self.s = src
        self.n = len(src)
        self.name = name

    def err(self, pos, msg):
        line = self.s.count("\n", 0, pos) + 1
        col = pos - (self.s.rfind("\n", 0, pos) + 1) + 1
        raise ParseError("%s:%d:%d: %s" % (self.name, line, col, msg))

    def col(self, pos):
        return pos - (self.s.rfind("\n", 0, pos) + 1)

    def in_word(self, pos):
        s = self.s
        return (pos > 0 and pos + 1 < self.n and s[pos - 1].isalnum()
                and s[pos + 1].isalnum())

    def code_starts(self, pos):
        if pos >= self.n:
            return False
        c = self.s[pos]
        return is_ident_start(c) or c in '([{"'

    # ---------------------------------------------------------- markup

    def parse(self):
        toks, pos = self.markup(0, "", True)
        if pos != self.n:
            self.err(pos, "unexpected '%s'" % self.s[pos])
        return toks

    def markup(self, pos, stops, line_start):
        s = self.s
        n = self.n
        toks = []
        while pos < n:
            c = s[pos]
            if c in stops and (c == "]" or not self.in_word(pos)):
                break
            if c in WS:
                j = pos
                nl = 0
                while j < n and s[j] in WS:
                    if s[j] == "\n":
                        nl += 1
                    j += 1
                toks.append(Node("parbreak" if nl >= 2 else "space", pos, j,
                                 nl=nl))
                if nl:
                    line_start = True
                pos = j
                continue
            if s.startswith("//", pos):
                j = s.find("\n", pos)
                j = n if j < 0 else j
                toks.append(Node("comment", pos, j))
                pos = j
                continue
            if s.startswith("/*", pos):
                j = self.block_comment_end(pos)
                toks.append(Node("comment", pos, j))
                pos = j
                line_start = False
                continue
            if line_start:
                t = self.marker(pos)
                if t is not None:
                    toks.append(t)
                    pos = t.end
                    line_start = False
                    continue
            line_start = False
            if c == "\\":
                if pos + 1 >= n or s[pos + 1] in WS:
                    toks.append(Node("linebreak", pos, pos + 1))
                    pos += 1
                    continue
            elif c == "`":
                j = self.raw_end(pos)
                toks.append(Node("raw", pos, j,
                                 block=s.startswith("```", pos)))
                pos = j
                continue
            elif c == "$":
                j, code = self.math_end(pos + 1)
                toks.append(Node("math", pos, j, code=code))
                pos = j
                continue
            elif c == "#" and self.code_starts(pos + 1):
                expr, j = self.embedded(pos + 1)
                semi = j < n and s[j] == ";"
                if semi:
                    j += 1
                toks.append(Node("code", pos, j, expr=expr, semi=semi))
                pos = j
                continue
            elif c == "@":
                m = REF_RE.match(s, pos)
                if m:
                    j = m.end()
                    supp = None
                    if j < n and s[j] == "[":
                        inner, k = self.markup(j + 1, "]", False)
                        if k >= n:
                            self.err(j, "unclosed bracket")
                        supp = Node("bracket", j, k + 1, toks=inner)
                        j = k + 1
                    toks.append(Node("ref", pos, j, name=m.group(1),
                                     supp=supp))
                    pos = j
                    continue
            elif c == "<":
                m = LABEL_RE.match(s, pos)
                if m:
                    toks.append(Node("label", pos, m.end(), name=m.group(1)))
                    pos = m.end()
                    continue
            elif c == "[":
                inner, j = self.markup(pos + 1, "]", False)
                if j >= n:
                    self.err(pos, "unclosed bracket")
                toks.append(Node("bracket", pos, j + 1, toks=inner))
                pos = j + 1
                continue
            elif c in "*_" and not self.in_word(pos):
                inner, j = self.markup(pos + 1, stops + c, False)
                end = j + 1 if j < n and s[j] == c else j
                toks.append(Node("strong" if c == "*" else "emph", pos, end,
                                 toks=inner, closed=end > j))
                pos = end
                continue
            elif (c == "h" and s.startswith(("http://", "https://"), pos)
                  and (pos == 0 or not s[pos - 1].isalnum())):
                j = self.url_end(pos)
                toks.append(Node("url", pos, j))
                pos = j
                continue
            j = self.word_end(pos, stops)
            toks.append(Node("text", pos, j))
            pos = j
        return toks, pos

    def marker(self, pos):
        s = self.s
        c = s[pos]
        nxt = s[pos + 1] if pos + 1 < self.n else "\n"
        if c == "=":
            m = HEADING_RE.match(s, pos)
            if m:
                return Node("heading", pos, m.end(), level=m.end() - pos)
        elif c == "-" and nxt in WS:
            return Node("list", pos, pos + 1)
        elif c == "+" and nxt in WS:
            return Node("enum", pos, pos + 1)
        elif c == "/" and nxt in " \t":
            return Node("term", pos, pos + 1)
        elif c.isdigit():
            m = ENUM_RE.match(s, pos)
            if m:
                return Node("enum", pos, m.end())
        return None

    def word_end(self, pos, stops):
        s = self.s
        n = self.n
        if s[pos] in PUNCT:
            return pos + 1
        j = pos
        while j < n:
            ch = s[j]
            if ch in WS or ch in PUNCT:
                break
            if ch == "\\":
                if j + 1 < n and s[j + 1] not in WS:
                    if s.startswith("\\u{", j):
                        k = s.find("}", j)
                        j = n if k < 0 else k + 1
                    else:
                        j += 2
                    continue
                break
            if ch in "*_":
                if self.in_word(j):
                    j += 1
                    continue
                break
            if ch in "`$[]":
                break
            if ch == "#" and self.code_starts(j + 1):
                break
            if ch == "@" and REF_RE.match(s, j):
                break
            if ch == "<" and LABEL_RE.match(s, j):
                break
            if ch == "/" and s.startswith(("//", "/*"), j):
                break
            if (ch == "h" and s.startswith(("http://", "https://"), j)
                    and (j == 0 or not s[j - 1].isalnum())):
                break
            j += 1
        return max(j, pos + 1)

    def url_end(self, pos):
        s = self.s
        j = pos
        depth = []
        while j < self.n:
            ch = s[j]
            if ch in WS or ch in '<>"':
                break
            if ch in "([":
                depth.append(ch)
            elif ch in ")]":
                if not depth:
                    break
                depth.pop()
            j += 1
        while j > pos and s[j - 1] in ".,;:!?'":
            j -= 1
        return j

    def block_comment_end(self, pos):
        s = self.s
        depth = 0
        j = pos
        while j < self.n:
            if s.startswith("/*", j):
                depth += 1
                j += 2
            elif s.startswith("*/", j):
                depth -= 1
                j += 2
                if depth == 0:
                    return j
            else:
                j += 1
        self.err(pos, "unclosed block comment")

    def raw_end(self, pos):
        s = self.s
        j = pos
        while j < self.n and s[j] == "`":
            j += 1
        k = j - pos
        if k == 2:
            return j
        e = s.find("`" * k, j)
        if e < 0:
            self.err(pos, "unclosed raw text")
        e += k
        if k >= 3:
            while e < self.n and s[e] == "`":
                e += 1
        return e

    def string_end(self, pos):
        s = self.s
        j = pos + 1
        while j < self.n:
            ch = s[j]
            if ch == "\\":
                j += 2
                continue
            if ch == '"':
                return j + 1
            if ch == "\n":
                break
            j += 1
        self.err(pos, "unclosed string")

    def math_end(self, pos):
        s = self.s
        j = pos
        code = []
        while j < self.n:
            ch = s[j]
            if ch == "\\":
                j += 2
            elif ch == '"':
                j = self.string_end(j)
            elif ch == "#" and self.code_starts(j + 1):
                expr, j = self.embedded(j + 1)
                code.append(expr)
                if j < self.n and s[j] == ";":
                    j += 1
            elif s.startswith("//", j):
                k = s.find("\n", j)
                j = self.n if k < 0 else k
            elif s.startswith("/*", j):
                j = self.block_comment_end(j)
            elif ch == "$":
                return j + 1, code
            else:
                j += 1
        self.err(pos - 1, "unclosed math")

    # ------------------------------------------------------------ code

    def skip_trivia(self, j, nl):
        s = self.s
        n = self.n
        while j < n:
            ch = s[j]
            if ch in " \t\r" or (nl and ch == "\n"):
                j += 1
            elif s.startswith("//", j):
                k = s.find("\n", j)
                j = n if k < 0 else k
            elif s.startswith("/*", j):
                j = self.block_comment_end(j)
            else:
                break
        return j

    def embedded(self, pos):
        """An embedded expression after '#' in markup or math."""
        s = self.s
        c = s[pos]
        if is_ident_start(c):
            m = IDENT_RE.match(s, pos)
            name = m.group()
            if name in STATEMENT_KWS or name in ("return", "context"):
                return self.keyword(name, pos, "embedded")
            if name in ("if", "for", "while"):
                return self.control(name, pos, "embedded")
            return self.postfix(Node("ident", pos, m.end(), name=name),
                                m.end())
        atom, j = self.primary(pos, "embedded")
        return self.postfix(atom, j)

    def postfix(self, base, pos):
        s = self.s
        ops = []
        while pos < self.n:
            c = s[pos]
            if (c == "." and pos + 1 < self.n
                    and is_ident_start(s[pos + 1])):
                m = IDENT_RE.match(s, pos + 1)
                ops.append(("field", m.group(), pos, m.end()))
                pos = m.end()
            elif c == "(":
                p, pos = self.paren(pos)
                ops.append(("args", p))
            elif c == "[":
                cb, pos = self.content(pos)
                ops.append(("content", cb))
            else:
                break
        if not ops:
            return base, pos
        return Node("chain", base.start, pos, base=base, ops=ops), pos

    def primary(self, pos, ctx):
        s = self.s
        if pos >= self.n:
            self.err(pos, "expected expression")
        c = s[pos]
        if c == "(":
            return self.paren(pos)
        if c == "[":
            return self.content(pos)
        if c == "{":
            return self.codeblock(pos)
        if c == '"':
            j = self.string_end(pos)
            return Node("str", pos, j, value=decode_str(s[pos + 1:j - 1])), j
        if c == "`":
            j = self.raw_end(pos)
            return Node("raw", pos, j), j
        if c == "$":
            j, code = self.math_end(pos + 1)
            return Node("math", pos, j, code=code), j
        if c == "<":
            m = LABEL_RE.match(s, pos)
            if m:
                return Node("label", pos, m.end(), name=m.group(1)), m.end()
        if c.isdigit() or (c == "." and pos + 1 < self.n
                           and s[pos + 1].isdigit()):
            m = NUM_RE.match(s, pos)
            return Node("num", pos, m.end()), m.end()
        if is_ident_start(c):
            m = IDENT_RE.match(s, pos)
            name = m.group()
            if name in STATEMENT_KWS or name in ("return", "context"):
                return self.keyword(name, pos, ctx)
            if name in ("if", "for", "while"):
                return self.control(name, pos, ctx)
            return Node("ident", pos, m.end(), name=name), m.end()
        self.err(pos, "unexpected '%s' in code" % c)

    def unary(self, pos, nl):
        s = self.s
        j = self.skip_trivia(pos, nl)
        while j < self.n:
            if s[j] in "+-" and not s.startswith(("+=", "-="), j):
                j = self.skip_trivia(j + 1, nl)
            elif (s.startswith("not", j) and
                  not (j + 3 < self.n and (s[j + 3].isalnum()
                                           or s[j + 3] in "_-"))):
                j = self.skip_trivia(j + 3, nl)
            else:
                break
        return j

    def binop(self, j):
        s = self.s
        for kw in ("and", "or", "in", "not"):
            if s.startswith(kw, j):
                e = j + len(kw)
                if not (e < self.n and (s[e].isalnum() or s[e] in "_-")):
                    if kw == "not":
                        k = self.skip_trivia(e, False)
                        if s.startswith("in", k):
                            return k + 2 - j
                        return 0
                    return len(kw)
        for op in BINOPS:
            if s.startswith(op, j):
                if op in ("<", "*", "/") and s.startswith(("<<", "//", "/*"),
                                                         j):
                    return 0
                return len(op)
        return 0

    def expr(self, pos, ctx):
        nl = ctx == "paren"
        j = self.unary(pos, nl)
        atom, j = self.atom(j, ctx)
        parts = [atom]
        while True:
            k = self.skip_trivia(j, nl)
            if k >= self.n:
                break
            ln = self.binop(k)
            if not ln:
                break
            parts.append(Node("op", k, k + ln, op=self.s[k:k + ln]))
            k = self.unary(k + ln, True)
            atom, j = self.atom(k, ctx)
            parts.append(atom)
        if len(parts) == 1:
            return parts[0], j
        return Node("expr", pos, j, parts=parts), j

    def atom(self, pos, ctx):
        node, j = self.primary(pos, ctx)
        if node.kind == "kw":
            return node, j
        return self.postfix(node, j)

    def paren(self, pos):
        s = self.s
        items = []
        j = pos + 1
        trailing = False
        while True:
            j = self.skip_trivia(j, True)
            if j >= self.n:
                self.err(pos, "unclosed parenthesis")
            if s[j] == ")":
                j += 1
                break
            istart = j
            spread = False
            name = None
            if s.startswith("..", j):
                spread = True
                j += 2
                k = self.skip_trivia(j, True)
                if k < self.n and s[k] in ",)":
                    items.append(Item(None, True, None, istart, j))
                    j = k
                    trailing = False
                    if s[j] == ",":
                        j += 1
                        trailing = True
                    continue
            elif s.startswith("(:)", j):
                pass
            elif s[j] == ":" and s.startswith(":)", j):
                j += 1
                continue
            else:
                m = IDENT_RE.match(s, j)
                if m:
                    k = self.skip_trivia(m.end(), True)
                    if k < self.n and s[k] == ":":
                        name = m.group()
                        j = k + 1
                elif s[j] == '"':
                    e = self.string_end(j)
                    k = self.skip_trivia(e, True)
                    if k < self.n and s[k] == ":":
                        name = decode_str(s[j + 1:e - 1])
                        j = k + 1
            j = self.skip_trivia(j, True)
            val, j = self.expr(j, "paren")
            items.append(Item(name, spread, val, istart, j))
            j = self.skip_trivia(j, True)
            if j < self.n and s[j] == ",":
                j += 1
                trailing = True
                continue
            trailing = False
            if j < self.n and s[j] == ")":
                j += 1
                break
            self.err(j, "expected ',' or ')'")
        return Node("paren", pos, j, items=items, trailing=trailing), j

    def content(self, pos):
        toks, j = self.markup(pos + 1, "]", True)
        if j >= self.n or self.s[j] != "]":
            self.err(pos, "unclosed content block")
        return Node("content", pos, j + 1, toks=toks, inner=(pos + 1, j)), \
            j + 1

    def codeblock(self, pos):
        s = self.s
        stmts = []
        j = pos + 1
        while True:
            while True:
                j = self.skip_trivia(j, True)
                if j < self.n and s[j] == ";":
                    j += 1
                else:
                    break
            if j >= self.n:
                self.err(pos, "unclosed code block")
            if s[j] == "}":
                j += 1
                break
            st, j = self.expr(j, "block")
            stmts.append(st)
            k = self.skip_trivia(j, False)
            if k < self.n and s[k] not in "\n;}":
                self.err(k, "expected end of statement")
            j = k
        return Node("codeblock", pos, j, stmts=stmts), j

    def keyword(self, kw, pos, ctx):
        s = self.s
        nl = ctx == "paren"
        j = self.skip_trivia(pos + len(kw), nl)
        a = {"kw": kw}
        subs = []
        if kw == "let":
            names = []
            params = None
            if s[j] == "(":
                pat, j = self.paren(j)
                for it in pat.a["items"]:
                    v = it.value
                    if v is not None and v.kind == "ident":
                        names.append(v.a["name"])
                    elif it.name:
                        names.append(it.name)
            else:
                m = IDENT_RE.match(s, j)
                if not m:
                    self.err(j, "expected pattern after let")
                names.append(m.group())
                j = m.end()
                if j < self.n and s[j] == "(":
                    pat, j = self.paren(j)
                    params = pat
            a["names"] = names
            a["params"] = params
            k = self.skip_trivia(j, nl)
            if k < self.n and s[k] == "=" and not s.startswith("==", k):
                val, j = self.expr(self.skip_trivia(k + 1, nl), ctx)
                a["value"] = val
                subs.append(val)
        elif kw == "set":
            target, j = self.atom(j, ctx)
            a["target"] = target
            subs.append(target)
            k = self.skip_trivia(j, nl)
            if s.startswith("if", k) and not (k + 2 < self.n
                                              and s[k + 2].isalnum()):
                cond, j = self.expr(self.skip_trivia(k + 2, nl), ctx)
                subs.append(cond)
        elif kw == "show":
            sel = None
            if s[j] != ":":
                sel, j = self.expr(j, ctx)
                j = self.skip_trivia(j, nl)
            if j >= self.n or s[j] != ":":
                self.err(j, "expected ':' in show rule")
            tr, j = self.expr(self.skip_trivia(j + 1, nl), ctx)
            a["selector"] = sel
            a["transform"] = tr
            subs += [sel, tr]
        elif kw == "import":
            src, j = self.atom(j, ctx)
            a["source"] = src
            subs.append(src)
            a["alias"] = None
            a["star"] = False
            a["items"] = None
            k = self.skip_trivia(j, nl)
            if s.startswith("as", k) and not s[k + 2:k + 3].isalnum():
                k = self.skip_trivia(k + 2, nl)
                m = IDENT_RE.match(s, k)
                a["alias"] = m.group()
                j = m.end()
                k = self.skip_trivia(j, nl)
            if k < self.n and s[k] == ":":
                k = self.skip_trivia(k + 1, nl)
                if s[k] == "*":
                    a["star"] = True
                    j = k + 1
                else:
                    items, j = self.import_items(k, nl)
                    a["items"] = items
        elif kw == "include":
            src, j = self.expr(j, ctx)
            a["source"] = src
            subs.append(src)
        elif kw == "return":
            k = self.skip_trivia(j, nl)
            if k < self.n and s[k] not in "\n;}])":
                val, j = self.expr(k, ctx)
                subs.append(val)
        elif kw == "context":
            val, j = self.expr(j, ctx)
            subs.append(val)
        a["subs"] = subs
        return Node("kw", pos, j, **a), j

    def import_items(self, k, nl):
        s = self.s
        paren = s[k] == "("
        if paren:
            k += 1
            nl = True
        items = []
        while True:
            k = self.skip_trivia(k, nl)
            m = IDENT_RE.match(s, k)
            if not m:
                break
            name = m.group()
            k = m.end()
            while k < self.n and s[k] == "." and IDENT_RE.match(s, k + 1):
                m = IDENT_RE.match(s, k + 1)
                name += "." + m.group()
                k = m.end()
            alias = None
            k2 = self.skip_trivia(k, nl)
            if s.startswith("as", k2) and not s[k2 + 2:k2 + 3].isalnum():
                k2 = self.skip_trivia(k2 + 2, nl)
                m = IDENT_RE.match(s, k2)
                alias = m.group()
                k = m.end()
                k2 = self.skip_trivia(k, nl)
            items.append((name, alias))
            if k2 < self.n and s[k2] == ",":
                k = k2 + 1
                continue
            break
        if paren:
            k = self.skip_trivia(k, True)
            if k >= self.n or s[k] != ")":
                self.err(k, "expected ')' in import")
            k += 1
        return items, k

    def control(self, kw, pos, ctx):
        s = self.s
        nl = ctx == "paren"
        j = self.skip_trivia(pos + len(kw), nl)
        subs = []
        if kw == "for":
            if s[j] == "(":
                pat, j = self.paren(j)
            else:
                m = IDENT_RE.match(s, j)
                j = m.end()
            j = self.skip_trivia(j, nl)
            if not s.startswith("in", j):
                self.err(j, "expected 'in'")
            j += 2
        cond, j = self.expr(self.skip_trivia(j, nl), ctx)
        subs.append(cond)
        j = self.skip_trivia(j, nl)
        body, j = self.body(j)
        subs.append(body)
        if kw == "if":
            k = self.skip_trivia(j, ctx != "embedded")
            if s.startswith("else", k) and not s[k + 4:k + 5].isalnum():
                k = self.skip_trivia(k + 4, nl)
                if s.startswith("if", k) and not s[k + 2:k + 3].isalnum():
                    other, j = self.control("if", k, ctx)
                else:
                    other, j = self.body(k)
                subs.append(other)
        return Node("kw", pos, j, kw=kw, subs=subs), j

    def body(self, j):
        if j < self.n and self.s[j] == "{":
            return self.codeblock(j)
        if j < self.n and self.s[j] == "[":
            return self.content(j)
        self.err(j, "expected block")


def decode_str(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            d = s[i + 1]
            if d == "u" and s.startswith("u{", i + 1):
                k = s.find("}", i)
                try:
                    out.append(chr(int(s[i + 3:k], 16)))
                except ValueError:
                    pass
                i = k + 1
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(d, d))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def callee_of(expr):
    """The callee of a call ('figure', 'table.cell', 'tmpl.with') or None."""
    if expr is None or expr.kind != "chain":
        return None
    base = expr.a["base"]
    if base.kind != "ident":
        return None
    name = base.a["name"]
    ops = expr.a["ops"]
    i = 0
    while i < len(ops) and ops[i][0] == "field":
        name += "." + ops[i][1]
        i += 1
    if i == len(ops):
        return None
    for op in ops[i:]:
        if op[0] == "field":
            return None
    return name


def has_box(expr):
    """Whether a code block (or call) produces a figure, table or the like
    at its top level."""
    if expr is None:
        return False
    if expr.kind == "codeblock":
        return any(has_box(st) for st in expr.a["stmts"])
    return callee_of(expr) in BOX_CALLEES


def call_args(expr):
    """Positional and named arguments of a call."""
    if callee_of(expr) is None:
        return None
    pos = []
    named = {}
    for op in expr.a["ops"]:
        if op[0] == "args":
            for it in op[1].a["items"]:
                if it.spread:
                    pos.append(it)
                elif it.name is not None:
                    named[it.name] = it
                else:
                    pos.append(it)
        elif op[0] == "content":
            pos.append(Item(None, False, op[1], op[1].start, op[1].end))
    return pos, named


# --------------------------------------------------------------------------
# Blocks
# --------------------------------------------------------------------------

class Block:
    """A block of markup: paragraph, heading, list/enum/term item, comment,
    statement, standalone call or code, raw block."""

    def __init__(self, kind, toks, **a):
        self.kind = kind
        self.toks = toks
        self.start = toks[0].start
        self.end = toks[-1].end
        self.a = a

    def __repr__(self):
        return "Block(%s, %d, %d)" % (self.kind, self.start, self.end)


def is_nl(t):
    return t.kind == "parbreak" or (t.kind == "space" and t.a["nl"] > 0)


def stmt_kw(t):
    if t.kind != "code":
        return None
    e = t.a["expr"]
    if e.kind == "kw" and e.a["kw"] in STATEMENT_KWS:
        return e.a["kw"]
    return None


class Grouper:
    def __init__(self, parser):
        self.p = parser

    def col(self, t):
        return self.p.col(t.start)

    def line_end(self, toks, i):
        """Index of the first newline token at or after i."""
        while i < len(toks) and not is_nl(toks[i]):
            i += 1
        return i

    def standalone_end(self, toks, i):
        """If toks[i] is the only element on its line (but for a label
        and comments), the index after it (and the label), else None."""
        k = i + 1
        n = len(toks)
        lab = None
        j = k
        while j < n and toks[j].kind in ("space", "comment") \
                and not is_nl(toks[j]):
            j += 1
        if j < n and toks[j].kind == "label":
            lab = j
            j += 1
            while j < n and toks[j].kind in ("space", "comment") \
                    and not is_nl(toks[j]):
                j += 1
        if j < n and not is_nl(toks[j]):
            return None
        return lab + 1 if lab is not None else k

    def block_like_line(self, toks, k):
        """Whether the line starting at toks[k] starts a block."""
        if k >= len(toks):
            return True
        t = toks[k]
        if t.kind in ("heading", "list", "enum", "term"):
            return True
        if stmt_kw(t):
            return True
        if t.kind == "comment":
            e = k + 1
            return e >= len(toks) or is_nl(toks[e])
        if t.kind in ("code", "raw"):
            e = self.standalone_end(toks, k)
            if e is not None:
                return True
        return False

    def is_block_call(self, t):
        if t.kind == "raw":
            return t.a["block"]
        return callee_of(t.a["expr"]) in BLOCK_CALLEES

    def group(self, toks):
        blocks = []
        i = 0
        n = len(toks)
        while i < n:
            t = toks[i]
            if t.kind in ("space", "parbreak"):
                i += 1
                continue
            ls = i == 0 or is_nl(toks[i - 1])
            if ls and t.kind == "heading":
                j = self.line_end(toks, i + 1)
                blocks.append(self.heading(toks, i, j))
                i = j
                continue
            if ls and t.kind in ("list", "enum", "term"):
                j = self.item_end(toks, i)
                blocks.append(self.item(toks, i, j))
                i = j
                continue
            if ls and t.kind == "comment" and (i + 1 >= n
                                               or is_nl(toks[i + 1])):
                blocks.append(Block("comment", [t]))
                i += 1
                continue
            if ls and stmt_kw(t):
                blocks.append(Block("stmt", [t], kw=stmt_kw(t),
                                    expr=t.a["expr"]))
                i += 1
                continue
            if ls and t.kind in ("code", "raw"):
                e = self.standalone_end(toks, i)
                if e is not None:
                    k = self.line_end(toks, e)
                    nxt = k + 1
                    if (self.is_block_call(t) or k >= n
                            or toks[k].kind == "parbreak"
                            or self.block_like_line(toks, nxt)):
                        blocks.append(self.call(toks, i, e))
                        i = e
                        continue
            j = self.par_end(toks, i)
            blocks.append(Block("par", toks[i:j]))
            i = j
        return blocks

    def call(self, toks, i, e):
        t = toks[i]
        label = toks[e - 1] if e - 1 > i and toks[e - 1].kind == "label" \
            else None
        if t.kind == "raw":
            return Block("raw", toks[i:e], label=label)
        expr = t.a["expr"]
        callee = callee_of(expr)
        return Block("call" if callee else "code", toks[i:e], label=label,
                     code=t, expr=expr, callee=callee)

    def par_end(self, toks, i):
        n = len(toks)
        j = i
        while j < n:
            t = toks[j]
            if t.kind == "parbreak":
                break
            if is_nl(t) and j + 1 < n:
                k = j + 1
                u = toks[k]
                if u.kind in ("heading", "list", "enum", "term") \
                        or stmt_kw(u):
                    break
                if u.kind in ("code", "raw") and self.is_block_call(u) \
                        and self.standalone_end(toks, k) is not None:
                    break
            j += 1
        while j > i + 1 and toks[j - 1].kind in ("space", "parbreak",
                                                  "comment"):
            j -= 1
        return j

    def heading(self, toks, i, j):
        body = toks[i + 1:j]
        while body and body[0].kind in ("space", "comment"):
            body = body[1:]
        while body and body[-1].kind in ("space", "comment"):
            body = body[:-1]
        label = None
        if body and body[-1].kind == "label":
            label = body[-1]
            body = body[:-1]
            while body and body[-1].kind == "space":
                body = body[:-1]
        end = j
        while end > i + 1 and toks[end - 1].kind in ("space", "comment"):
            end -= 1
        return Block("heading", toks[i:end], level=toks[i].a["level"],
                     body=body, label=label, marker=toks[i])

    def item_end(self, toks, i):
        mc = self.col(toks[i])
        n = len(toks)
        j = i + 1
        while j < n:
            t = toks[j]
            if is_nl(t):
                k = j + 1
                if k >= n or self.col(toks[k]) <= mc:
                    break
            j += 1
        while j > i + 1 and toks[j - 1].kind in ("space", "parbreak"):
            j -= 1
        return j

    def item(self, toks, i, j):
        marker = toks[i]
        body = toks[i + 1:j]
        while body and body[0].kind == "space" and not is_nl(body[0]):
            body = body[1:]
        a = {"marker": marker, "mtype": marker.kind,
             "base": self.col(marker) + (marker.end - marker.start) + 1}
        if marker.kind == "term":
            k = 0
            while k < len(body) and not (body[k].kind == "text"
                                         and self.p.s[body[k].start] == ":"):
                k += 1
            term = body[:k]
            desc = body[k + 1:]
            while desc and desc[0].kind == "space" and not is_nl(desc[0]):
                desc = desc[1:]
            a["term"] = term
            a["colon"] = body[k] if k < len(body) else None
            a["body"] = self.group(desc)
        else:
            a["body"] = self.group(body)
        return Block("item", toks[i:j], **a)


# --------------------------------------------------------------------------
# Files and trees
# --------------------------------------------------------------------------

class SourceFile:
    """A parsed Typst file of one side (OLD or NEW)."""

    def __init__(self, side, rel, src):
        self.side = side
        self.rel = rel
        self.src = src
        self.parser = Parser(src, os.path.join(side.root, rel) if rel
                             else "<empty>")
        self.toks = self.parser.parse()
        self.grouper = Grouper(self.parser)
        self.blocks = self.grouper.group(self.toks)
        self.string_lets = {}
        for b in self.blocks:
            if b.kind == "stmt" and b.a["kw"] == "let":
                e = b.a["expr"]
                v = e.a.get("value")
                if (v is not None and v.kind == "str"
                        and len(e.a["names"]) == 1
                        and e.a["params"] is None):
                    self.string_lets[e.a["names"][0]] = v.a["value"]
        self._assets = {}
        self.edits = None

    def text(self, a, b):
        return self.src[a:b]

    def eval_str(self, node):
        if node is None:
            return None
        if node.kind == "str":
            return node.a["value"]
        if node.kind == "ident":
            return self.string_lets.get(node.a["name"])
        if node.kind == "expr":
            parts = node.a["parts"]
            out = []
            for k, p in enumerate(parts):
                if k % 2:
                    if p.a["op"] != "+":
                        return None
                    continue
                v = self.eval_str(p)
                if v is None:
                    return None
                out.append(v)
            return "".join(out)
        return None

    def resolve(self, path):
        """Path relative to the root of a path used in this file."""
        if path.startswith("/"):
            return os.path.normpath(path[1:])
        return os.path.normpath(os.path.join(os.path.dirname(self.rel),
                                             path))

    def asset_args(self, node):
        """(first argument node, resolved path) of the asset calls in a
        subtree."""
        out = []
        for n in walk(node):
            if n.kind == "chain":
                callee = callee_of(n)
                if callee in ASSET_FUNCS:
                    args = call_args(n)
                    if args and args[0] and args[0][0].value is not None:
                        v = args[0][0].value
                        p = self.eval_str(v)
                        if p is not None and not p.startswith("@"):
                            out.append((v, self.resolve(p)))
        return out

    def assets(self, nodes):
        """Digests of the assets referenced in nodes (memoized)."""
        if isinstance(nodes, Node):
            nodes = [nodes]
        key = tuple(id(n) for n in nodes)
        if key in self._assets:
            return self._assets[key]
        out = []
        for node in nodes:
            for _, rel in self.asset_args(node):
                out.append(self.side.digest(rel))
        out = tuple(out)
        self._assets[key] = out
        return out


class Side:
    def __init__(self, root, name):
        self.root = root
        self.name = name
        self.files = {}
        self.digests = {}
        self.modules = {}

    def exists(self, rel):
        return os.path.isfile(os.path.join(self.root, rel))

    def digest(self, rel):
        if rel not in self.digests:
            p = os.path.join(self.root, rel)
            try:
                with open(p, "rb") as f:
                    self.digests[rel] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                self.digests[rel] = "missing:" + rel
        return self.digests[rel]

    def file(self, rel):
        if rel not in self.files:
            with open(os.path.join(self.root, rel), encoding="utf-8") as f:
                src = f.read()
            self.files[rel] = SourceFile(self, rel, src)
        return self.files[rel]

    def module(self, rel, seen=None):
        """Names (and function parameters) a module exports."""
        if rel in self.modules:
            return self.modules[rel]
        seen = set() if seen is None else seen
        if rel in seen or not self.exists(rel):
            return {}, {}
        seen.add(rel)
        try:
            f = self.file(rel)
        except (ParseError, UnicodeDecodeError, OSError):
            self.modules[rel] = ({}, {})
            return self.modules[rel]
        names, funcs = scope_of(f, seen)
        self.modules[rel] = (names, funcs)
        return names, funcs


def param_info(paren):
    """{parameter name: kind of its default ('none', 'content', 'other' or
    None for a positional parameter)} or None if it takes any argument."""
    ps = {}
    for it in paren.a["items"]:
        if it.spread:
            return None
        if it.name is not None:
            v = it.value
            ps[it.name] = "none" if (v.kind == "ident" and
                                     v.a["name"] == "none") else \
                "content" if v.kind == "content" else "other"
        elif it.value is not None and it.value.kind == "ident":
            ps[it.value.a["name"]] = None
    return ps


def let_funcs(expr):
    """{name: parameters (see param_info) or None (accepts anything)}."""
    out = {}
    params = expr.a.get("params")
    names = expr.a["names"]
    if params is not None and len(names) == 1:
        out[names[0]] = param_info(params)
    else:
        v = expr.a.get("value")
        for nm in names:
            out[nm] = None
        if v is not None and len(names) == 1 and v.kind == "expr":
            parts = v.a["parts"]
            if (len(parts) >= 3 and parts[0].kind == "paren"
                    and parts[1].kind == "op" and parts[1].a["op"] == "=>"):
                out[names[0]] = param_info(parts[0])
    return out


def import_names(f, expr, seen):
    """Names an import statement binds: {name: params}."""
    src = f.eval_str(expr.a["source"])
    if src is None:
        return {}, None
    if src.startswith("@"):
        rel = None
        names_mod, funcs_mod = {}, {}
    else:
        rel = f.resolve(src)
        names_mod, funcs_mod = f.side.module(rel, seen)
    out = {}
    if expr.a["star"]:
        for nm in names_mod:
            out[nm] = funcs_mod.get(nm)
    elif expr.a["items"]:
        for name, alias in expr.a["items"]:
            base = name.split(".")[-1]
            out[alias or base] = funcs_mod.get(base) if "." not in name \
                else None
    elif expr.a["alias"]:
        out[expr.a["alias"]] = None
    else:
        stem = os.path.splitext(os.path.basename(src))[0]
        out[stem] = None
    return out, rel


def scope_of(f, seen=None):
    """Top-level names of a file: (names, funcs)."""
    names = {}
    funcs = {}
    for b in f.blocks:
        if b.kind != "stmt":
            continue
        e = b.a["expr"]
        if b.a["kw"] == "let":
            for nm, ps in let_funcs(e).items():
                names[nm] = True
                funcs[nm] = ps
        elif b.a["kw"] == "import":
            got, _ = import_names(f, e, set() if seen is None else seen)
            for nm, ps in got.items():
                names[nm] = True
                funcs[nm] = ps
    return names, funcs


def collect_labels(f):
    labels = set()
    for t in f.toks:
        for n in walk(t):
            if n.kind == "label":
                labels.add(n.a["name"])
            elif n.kind == "chain" and callee_of(n) == "label":
                args = call_args(n)
                if args and args[0] and args[0][0].value is not None \
                        and args[0][0].value.kind == "str":
                    labels.add(args[0][0].value.a["value"])
    return labels


BIB_ENTRY_RE = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,")


def bib_entries(text):
    """[(key, entry text)] of a BibTeX file."""
    out = []
    for m in BIB_ENTRY_RE.finditer(text):
        if m.group(1).lower() in ("comment", "string", "preamble"):
            continue
        i = text.index("{", m.start())
        depth = 0
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.group(2), text[m.start():j + 1]))
    return out


# --------------------------------------------------------------------------
# Alignment
# --------------------------------------------------------------------------

def norm(text):
    return " ".join(text.split())


def ratio(a, b):
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.real_quick_ratio() < 0.2 or sm.quick_ratio() < 0.2:
        return 0.0
    return sm.ratio()


def align(okeys, nkeys, simf, force=None, oo=0, no=0):
    """Align two sequences: [('eq', i, j) | ('pair', i, j) | ('del', i) |
    ('ins', j)]. simf(i, j) gives the similarity score of a pairable
    pair (above its threshold, as score > 0) or None. force(i, j): pair a
    lone replaced element with a lone replacement of the same kind. oo, no:
    offsets added to the indices (when aligning a part of a sequence)."""
    sm = difflib.SequenceMatcher(None, okeys, nkeys, autojunk=False)
    ops = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            ops.extend(("eq", oo + i1 + k, no + j1 + k)
                       for k in range(i2 - i1))
        else:
            ops.extend(dp_pair(list(range(oo + i1, oo + i2)),
                               list(range(no + j1, no + j2)), simf, force))
    return ops


def align_anchored(okeys, nkeys, oanchors, nanchors, simf, force=None):
    """Align with anchors: elements with equal anchor keys (a title, the
    text of a heading - else the key itself) are matched first, as equal
    elements if their keys are equal too, else as a pair; the ranges
    between the anchors are aligned with align()."""
    sm = difflib.SequenceMatcher(None, oanchors, nanchors, autojunk=False)
    ops = []
    pi = pj = 0
    for i, j, size in sm.get_matching_blocks():
        ops.extend(align(okeys[pi:i], nkeys[pj:j], simf, force, pi, pj))
        for k in range(size):
            ops.append(("eq" if okeys[i + k] == nkeys[j + k] else "pair",
                        i + k, j + k))
        pi, pj = i + size, j + size
    return ops


def dp_pair(I, J, simf, force=None):
    n = len(I)
    m = len(J)
    pairs = []
    if n == 1 and m == 1 and force is not None and force(I[0], J[0]):
        pairs = [(0, 0)]
    elif n and m and n * m <= 400000:
        score = [[0.0] * (m + 1) for _ in range(n + 1)]
        back = [[0] * (m + 1) for _ in range(n + 1)]
        for a in range(1, n + 1):
            row = score[a]
            prev = score[a - 1]
            brow = back[a]
            for b in range(1, m + 1):
                best = prev[b]
                bp = 1
                if row[b - 1] > best:
                    best = row[b - 1]
                    bp = 2
                s = simf(I[a - 1], J[b - 1])
                if s is not None and prev[b - 1] + s > best:
                    best = prev[b - 1] + s
                    bp = 3
                row[b] = best
                brow[b] = bp
        a, b = n, m
        while a > 0 and b > 0:
            bp = back[a][b]
            if bp == 3:
                pairs.append((a - 1, b - 1))
                a -= 1
                b -= 1
            elif bp == 1:
                a -= 1
            else:
                b -= 1
        pairs.reverse()
    ops = []
    a = b = 0
    for pa, pb in pairs + [(n, m)]:
        ops.extend(("del", I[k]) for k in range(a, pa))
        ops.extend(("ins", J[k]) for k in range(b, pb))
        if pa < n:
            ops.append(("pair", I[pa], J[pb]))
        a, b = pa + 1, pb + 1
    return ops


# --------------------------------------------------------------------------
# Diff engine
# --------------------------------------------------------------------------

REPLACE = object()


class Res:
    """Result of diffing two values: text (None: keep the NEW text) and
    whether a change not shown inline happened."""

    __slots__ = ("text", "changed")

    def __init__(self, text, changed):
        self.text = text
        self.changed = changed


class Out:
    """Concatenation of inline pieces which keeps embedded expressions
    from swallowing the text after them."""

    def __init__(self):
        self.parts = []
        self.code_end = False

    def add(self, text, code_end=False):
        if not text:
            return
        if self.code_end and text[0] in "([.":
            self.parts.append(";")
        self.parts.append(text)
        self.code_end = code_end and not text.endswith(";")

    def empty(self):
        return not self.parts

    def get(self):
        return "".join(self.parts)


def escape_start(text):
    """Escape a list/enum/heading/term marker at the start of wrapped text."""
    m = re.match(r"([-+/]|=+)(?=\s|$)", text)
    if m:
        return "\\" + text
    m = re.match(r"(\d+)\.(?=\s|$)", text)
    if m:
        return m.group(1) + "\\." + text[m.end():]
    return text


def shift(text, delta):
    if delta == 0 or "\n" not in text:
        return text
    lines = text.split("\n")
    for k in range(1, len(lines)):
        line = lines[k]
        if delta > 0:
            if line.strip():
                lines[k] = " " * delta + line
        else:
            strip = 0
            while strip < -delta and strip < len(line) and line[strip] == " ":
                strip += 1
            lines[k] = line[strip:]
    return "\n".join(lines)


def norm_title(text):
    """A title for matching: no line breaks, collapsed space, any case."""
    return norm(re.sub(r"\\(?=\s)", " ", text)).casefold()


def word_join(a, b):
    """Whether a deleted text a and the inserted text b replacing it are
    words that need a space between them."""
    return bool(a) and bool(b) and a[-1] not in PUNCT and b[0] not in PUNCT


def strip_comments(ws):
    ws = re.sub(r"/\*.*?\*/", "", ws, flags=re.S)
    return re.sub(r"//[^\n]*", "", ws)


class Global:
    """State shared by all files of one run."""

    def __init__(self, opts, old, new):
        self.opts = opts
        self.old = old
        self.new = new
        self.new_labels = set()
        self.kept_old_labels = set()
        self.bib_keys = set()
        self.placeholders = []
        self.slide_callees = set(opts.slide_callee)
        self.diff_old = set()
        self.paired_old = set()


class FileDiff:
    """Merges the OLD and NEW version of one file."""

    def __init__(self, g, ofile, nfile, entry):
        self.g = g
        self.o = ofile
        self.n = nfile
        self.entry = entry
        self.nscope_names, self.nscope_funcs = scope_of(nfile)
        self.old_sources = self.import_sources(ofile)
        self.old_modules = []     # OLD modules deleted calls fall back to
        self.used_modules = set()
        self.emitted = []         # spans of OLD text emitted
        self.compute_old_edits()

    def import_sources(self, f):
        """{name: module (relative path) an import of f binds it from}."""
        out = {}
        for b in f.blocks:
            if b.kind != "stmt" or b.a["kw"] != "import":
                continue
            e = b.a["expr"]
            p = f.eval_str(e.a["source"])
            if p is None or p.startswith("@"):
                continue
            rel = f.resolve(p)
            if e.a["star"]:
                for nm in f.side.module(rel)[0]:
                    out.setdefault(nm, rel)
            elif e.a["items"]:
                for name, alias in e.a["items"]:
                    if "." not in name and alias is None:
                        out.setdefault(name, rel)
        return out

    def fallback_edit(self, n):
        """A call of deleted content that the NEW definition of its callee
        does not accept: call the OLD definition instead."""
        callee = callee_of(n)
        if callee is None or "." in callee:
            return None
        params = self.nscope_funcs.get(callee)
        rel = self.old_sources.get(callee)
        if params is None or rel is None:
            return None
        pos, named = call_args(n)
        npos = sum(1 for v in params.values() if v is None)
        if all(nm in params for nm in named) and len(pos) <= npos:
            return None
        if rel not in self.old_modules:
            self.old_modules.append(rel)
        k = self.old_modules.index(rel)
        base = n.a["base"]
        return (base.start, base.end, "td-old-%d.%s" % (k, callee),
                ("module", rel))

    # ---------------------------------------------------------- OLD text

    def compute_old_edits(self):
        """Edits applied to every piece of OLD text emitted: labels NEW
        defines are dropped, references are resolved at the end, paths are
        redirected into the copy of OLD, deleted figures are not outlined."""
        f = self.o
        edits = []
        for t in f.toks:
            for n in walk(t):
                k = n.kind
                if k == "label":
                    if n.a["name"] in self.g.new_labels:
                        edits.append((n.start, n.end, "", None))
                    else:
                        edits.append((n.start, n.end, f.src[n.start:n.end],
                                      ("label", n.a["name"])))
                elif k == "ref":
                    idx = len(self.g.placeholders)
                    self.g.placeholders.append(
                        (n.a["name"], f.src[n.start:n.end]))
                    edits.append((n.start, n.end, "\x00%d\x00" % idx, None))
                elif k == "chain":
                    callee = callee_of(n)
                    fb = self.fallback_edit(n)
                    if fb is not None:
                        edits.append(fb)
                    if callee == "figure" and \
                            "outlined" not in call_args(n)[1]:
                        ops = n.a["ops"]
                        first = ops[0]
                        if first[0] == "args":
                            p = first[1]
                            edits.append((p.start + 1, p.start + 1,
                                          "outlined: false, ", None))
                        else:
                            pos = first[1].start
                            edits.append((pos, pos, "(outlined: false)",
                                          None))
                elif k == "kw" and n.a["kw"] in ("import", "include"):
                    src = n.a["source"]
                    p = f.eval_str(src)
                    if p is not None and not p.startswith("@"):
                        edits.append((src.start, src.end, '"/%s/%s"' % (
                            OLD_DIR, f.resolve(p)), None))
            for v, rel in f.asset_args(t):
                edits.append((v.start, v.end, '"/%s/%s"' % (OLD_DIR, rel),
                              None))
        edits.sort(key=lambda e: (e[0], e[1]))
        clean = []
        last = -1
        for e in edits:
            if e[0] < last:
                continue
            clean.append(e)
            last = max(last, e[1])
        f.edits = clean

    def old_text(self, a, b, delta=0):
        f = self.o
        out = []
        pos = a
        import bisect
        idx = bisect.bisect_left(f.edits, (a, -1))
        while idx < len(f.edits):
            s, e, text, lab = f.edits[idx]
            if s >= b or e > b:
                if s >= b:
                    break
                idx += 1
                continue
            if s >= pos:
                out.append(f.src[pos:s])
                out.append(text)
                if lab is not None and lab[0] == "label":
                    self.g.kept_old_labels.add(lab[1])
                elif lab is not None:
                    self.used_modules.add(lab[1])
                pos = e
            idx += 1
        out.append(f.src[pos:b])
        self.emitted.append((a, b))
        return shift("".join(out), delta)

    def used_names(self):
        """Identifiers in the OLD text emitted."""
        import bisect
        merged = []
        for a, b in sorted(self.emitted):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        starts = [m[0] for m in merged]
        names = set()
        for t in self.o.toks:
            for n in walk(t):
                if n.kind == "ident":
                    i = bisect.bisect_right(starts, n.start) - 1
                    if i >= 0 and n.end <= merged[i][1]:
                        names.add(n.a["name"])
        return names

    def new_text(self, a, b):
        return self.n.src[a:b]

    # ------------------------------------------------------- similarity

    def words(self, f, nodes):
        a = nodes[0].start
        b = nodes[-1].end
        return WORD_RE.findall(f.src[a:b])

    # ----------------------------------------------------------- blocks

    def block_key(self, f, b):
        text = norm(f.src[b.start:b.end])
        extra = ""
        if b.kind == "item":
            extra = b.a["mtype"]
        elif b.kind in ("call",):
            extra = b.a["callee"]
        return (b.kind, extra, text, f.assets(b.toks))

    def title_text(self, f, b):
        """Normalized text of the title argument of a slide call."""
        if b.kind != "call" or b.a["callee"] not in self.g.slide_callees:
            return None
        args = call_args(b.a["expr"])
        t = args[1].get("title") if args else None
        if t is None or t.value is None or t.value.kind != "content":
            return None
        s, e = t.value.a["inner"]
        return norm_title(f.src[s:e])

    def anchor_key(self, f, b, key):
        """What blocks are matched by first: slides by their title,
        headings by their text; other blocks by their key."""
        t = self.title_text(f, b)
        if t:
            return ("title", b.a["callee"], t)
        if b.kind == "heading" and b.a["body"]:
            return ("heading", norm_title(f.src[b.a["body"][0].start:
                                                b.a["body"][-1].end]))
        return key

    def content_args(self, expr):
        """The content arguments of a call (content blocks and arrays of
        content) - not its layout arguments."""
        args = call_args(expr)
        if not args:
            return []
        return [it.value for it in args[0] + list(args[1].values())
                if self.contentish(it.value)]

    def block_content_words(self, f, b):
        if b.kind in ("call", "stmt"):
            ws = []
            expr = b.a["expr"]
            if b.kind == "stmt" and b.a["kw"] == "show":
                expr = expr.a["transform"]
            nodes = self.content_args(expr) if b.kind == "call" else [expr]
            for v in nodes:
                for n in walk(v):
                    if n.kind == "content":
                        s, e = n.a["inner"]
                        ws.extend(WORD_RE.findall(f.src[s:e]))
            if ws:
                return ws
        if b.kind == "heading":
            if not b.a["body"]:
                return []
            return self.words(f, b.a["body"])
        return WORD_RE.findall(f.src[b.start:b.end])

    def pairable(self, ob, nb):
        if ob.kind != nb.kind:
            return None
        k = ob.kind
        if k == "par":
            return 0.35
        if k == "heading":
            return 0.3
        if k == "item":
            return 0.4 if ob.a["mtype"] == nb.a["mtype"] else None
        if k == "call":
            if ob.a["callee"] != nb.a["callee"] or \
                    ob.a["callee"] in ATOMIC_CALLEES:
                return None
            return 0.35
        if k == "stmt":
            if ob.a["kw"] == nb.a["kw"] == "show" and \
                    ob.a["expr"].a["selector"] is None and \
                    nb.a["expr"].a["selector"] is None:
                oc = callee_of(ob.a["expr"].a["transform"])
                if oc is not None and oc == callee_of(
                        nb.a["expr"].a["transform"]):
                    return 0.0
            return None
        if k in ("raw", "code"):
            return 0.5
        return None

    def diff_seq(self, oblocks, nblocks, obase, nbase, header_after=None):
        """Merge two block sequences; returns the text from the start of
        the first block to the end of the last one."""
        o, n = self.o, self.n
        onc = [i for i, b in enumerate(oblocks) if b.kind != "comment"]
        nnc = [j for j, b in enumerate(nblocks) if b.kind != "comment"]
        okeys = [self.block_key(o, oblocks[i]) for i in onc]
        nkeys = [self.block_key(n, nblocks[j]) for j in nnc]
        owords = {}
        nwords = {}

        def simf(a, b):
            ob = oblocks[onc[a]]
            nb = nblocks[nnc[b]]
            thr = self.pairable(ob, nb)
            if thr is None:
                return None
            if a not in owords:
                owords[a] = self.block_content_words(o, ob)
            if b not in nwords:
                nwords[b] = self.block_content_words(n, nb)
            r = ratio(owords[a], nwords[b]) if (owords[a] or nwords[b]) \
                else 1.0
            if ob.kind == "heading" and ob.a["body"] and nb.a["body"]:
                ob_, nb_ = ob.a["body"], nb.a["body"]
                r = max(r, ratio(o.src[ob_[0].start:ob_[-1].end],
                                 n.src[nb_[0].start:nb_[-1].end]))
            lo = ob.a.get("label")
            ln = nb.a.get("label")
            if lo is not None and ln is not None and \
                    lo.a["name"] == ln.a["name"]:
                r = 1.0
            if r < thr:
                return None
            return r - thr + 0.05

        def force(a, b):
            ob = oblocks[onc[a]]
            nb = nblocks[nnc[b]]
            return ob.kind in ("par", "item", "heading", "call") and \
                self.pairable(ob, nb) is not None

        oanch = [self.anchor_key(o, oblocks[i], okeys[k])
                 for k, i in enumerate(onc)]
        nanch = [self.anchor_key(n, nblocks[j], nkeys[k])
                 for k, j in enumerate(nnc)]
        ops = align_anchored(okeys, nkeys, oanch, nanch, simf, force)
        # Map to full indices, put NEW comments back in place.
        full = []
        emitted_new = 0

        def flush_comments(upto):
            nonlocal emitted_new
            while emitted_new < upto:
                if nblocks[emitted_new].kind == "comment":
                    full.append(("eq", None, emitted_new))
                emitted_new += 1

        for op in ops:
            if op[0] == "del":
                full.append(("del", onc[op[1]], None))
                continue
            j = nnc[op[2] if op[0] != "ins" else op[1]]
            flush_comments(j)
            if op[0] == "ins":
                full.append(("ins", None, j))
            else:
                full.append((op[0], onc[op[1]], j))
            emitted_new = j + 1
        flush_comments(len(nblocks))

        pieces = []   # (text, side, index, kind, col)
        delta = nbase - obase
        enum_count = 0
        after_del = False
        for tag, i, j in full:
            if tag == "eq":
                b = nblocks[j]
                text = self.new_text(b.start, b.end)
                if b.kind == "item" and b.a["mtype"] == "enum":
                    enum_count += 1
                    text = self.renumber(b, text, enum_count, after_del)
                elif b.kind != "comment":
                    enum_count = 0
                after_del = False
                pieces.append((text, "new", j, b.kind, n.parser.col(b.start)))
            elif tag == "ins":
                b = nblocks[j]
                text = self.insert_block(b)
                if b.kind == "item" and b.a["mtype"] == "enum":
                    enum_count += 1
                    text = self.renumber(b, text, enum_count, after_del)
                elif b.kind != "comment":
                    enum_count = 0
                after_del = False
                pieces.append((text, "new", j, b.kind, n.parser.col(b.start)))
            elif tag == "del":
                b = oblocks[i]
                text = self.delete_block(b, delta)
                if text:
                    if b.kind == "item" and b.a["mtype"] == "enum":
                        after_del = True
                    pieces.append((text, "old", i, b.kind,
                                   o.parser.col(b.start) + delta))
            else:
                ob = oblocks[i]
                nb = nblocks[j]
                res = self.pair_blocks(ob, nb, obase, nbase)
                if nb.kind == "item" and nb.a["mtype"] == "enum":
                    enum_count += 1
                elif nb.kind != "comment":
                    enum_count = 0
                if res is REPLACE:
                    pieces.append((self.delete_block(ob, delta), "old", i,
                                   ob.kind, o.parser.col(ob.start) + delta))
                    pieces.append((self.insert_block(nb), "new", j, nb.kind,
                                   n.parser.col(nb.start)))
                    after_del = False
                else:
                    if nb.kind == "item" and nb.a["mtype"] == "enum":
                        res = self.renumber(nb, res, enum_count, after_del)
                    after_del = False
                    pieces.append((res, "new", j, nb.kind,
                                   n.parser.col(nb.start)))
            if header_after is not None and tag != "del" and j == header_after:
                pieces.append((None, "header", None, "stmt", 0))
        return self.join_pieces(pieces, oblocks, nblocks, delta)

    def renumber(self, b, text, count, after_del):
        """Give an automatically numbered enum item after a deleted item its
        number explicitly, so that the numbering stays the one of NEW."""
        if not after_del or self.n.src[b.start] != "+":
            return text
        return "%d." % count + text[1:]

    def join_pieces(self, pieces, oblocks, nblocks, delta):
        out = []
        prev = None
        prev_par = None   # last non-comment piece
        blank_since = False
        para_kinds = ("par", "call", "code", "raw")
        for piece in pieces:
            text, side, idx, kind, col = piece
            if side == "header":
                out.append("\n" + self.header())
                continue
            if prev is not None:
                pt, ps, pidx, pkind, _ = prev
                if ps == side == "new" and pidx is not None and \
                        idx == pidx + 1:
                    sep = self.n.src[nblocks[pidx].end:nblocks[idx].start]
                elif ps == side == "old" and idx == pidx + 1:
                    sep = shift(self.o.src[oblocks[pidx].end:
                                           oblocks[idx].start], delta)
                    sep = strip_comments(sep)
                    nls = max(1, sep.count("\n"))
                    sep = "\n" * nls + " " * max(col, 0)
                else:
                    blocks = nblocks if side == "new" else oblocks
                    src = self.n.src if side == "new" else self.o.src
                    if idx > 0:
                        nls = src.count("\n", blocks[idx - 1].end,
                                        blocks[idx].start)
                    else:
                        nls = 2 if kind in para_kinds else 1
                    sep = "\n" * max(1, min(nls, 2)) + " " * max(col, 0)
                if kind in para_kinds and prev_par is not None and \
                        prev_par[3] in para_kinds and not blank_since and \
                        "\n\n" not in sep.replace(" ", ""):
                    orig = (prev_par[1] == side == "new" and all(
                        nblocks[k].kind == "comment"
                        for k in range(prev_par[2] + 1, idx)))
                    if not orig:
                        sep = "\n\n" + " " * max(col, 0)
                out.append(sep)
                if "\n\n" in sep.replace(" ", "").replace("\t", ""):
                    blank_since = True
            out.append(text)
            prev = piece
            if kind != "comment":
                prev_par = piece
                blank_since = False
        return "".join(out)

    # Whole blocks.

    def insert_block(self, b):
        n = self.n
        k = b.kind
        text = self.new_text(b.start, b.end)
        if k in ("stmt", "comment"):
            return text
        if k == "par":
            return "#tins[" + text + "]"
        if k == "heading":
            body = self.new_text(b.a["body"][0].start, b.a["body"][-1].end) \
                if b.a["body"] else ""
            out = "=" * b.a["level"] + " " + ("#tins[" + body + "]"
                                             if body else "")
            if b.a["label"] is not None:
                out += " " + self.new_text(b.a["label"].start,
                                           b.a["label"].end)
            return out
        if k == "item":
            marker = self.new_text(b.a["marker"].start, b.a["marker"].end)
            if b.a["mtype"] == "term":
                term = b.a["term"]
                tt = self.new_text(term[0].start, term[-1].end) if term \
                    else ""
                desc = b.a["body"]
                dt = self.new_text(desc[0].start, desc[-1].end) if desc \
                    else ""
                return marker + " #tins[" + tt + "]: " + (
                    "#tins[" + dt + "]" if dt else "")
            body = b.a["body"]
            if not body:
                return marker
            return marker + " " + self.wrap_seq(body, "ins")
        if k == "call":
            if b.a["callee"] in self.g.slide_callees:
                return "#tslide-ins[" + text + "]"
            if b.a["callee"] in BOX_CALLEES:
                return "#tins-block[" + text + "]"
            return self.wrap_call(b, "ins", 0)
        if k == "raw" or has_box(b.toks[0].a.get("expr")):
            return "#tins-block[" + text + "]"
        return "#tins-par[" + text + "]"

    def delete_block(self, b, delta):
        k = b.kind
        if k == "comment":
            return ""
        if k == "stmt":
            return self.delete_stmt(b, delta)
        if k in ("par", "call", "raw", "code"):
            text = self.old_text(b.start, b.end, delta)
        if k == "par":
            return "#tdel[" + text + "]"
        if k == "heading":
            body = self.old_text(b.a["body"][0].start, b.a["body"][-1].end,
                                 delta) if b.a["body"] else ""
            return "#tdel-heading(level: %d)[%s]" % (b.a["level"], body)
        if k == "item":
            mt = b.a["mtype"]
            marker = "+" if mt == "enum" else \
                self.o.src[b.a["marker"].start:b.a["marker"].end]
            if mt == "term":
                term = b.a["term"]
                tt = self.old_text(term[0].start, term[-1].end, delta) \
                    if term else ""
                desc = b.a["body"]
                dt = self.old_text(desc[0].start, desc[-1].end, delta) \
                    if desc else ""
                return marker + " #tdel[" + tt + "]: " + (
                    "#tdel[" + dt + "]" if dt else "")
            body = b.a["body"]
            if not body:
                return marker + " #tdel[]"
            return marker + " " + self.wrap_seq(body, "del", delta)
        if k == "call":
            if b.a["callee"] in self.g.slide_callees:
                return "#tslide-del[" + text + "]"
            if b.a["callee"] in BOX_CALLEES:
                return "#tdel-block[" + text + "]"
            return self.wrap_call(b, "del", delta)
        if k == "raw" or has_box(b.toks[0].a.get("expr")):
            return "#tdel-block[" + text + "]"
        return "#tdel-par[" + text + "]"

    def wrap_seq(self, blocks, kind, delta=0):
        """A sequence of blocks inserted or deleted as a whole."""
        f = self.n if kind == "ins" else self.o
        out = []
        for k, b in enumerate(blocks):
            if k:
                sep = f.src[blocks[k - 1].end:b.start]
                if kind == "del":
                    nls = max(1, min(2, sep.count("\n")))
                    sep = "\n" * nls + " " * max(0, f.parser.col(b.start)
                                                  + delta)
                out.append(sep)
            out.append(self.insert_block(b) if kind == "ins"
                       else self.delete_block(b, delta))
        return "".join(out)

    def wrap_call(self, b, kind, delta):
        """A standalone call inserted or deleted as a whole: its content
        arguments are marked (so that it keeps its layout), a call without
        content arguments is marked as a block."""
        f = self.n if kind == "ins" else self.o
        get = self.new_text if kind == "ins" else \
            (lambda a, e: self.old_text(a, e, delta))
        w = "tins" if kind == "ins" else "tdel"
        points = []
        args = call_args(b.a["expr"])
        for it in (args[0] + list(args[1].values())) if args else []:
            v = it.value
            if v is None:
                continue
            if v.kind == "content":
                s, e = v.a["inner"]
                if f.src[s:e].strip():
                    points.append((s, "#%s[" % w))
                    points.append((e, "]"))
            elif self.is_content_array(v) and v.a["items"]:
                points.append((v.start, "%s-arr(" % w))
                points.append((v.end, ")"))
        if not points:
            return "#%s-par[" % w + get(b.start, b.end) + "]"
        points.sort(key=lambda p: p[0])
        out = []
        pos = b.start
        for p, t in points:
            out.append(get(pos, p))
            out.append(t)
            pos = p
        out.append(get(pos, b.end))
        return "".join(out)

    def delete_stmt(self, b, delta):
        kw = b.a["kw"]
        e = b.a["expr"]
        if kw == "let":
            names = e.a["names"]
            if names and not any(nm in self.nscope_names for nm in names):
                return self.old_text(b.start, b.end, delta)
            return ""
        if kw == "include":
            p = self.o.eval_str(e.a["source"])
            if p is None:
                return ""
            rel = self.o.resolve(p)
            if rel in self.g.paired_old or self.g.new.exists(rel):
                return ""
            if rel in self.g.diff_old:
                return '#include "/%s"' % rel
            return ""
        return ""

    def header(self):
        lines = ['#import "/%s": *' % HELPER_NAME]
        lines.extend(self.old_imports())
        if self.entry:
            lines.append("#show: td-setup" if not self.g.opts.no_legend
                         else "#show: td-setup.with(legend: false)")
        return "\n".join(lines)

    def old_imports(self):
        """Imports of the names OLD had in scope but NEW has not, from the
        copy of OLD, for deleted content using them."""
        f = self.o
        out = []
        helper = HELPER_NAMES
        used = self.used_names()
        for k, rel in enumerate(self.old_modules):
            if rel in self.used_modules:
                out.append('#import "/%s/%s" as td-old-%d' % (OLD_DIR, rel,
                                                            k))
        for b in f.blocks:
            if b.kind != "stmt" or b.a["kw"] != "import":
                continue
            e = b.a["expr"]
            p = f.eval_str(e.a["source"])
            if p is None or p.startswith("@"):
                continue
            rel = f.resolve(p)
            if not self.g.old.exists(rel):
                continue
            path = "/%s/%s" % (OLD_DIR, rel)
            if e.a["star"]:
                names_mod, _ = self.g.old.module(rel)
                names = sorted(nm for nm in names_mod
                               if nm not in self.nscope_names
                               and nm not in helper and nm in used)
                if names:
                    out.append('#import "%s": %s' % (path, ", ".join(names)))
            elif e.a["items"]:
                items = []
                for name, alias in e.a["items"]:
                    bound = alias or name.split(".")[-1]
                    if bound in self.nscope_names or bound in helper or \
                            bound not in used:
                        continue
                    items.append(name + (" as " + alias if alias else ""))
                if items:
                    out.append('#import "%s": %s' % (path, ", ".join(items)))
            else:
                bound = e.a["alias"] or os.path.splitext(
                    os.path.basename(p))[0]
                if bound not in self.nscope_names and bound not in helper \
                        and bound in used:
                    out.append('#import "%s" as %s' % (path, bound))
        return out

    # Paired blocks.

    def pair_blocks(self, ob, nb, obase, nbase):
        k = nb.kind
        o, n = self.o, self.n
        delta = nbase - obase
        if k == "par":
            return self.diff_inline(ob.toks, nb.toks, delta)
        if k == "heading":
            body = self.diff_inline(ob.a["body"], nb.a["body"], delta,
                                    heading=True)
            out = "=" * nb.a["level"] + (" " + body if body else "")
            if nb.a["label"] is not None:
                out += " " + self.new_text(nb.a["label"].start,
                                           nb.a["label"].end)
            return out
        if k == "item":
            marker = self.new_text(nb.a["marker"].start, nb.a["marker"].end)
            ob_base = ob.a["base"]
            nb_base = nb.a["base"]
            if nb.a["mtype"] == "term":
                term = self.diff_inline(ob.a["term"], nb.a["term"],
                                        nb_base - ob_base)
                body = self.diff_seq(ob.a["body"], nb.a["body"], ob_base,
                                     nb_base)
                return marker + " " + term + ":" + (" " + body if body
                                                    else "")
            body = self.diff_seq(ob.a["body"], nb.a["body"], ob_base, nb_base)
            return marker + (" " + body if body else "")
        if k == "call":
            res = self.diff_chain(ob.a["expr"], nb.a["expr"])
            if res is REPLACE:
                return REPLACE
            code = nb.a["code"]
            text = "#" + (res.text if res.text is not None else
                          self.new_text(nb.a["expr"].start,
                                        nb.a["expr"].end))
            if code.a["semi"]:
                text += ";"
            orig = self.new_text(code.start, code.end)
            tail = self.new_text(code.end, nb.end)
            if nb.a["callee"] in self.g.slide_callees:
                if res.changed or text != orig:
                    return "#tslide-chg[" + text + tail + "]"
                return text + tail
            if res.changed:
                return "#tchg[" + text + tail + "]"
            return text + tail
        if k == "stmt":
            ot = ob.a["expr"].a["transform"]
            nt = nb.a["expr"].a["transform"]
            res = self.diff_chain(ot, nt)
            if res is REPLACE or res.text is None:
                return self.new_text(nb.start, nb.end)
            return self.new_text(nb.start, nt.start) + res.text + \
                self.new_text(nt.end, nb.end)
        if k == "raw":
            return REPLACE
        # other code
        oe = ob.toks[0].a["expr"]
        ne = nb.toks[0].a["expr"]
        if oe.kind == "codeblock" and ne.kind == "codeblock":
            res = self.diff_codeblock(oe, ne)
            if res is REPLACE:
                return REPLACE
            text = self.new_text(nb.start, ne.start) + (
                res.text if res.text is not None else
                self.new_text(ne.start, ne.end)) + \
                self.new_text(ne.end, nb.end)
            return "#tchg[" + text + "]" if res.changed else text
        if o.assets(oe) != n.assets(ne):
            return REPLACE
        if self.masked(o, ob.toks[0]) == self.masked(n, nb.toks[0]):
            return self.new_text(nb.start, nb.end)
        return "#tchg[" + self.new_text(nb.start, nb.end) + "]"

    # ----------------------------------------------------------- inline

    def units(self, f, toks):
        us = []
        prev = toks[0].start if toks else 0
        for t in toks:
            if t.kind in ("space", "parbreak", "linebreak", "comment"):
                continue
            if t.kind == "label" and us:
                us[-1]["end"] = t.end
                us[-1]["label"] = t
                prev = t.end
                continue
            us.append({"tok": t, "start": t.start, "end": t.end,
                       "pre": prev, "label": None})
            prev = t.end
        return us

    def unit_key(self, f, u):
        t = u["tok"]
        text = f.src[u["start"]:u["end"]]
        if t.kind == "text":
            return text
        if t.kind == "code":
            return ("code", norm(text), f.assets(t))
        return (t.kind, norm(text))

    def unit_pairable(self, ou, nu):
        ot = ou["tok"]
        nt = nu["tok"]
        if ot.kind != nt.kind:
            return False
        if ot.kind in ("strong", "emph", "bracket"):
            return True
        if ot.kind == "code":
            c = callee_of(ot.a["expr"])
            return c is not None and c not in ATOMIC_CALLEES and \
                c == callee_of(nt.a["expr"])
        return False

    def diff_inline(self, otoks, ntoks, delta, heading=False):
        """Word diff of two inline token sequences. In a heading, a deleted
        run takes the space after it along, so that the outline (which
        leaves deleted text out) shows no double spaces."""
        o, n = self.o, self.n
        ou = self.units(o, otoks)
        nu = self.units(n, ntoks)
        okeys = [self.unit_key(o, u) for u in ou]
        nkeys = [self.unit_key(n, u) for u in nu]

        def simf(a, b):
            if not self.unit_pairable(ou[a], nu[b]):
                return None
            r = ratio(WORD_RE.findall(o.src[ou[a]["start"]:ou[a]["end"]]),
                      WORD_RE.findall(n.src[nu[b]["start"]:nu[b]["end"]]))
            return r - 0.25 + 0.05 if r >= 0.25 else None

        ops = align(okeys, nkeys, simf)
        ops = self.cleanup(ops, ou, nu, o, n)
        out = Out()
        pending = [None]     # deleted text not yet closed (headings)

        def started():
            return not out.empty() or pending[0] is not None

        def close(pre):
            """Close a pending deleted run; returns the remaining pre."""
            if pending[0] is None:
                return pre
            text = escape_start(pending[0])
            pending[0] = None
            if pre and not pre.strip() and "\n" not in pre:
                out.add("#tdel[" + text + " ]", code_end=True)
                return ""
            out.add("#tdel[" + text + "]", code_end=True)
            return pre

        def put_del(pre, text):
            pre = close(pre)
            out.add(pre)
            if heading:
                pending[0] = text
            else:
                out.add("#tdel[" + escape_start(text) + "]", code_end=True)

        def put(pre, text, code_end=True):
            pre = close(pre)
            out.add(pre)
            out.add(text, code_end=code_end)

        after_del = False
        k = 0
        while k < len(ops):
            op = ops[k]
            if op[0] in ("del", "ins"):
                dels = []
                inss = []
                while k < len(ops) and ops[k][0] == "del":
                    dels.append(ops[k][1])
                    k += 1
                while k < len(ops) and ops[k][0] == "ins":
                    inss.append(ops[k][1])
                    k += 1
                while k < len(ops) and ops[k][0] == "del":
                    dels.append(ops[k][1])
                    k += 1
                if dels:
                    d0, d1 = ou[dels[0]], ou[dels[-1]]
                    pre = self.old_pre(o, d0, delta) if started() else ""
                    put_del(pre, self.old_text(d0["start"], d1["end"], delta))
                    after_del = True
                if inss:
                    i0, i1 = nu[inss[0]], nu[inss[-1]]
                    pre = n.src[i0["pre"]:i0["start"]]
                    text = n.src[i0["start"]:i1["end"]]
                    if not started():
                        pre = ""
                    elif after_del:
                        dtext = o.src[ou[dels[-1]]["start"]:
                                      ou[dels[-1]]["end"]]
                        pre = " " if (pre or self.old_pre(o, ou[dels[0]],
                                                          delta)
                                      or word_join(dtext, text)) else ""
                    put(pre, "#tins[" + escape_start(text) + "]")
                    after_del = False
                continue
            _, i, j = op
            u = nu[j]
            pre = n.src[u["pre"]:u["start"]]
            if not started():
                pre = ""
            elif after_del and not pre:
                pre = self.old_pre(o, ou[i], delta)
            if op[0] == "eq":
                put(pre, n.src[u["start"]:u["end"]],
                    code_end=u["tok"].kind == "code")
            else:
                text = self.diff_unit(ou[i], u, delta)
                if text is None:
                    otext = self.old_text(ou[i]["start"], ou[i]["end"],
                                          delta)
                    pre_o = self.old_pre(o, ou[i], delta) if started() \
                        else ""
                    put_del(pre_o, otext)
                    put(" " if (pre or pre_o or word_join(
                        o.src[ou[i]["start"]:ou[i]["end"]],
                        n.src[u["start"]:u["end"]])) else "",
                        "#tins[" + escape_start(
                            n.src[u["start"]:u["end"]]) + "]")
                else:
                    put(pre, text)
            after_del = False
            k += 1
        close("")
        return out.get()

    def cleanup(self, ops, ou, nu, o, n):
        """Merge short equal runs (one short word or punctuation) between
        two changes into the changes: fewer, longer runs read better."""
        res = list(ops)
        changed = True
        while changed:
            changed = False
            for k in range(1, len(res) - 1):
                if res[k][0] != "eq":
                    continue
                if res[k - 1][0] in ("del", "ins") and \
                        res[k + 1][0] in ("del", "ins"):
                    _, i, j = res[k]
                    text = n.src[nu[j]["start"]:nu[j]["end"]]
                    if len(text) <= 3 and nu[j]["tok"].kind == "text":
                        res[k:k + 1] = [("del", i), ("ins", j)]
                        changed = True
                        break
        # Order every run of changes: deletions first.
        out = []
        k = 0
        while k < len(res):
            if res[k][0] in ("del", "ins"):
                run = []
                while k < len(res) and res[k][0] in ("del", "ins"):
                    run.append(res[k])
                    k += 1
                out.extend([r for r in run if r[0] == "del"])
                out.extend([r for r in run if r[0] == "ins"])
            else:
                out.append(res[k])
                k += 1
        return out

    def old_pre(self, o, u, delta):
        pre = strip_comments(o.src[u["pre"]:u["start"]])
        if "\n" in pre:
            return "\n" + " " * max(0, len(pre) - pre.rfind("\n") - 1 + delta)
        return " " if pre else ""

    def diff_unit(self, ou, nu, delta):
        o, n = self.o, self.n
        ot = ou["tok"]
        nt = nu["tok"]
        label = ""
        if nu["label"] is not None:
            label = n.src[nt.end:nu["end"]]
        if nt.kind in ("strong", "emph", "bracket"):
            inner = self.diff_inline(ot.a["toks"], nt.a["toks"], delta)
            if nt.kind == "bracket":
                return "[" + inner + "]" + label
            d = n.src[nt.start]
            close = d if nt.a.get("closed", True) else ""
            return d + inner + close + label
        if nt.kind == "code":
            res = self.diff_chain(ot.a["expr"], nt.a["expr"])
            if res is REPLACE:
                return None
            text = "#" + (res.text if res.text is not None else
                          n.src[nt.a["expr"].start:nt.a["expr"].end])
            if nt.a["semi"]:
                text += ";"
            if res.changed:
                return "#tchg[" + text + label + "]"
            return text + label
        return None

    # ------------------------------------------------------------- code

    def masked(self, f, node):
        """Text of a node with layout-only literals masked."""
        spans = []
        for x in walk(node):
            if x.kind == "num":
                spans.append((x.start, x.end))
            elif x.kind == "ident" and x.a["name"] in LAYOUT_IDENTS:
                spans.append((x.start, x.end))
        spans.sort()
        out = []
        pos = node.start
        for s, e in spans:
            if s < pos:
                continue
            out.append(f.src[pos:s])
            out.append("0")
            pos = e
        out.append(f.src[pos:node.end])
        return norm("".join(out))

    def is_content_array(self, node):
        if node is None or node.kind != "paren":
            return False
        items = node.a["items"]
        if any(it.name is not None or it.spread for it in items):
            return False
        if len(items) == 1 and not node.a["trailing"]:
            return False
        for it in items:
            v = it.value
            if v.kind == "content":
                continue
            if self.is_content_array(v):
                continue
            return False
        return True

    def diff_value(self, ov, nv):
        o, n = self.o, self.n
        if o.assets(ov) != n.assets(nv):
            return REPLACE
        if norm(o.src[ov.start:ov.end]) == norm(n.src[nv.start:nv.end]):
            return Res(None, False)
        if ov.kind == "content" and nv.kind == "content":
            return Res("[" + self.diff_content(ov, nv) + "]", False)
        if self.is_content_array(ov) and self.is_content_array(nv):
            return self.diff_array(ov, nv)
        if ov.kind == "chain" and nv.kind == "chain":
            c = callee_of(nv)
            if c is not None and c == callee_of(ov) and \
                    c not in ATOMIC_CALLEES:
                return self.diff_chain(ov, nv)
        if ov.kind == "codeblock" and nv.kind == "codeblock":
            return self.diff_codeblock(ov, nv)
        if ov.kind in ("math", "raw") or nv.kind in ("math", "raw"):
            return REPLACE
        if ov.kind == "chain" and callee_of(ov) in ATOMIC_CALLEES:
            return REPLACE
        if self.masked(o, ov) == self.masked(n, nv):
            return Res(None, False)
        return Res(None, True)

    def line_indent(self, f, pos):
        ls = f.src.rfind("\n", 0, pos) + 1
        k = ls
        while k < len(f.src) and f.src[k] == " ":
            k += 1
        return k - ls

    def diff_content(self, ov, nv):
        o, n = self.o, self.n
        obl = o.grouper.group(ov.a["toks"])
        nbl = n.grouper.group(nv.a["toks"])
        s, e = nv.a["inner"]
        if not obl and not nbl:
            return n.src[s:e]
        if len(obl) <= 1 and len(nbl) <= 1 and \
                all(b.kind == "par" for b in obl + nbl):
            # Inline content: a word diff, no paragraphs.
            os_, oe = ov.a["inner"]
            otoks = obl[0].toks if obl else []
            ntoks = nbl[0].toks if nbl else []
            lead = n.src[s:nbl[0].start] if nbl else ""
            trail = n.src[nbl[-1].end:e] if nbl else ""
            delta = self.line_indent(n, nv.start) - \
                self.line_indent(o, ov.start)
            return lead + self.diff_inline(otoks, ntoks, delta) + trail
        obase = self.line_indent(o, ov.start)
        nbase = self.line_indent(n, nv.start)
        lead = n.src[s:nbl[0].start] if nbl else ""
        trail = n.src[nbl[-1].end:e] if nbl else ""
        body = self.diff_seq(obl, nbl, obase, nbase)
        return lead + body + trail

    def diff_chain(self, ov, nv):
        o, n = self.o, self.n
        oargs = call_args(ov)
        nargs = call_args(nv)
        if oargs is None or nargs is None:
            if o.assets(ov) != n.assets(nv):
                return REPLACE
            return Res(None, self.masked(o, ov) != self.masked(n, nv))
        if o.assets(ov) == n.assets(nv) and \
                norm(o.src[ov.start:ov.end]) == norm(n.src[nv.start:nv.end]):
            return Res(None, False)
        opos, onamed = oargs
        npos, nnamed = nargs
        callee = callee_of(nv)
        # A slide is diffed as a whole even if its figures changed: an
        # argument that would replace it takes the NEW value, marked.
        soft = callee in self.g.slide_callees
        edits = []
        changed = False
        pairs = list(zip(opos, npos))
        if len(opos) != len(npos):
            # Cells of a table pair one to one only; other calls pair their
            # content arguments in order, positional arguments added or
            # removed besides are a change unless they are layout literals.
            if callee.split(".")[0] in TABLE_CALLEES:
                return REPLACE
            oc = [a for a in opos if self.contentish(a.value)]
            nc = [a for a in npos if self.contentish(a.value)]
            if len(oc) != len(nc):
                return REPLACE
            pairs = list(zip(oc, nc))
            for f, rest in ((o, [a for a in opos if a not in oc]),
                            (n, [a for a in npos if a not in nc])):
                for a in rest:
                    if a.value is None:
                        continue
                    if f.assets(a.value) and not soft:
                        return REPLACE
                    if not self.layout_only(f, a.value):
                        changed = True
        for oa, na in pairs:
            if oa.value is None or na.value is None:
                if (oa.value is None) != (na.value is None):
                    return REPLACE
                continue
            r = self.diff_value(oa.value, na.value)
            if r is REPLACE and soft and not self.contentish(na.value):
                changed = True
                continue
            if r is REPLACE:
                return REPLACE
            if r.text is not None:
                edits.append((na.value.start, na.value.end, r.text))
            changed |= r.changed
        for name, na in nnamed.items():
            oa = onamed.get(name)
            if oa is None:
                v = na.value
                if n.assets(v) and not soft:
                    return REPLACE
                if v.kind == "content":
                    edits.append((v.start, v.start, "tins"))
                elif self.is_content_array(v):
                    edits.append((v.start, v.start, "tins-arr("))
                    edits.append((v.end, v.end, ")"))
                elif not self.layout_only(n, v):
                    changed = True
                continue
            r = self.diff_value(oa.value, na.value)
            if r is REPLACE and soft and not self.contentish(na.value):
                changed = True
                continue
            if r is REPLACE:
                return REPLACE
            if r.text is not None:
                edits.append((na.value.start, na.value.end, r.text))
            changed |= r.changed
        extra = []
        params = self.nscope_funcs.get(callee.split(".")[0]) \
            if "." not in callee else None
        for name, oa in onamed.items():
            if name in nnamed:
                continue
            v = oa.value
            if o.assets(v):
                if soft:
                    changed = True
                    continue
                return REPLACE
            accepted = params is None or name in params
            if accepted and v.kind == "content":
                extra.append("%s: tdel%s" % (name, self.old_text(v.start,
                                                                  v.end)))
            elif accepted and self.is_content_array(v):
                extra.append("%s: tdel-arr(%s)" % (
                    name, self.old_text(v.start, v.end)))
            elif params is not None and params.get(name) in ("none",
                                                             "content") \
                    and v.kind in ("chain", "codeblock", "ident"):
                # A removed argument the callee takes as content (its
                # default is none or content): show it as deleted.
                extra.append("%s: td-del-style(%s)" % (
                    name, self.old_text(v.start, v.end)))
                changed = True
            elif not self.layout_only(o, v):
                changed = True
        if extra:
            groups = [op[1] for op in nv.a["ops"] if op[0] == "args"]
            if groups:
                g = groups[-1]
                close = g.end - 1
                if g.a["items"] and not g.a["trailing"]:
                    ins = ", " + ", ".join(extra)
                elif g.a["items"]:
                    ins = " " + ", ".join(extra) + ","
                else:
                    ins = ", ".join(extra)
                edits.append((close, close, ins))
            else:
                first = [op for op in nv.a["ops"] if op[0] != "field"][0]
                pos = first[1].start
                edits.append((pos, pos, "(" + ", ".join(extra) + ")"))
        return Res(apply_edits(n.src, nv.start, nv.end, edits), changed)

    def contentish(self, v):
        return v is not None and (v.kind == "content"
                                  or self.is_content_array(v))

    def layout_only(self, f, v):
        """Whether a value consists of layout literals only."""
        return re.fullmatch(r"[0\s(),:+\-*/.]*", self.masked(f, v)) \
            is not None

    def diff_array(self, ov, nv):
        o, n = self.o, self.n
        oit = [it.value for it in ov.a["items"]]
        nit = [it.value for it in nv.a["items"]]

        def kind(v):
            return "content" if v.kind == "content" else "array"

        okeys = [(kind(v), norm(o.src[v.start:v.end]), o.assets(v))
                 for v in oit]
        nkeys = [(kind(v), norm(n.src[v.start:v.end]), n.assets(v))
                 for v in nit]

        def simf(a, b):
            if kind(oit[a]) != kind(nit[b]):
                return None
            r = ratio(WORD_RE.findall(o.src[oit[a].start:oit[a].end]),
                      WORD_RE.findall(n.src[nit[b].start:nit[b].end]))
            return r - 0.3 + 0.05 if r >= 0.3 else None

        ops = align(okeys, nkeys, simf,
                    lambda a, b: kind(oit[a]) == kind(nit[b]))
        edits = []
        changed = False
        pending = []   # deleted elements waiting for the next NEW element

        def deleted(v):
            t = self.old_text(v.start, v.end)
            return ("tdel" + t) if v.kind == "content" else \
                ("tdel-arr(" + t + ")")

        def flush(before):
            if not pending:
                return
            ls = n.src.rfind("\n", 0, before.start)
            pre = n.src[ls + 1:before.start] if ls >= 0 else ""
            if pre.strip() == "" and ls >= nv.start:
                sep = ",\n" + pre
            else:
                sep = ", "
            edits.append((before.start, before.start,
                          sep.join(pending) + sep))
            pending.clear()

        for op in ops:
            if op[0] == "del":
                pending.append(deleted(oit[op[1]]))
            elif op[0] == "ins":
                v = nit[op[1]]
                flush(v)
                if v.kind == "content":
                    edits.append((v.start, v.start, "tins"))
                else:
                    edits.append((v.start, v.start, "tins-arr("))
                    edits.append((v.end, v.end, ")"))
            elif op[0] == "eq":
                flush(nit[op[2]])
            else:
                v = nit[op[2]]
                flush(v)
                r = self.diff_value(oit[op[1]], v)
                if r is REPLACE:
                    edits.append((v.start, v.start,
                                  deleted(oit[op[1]]) + ", "))
                    if v.kind == "content":
                        edits.append((v.start, v.start, "tins"))
                    else:
                        edits.append((v.start, v.start, "tins-arr("))
                        edits.append((v.end, v.end, ")"))
                    continue
                if r.text is not None:
                    edits.append((v.start, v.end, r.text))
                changed |= r.changed
        if pending:
            if nit:
                last = nit[-1]
                edits.append((last.end, last.end, ", " + ", ".join(pending)))
            else:
                return Res("(" + ", ".join(pending) + ",)", changed)
        if len(nit) == 1 and not nv.a["trailing"]:
            pass
        text = apply_edits(n.src, nv.start, nv.end, edits)
        return Res(text, changed)

    def diff_codeblock(self, ov, nv):
        o, n = self.o, self.n
        ost = ov.a["stmts"]
        nst = nv.a["stmts"]
        okeys = [(norm(o.src[s.start:s.end]), o.assets(s)) for s in ost]
        nkeys = [(norm(n.src[s.start:s.end]), n.assets(s)) for s in nst]

        def simf(a, b):
            c = callee_of(ost[a])
            if c is None or c != callee_of(nst[b]):
                return None
            return 1.0

        ops = align(okeys, nkeys, simf)
        edits = []
        changed = False
        for op in ops:
            if op[0] == "pair":
                r = self.diff_value(ost[op[1]], nst[op[2]])
                if r is REPLACE:
                    return REPLACE
                if r.text is not None:
                    edits.append((nst[op[2]].start, nst[op[2]].end, r.text))
                changed |= r.changed
            elif op[0] == "del":
                if o.assets(ost[op[1]]):
                    return REPLACE
                changed = True
            elif op[0] == "ins":
                if n.assets(nst[op[1]]):
                    return REPLACE
                changed = True
        return Res(apply_edits(n.src, nv.start, nv.end, edits), changed)


def apply_edits(src, a, b, edits):
    edits = sorted(enumerate(edits), key=lambda e: (e[1][0], e[0]))
    out = []
    pos = a
    for _, (s, e, text) in edits:
        if s < pos:
            continue
        out.append(src[pos:s])
        out.append(text)
        pos = e
    out.append(src[pos:b])
    return "".join(out)


HELPER_NAMES = {
    "td-del-color", "td-ins-color", "td-chg-color", "td-labels", "td-plain",
    "td-del-style", "td-ins-style", "tdel", "tins", "tchg", "tdel-par",
    "tins-par", "tdel-block", "tins-block", "tdel-arr", "tins-arr",
    "tdel-heading", "tdref", "tslide-ins", "tslide-del", "tslide-chg",
    "td-legend", "td-foreground", "td-setup",
}


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def rel_files(root, skip_dirs, excludes):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rd = os.path.relpath(dirpath, root)
        rd = "" if rd == "." else rd
        keep = []
        for d in sorted(dirnames):
            full = os.path.realpath(os.path.join(dirpath, d))
            rel = os.path.join(rd, d)
            if full in skip_dirs or excluded(rel, excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = os.path.join(rd, fn)
            if not excluded(rel, excludes):
                out.append(rel)
    return sorted(out)


def excluded(rel, excludes):
    rel = rel.replace(os.sep, "/")
    parts = rel.split("/")
    for pat in excludes:
        pat = pat.rstrip("/")
        if fnmatch.fnmatchcase(rel, pat):
            return True
        if "/" not in pat and any(fnmatch.fnmatchcase(p, pat) for p in parts):
            return True
    return False


def matches(rel, patterns):
    rel = rel.replace(os.sep, "/")
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns)


def copy_tree(src, dst, skip_dirs, excludes):
    for rel in rel_files(src, skip_dirs, excludes):
        s = os.path.join(src, rel)
        d = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(s, d)


def prepare_out(out, new, old):
    if os.path.exists(out):
        if not os.path.isdir(out):
            raise TypstDiffError("%s exists and is no directory" % out)
        entries = os.listdir(out)
        if entries and MARKER_FILE not in entries:
            raise TypstDiffError(
                "%s exists, is not empty and was not written by typstdiff; "
                "remove it first" % out)
        shutil.rmtree(out)
    os.makedirs(out)
    with open(os.path.join(out, MARKER_FILE), "w") as f:
        f.write("written by typstdiff.py; removed on the next run\n")


def resolve_placeholders(text, g):
    def repl(m):
        name, orig = g.placeholders[int(m.group(1))]
        if name in g.new_labels or name in g.kept_old_labels or \
                name in g.bib_keys:
            return orig
        return '#tdref("%s")' % name
    return re.sub("\x00(\\d+)\x00", repl, text)


def includes_of(f):
    out = set()
    for t in f.toks:
        for n in walk(t):
            if n.kind == "kw" and n.a["kw"] == "include":
                p = f.eval_str(n.a["source"])
                if p is not None:
                    out.add(f.resolve(p))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Merge two versions of a Typst document tree into one "
        "whose compiled document shows the changes.")
    ap.add_argument("--old", required=True, help="tree of the old version")
    ap.add_argument("--new", required=True, help="tree of the new version")
    ap.add_argument("--out", required=True, help="output tree (a copy of "
                    "NEW with the merged files; removed and rewritten)")
    ap.add_argument("--diff", action="append", default=[], metavar="PATTERN",
                    help="glob of files (relative paths) to merge")
    ap.add_argument("--pair", action="append", default=[],
                    metavar="OLDPATH=NEWPATH",
                    help="diff OLDPATH against NEWPATH (renamed file)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="paths (relative to NEW, also applied to OLD) not "
                    "to copy")
    ap.add_argument("--entry", action="append", default=None,
                    metavar="PATH", help="merged file that is compiled "
                    "(gets the change bars and the legend); default: the "
                    "merged files no other file includes")
    ap.add_argument("--label-old", default="old", metavar="LABEL",
                    help="name of the old version in the legend")
    ap.add_argument("--label-new", default="new", metavar="LABEL",
                    help="name of the new version in the legend and badges")
    ap.add_argument("--slide-callee", action="append",
                    default=None, metavar="NAME",
                    help="function of a slide (default: slide, title-slide)")
    ap.add_argument("--no-legend", action="store_true",
                    help="no legend on the first page")
    opts = ap.parse_args(argv)
    if opts.slide_callee is None:
        opts.slide_callee = ["slide", "title-slide"]
    try:
        run(opts)
    except TypstDiffError as e:
        print("typstdiff: error: %s" % e, file=sys.stderr)
        return 1
    return 0


def run(opts):
    old_root = os.path.abspath(opts.old)
    new_root = os.path.abspath(opts.new)
    out_root = os.path.abspath(opts.out)
    for d in (old_root, new_root):
        if not os.path.isdir(d):
            raise TypstDiffError("%s is no directory" % d)
    if out_root in (old_root, new_root):
        raise TypstDiffError("OUT must differ from OLD and NEW")
    skip = {os.path.realpath(out_root), os.path.realpath(old_root),
            os.path.realpath(new_root)}
    old = Side(old_root, "old")
    new = Side(new_root, "new")
    g = Global(opts, old, new)

    pairs = {}
    for p in opts.pair:
        if "=" not in p:
            raise TypstDiffError("--pair needs OLDPATH=NEWPATH: %s" % p)
        a, b = p.split("=", 1)
        pairs[os.path.normpath(b)] = os.path.normpath(a)

    new_files = rel_files(new_root, skip - {os.path.realpath(new_root)},
                          opts.exclude)
    old_files = rel_files(old_root, skip - {os.path.realpath(old_root)},
                          opts.exclude)
    new_set = set(new_files)
    old_set = set(old_files)

    # The files to merge.
    jobs = []     # (old_rel or None, new_rel or None, out_rel)
    used_old = set()
    for rel in new_files:
        if rel.endswith(".typ") and (matches(rel, opts.diff) or rel in pairs):
            orel = pairs.get(rel, rel)
            if orel not in old_set:
                if rel in pairs:
                    raise TypstDiffError("paired file %s not in OLD" % orel)
                orel = None
            else:
                used_old.add(orel)
            jobs.append((orel, rel, rel))
    for rel in old_files:
        if rel.endswith(".typ") and matches(rel, opts.diff) and \
                rel not in used_old and rel not in new_set:
            jobs.append((rel, None, rel))
    g.paired_old = set(used_old)
    g.diff_old = {j[0] for j in jobs if j[1] is None}

    # Labels and bibliography keys of the result.
    for rel in new_files:
        if rel.endswith(".typ"):
            try:
                g.new_labels |= collect_labels(new.file(rel))
            except ParseError:
                if any(j[1] == rel for j in jobs):
                    raise
                with open(os.path.join(new_root, rel), encoding="utf-8",
                          errors="replace") as f:
                    g.new_labels |= set(LABEL_RE.findall(f.read()))
    bibs = {}
    for side, files in ((old, old_files), (new, new_files)):
        for rel in files:
            if rel.endswith(".bib"):
                with open(os.path.join(side.root, rel), encoding="utf-8",
                          errors="replace") as f:
                    ents = bib_entries(f.read())
                bibs[(side.name, rel)] = ents
                g.bib_keys |= {k for k, _ in ents}

    # Entry files.
    if opts.entry is not None:
        entries = {os.path.normpath(e) for e in opts.entry}
    else:
        included = set()
        for rel in new_files:
            if rel.endswith(".typ"):
                try:
                    included |= includes_of(new.file(rel))
                except ParseError:
                    pass
        entries = {j[2] for j in jobs if j[1] is not None
                   and j[2] not in included}

    # Merge.
    results = {}
    for orel, nrel, outrel in jobs:
        of = old.file(orel) if orel else SourceFile(old, nrel, "")
        nf = new.file(nrel) if nrel else SourceFile(new, orel, "")
        fd = FileDiff(g, of, nf, outrel in entries)
        results[outrel] = merge_file(fd)

    # Write the tree.
    prepare_out(out_root, new_root, old_root)
    copy_tree(new_root, out_root, skip, opts.exclude)
    copy_tree(old_root, os.path.join(out_root, OLD_DIR), skip, opts.exclude)
    helper_src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              HELPER_NAME)
    if os.path.exists(os.path.join(out_root, HELPER_NAME)):
        raise TypstDiffError("NEW has a file %s" % HELPER_NAME)
    with open(helper_src, encoding="utf-8") as f:
        helper = f.read()
    labels = '#let td-labels = (old: "%s", new: "%s")' % (
        opts.label_old.replace("\\", "\\\\").replace('"', '\\"'),
        opts.label_new.replace("\\", "\\\\").replace('"', '\\"'))
    helper = re.sub(r"^#let td-labels = .*// typstdiff:labels$", labels,
                    helper, flags=re.M)
    with open(os.path.join(out_root, HELPER_NAME), "w",
              encoding="utf-8") as f:
        f.write(helper)
    for outrel, text in sorted(results.items()):
        text = resolve_placeholders(text, g)
        p = os.path.join(out_root, outrel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
    # Bibliographies: entries OLD cites that NEW lacks.
    for (sname, rel), ents in sorted(bibs.items()):
        if sname != "old" or ("new", rel) not in bibs:
            continue
        have = {k for k, _ in bibs[("new", rel)]}
        missing = [t for k, t in ents if k not in have]
        if missing:
            with open(os.path.join(out_root, rel), "a",
                      encoding="utf-8") as f:
                f.write("\n\n% Entries of the old version (typstdiff)\n\n")
                f.write("\n\n".join(missing) + "\n")


def merge_file(fd):
    n = fd.n
    o = fd.o
    # The helper import goes after the leading imports of NEW.
    header_after = None
    for j, b in enumerate(n.blocks):
        if b.kind == "comment":
            continue
        if b.kind == "stmt" and b.a["kw"] == "import":
            header_after = j
            continue
        break
    body = fd.diff_seq(o.blocks, n.blocks, 0, 0, header_after=header_after)
    if n.blocks:
        lead = n.src[:n.blocks[0].start]
        trail = n.src[n.blocks[-1].end:]
    else:
        lead = ""
        trail = "\n"
    if header_after is None:
        return fd.header() + "\n\n" + lead + body + trail
    return lead + body + trail


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TypstDiffError as e:
        print("typstdiff: error: %s" % e, file=sys.stderr)
        sys.exit(1)
    except Exception:  # an internal error: report it, fail
        import traceback
        traceback.print_exc()
        print("typstdiff: internal error", file=sys.stderr)
        sys.exit(2)
