#!/usr/bin/env python3
#
# Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

"""
Collect the data of the security test report, which security_report.typ
typesets.

The tests of a suite come from "meson introspect --tests", each naming its
headline, description, source file and test function in ESDM_TEST_HEADLINE,
ESDM_TEST_DESCRIPTION, ESDM_TEST_FILE and ESDM_TEST_FUNCTION. The function is
found with tree-sitter: its TEST_STEPs are the test plan, and its code goes into
the report as well. What a run made of the plan comes from its JUnit log.

A test plan marker outside the test function, or a step that is not a string
literal, ends the script with an error - see tests/test_plan.h.

  meson introspect --tests build > tests.json
  security_report.py --tests tests.json \\
          --junit build/meson-logs/testlog.junit.xml \\
          --source-root . --grammar <tree-sitter-c>/parser \\
          --output security-report.json
  typst compile security_report.typ    # next to security-report.json
"""

import argparse
import ast
import ctypes
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from tree_sitter import Language, Parser

MARKERS = ("TEST_STEP", "TEST_REQUIRE", "TEST_RUNUNTIL", "TEST_CHECK")

# A line of test output: a test plan marker, see tests/test_plan.h
OUTPUT_MARKER = re.compile(
    r"^(HEADLINE|DESCRIPTION|FILE|FUNCTION|STEP|REQUIRE|RUNUNTIL|CHECK): "
    r"(.*)$")
# A CHECK: the check as written and its verdict, then the actual value
OUTPUT_CHECK = re.compile(r"^(\[.*\] (is ok|has failed)) \(actual: .*\)$")

# How much of the log on stderr a test that did not pass carries along
STDERR_TAIL = 100


def fail(msg):
    sys.exit(f"security_report: {msg}")


def c_language(grammar):
    """
    The C grammar from its library, wrapped in the capsule a binding of it
    would hand out - the one nixpkgs has does not build.
    """
    lib = ctypes.CDLL(grammar)
    lib.tree_sitter_c.restype = ctypes.c_void_p
    capsule_new = ctypes.pythonapi.PyCapsule_New
    capsule_new.restype = ctypes.py_object
    capsule_new.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)
    # The library stays loaded for the lifetime of the process
    return Language(
        capsule_new(lib.tree_sitter_c(), b"tree_sitter.Language", None))


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def line_of(node):
    return node.start_point.row + 1


def code(node):
    """Source text of an expression, on one line"""
    return " ".join(node.text.decode().split())


def declared_name(function):
    decl = function.child_by_field_name("declarator")
    while decl is not None and decl.type != "identifier":
        decl = decl.child_by_field_name("declarator")
    return decl.text.decode() if decl is not None else None


def literal(node, where):
    """The value of a string literal, adjacent literals concatenated"""
    try:
        # Python reads a C string literal alike, escapes included
        value = ast.literal_eval(f"({node.text.decode()})")
    except (ValueError, SyntaxError):
        value = None
    if not isinstance(value, str):
        fail(f"{where}: {code(node)} is not a string literal")
    return value


def context(node, body):
    """The branches and loops of the test function the marker is in"""
    ctx = []
    child, parent = node, node.parent
    while parent is not None and parent != body:
        if parent.type == "if_statement":
            cond = code(parent.child_by_field_name("condition"))
            if child == parent.child_by_field_name("consequence"):
                ctx.append(f"if {cond}")
            elif child == parent.child_by_field_name("alternative"):
                ctx.append(f"if not {cond}")
        elif parent.type in ("for_statement", "while_statement",
                             "do_statement"):
            if child == parent.child_by_field_name("body"):
                ctx.append("repeated in a loop")
        child, parent = parent, parent.parent
    return list(reversed(ctx))


def marker_calls(node):
    """The calls of test plan markers below @node, with their names"""
    for n in walk(node):
        if n.type == "call_expression":
            name = n.child_by_field_name("function").text.decode()
            if name in MARKERS:
                yield name, n


def test_function(parser, source_root, file, function):
    path = source_root / file
    try:
        tree = parser.parse(path.read_bytes())
    except OSError as e:
        fail(f"cannot read {path}: {e}")

    found = [n for n in walk(tree.root_node)
             if n.type == "function_definition"
             and declared_name(n) == function]
    if len(found) != 1:
        fail(f"{file}: {len(found)} definitions of {function}(), expected 1")
    fn = found[0]
    if fn.has_error:
        fail(f"{file}:{line_of(fn)}: {function}() does not parse")

    for _, call in marker_calls(tree.root_node):
        if not fn.start_byte <= call.start_byte < fn.end_byte:
            fail(f"{file}:{line_of(call)}: test plan marker outside "
                 f"{function}()")

    body = fn.child_by_field_name("body")
    steps = []
    for name, call in marker_calls(body):
        if name != "TEST_STEP":
            continue
        where = f"{file}:{line_of(call)}"
        args = [a for a in call.child_by_field_name("arguments").named_children
                if a.type != "comment"]
        if len(args) != 1:
            fail(f"{where}: TEST_STEP takes one string literal")
        steps.append({
            "line": line_of(call),
            "text": literal(args[0], where),
            "context": context(call, body),
        })

    return {
        "lines": [line_of(fn), fn.end_point.row + 1],
        "code": fn.text.decode(),
        "steps": steps,
    }


def junit_cases(path):
    try:
        return list(ET.parse(path).getroot().iter("testcase"))
    except (OSError, ET.ParseError) as e:
        fail(f"cannot read {path}: {e}")


def junit_case(cases, name):
    """
    The testcase of a test. Its JUnit name carries the suites and the project
    in front of the test name, separated by a colon.
    """
    match = [c for c in cases
             if c.get("name") == name or
             c.get("name", "").endswith(":" + name)]
    if len(match) > 1:
        fail(f"{len(match)} JUnit testcases for {name}")
    return match[0] if match else None


def junit_result(case):
    for tag, result in (("failure", "FAIL"), ("error", "ERROR"),
                        ("skipped", "SKIP")):
        if case.find(tag) is not None:
            return result
    return "PASS"


def output_lines(text):
    """The lines a test printed, a CHECK without its actual value"""
    lines = []
    for line in (text or "").splitlines():
        entry = {"marker": None, "text": line, "ok": None}
        m = OUTPUT_MARKER.match(line)
        if m:
            entry["marker"], entry["text"] = m.groups()
        if entry["marker"] == "CHECK":
            c = OUTPUT_CHECK.match(entry["text"])
            entry["ok"] = bool(c) and c.group(2) == "is ok"
            if c:
                entry["text"] = c.group(1)
        lines.append(entry)
    return lines


def run(case):
    if case is None:
        return {"result": "NOT RUN", "duration": None, "stdout": [],
                "stderr_lines": 0, "stderr_tail": [], "checks_ok": 0,
                "checks_failed": 0}

    stdout = output_lines(case.findtext("system-out"))
    stderr = (case.findtext("system-err") or "").splitlines()
    result = junit_result(case)
    checks = [line["ok"] for line in stdout if line["marker"] == "CHECK"]
    return {
        "result": result,
        "duration": float(case.get("time", "0")),
        "stdout": stdout,
        "stderr_lines": len(stderr),
        "stderr_tail": [] if result == "PASS" else stderr[-STDERR_TAIL:],
        "checks_ok": checks.count(True),
        "checks_failed": checks.count(False),
    }


def in_suite(test, suite):
    return any(s == suite or s.endswith(":" + suite) for s in test["suite"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tests", required=True, type=Path,
                    help="output of meson introspect --tests")
    ap.add_argument("--junit", required=True, type=Path,
                    help="JUnit log of the test run")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--grammar", required=True,
                    help="library of the tree-sitter C grammar")
    ap.add_argument("--suite", default="security")
    ap.add_argument("--version", default="")
    ap.add_argument("--revision", default="")
    ap.add_argument("--run-date", default="")
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    try:
        tests = json.loads(args.tests.read_text())
    except (OSError, ValueError) as e:
        fail(f"cannot read {args.tests}: {e}")
    tests = [t for t in tests if in_suite(t, args.suite)]
    if not tests:
        fail(f"no test in suite {args.suite}")

    parser = Parser(c_language(args.grammar))
    cases = junit_cases(args.junit)

    report = []
    for t in tests:
        env = t.get("env") or {}
        missing = [v for v in ("ESDM_TEST_FILE", "ESDM_TEST_FUNCTION",
                               "ESDM_TEST_HEADLINE", "ESDM_TEST_DESCRIPTION")
                   if not env.get(v)]
        if missing:
            fail(f"{t['name']}: {', '.join(missing)} not set")

        file, function = env["ESDM_TEST_FILE"], env["ESDM_TEST_FUNCTION"]
        report.append({
            "name": t["name"],
            "headline": env["ESDM_TEST_HEADLINE"],
            "description": env["ESDM_TEST_DESCRIPTION"],
            "file": file,
            "function": function,
            "timeout": t.get("timeout"),
            "args": t["cmd"][1:],
            **test_function(parser, args.source_root, file, function),
            **run(junit_case(cases, t["name"])),
        })

    args.output.write_text(json.dumps({
        "suite": args.suite,
        "version": args.version,
        "revision": args.revision,
        "run_date": args.run_date,
        "tests": report,
    }, indent=1) + "\n")


if __name__ == "__main__":
    main()
