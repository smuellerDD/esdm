// ESDM security test report, typeset from security-report.json next to this
// file - security_report.py collects it.
//
//   typst compile security_report.typ

#let data = json("security-report.json")

#let result-colors = (
  "PASS": rgb("#1a7f37"),
  "FAIL": rgb("#cf222e"),
  "ERROR": rgb("#cf222e"),
  "SKIP": rgb("#9a6700"),
  "NOT RUN": rgb("#57606a"),
)
#let marker-colors = (
  "STEP": rgb("#0550ae"),
  "REQUIRE": rgb("#8250df"),
  "RUNUNTIL": rgb("#0a7480"),
  "CHECK": rgb("#57606a"),
)
#let mono = "DejaVu Sans Mono"

#let badge(result) = {
  let c = result-colors.at(result, default: gray)
  box(
    fill: c.lighten(88%),
    stroke: 0.6pt + c,
    inset: (x: 3pt, y: 1.5pt),
    outset: (y: 1pt),
    radius: 2pt,
    text(fill: c, weight: "bold", size: 0.8em, result),
  )
}

#let duration(d) = if d == none { [--] } else { [#calc.round(d, digits: 2) s] }

#let test-label(i) = label("test-" + str(i))

// A table of names and values, without lines
#let info-table(..rows) = table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (x: 0pt, y: 3pt),
  column-gutter: 1.5em,
  ..rows,
)

#let output-line(l) = {
  if l.marker == none {
    text(fill: luma(100), raw(l.text))
  } else {
    text(fill: marker-colors.at(l.marker, default: black), weight: "bold",
      l.marker + ": ")
    if l.marker == "CHECK" {
      text(fill: if l.ok { result-colors.PASS } else { result-colors.FAIL },
        raw(l.text))
    } else {
      raw(l.text)
    }
  }
}

#let output-block(body) = block(
  width: 100%,
  fill: luma(246),
  inset: 6pt,
  radius: 2pt,
  breakable: true,
  {
    set text(font: mono, size: 7pt)
    set par(leading: 0.5em, justify: false)
    body
  },
)

// The code of a test function, numbered by the lines of its file from @first
// on. The numbers have a column of their own, so a line too long for the page
// wraps within the code. Typst ignores tab-size as an argument of raw, but not
// as a set rule; and the lines of a raw block overlap in a grid, their bodies
// do not.
#let code-block(code, first) = output-block({
  set raw(tab-size: 8)
  show raw.where(block: true): it => grid(
    columns: (auto, 1fr),
    column-gutter: 1em,
    row-gutter: 0.5em,
    align: (right, left),
    ..it.lines.map(l => (text(fill: gray, str(first + l.number - 1)), l.body))
      .flatten(),
  )
  raw(code, lang: "c", block: true)
})

#set document(title: [ESDM security test report])
#set page(
  paper: "a4",
  margin: (x: 1.8cm, y: 2cm),
  numbering: "1 / 1",
  header: context if here().page() > 1 {
    set text(size: 8pt, fill: gray)
    [ESDM #data.version security test report #h(1fr) #data.revision]
  },
)
#set text(size: 10pt, lang: "en")
#set heading(numbering: "1.1")
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  it
}
#show raw: set text(font: mono)

#align(center, text(size: 20pt, weight: "bold")[ESDM security test report])
#v(1em)

#info-table(
  [*ESDM version*], [#data.version],
  [*Revision*], raw(data.revision),
  [*Test run*], [#data.run_date],
  [*Suite*], raw(data.suite),
)

Every test of the suite checks one security property of the ESDM, stated in its
description. Its test plan is read from the source of the function that runs
the test: the steps it takes, in source order and with the branches and loops
they sit in. The run shows what the test printed, taken from the JUnit log: the
plan as it was followed and each check with its verdict. Last comes the code of
the test function, numbered by the lines of its file.

#let results = data.tests.map(t => t.result)
#let count(r) = results.filter(x => x == r).len()

#v(0.5em)
*#data.tests.len() tests:* #count("PASS") passed, #(count("FAIL") + count("ERROR"))
failed, #count("SKIP") skipped#if count("NOT RUN") > 0 [, #count("NOT RUN") not run].

#table(
  columns: (auto, 1fr, auto, auto, auto),
  stroke: (x, y) => if y > 0 { (top: 0.5pt + luma(200)) },
  inset: 5pt,
  align: (right, left, center, right, right),
  table.header([*\#*], [*Test*], [*Result*], [*Checks ok / failed*], [*Duration*]),
  ..for (i, t) in data.tests.enumerate() {
    (
      [#(i + 1)],
      link(test-label(i), t.headline),
      badge(t.result),
      [#t.checks_ok / #t.checks_failed],
      duration(t.duration),
    )
  },
)

#for (i, t) in data.tests.enumerate() [
  #heading(level: 1, t.headline) #test-label(i)

  #info-table(
    [*Test*], [#t.name],
    [*Result*],
    [#badge(t.result) #h(0.4em) #duration(t.duration), #t.checks_ok checks
      ok, #t.checks_failed failed],
    [*Description*], [#t.description],
    [*Source*],
    [#raw(t.file + ":" + str(t.lines.at(0)) + "-" + str(t.lines.at(1))),
      function #raw(t.function + "()")],
    [*Timeout*], [#t.timeout s],
    ..if t.args.len() > 0 { ([*Arguments*], t.args.map(raw).join(" ")) },
  )

  == Test plan

  #table(
    columns: (auto, 1fr),
    stroke: (x, y) => if y > 0 { (top: 0.5pt + luma(220)) },
    inset: 4pt,
    align: (right, left),
    table.header([*Line*], [*Step*]),
    ..for s in t.steps {
      (
        text(fill: gray, str(s.line)),
        [#s.text #if s.context.len() > 0 {
          linebreak()
          text(size: 0.85em, fill: gray, style: "italic", s.context.join("; "))
        }],
      )
    },
  )

  == Run

  #if t.stdout.len() == 0 [
    The test printed nothing#if t.result == "NOT RUN" [: it is not in the
      JUnit log of the run].
  ] else {
    output-block(for l in t.stdout { output-line(l); linebreak() })
  }

  #if t.stderr_tail.len() > 0 [
    === Log

    The last #t.stderr_tail.len() of the #t.stderr_lines lines the test
    logged:

    #output-block(raw(t.stderr_tail.join("\n"), block: true))
  ] else if t.stderr_lines > 0 [
    #text(size: 0.9em, fill: gray)[The #t.stderr_lines lines the test logged
      are in the JUnit log of the run.]
  ]

  == Test function

  #code-block(t.code, t.lines.at(0))
]
