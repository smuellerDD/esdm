// Document template of the ESDM design document.
//
// The numbering follows the LaTeX article class the document was originally
// typeset with - numbered sections, figures and equations numbered per
// section -, the look is a calmer, more open one: the text in New Computer
// Modern at 10.5pt with generous leading and spacing between paragraphs
// instead of indents, side margins of 25 mm; headings, captions, the title
// page and the running header in Source Sans 3 - the face of the slides - in
// dark slate with one blue accent; chapters open a page under a large
// chapter number; tables with horizontal rules only and a light blue header
// row; code in soft grey cards.

#let body-font = "New Computer Modern"
#let sans-font = "Source Sans 3"
#let mono-font = "Source Code Pro"

#let accent = rgb("#1d4ed8")
#let accent-light = rgb("#eff6ff")
#let ink = rgb("#1e293b")
#let muted = rgb("#64748b")
#let hairline = rgb("#cbd5e1")
#let code-fill = rgb("#f8fafc")
#let code-stroke = rgb("#e2e8f0")

// What the running header names on the left of every page
#let doc-title = state("esdm-doc-title", none)

// Paragraph with a run-in heading (LaTeX \paragraph).
#let paragraph(title, body) = block(above: 1.4em, below: 0.6em,
  par(first-line-indent: 0pt)[#text(font: sans-font, weight: "semibold",
    fill: ink, title)#h(0.8em)#body])

// Number of the current section, used for per-section numbering.
#let section-number(loc) = {
  let h = counter(heading).at(loc)
  if h.len() == 0 { 0 } else { h.first() }
}

// Format a per-section number "S.N" for a counter value at a location.
#let per-section(kind-counter, loc, fmt: "1.1") = {
  let s = counter(heading).at(loc)
  let n = kind-counter.at(loc).first()
  numbering(fmt, if s.len() == 0 { 0 } else { s.first() }, n)
}

// Reference to an equation without parentheses ("equation 2.3").
#let eqref(label) = context {
  let el = query(label).first()
  link(el.location(), per-section(counter(math.equation), el.location()))
}

// The number of a heading as it is displayed.
#let heading-number(h) = numbering(h.numbering,
  ..counter(heading).at(h.location()))

// A title of the front matter (contents, lists): set like a chapter title,
// but no heading - it neither numbers nor appears in the outline.
#let front-title(body) = block(below: 1.4em, {
  text(font: sans-font, size: 22pt, weight: "semibold", fill: ink, body)
  v(6pt, weak: true)
  line(length: 36pt, stroke: 2.5pt + accent)
})

// The running header: the title of the document on the left, the chapter
// on the right, over a hairline; none on the title page and on the first
// page of a chapter.
#let running-header = context {
  let page = here().page()
  if page == 1 { return }
  if query(heading.where(level: 1)).any(h => h.location().page() == page) {
    return
  }
  let chapters = query(heading.where(level: 1).before(here()))
    .filter(h => h.outlined)
  set text(font: sans-font, size: 8.5pt, fill: muted)
  grid(columns: (1fr, auto), column-gutter: 1em,
    doc-title.get(),
    if chapters.len() > 0 {
      let chapter = chapters.last()
      if chapter.numbering != none [#heading-number(chapter)#h(0.6em)]
      chapter.body
    })
  v(-5pt)
  line(length: 100%, stroke: 0.4pt + hairline)
}

#let running-footer = context {
  if here().page() == 1 { return }
  set text(font: sans-font, size: 9pt, fill: muted)
  align(center, counter(page).display("1"))
}

#let esdm-doc(
  title: none,
  author: none,
  date: none,
  abstract: none,
  body,
) = {
  set document(title: title, author: "Stephan Müller")
  doc-title.update(title)
  set page(
    paper: "a4",
    margin: (x: 25mm, top: 30mm, bottom: 27mm),
    header-ascent: 40%,
    footer-descent: 40%,
    header: running-header,
    footer: running-footer,
  )
  set text(font: body-font, size: 10.5pt, lang: "en", fill: rgb("#111827"))
  set par(justify: true, leading: 0.68em, spacing: 1.05em,
    first-line-indent: 0pt)
  // Typst sets raw text at 0.8em: Source Code Pro at 0.88 of the text
  // matches the x-height of New Computer Modern.
  show raw: set text(font: mono-font, size: 1.1em)
  show raw.where(block: true): set par(justify: false, leading: 0.55em)
  show raw.where(block: true): it => block(width: 100%, fill: code-fill,
    stroke: 0.5pt + code-stroke, radius: 3pt, inset: (x: 9pt, y: 7pt), it)
  // Long identifiers may break after an underscore or a slash rather than
  // stretching the line.
  show raw.where(block: false): it => text(font: mono-font,
    fill: rgb("#334155"),
    it.text.replace("_", "_\u{200B}").replace("/", "/\u{200B}"))
  show math.equation: set text(font: "New Computer Modern Math")
  show math.equation.where(block: true): set block(above: 1.1em,
    below: 1.1em)

  set list(indent: 0.3em, body-indent: 0.6em, spacing: 0.8em,
    marker: (text(fill: accent)[•], text(fill: muted)[–],
      text(fill: muted)[◦]))
  set enum(indent: 0.2em, body-indent: 0.6em, spacing: 0.8em, full: true,
    numbering: (..ns) => {
      let ns = ns.pos()
      text(fill: accent, numbering(("1.", "(a)", "i.").at(
        calc.min(ns.len(), 3) - 1), ns.last()))
    })
  set terms(separator: h(0.6em), hanging-indent: 1.5em, spacing: 0.7em)
  show terms.item: it => block[#text(font: sans-font, weight: "semibold",
    fill: ink, it.term)#h(0.6em)#it.description]
  show list: set block(above: 0.95em, below: 0.95em)
  show enum: set block(above: 0.95em, below: 0.95em)
  show strong: set text(fill: ink)

  show link: it => if type(it.dest) == str {
    text(fill: accent, it)
  } else { it }

  // Headings in Source Sans 3: a chapter opens a page, under its number in
  // light blue - "Appendix A" in the appendix -, the others carry their
  // number in blue in front of a hanging title.
  set heading(numbering: "1.1.1")
  show heading: set text(font: sans-font, fill: ink)
  show heading: it => {
    let size = (14pt, 11.5pt, 10.5pt).at(calc.min(it.level, 4) - 2,
      default: 10.5pt)
    set text(size: size, weight: "semibold")
    set par(first-line-indent: 0pt, justify: false, leading: 0.5em)
    block(above: if it.level == 2 { 2em } else { 1.7em },
      below: if it.level == 2 { 1em } else { 0.85em },
      sticky: true,
      if it.numbering != none {
        grid(columns: (auto, 1fr), column-gutter: 0.75em,
          text(fill: accent, counter(heading).display(it.numbering)),
          it.body)
      } else { it.body })
  }
  // Figures and equations are numbered per chapter.
  show heading.where(level: 1): it => {
    counter(figure.where(kind: image)).update(0)
    counter(math.equation).update(0)
    pagebreak(weak: true)
    set par(first-line-indent: 0pt, justify: false, leading: 0.4em)
    block(above: 0pt, below: 2.4em, sticky: true, {
      v(26pt)
      if it.numbering != none {
        let num = counter(heading).display(it.numbering)
        if type(it.numbering) == str and it.numbering.starts-with("A") {
          text(size: 10pt, weight: "semibold", fill: accent,
            tracking: 0.12em, upper[Appendix])
          v(2pt)
        }
        text(size: 44pt, weight: "light", fill: accent, num)
        v(10pt, weak: true)
      }
      text(size: 24pt, weight: "semibold", it.body)
      v(12pt, weak: true)
      line(length: 36pt, stroke: 2.5pt + accent)
    })
  }
  set figure(numbering: n => context {
    let s = counter(heading).get()
    numbering("1.1", if s.len() == 0 { 0 } else { s.first() }, n)
  })
  show figure.where(kind: table): set figure(numbering: "1")
  show figure.where(kind: table): set figure.caption(position: top)
  set figure(gap: 1em)
  show figure: set block(above: 1.8em, below: 1.8em)
  show figure.caption: it => {
    set text(size: 9.5pt)
    set par(justify: false, leading: 0.55em)
    let label = text(font: sans-font, weight: "semibold", fill: accent,
      [#it.supplement #context it.counter.display(it.numbering)])
    block(width: 100%, align(center, [#label#h(0.5em)#it.body]))
  }
  set math.equation(numbering: n => context {
    let s = counter(heading).get()
    text(fill: muted, numbering("(1.1)", if s.len() == 0 { 0 } else {
      s.first() }, n))
  })
  // References show the bare number: the text says "figure 2.1",
  // "section 2.2" or "chapter 3" itself.
  set ref(supplement: none)
  show ref: it => {
    let el = it.element
    if el != none and el.func() == math.equation {
      link(el.location(), per-section(counter(math.equation), el.location()))
    } else if el != none and el.func() == figure and el.kind == image {
      link(el.location(),
        per-section(counter(figure.where(kind: image)), el.location()))
    } else { it }
  }

  // Tables: horizontal rules only, a light blue header row in Source Sans
  // 3 semibold.
  set table(
    stroke: (x, y) => (top: if y == 0 { 0.8pt + ink } else {
      0.4pt + hairline }, bottom: 0.8pt + ink, left: none, right: none),
    fill: (x, y) => if y == 0 { accent-light },
    inset: (x: 6pt, y: 4.5pt),
  )
  show table.cell.where(y: 0): set text(font: sans-font, weight: "semibold",
    fill: ink)
  set footnote.entry(separator: line(length: 30%, stroke: 0.5pt + hairline),
    gap: 0.5em)
  show footnote.entry: set text(size: 8.5pt)
  show footnote.entry: set par(first-line-indent: 0pt, leading: 0.5em)

  // The title page: a blue band on top, the title in Source Sans 3 with a
  // short blue line under it, author and version, the abstract on a light
  // blue card at the foot of the page.
  page(margin: (x: 25mm, top: 0pt, bottom: 25mm), header: none,
    footer: none, {
    set par(first-line-indent: 0pt, justify: false)
    place(top + left, dx: -25mm, rect(width: 210mm, height: 9mm,
      fill: accent))
    v(62mm)
    text(font: sans-font, size: 10pt, weight: "semibold", fill: accent,
      tracking: 0.14em, upper[ESDM Design Document])
    v(6mm)
    block(text(font: sans-font, size: 32pt, weight: "bold", fill: ink,
      title))
    v(5mm)
    line(length: 44pt, stroke: 3pt + accent)
    v(9mm)
    text(font: sans-font, size: 13pt, fill: ink, author)
    v(3mm)
    text(font: sans-font, size: 11.5pt, fill: muted, date)
    v(1fr)
    if abstract != none {
      block(width: 100%, fill: accent-light, radius: 4pt, inset: 14pt, {
        text(font: sans-font, size: 9pt, weight: "semibold", fill: accent,
          tracking: 0.12em, upper[Abstract])
        v(4pt)
        set text(size: 9.5pt)
        set par(justify: true, leading: 0.6em)
        abstract
      })
    }
  })

  // Table of contents, lists of figures and tables.
  {
    set par(first-line-indent: 0pt, justify: false)
    front-title[Contents]
    show outline.entry.where(level: 1): it => {
      v(1.1em, weak: true)
      link(it.element.location(), text(font: sans-font, weight: "semibold",
        fill: ink, it.indented(text(fill: accent, it.prefix()),
        [#it.body()#h(1fr)#it.page()])))
    }
    set outline.entry(fill: box(width: 1fr, repeat(gap: 0.5em,
      text(fill: hairline)[.])))
    outline(title: none, indent: auto, depth: 3)
    pagebreak(weak: true)
    // Entries of the lists of figures and tables: number, caption, dots.
    show outline.entry: it => {
      if it.element.func() != figure { return it }
      let loc = it.element.location()
      let num = if it.element.kind == image {
        per-section(counter(figure.where(kind: image)), loc)
      } else {
        str(counter(figure.where(kind: table)).at(loc).first())
      }
      block(above: 0.6em, below: 0.6em, link(loc, grid(
        columns: (2.6em, 1fr),
        text(font: sans-font, fill: accent, num),
        par(justify: false)[#it.element.caption.body#box(width: 1fr,
          repeat(gap: 0.5em, text(fill: hairline)[.]))#it.page()])))
    }
    front-title[List of Figures]
    outline(title: none, target: figure.where(kind: image))
    v(2em)
    front-title[List of Tables]
    outline(title: none, target: figure.where(kind: table))
  }

  body
}

// Switch to appendix numbering (A, B, ...).
#let appendix(body) = {
  counter(heading).update(0)
  set heading(numbering: "A.1")
  body
}
