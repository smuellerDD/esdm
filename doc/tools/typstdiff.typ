// Helper library of typstdiff.py: the documents it merges from two versions
// of a Typst tree import this file and mark their changes with it.
//
//   tdel[..] / tins[..]        deleted / inserted text (red struck through /
//                              green underlined), inline
//   tdel-par / tins-par        the same for a whole block (a paragraph-like
//                              element of its own)
//   tdel-block / tins-block    deleted / inserted figure, table or code
//                              block in a tinted box
//   tdel-arr / tins-arr        deleted / inserted array of content (nested
//                              arrays are sub-levels and stay arrays)
//   tdel-heading(level: n)     a deleted heading: looks like one, but is no
//                              heading (no number, no outline entry)
//   tchg[..]                   an element changed in a way not shown inline
//   tslide-ins / -del / -chg   a new / removed / changed slide (badge)
//   tdref("label")             a reference in deleted text whose target no
//                              longer exists
//   td-setup                   show rule of the compiled file: change bars
//                              in the left margin, slide badges, legend on
//                              the first page, outlines without diff markup
//   td-legend()                the legend, to place it elsewhere
//
// The change bars are drawn by the page foreground from metadata markers
// around every change.

#let td-del-color = rgb("#cf222e")
#let td-ins-color = rgb("#1a7f37")
#let td-chg-color = rgb("#bf8700")

// typstdiff.py fills in the version labels when it copies this file.
#let td-labels = (old: "old", new: "new") // typstdiff:labels

// True inside an outline: deleted text and the markers are left out.
#let td-plain = state("typstdiff-plain", false)

// Markers: `up` / `down` extend the change bar above the start / below the
// end position (inline markers sit on the baseline).
#let _td-start(kind, inline: true) = context if not td-plain.get() {
  metadata((typstdiff: kind,
    up: if inline { 0.8 * text.size } else { 1pt }))
}
#let _td-end(inline: true) = context if not td-plain.get() {
  metadata((typstdiff: "end",
    down: if inline { 0.3 * text.size } else { 1pt }))
}

// Inserted text is underlined; td-setup colours this underline (and not
// inside outlines, which show the new text plainly).
#let _td-ins-offset = 1.61pt

#let td-del-style(body) = {
  set text(fill: td-del-color)
  strike(stroke: 0.6pt + td-del-color, body)
}

#let td-ins-style(body) = underline(stroke: 0.6pt + td-ins-color,
  offset: _td-ins-offset, evade: false, body)

// The zero-width spacing keeps the markers inside the paragraph (markers at
// its start or end would be moved out of it) without allowing line breaks.
#let tdel(body) = context if not td-plain.get() {
  h(0pt)
  _td-start("del")
  td-del-style(body)
  _td-end()
  h(0pt)
}

#let tins(body) = {
  h(0pt)
  _td-start("ins")
  td-ins-style(body)
  _td-end()
  h(0pt)
}

#let tchg(body) = {
  _td-start("chg", inline: false)
  body
  _td-end(inline: false)
}

#let _td-par(kind, style, body) = block(width: 100%, breakable: true, {
    _td-start(kind, inline: false)
    style(body)
    _td-end(inline: false)
  })

#let tdel-par(body) = _td-par("del", td-del-style, body)
#let tins-par(body) = _td-par("ins", td-ins-style, body)

#let _td-box(color, kind, style, body) = block(
  width: 100%,
  fill: color.lighten(92%),
  stroke: (left: 1.5pt + color),
  inset: (x: 6pt, y: 5pt),
  radius: 2pt,
  breakable: true,
  {
    _td-start(kind, inline: false)
    style(body)
    _td-end(inline: false)
  },
)

#let tdel-block(body) = _td-box(td-del-color, "del", td-del-style, body)
#let tins-block(body) = _td-box(td-ins-color, "ins", it => {
  set text(fill: td-ins-color)
  it
}, body)

#let tdel-arr(items) = items.map(it => if type(it) == array {
  tdel-arr(it)
} else { tdel(it) })

#let tins-arr(items) = items.map(it => if type(it) == array {
  tins-arr(it)
} else { tins(it) })

#let tdel-heading(level: 1, body) = block(
  above: 1.5em, below: 1em, sticky: true, {
    _td-start("del", inline: false)
    set par(first-line-indent: 0pt, justify: false)
    set text(weight: "bold",
      size: (1.44em, 1.2em, 1em).at(calc.min(level, 3) - 1))
    td-del-style(body)
    _td-end(inline: false)
  })

#let tdref(name) = text(fill: td-del-color, raw("@" + name))

// Slides: the badge is drawn by td-setup on the page of the marker.
#let tslide-ins(body) = {
  metadata((typstdiff: "slide-ins"))
  set text(fill: td-ins-color)
  body
}

#let tslide-del(body) = {
  metadata((typstdiff: "slide-del"))
  td-del-style(body)
}

#let tslide-chg(body) = {
  metadata((typstdiff: "slide-chg"))
  body
}

#let td-legend(old: auto, new: auto) = {
  let old = if old == auto { td-labels.old } else { old }
  let new = if new == auto { td-labels.new } else { new }
  box(fill: white, stroke: 0.5pt + luma(160), inset: (x: 6pt, y: 4pt),
    radius: 2pt, text(size: 8pt, fill: black, weight: "regular",
      [Changes from #old to #new: #td-del-style[deleted] #h(0.5em)
        #text(fill: td-ins-color, td-ins-style[inserted]) #h(0.5em)
        #box(width: 2pt, height: 0.8em, fill: td-chg-color) changed]))
}

// Resolve a margin of the page to a length.
#let _td-margin(m, side, base) = {
  let v = if m == auto { auto } else if type(m) == dictionary {
    m.at(side, default: m.at("rest", default: auto))
  } else { m }
  if v == auto { 2.5 / 21 * base }
  else if type(v) == relative { v.ratio * base + v.length.to-absolute() }
  else if type(v) == length { v.to-absolute() }
  else if type(v) == ratio { v * base }
  else { 0pt }
}

#let _td-is-mark(m) = type(m.value) == dictionary and "typstdiff" in m.value

// Pair the markers to ranges (kind, up, start, down, end).
#let _td-ranges(marks) = {
  let stack = ()
  let ranges = ()
  for m in marks {
    let k = m.value.typstdiff
    if k == "end" {
      if stack.len() > 0 {
        let s = stack.pop()
        ranges.push((s.value.typstdiff, s.value.up, s.location().position(),
          m.value.down, m.location().position()))
      }
    } else if k in ("del", "ins", "chg") {
      stack.push(m)
    }
  }
  ranges
}

#let td-foreground(legend: true) = context {
  let pg = here().page()
  let w = page.width
  let h = page.height
  if w == auto or h == auto { return }
  let short = calc.min(w, h)
  let m = page.margin
  let m-left = _td-margin(m, "left", short)
  let m-top = _td-margin(m, "top", short)
  let m-bottom = h - _td-margin(m, "bottom", short)
  let x = if m-left >= 30pt { m-left - 12pt } else { 4pt }
  let marks = query(metadata).filter(_td-is-mark)
  let colors = (del: td-del-color, ins: td-ins-color, chg: td-chg-color)
  for (kind, up, s, down, e) in _td-ranges(marks) {
    if s.page <= pg and pg <= e.page {
      let y0 = if s.page == pg { s.y - up } else { m-top }
      let y1 = if e.page == pg { e.y + down } else { m-bottom }
      if y1 < y0 + 4pt { y1 = y0 + 4pt }
      place(top + left, dx: x, dy: y0,
        rect(width: 2pt, height: y1 - y0, fill: colors.at(kind),
          stroke: none))
    }
  }
  let badges = (
    "slide-ins": (td-ins-color, [new in #td-labels.new]),
    "slide-del": (td-del-color, [removed in #td-labels.new]),
    "slide-chg": (td-chg-color, [changed in #td-labels.new]))
  for mk in marks {
    let k = mk.value.typstdiff
    if k in badges and mk.location().page() == pg {
      let (c, label) = badges.at(k)
      place(top + right, dx: -10pt, dy: 10pt,
        box(fill: c, inset: (x: 7pt, y: 4pt), radius: 3pt,
          text(size: 11pt, fill: white, weight: "bold", label)))
    }
  }
  if legend and pg == 1 {
    let dy = if m-top >= 40pt { m-top / 2 - 8pt } else { 8pt }
    place(top + center, dy: dy, td-legend())
  }
}

// Show rule for the compiled file, before its template: `#show: td-setup`.
#let td-setup(legend: true, body) = {
  set page(foreground: td-foreground(legend: legend))
  show underline.where(offset: _td-ins-offset): it => text(
    fill: td-ins-color, it)
  show outline: it => {
    td-plain.update(true)
    show underline.where(offset: _td-ins-offset): u => u.body
    it
    td-plain.update(false)
  }
  body
}
