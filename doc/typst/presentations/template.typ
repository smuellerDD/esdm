// Slide template of the ESDM presentations.
//
// A 16:9 page of 793.7pt x 446.5pt - the page and the text area of the
// LibreOffice Impress master of the original decks, so that the figures and
// windows placed on a slide keep their places - in a light, modern frame:
// Source Sans 3 in slate ink on white, one blue accent, titles beside a short
// blue line, a quiet footer with the name of the deck and "n / N", and dark
// terminal and editor cards in Source Code Pro.
//
// Outline bullets: a blue dot (level 1), a slate en dash (level 2) and a slate
// ring (level 3). Impress shrank the outline text of a slide until it fit; the
// factor is still given per slide as `scale` (1 = 32pt level-1 text). The
// decks of 1.2.4 and later keep it at 0.5 (16pt) or above.
//
// The slides are numbered by the page counter: the number a slide passes as
// first positional argument of slide() - as the deck of 1.2.3 does - is not
// used.

// ---------------------------------------------------------------- colours

#let ink = rgb("#0f172a") // slate-900: titles and body text
#let muted = rgb("#475569") // slate-600: second and third level, captions
#let faint = rgb("#94a3b8") // slate-400: footer
#let hairline = rgb("#e2e8f0") // slate-200: card borders, table rules
#let accent = rgb("#2563eb") // blue-600: bullets, accent lines
#let accent-text = rgb("#1d4ed8") // blue-700: blue text on white
#let accent-soft = rgb("#dbeafe") // blue-100: table header rows
#let navy = rgb("#0b1f3a") // background of the title slide
#let link-blue = accent-text

// ---------------------------------------------------------------- fonts

#let sans = "Source Sans 3"
#let mono = "Source Code Pro"

// ---------------------------------------------------------------- geometry

#let page-width = 793.701pt
#let page-height = 446.457pt

// Left edge of the outline text box and top of its first line; the right
// margin equals the left one.
#let body-x = 39.7pt
#let body-top = 130pt
#let body-right = page-width - body-x

// What the footer of every slide names
#let deck-name = [Entropy Source and DRNG Manager]

// A term highlighted in the text, the same as *strong*
#let hl(body) = text(fill: accent-text, weight: "semibold", body)

// The factor the space between the outline items of a deck is stretched by,
// and the top of the outline text, see setup()
#let outline-spacing = state("esdm-outline-spacing", 1)
#let outline-top = state("esdm-outline-top", body-top)

// Liberation Sans of the original decks laid out text with its hhea metrics
// (ascender 0.905em, descender 0.212em); the edges are kept, so the lines
// of an outline sit where they did. A deck composed for this template asks
// for more air: `spacing` stretches the space between the outline items,
// `leading` is the one between the lines of an item, and `top` moves the
// outline text - and with it the title above it - up or down.
#let setup(body, spacing: 1, leading: 0.08em, top: body-top) = {
  set document(author: "Stephan Müller")
  set page(width: page-width, height: page-height, margin: 0pt, fill: white)
  set text(font: sans, size: 18pt, lang: "en", fill: ink,
    top-edge: 0.905em, bottom-edge: -0.212em)
  set par(leading: leading, spacing: 0pt, justify: false)
  outline-spacing.update(spacing)
  outline-top.update(top)
  show strong: set text(weight: "semibold", fill: accent-text)
  show link: set text(fill: link-blue)
  show raw: set text(font: mono, size: 1.05em)
  set table(stroke: 0.5pt + hairline,
    fill: (_, y) => if y == 0 { accent-soft })
  body
}

// ---------------------------------------------------------------- frame

// The footer: the name of the deck on the left, "n / N" on the right.
#let footer = {
  set text(size: 9pt, fill: faint, top-edge: "cap-height",
    bottom-edge: "baseline")
  place(top + left, dx: body-x, dy: 431pt, deck-name)
  place(top + right, dx: -body-x, dy: 431pt, context {
    let n = counter(page).get().first()
    let total = counter(page).final().first()
    [#n / #total]
  })
}

// Title of a content slide: semibold, left aligned, its last line ending on
// the same baseline 24pt above the outline text (y = 106pt with the text
// area of the original decks) for one and two lines, with a short blue line
// below it.
#let slide-title(title) = context {
  let y = outline-top.get()
  place(top + left, dx: body-x, dy: y - 110pt,
    box(width: page-width - 2 * body-x, height: 86pt,
      align(left + bottom, {
        set text(size: 29pt, weight: "semibold", fill: ink,
          top-edge: "cap-height", bottom-edge: "baseline", tracking: -0.2pt)
        set par(leading: 0.32em)
        title
      })))
  place(top + left, dx: body-x, dy: y - 16pt,
    rect(width: 40pt, height: 3pt, radius: 1.5pt, fill: accent, stroke: none))
}

// ---------------------------------------------------------------- outline

// Outline levels: text size, indent of the bullet and the text, space after
// the paragraph (all for scale 1, as factors of the 32pt level-1 size).
#let levels = (
  (size: 32pt, marker-x: 8.6pt, text-x: 33.9pt, below: 14.2pt, fill: ink),
  (size: 28pt, marker-x: 42.6pt, text-x: 68.2pt, below: 11.5pt, fill: muted),
  (size: 24pt, marker-x: 79.0pt, text-x: 101.8pt, below: 8.3pt, fill: muted),
)

// The bullet of an outline level, positioned relative to the top of the
// first text line (whose baseline lies 0.905 * size below it) and centred on
// the middle of the lower case letters: a blue dot, a slate en dash, a slate
// ring.
#let marker(level, size, dx) = {
  let mid = (0.905 - 0.25) * size
  if level == 0 {
    let r = 0.12 * size
    place(top + left, dx: dx + 0.04 * size, dy: mid - r,
      circle(radius: r, fill: accent, stroke: none))
  } else if level == 1 {
    let d = 0.8 * size
    place(top + left, dx: dx, dy: (0.905 - 0.04) * size - 0.905 * d,
      text(size: d, fill: faint, "–"))
  } else {
    let r = 0.1 * size
    place(top + left, dx: dx + 0.05 * size, dy: mid - r,
      circle(radius: r, fill: none, stroke: 0.06 * size + faint))
  }
}

// Render outline items; every item is content and may be followed in the
// array by an array with its children (the next outline level).
#let outline-items(items, scale: 1, level: 0) = context {
  let lv = levels.at(level)
  let stretch = outline-spacing.get()
  let size = lv.size * scale
  let i = 0
  while i < items.len() {
    let it = items.at(i)
    let children = none
    if i + 1 < items.len() and type(items.at(i + 1)) == array {
      children = items.at(i + 1)
    }
    block(below: lv.below * scale * stretch, above: 0pt, {
      set text(size: size, fill: lv.fill)
      pad(left: lv.text-x * scale, {
        marker(level, size, (lv.marker-x - lv.text-x) * scale)
        it
      })
    })
    if children != none {
      outline-items(children, scale: scale, level: level + 1)
      i += 2
    } else {
      i += 1
    }
  }
}

// A content slide. `items`: outline (see outline-items), `scale`: size factor
// of the outline, `x`: left edge of the outline box, `width`: its width,
// `extra`: content placed on the slide (figures, windows). A leading
// positional argument (the slide number of the deck of 1.2.3) is ignored.
#let slide(..number, title: none, items: (), scale: 1, x: body-x,
    width: 740pt, extra: none) = {
  if title != none { slide-title(title) }
  if extra != none { extra }
  context place(top + left, dx: x, dy: outline-top.get(), block(width: width,
    outline-items(items, scale: scale)))
  footer
  pagebreak(weak: true)
}

// The title slide: deep navy, a blue line above the large white title, the
// subtitle and the version in blue, the author in light slate, and a few
// faint rings on the right.
#let title-slide(title: none, author: none, subtitle: none,
    version: none) = {
  place(top + left, rect(width: page-width, height: page-height,
    fill: navy, stroke: none))
  for (i, r) in (90pt, 150pt, 210pt, 270pt).enumerate() {
    place(top + left, dx: 690pt - r, dy: 330pt - r,
      circle(radius: r, fill: none,
        stroke: 0.8pt + accent.transparentize(55% + 10% * i)))
  }
  place(top + left, dx: 690pt - 14pt, dy: 330pt - 14pt,
    circle(radius: 14pt, fill: accent, stroke: none))
  place(top + left, dx: body-x + 8pt, dy: 92pt,
    rect(width: 56pt, height: 4pt, radius: 2pt, fill: accent, stroke: none))
  place(top + left, dx: body-x + 8pt, dy: 112pt, block(width: 640pt, {
    set text(top-edge: "cap-height", bottom-edge: "baseline")
    set par(leading: 0.36em)
    text(size: 42pt, weight: "semibold", fill: white, tracking: -0.4pt,
      title)
    if subtitle != none {
      v(18pt)
      text(size: 21pt, fill: rgb("#93c5fd"), subtitle)
    }
  }))
  place(top + left, dx: body-x + 8pt, dy: 318pt, block(width: 420pt, {
    set text(top-edge: "cap-height", bottom-edge: "baseline")
    set par(leading: 0.55em)
    if version != none {
      text(size: 12pt, weight: "semibold", fill: rgb("#60a5fa"),
        tracking: 1.2pt, upper(version))
      v(14pt)
    }
    text(size: 17pt, fill: rgb("#cbd5e1"), author)
  }))
  pagebreak(weak: true)
}

// ---------------------------------------------------------------- figures

// Place a figure scaled into the box x, y, w, h (in pt). Given as the path of
// an image (relative to this directory, like the deck), it is fitted into
// the box, aligned to `align`, on a white card with a hairline border; given
// as content (an image sized by the caller), it is centred in the box as it
// is.
#let fig(img, x, y, w, h, card: true, align: top + center, pad: 6pt) = place(
  top + left, dx: x, dy: y, box(width: w, height: h,
    std.align(if type(img) == str { align } else { center + horizon }, {
      if type(img) == str {
        context {
          let natural = measure(image(img))
          let inner = if card { pad } else { 0pt }
          let s = calc.min((w - 2 * inner) / natural.width,
            (h - 2 * inner) / natural.height)
          let body = image(img, width: natural.width * s)
          if card {
            box(fill: white, stroke: 0.6pt + hairline, radius: 5pt,
              inset: pad, body)
          } else {
            body
          }
        }
      } else {
        img
      }
    })))

// ---------------------------------------------------------------- windows

// The palette of the terminal and editor cards (Tailwind tones on slate-900).
#let code = (
  bg: rgb("#0f172a"),
  bar: rgb("#1e293b"),
  border: rgb("#334155"),
  dot: rgb("#475569"),
  title: rgb("#94a3b8"),
  fg: rgb("#e2e8f0"),
  comment: rgb("#94a3b8"),
  keyword: rgb("#93c5fd"),
  string: rgb("#86efac"),
  prompt: rgb("#60a5fa"),
  ok: rgb("#4ade80"),
  skip: rgb("#fbbf24"),
  warn: rgb("#fdba74"),
  debug: rgb("#93c5fd"),
  verbose: rgb("#a7f3d0"),
  match: rgb("#f472b6"),
  search-bg: rgb("#fbbf24"),
  search-fg: rgb("#0f172a"),
)

// The colour names of the Zenburn windows of the deck of 1.2.3, mapped onto
// the palette above.
#let zenburn = (
  bg: code.bg,
  fg: code.fg,
  green: code.prompt,
  ok: code.ok,
  blue: code.debug,
  orange: code.warn,
  match: code.match,
  cyan: code.keyword,
  pink: code.string,
  yellow: code.skip,
  search: code.search-fg,
)

// Height of the title bar above the text area of a window
#let window-bar = 11pt

// A dark card: a slim title bar with three dots (and an optional title)
// above the text area x, y, w, h, which holds `lines` in Source Code Pro of
// `size` with a line pitch of `pitch`. Every line is a string (shown
// verbatim, styled by the regex `rules` given as (regex, function) pairs) or
// content. Without the `bar`, the card is the text area alone.
#let window(x, y, w, h, lines, size: 7pt, pitch: none, rules: (),
    inset-x: 6pt, inset-y: 4pt, title: none, bar: true) = {
  let pitch = if pitch == none { 1.3 * size } else { pitch }
  let bar-h = if bar { window-bar } else { 0pt }
  place(top + left, dx: x, dy: y - bar-h, block(width: w,
    height: h + bar-h, fill: code.bg, radius: 6pt, clip: true,
    stroke: 0.6pt + code.border, {
      if bar {
        place(top + left, rect(width: 100%, height: window-bar,
          fill: code.bar, stroke: none))
        for i in range(3) {
          place(top + left, dx: 7pt + i * 7pt, dy: window-bar / 2 - 2pt,
            circle(radius: 2pt, fill: code.dot, stroke: none))
        }
      }
      if bar and title != none {
        place(top + left, dy: 0pt, box(width: w, height: window-bar,
          std.align(center + horizon, text(font: mono, size: 6pt,
            fill: code.title, top-edge: "cap-height",
            bottom-edge: "baseline", title))))
      }
      place(top + left, dy: bar-h, block(width: w, height: h,
        inset: (left: inset-x, top: inset-y), {
          set text(font: mono, size: size, fill: code.fg,
            top-edge: 0.928em, bottom-edge: -0.236em, hyphenate: false)
          show raw: set text(font: mono, size: size)
          set raw(tab-size: 8)
          show: body => rules.fold(body, (b, r) => {
            show r.at(0): r.at(1)
            b
          })
          for l in lines {
            block(height: pitch, above: 0pt, below: 0pt, width: 10 * w,
              if type(l) == str { raw(l) } else { l })
          }
        }))
    }))
}

// The windows of the deck of 1.2.3, which recreated screenshots with 11px
// wide cells and a line pitch of 23px: `px` is the size of one screenshot
// pixel on the slide. They were placed right below the text, so they come
// without the title bar above them unless asked for.
#let screen(x, y, w, h, px, lines, rules: (), left-px: 4, top-px: 0,
    title: none, bar: false) = window(x, y, w, h, lines, size: 18.27 * px,
  pitch: 23.0 * px, rules: rules, inset-x: left-px * px, inset-y: top-px * px,
  title: title, bar: bar)

// Helpers for the editor windows of the deck of 1.2.3 (meson_options.txt)
#let ed-col(c, body) = text(fill: c, body)
#let ed-hl(body) = box(fill: code.search-bg, outset: (y: 1.5pt),
  text(fill: code.search-fg, body))

// An editor window showing lines of meson_options.txt: comments slate, the
// option keyword blue, strings - the ''' descriptions included - green.
// `lines` are the verbatim lines of the file.
#let meson-view(x, y, w, h, lines, size: 6.6pt, title: "meson_options.txt") = {
  let str-col(s) = text(fill: code.string, raw(s))
  // A line outside of a description: quoted strings coloured, the rest plain.
  let plain(s) = {
    let parts = ()
    let pos = 0
    for m in s.matches(regex("'[^']*'")) {
      parts.push(raw(s.slice(pos, m.start)))
      parts.push(str-col(m.text))
      pos = m.end
    }
    parts.push(raw(s.slice(pos)))
    parts.join()
  }
  let out = ()
  let in-str = false
  for l in lines {
    if in-str {
      let i = l.position("'''")
      if i == none {
        out.push(str-col(l))
      } else {
        out.push([#str-col(l.slice(0, i + 3))#raw(l.slice(i + 3))])
        in-str = false
      }
    } else if l.trim().starts-with("#") {
      out.push(text(fill: code.comment, raw(l)))
    } else {
      let i = l.position("'''")
      let head = if i == none { l } else { l.slice(0, i) }
      let lead = head.len() - head.trim(at: start).len()
      let body = if head.trim().starts-with("option") {
        [#raw(head.slice(0, lead))#text(fill: code.keyword,
          weight: "bold", raw("option"))#plain(head.slice(lead + 6))]
      } else { plain(head) }
      if i != none {
        let rest = l.slice(i + 3)
        let j = rest.position("'''")
        if j == none {
          body = [#body#str-col(l.slice(i))]
          in-str = true
        } else {
          body = [#body#str-col(l.slice(i, i + 3 + j + 3))#raw(rest.slice(j + 3))]
        }
      }
      out.push(body)
    }
  }
  window(x, y, w, h, out, size: size, title: title)
}
