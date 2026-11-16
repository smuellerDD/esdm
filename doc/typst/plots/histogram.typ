// Histograms of the raw noise source data (figures 3.1 to 3.6).
//
// The originals are R plots (hist() with the relative frequency, lines() of
// a density estimate, abline() markers for the quartiles, the mean and the
// median). The bar heights are transcribed from the rasters of the original
// PDF into data/<name>.csv; the density curve is recomputed here from the
// bins with a Gaussian kernel whose bandwidth was fitted to the curve of
// the original figure 3.5. Everything else (marker positions, subtitle,
// axis ticks) is taken verbatim from the original figures.
//
// Usage: #import "../plots/histogram.typ": histogram
//        #figure(histogram("riscv"), caption: [...])

// Per figure: largest value with data (defines the number of bars as in
// R's hist()), the marker positions, the y axis ticks (value, labelled?)
// and the two subtitle lines.
#let meta = (
  "riscv": (
    max: 255, q1: 63, median: 127, mean: 127.45, q3: 192,
    yticks: range(0, 5).map(i => (i * 0.001, true)),
    sub: (
      "Min: 0 - 1st Qu: 63 - Median: 127 - Mean: 127.45",
      "3rd Qu: 192 - Max: 255 - Sigma: 73.89 - Var Coeff: 0.579801",
    ),
  ),
  "usbarmory-mk2": (
    max: 255, q1: 63, median: 127, mean: 127.15, q3: 191,
    yticks: range(0, 5).map(i => (i * 0.001, true)),
    sub: (
      "Min: 0 - 1st Qu: 63 - Median: 127 - Mean: 127.15",
      "3rd Qu: 191 - Max: 255 - Sigma: 73.96 - Var Coeff: 0.581668",
    ),
  ),
  "armv7-timer": (
    max: 255, q1: 68, median: 128, mean: 121.05, q3: 191,
    yticks: range(0, 8).map(i => (i * 0.005, calc.even(i))),
    sub: (
      "Min: 0 - 1st Qu: 68 - Median: 128 - Mean: 121.05",
      "3rd Qu: 191 - Max: 255 - Sigma: 72.95 - Var Coeff: 0.60262",
    ),
  ),
  "systemz-z13": (
    max: 250, q1: 56, median: 120, mean: 118.27, q3: 184,
    yticks: range(0, 5).map(i => (i * 0.005, true)),
    sub: (
      "Min: 0 - 1st Qu: 56 - Median: 120 - Mean: 118.27",
      "3rd Qu: 184 - Max: 250 - Sigma: 73.58 - Var Coeff: 0.622112",
    ),
  ),
  "atom-without-gcd": (
    max: 252, q1: 64, median: 124, mean: 125.99, q3: 188,
    yticks: range(0, 4).map(i => (i * 0.005, true)),
    sub: (
      "Min: 0 - 1st Qu: 64 - Median: 124 - Mean: 125.99",
      "3rd Qu: 188 - Max: 252 - Sigma: 73.84 - Var Coeff: 0.586089",
    ),
  ),
  "atom-with-gcd": (
    max: 255, q1: 64, median: 128, mean: 127.58, q3: 192,
    yticks: range(0, 5).map(i => (i * 0.001, true)),
    sub: (
      "Min: 0 - 1st Qu: 64 - Median: 128 - Mean: 127.58",
      "3rd Qu: 192 - Max: 255 - Sigma: 73.93 - Var Coeff: 0.579468",
    ),
  ),
)

// Gaussian kernel density of the binned data (bins at integer values,
// weights = relative frequencies), evaluated like R's density(): from
// min - 3h to max + 3h.
#let density(bins, nbars, h) = {
  let pts = ()
  let step = 0.25
  let x = -3 * h
  let norm = 1 / (h * calc.sqrt(2 * calc.pi))
  while x <= (nbars - 1) + 3 * h {
    let lo = calc.max(0, calc.ceil(x - 5 * h))
    let hi = calc.min(nbars - 1, calc.floor(x + 5 * h))
    let y = 0.0
    for v in range(lo, hi + 1) {
      let w = bins.at(v)
      if w > 0 {
        let u = (x - v) / h
        y += w * calc.exp(-0.5 * u * u)
      }
    }
    pts.push((x, y * norm))
    x += step
  }
  pts
}

// The plot geometry follows the 768 x 480 px rasters of the original:
// plot region 65..736.6 px horizontally and 63.2..397.9 px vertically,
// font size 13.9 px. `width` scales everything.
#let histogram(
  name,
  width: 345.6pt,
  font: "Liberation Sans",
  bandwidth: 1.1,
  title: "Histogam Raw Time Stamps",
  ylabel: "Relative Frequency",
) = {
  let m = meta.at(name)
  let rows = csv("data/" + name + ".csv", row-type: dictionary)
  let bins = rows.map(r => float(r.relfreq))
  let nbars = m.max + 1
  let ymax = calc.max(..bins)

  let px = width / 768
  let height = 480 * px
  // plot region in px
  let (L, R, T, B) = (65.1, 736.6, 63.2, 397.9)
  let (xlo, xhi) = (-0.04 * nbars, 1.04 * nbars)
  let (ylo, yhi) = (-0.04 * ymax, 1.04 * ymax)
  let X(v) = (L + (v - xlo) / (xhi - xlo) * (R - L)) * px
  let Y(f) = (B - (f - ylo) / (yhi - ylo) * (B - T)) * px

  let lw = 1 * px
  let fs = 13.9 * px
  set text(font: font, size: fs)

  // centred text with its baseline at (x, y)
  let ctext(x, y, body, size: fs, weight: "regular") = place(
    top + left,
    dx: x - 300 * px,
    dy: y - 0.72 * size,
    box(width: 600 * px, align(center, text(size: size, weight: weight, body))),
  )
  // text rotated by -90deg, centred at y, glyph baseline at column x
  let vtext(x, y, body) = place(
    top + left,
    dx: x - 0.72 * fs,
    dy: y - 300 * px,
    box(height: 600 * px, align(horizon, rotate(-90deg, reflow: true, text(body)))),
  )

  box(width: width, height: height, {
    // bars: outlined rectangles from 0 to the relative frequency
    for v in range(nbars) {
      let f = bins.at(v)
      place(top + left, dx: X(v), dy: Y(f), rect(
        width: X(v + 1) - X(v),
        height: Y(0) - Y(f),
        fill: white,
        // Thinner than the other lines: the 1 px outlines of the
        // anti-aliased original come out grey at this size, not black.
        stroke: 0.5 * lw + black,
      ))
    }
    // density estimate
    let pts = density(bins, nbars, bandwidth)
    place(top + left, curve(
      stroke: lw + black,
      curve.move((X(pts.at(0).at(0)), Y(pts.at(0).at(1)))),
      ..pts.slice(1).map(p => curve.line((X(p.at(0)), Y(p.at(1))))),
    ))
    // markers: quartiles green, mean red, median blue
    for (v, c) in ((m.q1, rgb(0, 255, 0)), (m.q3, rgb(0, 255, 0)), (m.mean, rgb(255, 0, 0)), (m.median, rgb(0, 0, 255))) {
      place(top + left, line(start: (X(v), T * px), end: (X(v), B * px), stroke: lw + c))
    }
    // x axis
    place(top + left, line(start: (X(0), B * px), end: (X(250), B * px), stroke: lw + black))
    for v in range(0, 251, step: 50) {
      place(top + left, line(start: (X(v), B * px), end: (X(v), (B + 7.2) * px), stroke: lw + black))
      ctext(X(v), 426.5 * px, str(v))
    }
    // y axis
    let ticks = m.yticks
    place(top + left, line(
      start: (L * px, Y(ticks.first().at(0))),
      end: (L * px, Y(ticks.last().at(0))),
      stroke: lw + black,
    ))
    for (f, labelled) in ticks {
      place(top + left, line(start: ((L - 7.2) * px, Y(f)), end: (L * px, Y(f)), stroke: lw + black))
      if labelled {
        let s = str(calc.round(f * 1000) / 1000)
        // three decimals like R's axis labels
        let parts = s.split(".")
        let dec = if parts.len() > 1 { parts.at(1) } else { "" }
        while dec.len() < 3 { dec += "0" }
        vtext(45.5 * px, Y(f), parts.at(0) + "." + dec)
      }
    }
    // titles
    ctext((L + R) / 2 * px, 37.5 * px, title, size: 1.2 * fs, weight: "bold")
    vtext(13.5 * px, (T + B) / 2 * px, ylabel)
    ctext((L + R) / 2 * px, 441.5 * px, m.sub.at(0))
    ctext((L + R) / 2 * px, 457.5 * px, m.sub.at(1))
  })
}
