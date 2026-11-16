// ESDM presentation for release 1.2.4.
//
// Started as the Typst translation of doc/esdm_presentation_v1.0.0.pdf (the
// deck of 1.2.3, git tag doc-1.2.3) and brought in line with the code of
// ESDM 1.2.4. The editor windows show meson_options.txt verbatim
// (meson-excerpts.typ), the terminal windows program output of this release
// (screens.typ).
// Build from doc/typst: typst compile --root . presentations/<this file>

#import "template.typ": *
#import "screens.typ": *
#import "meson-excerpts.typ": *

// The text area of this deck starts higher than the one of the original
// decks, the titles move up with it.
#let body-top = 112pt
#show: setup.with(spacing: 1.3, leading: 0.14em, top: body-top)
#set document(title: "Entropy Source and DRNG Manager 1.2.4")

#let figdir = "../figures/"

// The grid of the slides: text columns start at body-x, a column beside them
// starts after a gap of 24pt and ends at body-right; figures and windows are
// aligned to the top of the text (body-top), and end above the footer.
#let gap = 24pt
#let content-bottom = 408pt
// A window whose card is aligned to the text top: its text area starts below
// the title bar.
#let win-y = body-top + window-bar
#let right-col(text-width) = body-x + text-width + gap
#let right-width(text-width) = body-right - right-col(text-width)

// Colours of the log lines in the terminal windows
#let log-rules = (
  (regex("^ESDM .*? Warning .*?\]:"), it => text(fill: code.warn, it)),
  (regex("^ESDM .*? Debug .*?\]:"), it => text(fill: code.debug, it)),
  (regex("^ESDM .*? Verbose .*?\]:"), it => text(fill: code.verbose, it)),
)
#let prompt-rule = (regex("^\$ .*"), it => text(fill: code.prompt, it))

// A command line in the text, kept on one line
#let cmd(s) = box(raw(s))

// ---------------------------------------------------------------- slide 1
#title-slide(
  title: [Entropy Source and \ DRNG Manager],
  subtitle: [...or /dev/random in User Space],
  version: [ESDM 1.2.4],
  author: [Stephan Müller \ \<smueller\@chronox.de\>],
)

// ---------------------------------------------------------------- slide 2
#slide(title: [Agenda], scale: 0.8, items: (
  [ESDM Goals],
  [ESDM Design],
  [Interfaces],
  [Initial Seeding Strategies],
  [Entropy Sources],
  [Self Tests and Testing],
))

// ---------------------------------------------------------------- slide 3
#slide(title: [ESDM Goals], scale: 0.5, width: 714pt, items: (
  [Full *user space* implementation], (
    [No kernel changes needed – only if the scheduler / interrupt ES of the kernel module is requested],
    [eBPF-based scheduler / interrupt ES on a stock kernel],
    [Independent of political games of developers],
  ),
  [API and ABI compliant *drop-in replacement* of Linux /dev/random, /dev/urandom and getrandom(2)],
  [Minimal dependencies on environment: Protobuf-c, json-c, FUSE / CUSE support],
  [Runs unprivileged – privileges dropped after initialization],
  [Sole use of cryptography for data processing],
  [Flexible configuration supporting wide range of use cases],
  [Standards compliance: *SP800-90A/B/C*, *AIS 20/31* 3.0 (NTG.1, DRG.3, DRG.4), FIPS IG 7.19 / D.K (use of DRBG as conditioner)],
))

// ---------------------------------------------------------------- slide 4
#slide(title: [ESDM Design], scale: 0.62, width: 714pt, items: (
  [12 Entropy Sources], (
    [8 external],
    [4 internal: interrupt / scheduler timing – kernel module or eBPF],
    [All ES treated equally],
    [No domination by any ES – seeding triggered by initialization process or DRNG],
    [At most one of the timing ES credited with entropy],
  ),
  [All ES but the auxiliary pool can be selectively disabled at compile time],
  [ES data fed into DRNG – ES credited with no entropy as additional input],
  [DRNG accessible with APIs],
))

// ---------------------------------------------------------------- slide 5
#slide(title: [ESDM Big Picture], extra: fig(figdir + "big-picture.svg",
  body-x, body-top - 4pt, body-right - body-x, content-bottom - body-top + 4pt))

// ---------------------------------------------------------------- slide 6
#slide(title: [ESDM Components], scale: 0.5, width: 270pt, items: (
  [*ESDM Server*], (
    [Using ESDM library],
    [Offering RPC Interface],
    [Protobuf-C RPC],
    [Sensitive operations require privilege],
    [Optional EGD interface],
  ),
  [ESDM RPC library], (
    [API for other clients],
  ),
  [EGD client library],
  [libesdm_es_ext: external ES providers],
), extra: fig(figdir + "deck-components.svg", right-col(270pt), body-top,
  right-width(270pt), content-bottom - body-top))

// ---------------------------------------------------------------- slide 7
#slide(title: [ESDM Frontends], scale: 0.5, width: 714pt, items: (
  [/dev/random CUSE, /dev/urandom CUSE], (
    [Fall back to the kernel device while the ESDM is not reachable],
  ),
  [/proc/sys/kernel/random FUSE],
  [libesdm-getrandom.so: getrandom(2) and getentropy(3)],
  [Kernel module *esdm_cdev*: /dev/esdm_random, /dev/esdm_urandom, /proc/esdm – served over the EGD socket],
  [*OpenSSL 3* providers], (
    [RNG, RNG with prediction resistance, SEED-SRC – over RPC],
    [EGD, EGD with prediction resistance – over the EGD sockets],
  ),
  [esdm-kernel-seeder: reseeds the kernel RNG periodically],
  [esdm-tool: status (text / JSON), self test, wait until fully seeded],
  [Auxiliary client library: wait until the ESDM needs entropy],
))

// ---------------------------------------------------------------- slide 8
// The commands of the EGD interface (service-egd/esdm_egd_protocol.h)
#let egd-table = {
  set text(size: 11pt, top-edge: "cap-height", bottom-edge: "baseline")
  set par(leading: 0.5em)
  table(
    columns: (76pt, 1fr),
    inset: (x: 7pt, y: 6.5pt),
    align: left + horizon,
    table.header([*Command*], [*Served*]),
    [0x00 – 0x04], [EGD: entropy count, reads, write, PID],
    [0xe0, 0xe1], [Read from the prediction resistance DRNG],
    [0xe2], [Read with the semantics of /dev/urandom],
    [0xe3 – 0xe5], [State, status as text, status as JSON],
    [0xe6 – 0xea], [Entropy count, clear pool, reseed, thresholds – privileged peer only],
    [0xeb, 0xec], [Bulk read and insert of up to 64 KiB],
  )
}
#slide(title: [EGD Interface], scale: 0.5, width: 340pt, items: (
  [*Entropy Gathering Daemon* protocol on a Unix domain socket – opt-in],
  [Serves legacy consumers: libgcrypt rndegd, OpenSSL RAND_egd()],
  [Second socket serving the *prediction resistance* DRNG], (
    [EGD cannot ask for it per request – a property of the socket],
  ),
  [ESDM commands for what EGD cannot express],
  [Entropy claims and pool operations: privileged peer only],
  [Clients: libesdm_egd_client, OpenSSL EGD providers, esdm_cdev],
), extra: place(top + left, dx: right-col(340pt), dy: body-top,
  block(width: right-width(340pt), egd-table)))

// ---------------------------------------------------------------- slide 9
#slide(title: [DRNG Output APIs], scale: 0.62, width: 714pt, items: (
  [Blocking APIs – deliver data only after fully initialized and fully seeded], (
    [When Linux compliant interfaces enabled: /dev/random, getrandom() system call],
    [/dev/esdm_random of the kernel module esdm_cdev],
    [ESDM RPC client API, EGD blocking read],
  ),
  [Get seed: getrandom(2) with flag GRND_SEED to obtain data from entropy sources directly],
  [All other APIs deliver data without waiting for all DRNGs to be fully seeded], (
    [No data before the ESDM is operational – its initial DRNG fully seeded],
    [/dev/urandom, /dev/esdm_urandom, getrandom(2) with GRND_INSECURE],
  ),
))

// ---------------------------------------------------------------- slide 10
#slide(title: [Prediction Resistance API], scale: 0.6, width: 714pt, items: (
  [Prediction Resistance API – deliver data only after fully initialized and successful reseed returning at most data equal to the amount of entropy], (
    [ESDM RPC client API],
    [Using /dev/random, /dev/urandom or the devices of esdm_cdev with O_SYNC],
    [Using getrandom(2) with flag GRND_RANDOM],
    [EGD: prediction resistance socket, ESDM commands 0xe0 / 0xe1],
  ),
  [Separate DRNG instance seeded with fresh entropy before every chunk of output],
  [Compliant with:], (
    [FIPS IG 7.19 / D.K to use DRBG as conditioning component for seeding other DRBGs],
    [SP800-90C RBG3(RS) when the entropy sources are oversampled],
    [German AIS 20/31 (2011) NTG.1 requirements],
  ),
))

// ---------------------------------------------------------------- slide 11
#slide(title: [DRNG Seeding], scale: 0.6, width: 714pt, items: (
  [Temporary seed buffer: concatenation of output from all ES],
  [Seeding during initialization: when 256 bits of entropy are available],
  [Seeding at runtime], (
    [After 2#super[20] generate requests or 10 minutes],
    [After forced reseed by user space],
    [At least 256 bits of total entropy must be available],
    [256 bits of entropy requested from each ES – ES may deliver less],
    [DRNG returns to not fully seeded when last seed with full entropy was > 2#super[30] generate operations ago],
  ),
  [Entropy sources fetched in parallel, one thread per source],
))

// ---------------------------------------------------------------- slide 12
#slide(title: [DRNG Seeding at Start-up], scale: 0.56, width: 714pt, items: (
  [Initial DRNG seeded first – the ESDM is operational once it is fully seeded],
  [Every ES fetched by a thread of its own (fj\_003, ...), unavailable ones deliver nothing],
), extra: window(body-x, 216pt, body-right - body-x, 184pt, seed-log-top,
  size: 6.2pt, pitch: 12pt, rules: log-rules,
  title: "esdm-server -f -vvvvv"))

// ---------------------------------------------------------------- slide 13
#slide(title: [Reseed Worker], scale: 0.56, width: 714pt, items: (
  [Asynchronous worker reseeds every DRNG whose interval elapsed – requested or not],
  [Brings up the DRNG instances that are not at the fully seeded level],
  [A reseed collects entropy without holding the DRNG – it keeps serving],
  [Seed times of the node DRNGs spread by a random offset of up to 10 % of the interval],
), extra: window(body-x, 282pt, body-right - body-x, 126pt, seed-log-bottom,
  size: 6.2pt, pitch: 10.6pt, rules: log-rules,
  title: "esdm-server -f -vvvvv"))

// ---------------------------------------------------------------- slide 14
#slide(title: [Initial Seeding Strategy I \ Default Operation], scale: 0.7,
  width: 714pt, items: (
  [DRNG is fully seeded with 256 bits of entropy],
  [Blocking interfaces released after DRNG is fully seeded], (
    [Emergency seeding: entropy pulled repeatedly until the fully seeded level is reached],
  ),
  [Default applied], (
    [No specific seeding strategy compiled],
  ),
))

// ---------------------------------------------------------------- slide 15
#slide(title: [Initial Seeding Strategy II \ Entropy Source Oversampling],
  scale: 0.5, width: 360pt, items: (
  [Fully seeded step changed],
  [Compile time option], (
    [sp80090c, fips140 or ais2031_drg3],
    [Applied whenever compiled in],
  ),
  [Initial conditioning: s + 64 bit],
  [Initial DRNG seeding: every entropy source requested for s + 128 bits], (
    [Every ES alone could provide all required entropy],
  ),
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all processing steps],
  [Can be used in parallel with seeding strategy III],
), extra: meson-view(right-col(360pt), win-y, right-width(360pt), 106pt,
  meson-sp80090c, size: 6.6pt))

// ---------------------------------------------------------------- slide 16
#slide(title: [SP800-90C Compliance], scale: 0.62, width: 714pt, items: (
  [SP800-90A DRBG with 256-bit strength / SHA-512 vetted conditioning component],
  [Complies with RBG2(NP) per default],
  [Prediction resistance DRNG provides RBG3(RS)],
  [ES credited with no entropy: additional input of the DRBG, never seed (section 2.6)],
  [Reseeding limits: no request after 2#super[17] output bits without full reseed],
  [Option fips140: in addition the FIPS 140 integrity test and FIPS mode detection],
))

// ---------------------------------------------------------------- slide 17
#slide(title: [Initial Seeding Strategy III \ Two Entropy Sources],
  scale: 0.5, width: 376pt, items: (
  [Fully seeded step changed],
  [Compile time option], (
    [Function only enabled with compile option “ais2031_ntg1”],
  ),
  [Initial DRNG seeding: two entropy sources must deliver 240 bits of entropy each], (
    [Or a Jitter RNG in its own NTG.1 mode alone (es_jent_ntg1)],
  ),
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all processing steps],
  [Can be used in parallel with seeding strategy II],
), extra: meson-view(right-col(376pt), win-y, right-width(376pt), 192pt,
  meson-ntg1, size: 6.6pt))

// ---------------------------------------------------------------- slide 18
#slide(title: [German AIS 20/31 3.0 (2024)], scale: 0.5, width: 360pt,
  items: (
  [*NTG.1*: two entropy sources reach at least 240 bits each – ais2031_ntg1],
  [*DRG.3*: option ais2031_drg3], (
    [Entropy source oversampling of SP800-90C],
    [Without the request size based reseeding limits],
  ),
  [*DRG.4*: option ais2031_drg4], (
    [No request after 2#super[17] output bits without successful reseed],
    [Reseed after three quarters of that at the latest],
  ),
  [DRG.3 and DRG.4 mutually exclusive],
  [Status reports the classes satisfied],
), extra: meson-view(right-col(360pt), win-y, right-width(360pt), 180pt,
  meson-drg4, size: 6.6pt))

// ---------------------------------------------------------------- slide 19
#slide(title: [DRNG Management], scale: 0.5, width: 360pt, items: (
  [One DRNG per CPU up to maximum of 64],
  [Each DRNG initializes from entropy sources],
  [Sequential initialization of DRNG – first is the initial DRNG (node 0)],
  [If one DRNG node is not yet fully seeded → use of another node or DRNG(Node 0)],
  [Each DRNG instance managed independently],
  [Each RPC worker served by a DRNG instance of its own],
  [Separate DRNG for prediction resistance],
  [Maximum node number is compile time option – #cmd("esdm-server --small_memory"): one],
), extra: {
  fig(figdir + "numa-drng.svg", right-col(360pt), body-top,
    right-width(360pt), 92pt)
  meson-view(right-col(360pt), body-top + 92pt + 14pt + window-bar,
    right-width(360pt), content-bottom - body-top - 92pt - 14pt - window-bar,
    meson-threads, size: 6.6pt)
})

// ---------------------------------------------------------------- slide 20
#slide(title: [Data Processing Primitives], scale: 0.52, width: 714pt,
  items: (
  [Sole use of cryptographic mechanisms for data compression],
  [Cryptographic primitives compile-time switchable], (
    [DRNG, Conditioning hash, SHAKE256 of the entropy pools],
    [Built-in: SP800-90A Hash DRBG SHA2-512 / SHA2-512],
  ),
  [Complete built-in cryptographic primitive testing available], (
    [Full ACVP test harness available: #link("https://github.com/smuellerDD/acvpparser")[https://github.com/smuellerDD/acvpparser]],
    [ChaCha20 DRNG userspace implementation: #link("https://github.com/smuellerDD/leancrypto")[https://github.com/smuellerDD/leancrypto]],
  ),
  [Other data processing primitives], (
    [Concatenation of data],
    [Truncation of message digest to heuristic entropy value],
  ),
  [Entropy behavior of all data processing primitives based on fully understood and uncontended operations],
))

// ---------------------------------------------------------------- slide 21
#slide(title: [Cryptographic Backends], scale: 0.5, width: 360pt, items: (
  [Built-in: Hash DRBG or ChaCha20 DRNG, SHA2-512 or SHA3-512, SHAKE256],
  [Available Crypto-providers], (
    [leancrypto ≥ 1.6.0: XDRBG-256],
    [OpenSSL ≥ 3.0: Hash, CTR or HMAC DRBG],
    [Botan ≥ 3.2: HMAC DRBG or ChaCha20 – with Botan ≥ 3.14 fast key erasure (DRG.3)],
    [GnuTLS ≥ 3.6.7: CTR DRBG with derivation function],
  ),
  [One backend per build, all of them tested in CI],
), extra: meson-view(right-col(360pt), win-y, right-width(360pt), 112pt,
  meson-backend, size: 6.6pt))

// ---------------------------------------------------------------- slide 22
#slide(title: [External Entropy Sources], scale: 0.56, x: body-x,
  width: 714pt, items: (
  [Use without additional conditioning – fast source], (
    [Jitter RNG, kernel Jitter RNG],
    [Kernel RNG],
    [CPU (e.g. Intel RDSEED, POWER DARN, RISC-V CSRRW, IBM Z PRNO, ARM RNDRRS)],
    [Linux /dev/hwrng, TPM 2.0 – credited with no entropy by default],
    [Data collected when ESDM requests it – nothing buffered ahead],
  ),
  [Additional conditioning – slow source: the auxiliary pool],
  [External ES providers: their own processes on a Unix domain socket],
  [Every entropy source has individual entropy estimate], (
    [Taken at face value – each ES requires its own entropy assessment],
  ),
))

// ---------------------------------------------------------------- slide 23
#slide(title: [Auxiliary Pool], scale: 0.5, width: 380pt, items: (
  [Additional conditioning – slow source], (
    [RNGDs],
    [Arbitrary writers to /dev/random],
    [Data “trickles in” over time],
  ),
  [All received data added to “auxiliary pool“ – an *XDRBG-256*], (
    [XDRBG over SHAKE256 with a 512-bit state],
    [Insert: seed of the next reseed],
    [Extract: reseed and generate – the output never reveals the state],
  ),
  [Pools told apart by the XDRBG additional input α],
  [Also the conditioning pool of the eBPF ES],
), extra: fig(figdir + "deck-xdrbg-pool.svg", right-col(380pt), body-top,
  right-width(380pt), content-bottom - body-top))

// ---------------------------------------------------------------- slide 24
#let es-ext-code = (
  "static const struct esdm_es_ext_plugin my_source = {",
  "\t.version = ESDM_ES_EXT_PLUGIN_VERSION,",
  "\t.name = \"my-noise-source\",",
  "\t.get_entropy = my_get_entropy,",
  "};",
  "",
  "int main(int argc, char *argv[])",
  "{",
  "\treturn esdm_es_ext_provider_main(&my_source, argc, argv);",
  "}",
)
#slide(title: [External ES Providers], scale: 0.5, width: 380pt, items: (
  [Noise source outside the ESDM served by a *provider*: a process of its own on a Unix domain socket],
  [Read by the ExternalSocket ES (#cmd("esdm-server --es_ext"))],
  [Provider programs developed against libesdm_es_ext], (
    [Callbacks: entropy, self test, status, entropy rate],
    [No code of a source runs in the ESDM],
  ),
  [Credited with what the provider claims – capped by its declared or the configured rate],
  [Shipped: esdm-es-pkcs11 (PKCS\#11 token), esdm-es-pcsc (smart card)],
), extra: window(right-col(380pt), win-y, right-width(380pt), 104pt,
  es-ext-code, size: 6.4pt, rules: (
    (regex("\b(static|const|struct|int|char|return)\b"),
      it => text(fill: code.keyword, it)),
    (regex("\"[^\"]*\""), it => text(fill: code.string, it)),
  ), title: "es-ext/esdm_es_ext.h"))

// ---------------------------------------------------------------- slide 25
#slide(title: [Jitter RNG Entropy Source], scale: 0.5, width: 380pt,
  items: (
  [SP800-90B entropy source of the Jitter RNG library],
  [Collectors working side by side, each behind a lock of its own], (
    [Default: 4 in a build reseeding often, 1 otherwise],
    [SP800-90C build, ten CPUs: 35000 → 90000 requests of 32 bytes per second with four],
  ),
  [NTG.1 mode (es_jent_ntg1, jitterentropy ≥ 3.7.0): NTG.1 conformant on its own],
  [jitterentropy ≥ 3.8.0: known-answer tests of its conditioning per collector],
  [Kernel Jitter RNG: kernel crypto API RNG over AF_ALG, name configurable],
), extra: meson-view(right-col(380pt), win-y, right-width(380pt), 92pt,
  meson-jent-instances, size: 6.6pt))

// ---------------------------------------------------------------- slide 26
#slide(title: [Hardware Entropy Sources], scale: 0.5, width: 380pt, items: (
  [*TPM 2.0*: TPM2_GetRandom on the resource manager /dev/tpmrm0], (
    [Optional TPM2_StirRandom before reading (es_tpm2_stir)],
  ),
  [Linux /dev/hwrng: hardware RNG framework of the kernel],
  [Both credited with no entropy by default – skipped while another seeding uses them],
  [Read by a thread of their own with a deadline of 2 s],
  [CPU: RDSEED, POWER DARN, RISC-V seed CSR, IBM Z PRNO, ARM RNDRRS],
), extra: meson-view(right-col(380pt), win-y, right-width(380pt), 116pt,
  meson-tpm2, size: 6.6pt))

// ---------------------------------------------------------------- slide 27
#slide(title: [Internal ES: \ Interrupts], scale: 0.6, width: 714pt, items: (
  [Interrupt timing], (
    [All interrupts are treated as one entropy source],
  ),
  [Data collection executed in IRQ context],
  [Collection: time stamp into a per-CPU ring – a couple of cycles],
  [Conditioning: DRBG of the ES seeded with the events when entropy is requested],
  [Kernel RNG lost access to its primary IRQ ES#sym.arrow esdm-kernel-seeder reseeds kernel RNG periodically],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree: kernel/esdm_es],
  ),
  [Alternative without kernel patch: eBPF-based interrupt ES],
))

// ---------------------------------------------------------------- slide 28
#slide(title: [Internal ES: IRQ \ Data Processing], scale: 0.5, width: 290pt,
  items: (
  [64-bit time stamp divided by GCD added to per-CPU ring], (
    [Entropy estimate: by default 1 bit per 3 events],
    [Health test in FIPS mode],
  ),
  [When ring full #sym.arrow new events dropped],
  [When entropy is required #sym.arrow events of all rings seed the DRBG of the ES], (
    [XDRBG-256 over the SHAKE256 of the kernel, HMAC DRBG without its SHA-3 library],
    [Addition of all per-CPU entropy estimates],
  ),
), extra: fig(figdir + "irq-processing.svg", right-col(290pt), body-top,
  right-width(290pt), content-bottom - body-top))

// ---------------------------------------------------------------- slide 29
#slide(title: [Internal ES: \ Scheduler Events], scale: 0.6, width: 714pt,
  items: (
  [Scheduler-based task wakeup timing], (
    [All task wakeups are treated as one entropy source],
  ),
  [Data collection executed in scheduler context], (
    [Collection: adding the time stamp into a per-CPU ring #sym.arrow high-performance (couple of cycles)],
  ),
  [Data compression executed in process context during reseeding of DRNG],
  [Data compression is the seeding of the DRBG of the ES],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree: kernel/esdm_es],
  ),
  [Alternative without kernel patch: eBPF-based scheduler ES],
))

// ---------------------------------------------------------------- slide 30
#slide(title: [Internal ES: Scheduler \ Data Processing], scale: 0.5,
  width: 290pt, items: (
  [64-bit time stamp divided by GCD added to per-CPU ring], (
    [Entropy estimate],
    [Health test in FIPS mode],
  ),
  [When ring full #sym.arrow new events dropped],
  [When entropy is required #sym.arrow events of all rings seed the DRBG of the ES], (
    [Addition of all per-CPU entropy estimates],
  ),
  [Scheduler ES credited with nothing by default],
), extra: fig(figdir + "sched-processing.svg", right-col(290pt), body-top,
  right-width(290pt), content-bottom - body-top))

// ---------------------------------------------------------------- slide 31
#slide(title: [Internal ES: eBPF], scale: 0.6, width: 714pt, items: (
  [eBPF programs on the *sched_switch* and *irq_handler_entry* tracepoints], (
    [Stock kernel with BTF, libbpf ≥ 1.2 – no kernel patch],
    [Loaded during the privileged initialization of the esdm-server],
  ),
  [SP800-90B health tests inside the eBPF program in FIPS or NTG.1 mode], (
    [Stuck test, RCT, APT, startup test],
  ),
  [Credited with no entropy by default – measure first (es_ebpf_testing)],
  [Collected samples wiped when the sources are unloaded],
))

// ---------------------------------------------------------------- slide 32
#slide(title: [Internal ES: eBPF \ Data Processing], scale: 0.56, width: 714pt,
  items: (
  [Time between successive events of a CPU collected in per-CPU batches],
  [Handed to a BPF ring buffer when full or after an idle deadline],
  [Conditioning: an XDRBG-256 pool per source in the esdm-server],
), extra: fig(figdir + "ebpf-processing.svg", body-x, 206pt,
  body-right - body-x, content-bottom - 206pt))

// ---------------------------------------------------------------- slide 33
// The entropy table of the assessment of the interrupt ES (appendix "SP800-90B
// Entropy Measurements" of the ESDM documentation)
#let entropy-table = {
  set text(size: 7.6pt, top-edge: "cap-height", bottom-edge: "baseline")
  set par(leading: 0.4em)
  table(
    columns: (1fr, 66pt, 44pt),
    align: (left + horizon, center + horizon, center + horizon),
    inset: (x: 5pt, y: 3.6pt),
    table.header([*Test System*], [*Entropy of \ 1,000,000 Traces*],
      [*Sufficient Entropy*]),
    [ARMv7 rev 5], [1.9344], [Y],
    [ARMv7 rev 5 (Freescale i.MX53)], [7.07088], [Y],
    [ARMv7 rev 5 (Freescale i.MX6 Ultralite)], [6.638399], [Y],
    [ARM 64 bit AppliedMicro X-Gene Mustang Board], [5.599128], [Y],
    [Intel Atom Z530 – using GUI], [3.38584], [Y],
    [Intel i7 7500U Skylake - 64-bit KVM environment], [3.452064], [Y],
    [Intel i7 8565U Whiskey Lake – 64-bit KVM environment], [7.400136], [Y],
    [Intel i7 8565U Whiskey Lake – 32-bit KVM environment], [7.405704], [Y],
    [Intel i7 8565U Whiskey Lake], [6.871], [Y],
    [Intel Xeon Gold 6234], [4.434168], [Y],
    [IBM POWER 8 LE 8286-42A], [6.830712], [Y],
    [IBM POWER 7 BE 8202-E4C], [4.233912], [Y],
    [IBM System Z z13 (machine 2964)], [4.366368], [Y],
    [IBM System Z z15 (machine 8561)], [5.691832], [Y],
    [MIPS Atheros AR7241 rev 1], [7.157064], [Y],
    [MIPS Lantiq 34Kc V5.6], [7.032740], [Y],
    [Qualcomm IPQ4019 ARMv7], [6.638405], [Y],
    [SiFive HiFive Unmatched RISC-V U74], [2.387470], [Y],
  )
}
#slide(title: [Internal ES Testing \ Interfaces], scale: 0.5, width: 380pt,
  items: (
  [Testing code is compile time option],
  [Access via DebugFS – not in lockdown mode],
  [Testing supports data collection at boot time and runtime:], (
    [Raw time stamp differences for Scheduler / IRQ ES],
    [Performance data for ESDM’s Scheduler / IRQ handler],
  ),
  [eBPF ES: raw collection with esdm-ebpf-collect],
  [Scheduler ES: Full SP800-90B assessment documentation yet pending],
  [IRQ ES: Full SP800-90B assessment available],
  [Raw entropy collection and analysis tools provided],
), extra: place(top + left, dx: right-col(380pt), dy: body-top - 2pt,
  block(width: right-width(380pt), entropy-table)))

// ---------------------------------------------------------------- slide 34
#slide(title: [Internal ES Health Test], scale: 0.62, width: 714pt, items: (
  [Health tests applied in FIPS mode],
  [SP800-90B startup test – no entropy delivered before it completed],
  [APT / RCT],
  [Time-Stamp Pattern detection: 1st/2nd/3rd discrete derivative of time ≠ 0],
  [Failure: collected events discarded, startup test again],
  [Cutoffs shared by the kernel module and the eBPF ES],
  [Provides SP800-90B compliance of internal ES],
))

// ---------------------------------------------------------------- slide 35
#let selftest-status = {
  let start = status-left.position(l => l.starts-with("Periodic self test"))
  status-left.slice(start)
}
#slide(title: [ESDM Self Tests], scale: 0.5, width: 400pt, items: (
  [Known-answer tests: hash, XDRBG-256, DRNG – each with two negative tests],
  [DRBG tests with CAVP records: instantiate, reseed and generate],
  [Self test of every entropy source],
  [At start-up, every 10 minutes and on request (#cmd("esdm-tool --selftest"))],
  [No random bits before the crypto self tests passed, nor after one failed],
  [A failing entropy source: logged, reported, no longer credited],
  [FIPS 140: integrity test of executable and library],
), extra: window(right-col(400pt), win-y, right-width(400pt), 92pt,
  selftest-status, size: 6.8pt, title: "esdm-tool --status"))

// ---------------------------------------------------------------- slide 36
#let json-excerpt = {
  let start = status-json.position(l => l.contains("\"drngs\""))
  status-json.slice(start, start + 29)
}
#slide(title: [ESDM Status], scale: 0.5, width: 380pt, items: (
  [Status of the ESDM and every ES as *JSON* – the text report rendered from it],
  [One section per DRNG instance: seeding state, reseed counters, seed generation],
  [Over RPC, EGD, CUSE and shared memory],
  [#cmd("esdm-tool --status"), #cmd("--status-json"), #cmd("--drng-status"), #cmd("--drng-status-json")],
  [A report that does not fit is reported (-EMSGSIZE), not truncated silently],
), extra: window(right-col(380pt), win-y, right-width(380pt),
  content-bottom - win-y, json-excerpt, size: 6.6pt, pitch: 9.6pt, rules: (
    (regex("\"[a-z_]+\":"), it => text(fill: code.keyword, it)),
  ), title: "esdm-tool --status-json"))

// ---------------------------------------------------------------- slide 37
#slide(title: [General Testing], scale: 0.5, width: 380pt, items: (
  [Automated regression test suite covering the different options of ESDM], (
    [Meson test harness – one suite per directory of tests],
  ),
  [Applied testing frameworks], (
    [ASAN: address, thread, undefined],
    [Fuzzing of the RPC, EGD and OpenSSL provider interfaces],
    [CodeQL static analysis, coverage builds],
  ),
  [Security tests typeset as a report of their run],
  [NixOS VM tests: eBPF ES, esdm_cdev, EGD with GnuPG and OpenSSH],
  [CI builds with all crypto backends],
), extra: window(right-col(380pt), win-y, right-width(380pt),
  content-bottom - win-y, meson-test-output, size: 6.2pt, pitch: 8.8pt,
  rules: (
    prompt-rule,
    (regex("\bOK\b"), it => text(fill: code.ok, weight: "bold", it)),
    (regex("\bSKIP\b"), it => text(fill: code.skip, weight: "bold", it)),
  ), title: "meson test"))

// ---------------------------------------------------------------- slide 38
#slide(title: [ESDM - Resources], scale: 0.6, width: 360pt, items: (
  [Code / Tests / Documentation: \ #link("https://github.com/smuellerDD/esdm")[https://github.com/smuellerDD/esdm]],
  [Testing conducted with], (
    [FIPS mode],
    [Without FIPS mode],
    [With SELinux enabled],
    [Without SELinux],
    [Production use],
  ),
), extra: window(right-col(360pt), win-y, right-width(360pt),
  content-bottom - win-y, status-left.slice(0, 33), size: 6pt, pitch: 8.1pt,
  title: "esdm-tool --status"))
