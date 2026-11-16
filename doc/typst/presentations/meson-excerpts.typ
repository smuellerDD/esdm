// Verbatim excerpts of meson_options.txt of ESDM 1.2.4 for the editor
// windows of the slides (Typst cannot read files outside doc/typst).
// Each is a line range of the file; regenerate them, do not edit.

// sp80090c: entropy source oversampling, meson_options.txt lines 624-634
#let meson-sp80090c = (
  "# Option for: ESDM_OVERSAMPLE_ENTROPY_SOURCES",
  "option('sp80090c', type: 'boolean', value: false,",
  "       description:'''SP800-90C compliance",
  "",
  "If enabled, the ESDM oversamples the entropy sources compliant to SP800-90C.",
  "",
  "The following oversampling is applied:",
  "* Seed the DRNG with 128 more bits of entropy from the conditioning component.",
  "* Inject 64 more bits of entropy from the noise source into the conditioning",
  "  component.",
  "''')",
)

// ais2031_ntg1: the NTG.1 seeding strategy, meson_options.txt lines 636-656
#let meson-ntg1 = (
  "# Option for: ESDM_AIS2031_NTG1_SEEDING_STRATEGY",
  "option('ais2031_ntg1', type: 'boolean', value: false,",
  "       description:'''German AIS 20/31 3.0 (2024) NTG.1 seeding strategy.",
  "",
  "When enabling this option, two entropy sources must",
  "deliver 240 bits of entropy each to consider a DRNG",
  "as fully seeded. Any two entropy sources can be used",
  "to fulfill this requirement. If specific entropy sources",
  "shall not be capable of contributing to this seeding",
  "strategy, the respective entropy source must be configured",
  "to provide less than 240 bits of entropy.",
  "",
  "The strategy is consistent with the requirements for",
  "NTG.1 compliance in German AIS 20/31 3.0 from 2024.",
  "",
  "The requirement of two entropy sources does not apply",
  "when the jitter RNG is operated in its own NTG.1 mode",
  "(option 'es_jent_ntg1' together with jitterentropy 3.7.0",
  "or later). Such a jitter RNG is NTG.1 conformant on its",
  "own and therefore seeds a DRNG without a second entropy",
  "source; 240 bits of entropy from it are then sufficient.",
)

// ais2031_drg4: the DRG.4 reseeding limits, meson_options.txt lines 683-701
#let meson-drg4 = (
  "option('ais2031_drg4', type: 'boolean', value: false,",
  "       description:'''German AIS 20/31 3.0 (2024) DRG.4 reseeding limits.",
  "",
  "When enabling this option, the request size based reseeding",
  "limits are capped to the values required by DRG.4.10 of",
  "German AIS 20/31 3.0 from 2024: a DRNG instance starts no",
  "request after 2**17 output bits without a successful reseed",
  "- one started before is completed, in generate operations",
  "of 2**19 bits at most - and tries to reseed after three",
  "quarters of that at the latest.",
  "",
  "Smaller values configured through 'drng_reseed_threshold_bits'",
  "and 'drng_max_reseed_bits' are kept as they are.",
  "",
  "The NTG.1 seeding strategy of the same standard is configured",
  "independently with the option 'ais2031_ntg1'.",
  "",
  "Mutually exclusive with 'ais2031_drg3'.",
  "''')",
)

// threading_max_worker_threads: the maximum number of DRNGs, meson_options.txt lines 703-720
#let meson-threads = (
  "# Option for: THREADING_MAX_WORKER_THREADS",
  "option('threading_max_worker_threads', type: 'integer', min: 1, value: 64,",
  "       description:'''Maximum number of concurrent worker threads supported.",
  "",
  "This value can be set to any arbitrary number. Depending on the number",
  "of threads, the required numbers of thread contexts are statically allocated.",
  "",
  "The number of threads define:",
  "",
  "* the number of concurrent DRNG instances that are maintained independent of",
  "  each other - this value is limited by the number of found CPUs as it makes no",
  "  sense to have more DRNG instances than CPUs that can execute them.",
  "",
  "There is no other value that needs changing if the number of threads",
  "shall be adjusted.",
  "",
  "The value must not be lower than 1.",
  "''')",
)

// crypto_backend: the cryptographic backend, meson_options.txt lines 813-824
#let meson-backend = (
  "option('crypto_backend', type: 'combo', value: 'builtin',",
  "       choices: ['builtin',",
  "\t\t 'leancrypto',",
  "\t\t 'openssl',",
  "\t\t 'botan',",
  "\t\t 'gnutls',",
  "\t\t],",
  "       description: '''Select the cryptographic backend",
  "",
  "The cryptographic backend provides the cryptographic primitives used by the",
  "ESDM for the conditioning operation as well as random number generation. Only",
  "one backend can be enabled.",
)

// es_tpm2_entropy_rate: the credit of the TPM 2.0 entropy source, meson_options.txt lines 474-486
#let meson-tpm2 = (
  "# Option for: ESDM_TPM2_ENTROPY_RATE",
  "option('es_tpm2_entropy_rate', type: 'integer', min: 0, max: 256, value: 0,",
  "       description:'''TPM 2.0 entropy source entropy rate.",
  "",
  "The option defines the amount of entropy the ESDM applies to 256",
  "bits of data obtained from the TPM 2.0 entropy source. The ESDM",
  "enforces the limit that this value must be in the range between 0 and 256.",
  "",
  "When configuring this value to 0, the default, the TPM 2.0 entropy source",
  "provides 256 bits of data without being credited to contain entropy. A",
  "seeding then skips the TPM while another uses it: it serves one command at a",
  "time, and waiting would serialize every seeding.",
  "''')",
)

// esdm-server-egd-pr-socket-path: the EGD socket of the prediction resistance DRNG, meson_options.txt lines 918-925
#let meson-egd-pr = (
  "option('esdm-server-egd-pr-socket-path', type: 'string', value: '/run/esdm-egd-pr.socket',",
  "       description: '''Path of the optional prediction resistance EGD socket",
  "",
  "       Counterpart of esdm-server-egd-socket-path serving the prediction",
  "       resistance generator. The EGD protocol cannot ask for prediction",
  "       resistance per request, so it is a property of the socket: everything",
  "       arriving here is answered from esdm_get_random_bytes_pr().",
  "       ''')",
)

// es_jent_instances: Jitter RNG collectors, meson_options.txt lines 77-86
#let meson-jent-instances = (
  "# Option for: ESDM_JENT_INSTANCES",
  "option('es_jent_instances', type: 'integer', min: 0, max: 64, value: 0,",
  "       description:'''Jitter RNG collectors working side by side",
  "",
  "Each collector serves DRNG seedings behind a lock of its own. Collecting",
  "dominates a seeding, so a build reseeding often (sp80090c, ais2031_drg4)",
  "scales with the CPUs for the collectors, at a collector's memory each. The",
  "default for esdm_config_es_jent_instances_set() and esdm-server",
  "--es_jent_instances; 0 picks 4 for a build reseeding often and 1 otherwise.",
  "''')",
)
