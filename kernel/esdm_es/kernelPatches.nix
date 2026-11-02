{
  lib,
  kernel,
  ...
}:

let
  # The hook patches only differ in their context: 6.6 added the
  # sched/isolation.h include random.c's hunk uses, 6.12 reworded the
  # kernel/sched/core.c header, 6.18 reordered both and 7.3 dropped the ibmasm
  # entry of drivers/misc/Makefile. A 7.3-rc version compares newer than
  # "7.3", so linux_testing gets the 7.3 series too.
  hooksVersion =
    if lib.versionOlder kernel.version "6.6" then
      "6.1"
    else if lib.versionOlder kernel.version "6.12" then
      "6.6"
    else if lib.versionOlder kernel.version "6.18" then
      "6.12"
    else if lib.versionOlder kernel.version "7.3" then
      "6.18"
    else
      "7.3";
in
[
  {
    name = "esdm_sched_es_hook";
    patch = ./. + "/0001-ESDM-scheduler-entropy-source-hooks_${hooksVersion}.patch";
  }
  {
    name = "esdm_inter_es_hook";
    patch = ./. + "/0002-ESDM-interrupt-entropy-source-hooks_${hooksVersion}.patch";
  }
]
# Since 7.2 the kernel DRBG is a private HMAC_DRBG without the internals this
# patch exported; esdm_es uses the XDRBG-256 of the ESDM over the kernel's
# SHAKE256 there (esdm_drbg_kcapi.c), as on every kernel with the SHA-3
# library.
# 6.12 and 6.18 differ only in the namespace of the exports, a string literal
# since 6.13.
++ lib.optional (lib.versionOlder kernel.version "7.2") {
  name = "esdm_drbg_visibility";
  patch =
    if lib.versionOlder kernel.version "6.12" then
      ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.6.patch
    else if lib.versionOlder kernel.version "6.13" then
      ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.12.patch
    else
      ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.18.patch;
}
