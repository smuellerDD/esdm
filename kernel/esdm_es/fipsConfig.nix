{
  lib,
  kernel,
  ...
}:

let
  # From 7.2 on CRYPTO_FIPS depends on the kernel's own DRBG being built in.
  # esdm_es does not use that DRBG there (drbg.nix).
  drbgConfig = lib.optionalAttrs (!lib.versionOlder kernel.version "7.2") (
    with lib.kernel;
    {
      CRYPTO_DRBG = yes;
    }
  );

  selfestConfig =
    if (lib.versionOlder kernel.version "6.15") then
      with lib.kernel;
      {
        CRYPTO_MANAGER_DISABLE_TESTS = lib.mkForce no; # <= 6.15
      }
    else
      with lib.kernel;
      {
        CRYPTO_SELFTESTS = yes; # > 6.15
      };
in
[
  {
    name = "extra_config_fips_development";
    patch = null;
    structuredExtraConfig =
      with lib.kernel;
      {
        CRYPTO_FIPS = yes;
        DEBUG_KERNEL = yes;
        MODULE_SIG = lib.mkForce yes;
        MODULE_SIG_ALL = yes;
      }
      // selfestConfig
      // drbgConfig;
  }
]
