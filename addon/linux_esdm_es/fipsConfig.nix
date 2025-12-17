{
  lib,
  kernel,
  ...
}:

let
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
        CRYPTO_DRBG = lib.mkForce yes;
        DEBUG_KERNEL = yes;
        MODULE_SIG = lib.mkForce yes;
        MODULE_SIG_ALL = yes;
      }
      // selfestConfig;
  }
]
