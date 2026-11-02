{
  lib,
  kernel,
  ...
}:

[
  {
    name = "extra_config_drbg";
    patch = null;
    structuredExtraConfig =
      with lib.kernel;
      # Up to 7.1 esdm_es uses the HMAC_DRBG of the kernel crypto API. From
      # 7.2 on it uses the ESDM's XDRBG-256 over the SHAKE256 of the kernel's
      # SHA-3 library, which CRYPTO_SHA3 selects.
      if lib.versionOlder kernel.version "7.2" then
        {
          CRYPTO_DRBG_MENU = yes;
          CRYPTO_DRBG_HMAC = yes;
        }
      else
        {
          CRYPTO_SHA3 = yes;
        };
  }
]
