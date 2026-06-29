{
  lib,
  kernel,
  ...
}:

[
  {
    name = "extra_config_drbg";
    patch = null;
    structuredExtraConfig = with lib.kernel; {
      CRYPTO_DRBG_MENU = yes;
      CRYPTO_DRBG_HMAC = yes;
      CRYPTO_DRBG_HASH = yes;
      CRYPTO_DRBG_CTR = yes;
    };
  }
]
