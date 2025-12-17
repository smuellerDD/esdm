{
  lib,
  kernel,
  ...
}:

if (lib.versionOlder kernel.version "6.18") then
  [
    {
      name = "esdm_sched_es_hook";
      patch = ./0001-ESDM-scheduler-entropy-source-hooks_6.6.patch;
    }
    {
      name = "esdm_inter_es_hook";
      patch = ./0002-ESDM-interrupt-entropy-source-hooks_6.6.patch;
    }
    {
      name = "esdm_drbg_visibility";
      patch = ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.6.patch;
    }
  ]
else
  [
    {
      name = "esdm_sched_es_hook";
      patch = ./0001-ESDM-scheduler-entropy-source-hooks_6.18.patch;
    }
    {
      name = "esdm_inter_es_hook";
      patch = ./0002-ESDM-interrupt-entropy-source-hooks_6.18.patch;
    }
    {
      name = "esdm_drbg_visibility";
      patch = ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.18.patch;
    }
  ]
