{
  lib,
  stdenv,
  kernel,
  kernelModuleMakeFlags,
  kmod,
  python3,
  esdm,
  # The debugfs raw entropy and performance interfaces (esdm_testing.c) are
  # for entropy assessments, nothing a regular system should carry.
  enableTesting ? false,
  # Turn the warnings of the extra set into errors, for the builds that check
  # the module against every kernel rather than install it.
  werror ? false,
}:

stdenv.mkDerivation rec {
  pname = "esdm_es";

  # The release of the tree, parsed from meson.build like the flake's esdm
  # package does, so the two cannot drift apart again.
  version =
    let
      lines = lib.splitString "\n" (builtins.readFile ../../meson.build);
      matches = builtins.filter (m: m != null) (
        map (l: builtins.match "[[:space:]]*version: '([0-9.]+)',?[[:space:]]*" l) lines
      );
    in
    builtins.head (builtins.head matches);
  # The sources of the module and those it shares with the ESDM
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ./Makefile
      (lib.fileset.fileFilter (file: file.hasExt "c" || file.hasExt "h") ./.)
      ../shared
      ../../esdm/drng/esdm_seed_sizes.h
      ../../esdm/crypto/esdm_xdrbg.c
      ../../esdm/crypto/esdm_xdrbg.h
      ../../esdm/crypto/esdm_xof.h
      ../../common/esdm_portable.h
      ../../common/selftest_kat.h
    ];
  };
  sourceRoot = "${src.name}/kernel/esdm_es";

  preBuild = ''
    sed -i '/depmod/d' Makefile
  '';

  # python3 for the kernel-doc check of W=1, which newer kernels run in it
  nativeBuildInputs = [
    kmod
    python3
  ]
  ++ kernel.moduleBuildDependencies;

  # Those of the kernel package set: its compiler, no depmod of this module
  # alone, and the signing that writes the .ko.cer NixOS merges for it
  makeFlags = kernelModuleMakeFlags ++ [
    "KERNELRELEASE=${kernel.modDirVersion}"
    "KERNEL_DIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    "BUILD_TESTING=${if enableTesting then "1" else "0"}"
    "BUILD_ES_IRQ=1"
    "BUILD_ES_SCHED=1"
    # Every warning of the extra set, which the module builds without
    "W=1"
  ]
  ++ lib.optional werror "KCFLAGS=-Werror";
  installFlags = makeFlags;

  enableParallelBuilding = true;

  meta = with lib; {
    description = "A kernel module for esdm entropy gathering";
    homepage = "http://www.chronox.de/esdm.html";
    license = [
      licenses.gpl2Only
      licenses.bsd2
    ];
    maintainers = with maintainers; [ thillux ];
    platforms = platforms.linux;
    broken = versionOlder kernel.version "6.1";
  };
}
