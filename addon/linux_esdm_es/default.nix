{
  lib,
  stdenv,
  kernel,
  kmod,
  esdm,
  callPackage,
  fipsMode ? false,
}:

let
  patchedKernel = kernel.override {
    kernelPatches =
      callPackage ./kernelPatches.nix { inherit kernel; }
      ++ (lib.optionals fipsMode (callPackage ./fipsConfig.nix { inherit kernel; }));
  };
in
stdenv.mkDerivation rec {
  pname = "esdm_es";

  version = "1.2.1";
  src = ./.;

  preBuild = ''
    sed -i '/depmod/d' Makefile
  '';

  nativeBuildInputs = [ kmod ] ++ patchedKernel.moduleBuildDependencies;

  makeFlags = [
    "KBUILD_OUTPUT=${patchedKernel.dev}/lib/modules/${patchedKernel.modDirVersion}/build"
    "KERNELRELEASE=${patchedKernel.modDirVersion}"
    "KERNEL_DIR=${patchedKernel.dev}/lib/modules/${patchedKernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    "BUILD_TESTING=1"
    "BUILD_ES_IRQ=1"
    "BUILD_ES_SCHED=1"
  ];
  installFlags = makeFlags;

  enableParallelBuilding = true;

  meta = with lib; {
    description = "A patchedKernel module for esdm entropy gathering";
    homepage = "http://www.chronox.de/esdm.html";
    license = [
      licenses.gpl2Only
      licenses.bsd2
    ];
    maintainers = with maintainers; [ thillux ];
    platforms = platforms.linux;
    broken = versionOlder kernel.version "6.6";
  };
}
