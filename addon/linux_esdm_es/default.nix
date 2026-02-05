{
  lib,
  stdenv,
  kernel,
  kmod,
  esdm,
}:

stdenv.mkDerivation rec {
  pname = "esdm_es";

  version = "1.2.1";
  src = ./.;

  preBuild = ''
    sed -i '/depmod/d' Makefile
  '';

  nativeBuildInputs = [ kmod ] ++ kernel.moduleBuildDependencies;

  makeFlags = [
    "KBUILD_OUTPUT=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "KERNELRELEASE=${kernel.modDirVersion}"
    "KERNEL_DIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    "BUILD_TESTING=1"
    "BUILD_ES_IRQ=1"
    "BUILD_ES_SCHED=1"
  ];
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
    broken = versionOlder kernel.version "6.6";
  };
}
