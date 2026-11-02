{
  lib,
  stdenv,
  kernel,
  kmod,
  python3,
  # Turn the warnings of the extra set into errors, for the builds that check
  # the module against every kernel rather than install it.
  werror ? false,
}:

stdenv.mkDerivation rec {
  pname = "esdm_cdev";

  # The release of the tree, parsed from meson.build like the esdm_es module
  # does, so the two cannot drift apart.
  version =
    let
      lines = lib.splitString "\n" (builtins.readFile ../../meson.build);
      matches = builtins.filter (m: m != null) (
        map (l: builtins.match "[[:space:]]*version: '([0-9.]+)',?[[:space:]]*" l) lines
      );
    in
    builtins.head (builtins.head matches);
  # The sources only, the EGD protocol of the ESDM included: a change of the
  # README or the VM test does not rebuild the module against every kernel.
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ./Makefile
      (lib.fileset.fileFilter (file: file.hasExt "c" || file.hasExt "h") ./.)
      ../../service-egd/esdm_egd_protocol.h
    ];
  };
  sourceRoot = "${src.name}/kernel/esdm_cdev";

  # python3 for the kernel-doc check of W=1, which newer kernels run in it
  nativeBuildInputs = [
    kmod
    python3
  ]
  ++ kernel.moduleBuildDependencies;

  makeFlags = [
    "KBUILD_OUTPUT=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "KERNELRELEASE=${kernel.modDirVersion}"
    "KERNEL_DIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    # Every warning of the extra set, which the module builds without
    "W=1"
  ]
  ++ lib.optional werror "KCFLAGS=-Werror";
  installFlags = makeFlags;

  enableParallelBuilding = true;

  meta = with lib; {
    description = "Character devices /dev/esdm_random, /dev/esdm_urandom and /proc/esdm served by the ESDM";
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
