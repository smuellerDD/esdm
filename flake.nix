{
  description = "ESDM testing/development flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:

    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;

        kernelDebug = false;
        kernelFips = true;
        debugEsdm = false;
        startEsdm = false;
        startCompat = false;

        baseModule =
          {
            kernel,
            lib,
            config,
            pkgs,
            ...
          }:
          {
            boot.kernelPackages = kernel;

            boot.kernelModules = [
              "jitterentropy_rng"
              "esdm_es"
            ];
            boot.kernelParams = [
              "fips=1"
            ];
            boot.extraModulePackages = [ config.boot.kernelPackages.esdm_es.out ];

            users.motd = ''
               _____ ____  ____  __  __   _____ _____ ____ _____  __     ____  __
              | ____/ ___||  _ \|  \/  | |_   _| ____/ ___|_   _| \ \   / /  \/  |
              |  _| \___ \| | | | |\/| |   | | |  _| \___ \ | |    \ \ / /| |\/| |
              | |___ ___) | |_| | |  | |   | | | |___ ___) || |     \ V / | |  | |
              |_____|____/|____/|_|  |_|   |_| |_____|____/ |_|      \_/  |_|  |_|
            ''
            + lib.optionalString (startEsdm) ''

              ESDM is already started via systemd. Disable again if necessary.
            ''
            + lib.optionalString (startCompat) ''

              ESDM compat services already started via systemd. Disable again if necessary.
            ''
            + ''

            '';

            users.users.root.initialPassword = "root";
            services.getty.autologinUser = lib.mkForce "root";

            services.esdm = {
              enable = startEsdm;
              enableLinuxCompatServices = startCompat;
              package = self.packages.${system}.esdm;
            };

            environment.systemPackages = with pkgs; [
              htop
              mc
              tmux
              vim
              self.packages.${system}.esdm
              gdb
              sp800-90b-entropyassessment
            ];

            console.keyMap = "de";
          };

        mkLiveSystem =
          { kernel, esdm }:
          nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              baseModule
              (
                {
                  lib,
                  config,
                  ...
                }:
                {
                  imports = [
                    "${pkgs.path}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
                  ];
                  isoImage = {
                    isoName = "esdm-live.iso";
                    volumeID = "CUSTOM_LIVE";
                  };
                }
              )
            ];
          };

        addEsdmToKernel = lpself: lpsuper: {
          kernel = lpsuper.kernel.override {
            kernelPatches =
              lpself.callPackage ./addon/linux_esdm_es/kernelPatches.nix { inherit (lpsuper) kernel; }
              ++ lib.optionals kernelFips (
                lpself.callPackage ./addon/linux_esdm_es/fipsConfig.nix { inherit (lpsuper) kernel; }
              )
              ++ lib.optionals kernelDebug (lpself.callPackage ./addon/linux_esdm_es/debug.nix { });
          };
          esdm_es = lpself.callPackage ./addon/linux_esdm_es { };
        };

        linuxPackages_6_6 = pkgs.linuxPackages_6_6.extend addEsdmToKernel;
        linuxPackages_6_12 = pkgs.linuxPackages_6_12.extend addEsdmToKernel;
        linuxPackages_6_18 = pkgs.linuxPackages_6_18.extend addEsdmToKernel;
        linuxPackages_latest = pkgs.linuxPackages_latest.extend addEsdmToKernel;
      in
      {
        # nix fmt
        formatter = pkgs.nixfmt-tree;

        checks = {
          # nix run .#checks.x86_64-linux.live_6_18.driverInteractive
          live_6_18 =
            let
              kernel = linuxPackages_6_18;
            in
            pkgs.testers.nixosTest {
              name = "basic test with esdm-tool";

              nodes.machine =
                { ... }:
                {
                  imports = [
                    (
                      { ... }:
                      {
                        _module.args.kernel = kernel;
                      }
                    )
                    baseModule
                    (
                      { ... }:
                      {
                        boot.kernelParams = [
                          "kmemleak=on"
                          "page_owner=on"
                          "log_buf_len=32M"
                        ];

                        virtualisation = {
                          efi.OVMF = pkgs.OVMFFull.fd;
                          useEFIBoot = true;
                          tpm = {
                            enable = true;
                          };
                          memorySize = 2048;
                          cores = 10;
                          qemu.options = [
                            "-smbios type=1,uuid=2715dd9b-5684-4eeb-ae88-a62bb4232563"
                          ];
                        };
                      }
                    )
                  ];
                };

              testScript = "";
            };
        };

        packages = {
          jitterentropy = pkgs.jitterentropy.overrideAttrs (
            _: {
              version = "3.7.0";
              src = pkgs.fetchFromGitHub {
                owner = "smuellerDD";
                repo = "jitterentropy-library";
                rev = "3a8ef4b7ace53ad7dcbb1b30a0b5bf984f994fa2";
                hash = "sha256-z2PJiHfeHXvSOu9i8oZNvz+5Zv9J0V2CyWORr/Pe4WA=";
              };
              patches = [ ];
              cmakeFlags = [
                "-DINTERNAL_TIMER=OFF"
                "-DBUILD_SHARED_LIBS=ON"
              ];
            }
          );

          # this currently defaults to the botan crypto backend
          esdm =
            (pkgs.esdm.override {
              selinux = false;
              esSched = true;
              esSchedEntropyRate = 0;
              esCPU = true;
              esCPUEntropyRate = 0;
              esIRQ = true;
              esIRQEntropyRate = 0;
              esHwrand = true;
              esHwrandEntropyRate = 0;
              esKernel = false;
              ais2031 = false;
              # remove later, for testing with NTG.1 capable jitterentropy
              inherit (self.packages.${system}) jitterentropy;
            }).overrideAttrs
              (prev: {
                mesonFlags =
                  (builtins.filter (
                    x: (!lib.hasInfix "max_threads" x) && (!lib.hasInfix "term-on-signal" x)
                  ) prev.mesonFlags)
                  ++ lib.optionals debugEsdm [
                    "-Db_sanitize=address,undefined"
                    "-Dstrip=false"
                  ]
                  ++ [
                    "-Des_jent_osr=4"
                  ];
                mesonBuildType = if debugEsdm then "debug" else "release";
                doCheck = false;
                src = lib.cleanSource ./.;
                dontStrip = debugEsdm;
              });

          # 6.6 is the first version currently supported by ESDM
          esdm_es_6_6 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            inherit (linuxPackages_6_6) kernel;
          };
          # 6.12 is the next LTS kernel after 6.6
          esdm_es_6_12 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            inherit (linuxPackages_6_12) kernel;
          };
          # 6.18 is the next LTS kernel after 6.12
          esdm_es_6_18 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            inherit (linuxPackages_6_18) kernel;
          };
          # always allow testing with latest kernel
          esdm_es_latest = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            inherit (linuxPackages_latest) kernel;
          };
        };

        nixosConfigurations = {
          live_6_6 = mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            kernel = linuxPackages_6_6;
          };
          live_6_12 = mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            kernel = linuxPackages_6_12;
          };
          live_6_18 = mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            kernel = linuxPackages_6_12;
          };
          live_latest = mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            kernel = linuxPackages_latest;
          };
        };

        # nix develop
        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              botan3
              fuse3
              gnutls
              self.packages.${system}.jitterentropy
              libkcapi
              libselinux
              openssl
              protobufc
            ];
            nativeBuildInputs = with pkgs; [
              pkg-config
              meson
              ninja
              cmake
            ];
          };
        };

        # shortcut for development
        liveIso = self.nixosConfigurations.${system}.live_6_18.config.system.build.isoImage;
      }
    );
}
