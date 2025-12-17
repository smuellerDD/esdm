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
            boot.kernelPatches =
              pkgs.callPackage ./addon/linux_esdm_es/kernelPatches.nix { inherit (kernel) kernel; }
              ++ pkgs.callPackage ./addon/linux_esdm_es/fipsConfig.nix { inherit (kernel) kernel; };
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

              ESDM is already started via systemd. Disable again if necessary.
            '';

            users.users.root.initialPassword = "root";
            services.getty.autologinUser = lib.mkForce "root";

            services.esdm = {
              enable = true;
              enableLinuxCompatServices = true;
              package = self.packages.${system}.esdm;
            };

            environment.systemPackages = with pkgs; [
              htop
              mc
              tmux
              vim
              self.packages.${system}.esdm
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

        linuxPackages_6_6 = pkgs.linuxPackages_6_6.extend (
          lpself: lpsuper: {
            esdm_es = lpself.callPackage ./addon/linux_esdm_es { fipsMode = true; };
          }
        );
        linuxPackages_6_12 = pkgs.linuxPackages_6_12.extend (
          lpself: lpsuper: {
            esdm_es = lpself.callPackage ./addon/linux_esdm_es { fipsMode = true; };
          }
        );
        linuxPackages_6_18 = pkgs.linuxPackages_6_18.extend (
          lpself: lpsuper: {
            esdm_es = lpself.callPackage ./addon/linux_esdm_es { fipsMode = true; };
          }
        );
        linuxPackages_latest = pkgs.linuxPackages_latest.extend (
          lpself: lpsuper: {
            esdm_es = lpself.callPackage ./addon/linux_esdm_es { fipsMode = true; };
          }
        );
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
                        virtualisation = {
                          efi.OVMF = pkgs.OVMFFull.fd;
                          useEFIBoot = true;
                          tpm = {
                            enable = true;
                          };
                          memorySize = 2048;
                          cores = 4;
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
          # this currently defaults to the botan crypto backend
          esdm =
            (pkgs.esdm.override {
              selinux = false;
              esSched = true;
              esSchedEntropyRate = 256;
              esCPU = true;
              esCPUEntropyRate = 0;
              esIRQ = true;
              esIRQEntropyRate = 0;
              esHwrand = true;
              esHwrandEntropyRate = 0;
              esKernel = false;
            }).overrideAttrs
              {
                src = lib.cleanSource ./.;
              };

          # 6.6 is the first version currently supported by ESDM
          esdm_es_6_6 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            kernel = pkgs.linux_6_6;
            fipsMode = true;
          };
          # 6.12 is the next LTS kernel after 6.6
          esdm_es_6_12 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            kernel = pkgs.linux_6_12;
            fipsMode = true;
          };
          # 6.18 is the next LTS kernel after 6.12
          esdm_es_6_18 = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            kernel = pkgs.linux_6_18;
            fipsMode = true;
          };
          # always allow testing with latest kernel
          esdm_es_latest = pkgs.callPackage ./addon/linux_esdm_es {
            inherit (pkgs) lib;
            kernel = pkgs.linux_latest;
            fipsMode = true;
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
              jitterentropy
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
        liveIso = self.nixosConfigurations.${system}.live_6_12.config.system.build.isoImage;
      }
    );
}
