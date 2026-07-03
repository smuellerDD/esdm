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
              { _module.args.kernel = kernel; }
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
              ++ lib.optionals kernelDebug (lpself.callPackage ./addon/linux_esdm_es/debug.nix { })
              ++ lpself.callPackage ./addon/linux_esdm_es/drbg.nix { };
          };
          esdm_es = lpself.callPackage ./addon/linux_esdm_es { };
        };

        # 6.6 is the first kernel version supported by ESDM.
        minKernel = {
          major = 6;
          minor = 6;
        };

        # All `linuxPackages_<major>_<minor>` sets nixpkgs currently exposes,
        # restricted to the versions ESDM supports (>= minKernel). Discovered
        # automatically so newly packaged kernels are picked up without editing
        # this file. Keyed by the suffix used for the generated outputs, e.g.
        # "6_6" -> live_6_6 / esdm_es_6_6. The rolling "latest" alias is added
        # on top for convenience.
        kernels =
          let
            versioned = builtins.listToAttrs (
              builtins.concatMap (
                name:
                let
                  m = builtins.match "linuxPackages_([0-9]+)_([0-9]+)" name;
                in
                if m == null then
                  [ ]
                else
                  let
                    major = lib.toInt (builtins.elemAt m 0);
                    minor = lib.toInt (builtins.elemAt m 1);
                    supported = major > minKernel.major || (major == minKernel.major && minor >= minKernel.minor);
                  in
                  lib.optional supported {
                    name = "${toString major}_${toString minor}";
                    value = pkgs.${name}.extend addEsdmToKernel;
                  }
              ) (builtins.attrNames pkgs)
            );
          in
          versioned // { latest = pkgs.linuxPackages_latest.extend addEsdmToKernel; };

        mkCheck =
          kernel:
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
                    { lib, pkgs, ... }:
                    {
                      # baseModule leaves the daemon disabled (startEsdm =
                      # false) for the interactive live images; the check must
                      # actually run it, otherwise there is nothing to test.
                      services.esdm.enable = lib.mkForce true;
                      services.esdm.enableLinuxCompatServices = lib.mkForce true;

                      # Make the startup-hang regression harness (and a Python
                      # to run it) available inside the VM so the check can
                      # execute it instead of letting it rot.
                      environment.systemPackages = [ pkgs.python3 ];
                      environment.etc."esdm-startup-loop.py".source =
                        ./tests/startup/esdm_startup_loop.py;

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

            testScript = ''
              machine.wait_for_unit("multi-user.target")

              # The kernel entropy-source module (irq/sched hooks) must load.
              machine.succeed("test -c /dev/esdm_es")

              # The daemon must come up and reach a fully-seeded DRNG. This is
              # the code path that the irq/sched deferred-logging deadlock fix
              # (commit c428c59) and the reinit locking work touch, so a
              # regression here should fail the check rather than pass silently.
              machine.wait_for_unit("esdm-server.service")
              machine.succeed("esdm-tool --wait-until-seeded 60")
              machine.succeed("esdm-tool --is-fully-seeded")
              machine.succeed("esdm-tool --status")

              # Draw random data over the RPC interface; 32 bytes are printed
              # hex-encoded, so expect at least 64 characters back.
              out = machine.succeed("esdm-tool --get-random 32").strip()
              assert len(out) >= 64, f"short random output: {out!r}"

              # Linux-compat frontends: /dev/random is served by the CUSE
              # daemon once the compat target is up.
              machine.wait_for_unit("esdm-linux-compat.target")
              machine.succeed("test \"$(head -c 32 /dev/random | wc -c)\" = 32")

              # A clean shutdown must not deadlock or leak (kmemleak is on).
              machine.succeed("systemctl stop esdm-server.service")

              # Now exercise the dedicated startup-hang regression harness
              # against the same binary. It repeatedly starts esdm-server in the
              # foreground, waits for the operational marker, fetches entropy
              # over RPC and checks for a clean SIGTERM shutdown - the exact
              # start/seed/teardown cycle the irq/sched deadlock fix touched.
              # The systemd instance is stopped above so the RPC sockets are
              # free for the harness to bind.
              server = machine.succeed("command -v esdm-server").strip()
              tool = machine.succeed("command -v esdm-tool").strip()
              machine.succeed(
                  f"python3 /etc/esdm-startup-loop.py --iterations 25 "
                  f"--binary {server} --tool {tool} --stop-on-failure"
              )
            '';
          };
      in
      {
        # nix fmt
        formatter = pkgs.nixfmt-tree;

        # One check per defined kernel version, e.g.:
        #   nix run .#checks.x86_64-linux.live_6_18.driverInteractive
        #   nix flake check
        checks = lib.mapAttrs' (name: kernel: lib.nameValuePair "live_${name}" (mkCheck kernel)) kernels;

        packages = {
          jitterentropy = pkgs.jitterentropy.overrideAttrs (_: {
            version = "3.7.0";
            src = pkgs.fetchFromGitHub {
              owner = "smuellerDD";
              repo = "jitterentropy-library";
              rev = "e783cf1c450bce4d72f95c9f9c84546a6094976a";
              hash = "sha256-sJWgPx3GbvnBBVlCML/eRtUoMXux38tpWi1ZKhz41xY=";
            };
            patches = [ ];
            cmakeFlags = [
              "-DINTERNAL_TIMER=OFF"
              "-DBUILD_SHARED_LIBS=ON"
            ];
          });

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
                buildInputs = prev.buildInputs ++ [ pkgs.libp11 ];
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
                # Keep the derivation version in sync with the local tree
                # (parsed from meson.build) instead of inheriting nixpkgs'
                # pinned version, which produced misleading esdm-1.2.3 store
                # paths and modinfo for a 1.2.4 checkout.
                version =
                  let
                    lines = lib.splitString "\n" (builtins.readFile ./meson.build);
                    matches = builtins.filter (m: m != null) (
                      map (l: builtins.match "[[:space:]]*version: '([0-9.]+)',?[[:space:]]*" l) lines
                    );
                  in
                  builtins.head (builtins.head matches);
                dontStrip = debugEsdm;
              });

          openssl-config =
            let
              esdm = self.packages.${system}.esdm;
            in
            pkgs.writeTextFile {
              name = "openssl.cnf";
              text = ''
                HOME                    = .
                RANDFILE                = $ENV::HOME/.rnd

                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect

                [provider_sect]
                esdm = esdm_sect
                default = default_sect

                [default_sect]
                activate = 1

                [esdm_sect]
                activate = 1
                module = ${esdm}/lib/libesdm-rng-provider.so
              '';
            };

          openssl-config-pr =
            let
              esdm = self.packages.${system}.esdm;
            in
            pkgs.writeTextFile {
              name = "openssl.cnf";
              text = ''
                HOME                    = .
                RANDFILE                = $ENV::HOME/.rnd

                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect

                [provider_sect]
                esdm = esdm_sect
                default = default_sect

                [default_sect]
                activate = 1

                [esdm_sect]
                activate = 1
                module = ${esdm}/lib/libesdm-rng-provider-pr.so
              '';
            };

        }
        # One out-of-tree esdm_es module build per defined kernel, e.g.
        # esdm_es_6_6 / esdm_es_latest.
        // lib.mapAttrs' (
          name: kernel:
          lib.nameValuePair "esdm_es_${name}" (
            pkgs.callPackage ./addon/linux_esdm_es {
              inherit (pkgs) lib;
              inherit (kernel) kernel;
            }
          )
        ) kernels;

        # One live system per defined kernel version, e.g. live_6_18.
        nixosConfigurations = lib.mapAttrs' (
          name: kernel:
          lib.nameValuePair "live_${name}" (mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            inherit kernel;
          })
        ) kernels;

        # nix develop
        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              libp11
              botan3
              fuse3
              gnutls
              libkcapi
              libselinux
              openssl
              protobufc
              self.packages.${system}.jitterentropy
            ];
            nativeBuildInputs = with pkgs; [
              cmake
              meson
              ninja
              pkg-config
            ];
          };
        };

        # shortcut for development
        liveIso = self.nixosConfigurations.${system}.live_6_18.config.system.build.isoImage;
      }
    );
}
