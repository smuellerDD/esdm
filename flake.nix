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
        # Stock (unpatched) `linuxPackages_<major>_<minor>` sets nixpkgs
        # currently exposes, restricted to the versions ESDM supports
        # (>= minKernel). Keyed by the suffix used for the generated outputs.
        stockKernels =
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
                    value = pkgs.${name};
                  }
              ) (builtins.attrNames pkgs)
            );
          in
          versioned // { latest = pkgs.linuxPackages_latest; };

        # The same kernels with the esdm_es patches applied.
        kernels = lib.mapAttrs (name: lp: lp.extend addEsdmToKernel) stockKernels;

        # VM check of the eBPF entropy sources: the ESDM server (built with
        # es_sched_ebpf/es_irq_ebpf) must load the eBPF programs and report
        # both sources as available on every supported kernel. The check
        # deliberately runs on the stock (unpatched) kernel - not requiring
        # kernel patches is the point of the eBPF entropy sources.
        mkEbpfCheck =
          kernel:
          let
            esdm-ebpf = self.packages.${system}.esdm-ebpf;
          in
          pkgs.testers.nixosTest {
            name = "eBPF entropy source test";

            nodes.machine =
              { ... }:
              {
                boot.kernelPackages = kernel;

                # The test framework forces clocksource=acpi_pm, which has no
                # vDSO: every clock read traps to the hypervisor and the eBPF
                # sources' high-resolution-timer probe fails on the read latency
                # alone, disabling them before they load. The TSC is vDSO-backed
                # and is what these sources time against on bare metal, so it is
                # also the more faithful thing to measure. mkAfter puts this
                # last, where the final clocksource= wins.
                boot.kernelParams = lib.mkAfter [ "clocksource=tsc" ];

                environment.systemPackages = [ esdm-ebpf ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 4;
                };
              };

            # Note, esdm-tool prints the status through the ESDM logger
            # which writes to stderr.
            testScript = ''
              machine.wait_for_unit("multi-user.target")
              # Trace level (-v past LOGGER_TRACE, the increment saturates)
              # logs one line per fetch that brought events, which is what
              # the fetch rate is measured with below.
              machine.succeed(
                  "${esdm-ebpf}/bin/esdm-server -f --pid /run/esdm-server.pid "
                  "-vvvvvvvvvv >/tmp/esdm.log 2>&1 & echo started"
              )
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -q SchedulerEBPF", 60
              )

              # The libbpf the sources actually loaded against decides which
              # program constructs are available to them, so it is reported.
              machine.succeed("grep -q 'using libbpf v' /tmp/esdm.log")
              machine.succeed(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -q InterruptEBPF"
              )

              # The programs have to load and attach on the stock kernel ...
              for source in ["SchedulerEBPF", "InterruptEBPF"]:
                  machine.wait_until_succeeds(
                      f"${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A6 'Name: {source}' "
                      "| grep -q 'eBPF programs loaded: true'", 60
                  )

              # ... and the collected events have to reach the conditioning
              # pool. Three digits distinguishes a real drain from a stray event
              # trickling in. Only the scheduler source is credited - the
              # interrupt source is built with an entropy rate of 0.
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A2 'Name: SchedulerEBPF' "
                  "| grep -qE 'Available entropy: [1-9][0-9][0-9]'", 60
              )

              # Fetching entropy must not ramp the accounting past what the
              # conditioning pool can deliver, but must still reach a full
              # digest: one output block costs a digest plus the SP800-90C
              # oversampling surcharge, so capping at the digest alone would
              # clip the surcharge and leave it stuck below.
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A2 'Name: SchedulerEBPF' "
                  "| grep -q 'Available entropy: 512'", 60
              )

              def avail():
                  return int(machine.succeed(
                      "${esdm-ebpf}/bin/esdm-tool -s 2>&1 "
                      "| grep -A2 'Name: SchedulerEBPF' "
                      "| sed -n 's/.*Available entropy: //p'"
                  ))

              peak = avail()
              for _ in range(20):
                  machine.succeed(
                      "${esdm-ebpf}/bin/esdm-tool --use-pr -r 32 >/dev/null 2>&1 || true"
                  )
                  peak = max(peak, avail())
              print(f"peak available entropy of the eBPF pool: {peak} bits")
              # The pool is a SHA-512 state and holds at most one digest of
              # entropy (SP800-90B section 3.1.5.1 table 1).
              assert peak <= 512, (
                  f"available entropy reached {peak} bits, more than the "
                  "conditioning pool can hold - the ingest credits events whose "
                  "entropy the pool has no capacity for"
              )

              # Once the pool holds everything one extraction can deliver the
              # monitor stops asking, so the hand-over has to go quiet - the
              # point of fetching on demand rather than being streamed at. A
              # monitor draining unconditionally produces ~220 batches in this
              # window on this VM, an idle demand-driven one a handful.
              def fetches():
                  return int(machine.succeed(
                      "grep -c 'SchedulerEBPF ES: fetched' /tmp/esdm.log || true"
                  ))

              before = fetches()
              machine.sleep(30)
              fetched = fetches() - before
              print(f"fetches while idle: {fetched} in 30s")
              assert fetched < 40, (
                  f"{fetched} fetches in 30s while the pool was full - the "
                  "server is reading the ring buffer instead of leaving the "
                  "events in it until it needs them"
              )

              # Unloading the sources has to erase the raw samples. User space
              # clears the collection buffers; the ring buffer - the one it
              # cannot write itself - is overwritten by the wipe program. The
              # message below is logged only once the filler has covered the
              # whole ring, so it reports load, run and wrap-around.
              machine.succeed("kill -TERM $(cat /run/esdm-server.pid)")
              for source in ["SchedulerEBPF", "InterruptEBPF"]:
                  machine.wait_until_succeeds(
                      f"grep -q '{source} ES: ring buffer erased' /tmp/esdm.log", 30
                  )
              for complaint in [
                  "ring buffer erased over",
                  "cannot run the ring buffer wipe",
                  "cannot clear the per-CPU state map",
                  "does not support BPF syscall programs",
              ]:
                  machine.fail(f"grep -q '{complaint}' /tmp/esdm.log")
            '';
          };

        # End-to-end raw entropy measurement of the eBPF scheduler source:
        # esdm-ebpf-collect gathers unconditioned time stamps in the VM and the
        # analysis scripts drive the NIST SP800-90B non-IID estimator over them.
        # This tests the measurement tooling, NOT a validation grade assessment
        # - a claim must be measured on the deployment environment, which a qemu
        # VM is not (see addon/es_ebpf_testing/README.md), so nothing is
        # asserted about the magnitude. Single kernel on purpose: the estimator
        # dominates the run time and nothing here is kernel specific.
        mkEbpfRawCheck =
          kernel:
          let
            esdm-ebpf = self.packages.${system}.esdm-ebpf;

            # The estimator is named explicitly rather than put on $PATH: a run
            # that silently picked up some other ea_non_iid would be
            # indistinguishable from the CI stub used elsewhere.
            eaNonIid = "${pkgs.sp800-90b-entropyassessment}/bin/ea_non_iid";

            # The example scripts live next to the collector and are what this
            # check drives - the pipeline is only worth testing as the tooling
            # a user would actually run.
            tools = lib.cleanSource ./addon/es_ebpf_testing;

            # Deltas to collect from the one CPU this assesses - the CPUs are
            # separate noise sources, so a collection is never split across
            # them. The estimator warns below 1,000,000 samples, which is the
            # count a real assessment starts at.
            events = 1000000;

            # The collection takes the events of one CPU out of a machine of
            # this width, so a wider VM would starve it.
            cores = 2;


          in
          pkgs.testers.nixosTest {
            name = "eBPF raw entropy measurement with SP800-90B assessment";

            nodes.machine =
              { ... }:
              {
                boot.kernelPackages = kernel;

                environment.systemPackages = [ esdm-ebpf ];

                virtualisation = {
                  memorySize = 4096;
                  inherit cores;
                  # The raw records are 32 bytes each and the per-CPU delta
                  # files add another byte per delta on top.
                  diskSize = 4096;
                };
              };

            testScript = ''
              import re

              machine.wait_for_unit("multi-user.target")

              # The scheduler source only observes events that happen, and an
              # idle VM switches a few hundred times per second - stress-ng's
              # context switch stressor reaches the requested count in seconds
              # instead of hours. The store path rather than a bare name:
              # systemd-run resolves against its own PATH, not a login shell's.
              machine.succeed(
                  "systemd-run --unit=esdm-load --collect "
                  "${pkgs.stress-ng}/bin/stress-ng "
                  "--switch ${toString cores} --timeout 600s"
              )

              # Raw sampling is a code path none of the entropy source tests
              # take, and one the eBPF verifier has to accept. The example
              # script drives it: collect one CPU, push the deltas through
              # esdm-extractlsb and assess both bit widths.
              out = machine.succeed(
                  "EA_NON_IID=${eaNonIid} "
                  "${tools}/analyze_non_iid.sh --source sched --cpu 0 "
                  "--events ${toString events} /tmp/ea-out 2>&1",
                  timeout=3600,
              )
              print(out)

              # The script passes the estimator's output through. Reaching
              # this without an estimate means the collection was not
              # something ea_non_iid could assess.
              m = re.search(
                  r"min\(H_original,[^)]*\)\s*:\s*(\d+(?:\.\d+)?)", out
              )
              assert m, "analyze_non_iid.sh produced no min-entropy estimate"

              # The magnitude is a property of this VM, not of the code, so it
              # is reported rather than asserted on - only the range is.
              h = float(m.group(1))
              assert 0.0 <= h <= 8.0, f"min-entropy out of range: {h}"
              print(f"per-event min-entropy (8 LSB) on this VM: {h} bits")

              machine.succeed("systemctl stop esdm-load.service")

              # analyze_restart.sh is deliberately not run here. ea_restart
              # takes nothing but a 1,000,000 sample matrix, which is 1000
              # loads of the eBPF programs plus 1000 collections - far beyond
              # what a check should spend, and anything smaller it rejects
              # outright rather than assesses. It stays example tooling.
            '';
          };

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
                      environment.etc."esdm-startup-loop.py".source = ./tests/startup/esdm_startup_loop.py;

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

        # The ESDM's EGD compatibility interface, exercised by a real consumer:
        # GnuPG through libgcrypt, rebuilt with --enable-random=egd so the EGD
        # is its ONLY entropy gathering module. libgcrypt then log_fatal()s as
        # soon as it cannot reach the socket, leaving no kernel RNG to paper
        # over a broken implementation - see the negative control at the end.
        # Defined once rather than per kernel: nothing here is kernel specific.
        mkEgdCheck =
          let
            esdm = self.packages.${system}.esdm;

            # Must agree with the ListenStream= of esdm-server-egd.socket,
            # i.e. with the esdm-server-egd-socket-path meson option, as
            # libgcrypt gets the path compiled in.
            egdSocket = "/run/esdm-egd.socket";

            libgcryptEgd = pkgs.libgcrypt.overrideAttrs (old: {
              configureFlags = old.configureFlags ++ [
                "--enable-random=egd"
                "--with-egd-socket=${egdSocket}"
              ];

              # The test suite draws random numbers, which this build can only
              # do through an EGD - and there is none in the build sandbox.
              doCheck = false;
            });

            # Only gnupg's own libgcrypt is swapped, so the rest of the
            # closure keeps the regular one and this stays a cheap rebuild.
            gnupgEgd = (pkgs.gnupg.override { libgcrypt = libgcryptEgd; }).overrideAttrs (_: {
              # Same reason as above - gnupg's test suite generates keys.
              doCheck = false;
            });

            gpgHome = "/root/gnupg-egd";
            gpg = "GNUPGHOME=${gpgHome} ${gnupgEgd}/bin/gpg --batch --no-tty";
          in
          pkgs.testers.nixosTest {
            name = "EGD interface serving GnuPG/libgcrypt";

            nodes.machine =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  # Not needed here - this check is about the EGD socket, and
                  # the CUSE daemons would only add startup surface.
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                # The EGD interface is opt-in: esdm-server.service only orders
                # itself after this socket unit, so enabling the unit is what
                # turns the interface on. This one line is the entire
                # administrative step the check is meant to cover.
                systemd.sockets."esdm-server-egd".wantedBy = [ "sockets.target" ];

                environment.systemPackages = [
                  esdm
                  gnupgEgd
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              machine.wait_for_unit("multi-user.target")

              # The socket unit creates the socket, the server picks the
              # descriptor up during its startup.
              machine.wait_for_unit("esdm-server-egd.socket")
              machine.wait_for_unit("esdm-server.service")
              machine.succeed("test -S ${egdSocket}")

              # Distinguish "systemd created the socket" from "the ESDM serves
              # it": only the latter logs this.
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")

              # Guard against testing the wrong libgcrypt: a gpg linked against
              # the stock one would happily pass everything below without ever
              # touching the EGD socket.
              machine.succeed(
                  "ldd ${gnupgEgd}/bin/gpg | grep -q '${libgcryptEgd.lib}'"
              )

              machine.succeed("mkdir -p ${gpgHome} && chmod 700 ${gpgHome}")

              # Raw output of libgcrypt's CSPRNG, which can only be seeded
              # through the ESDM here. Level 2 is GCRY_VERY_STRONG_RANDOM.
              out = machine.succeed(
                  "${gpg} --gen-random 2 32 | wc -c"
              ).strip()
              assert out == "32", f"gpg --gen-random returned {out} bytes"

              # Two consecutive draws must differ - a stuck or all-zero
              # response would satisfy the length check above.
              first = machine.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
              second = machine.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
              assert first != second, "gpg returned identical random data twice"

              # A request larger than the 255 byte cap of a single EGD transfer,
              # so the client has to issue several of them.
              out = machine.succeed("${gpg} --gen-random 2 4096 | wc -c").strip()
              assert out == "4096", f"gpg --gen-random returned {out} bytes"

              # The real thing: key generation consumes entropy through the
              # same path and is what a consumer actually does. The key is
              # generated with an empty passphrase, so no pinentry is
              # involved. (Single quoted Python strings here - an apostrophe
              # pair would end the Nix string this script lives in.)
              machine.succeed(
                  '${gpg} --pinentry-mode loopback --passphrase "" '
                  '--quick-generate-key "ESDM EGD test <egd@example.com>" '
                  'default default never'
              )
              machine.succeed("${gpg} --list-keys egd@example.com")

              # Encrypt/decrypt round trip on top of that key.
              machine.succeed(
                  'echo "entropy from the ESDM" | ${gpg} --yes --armor '
                  '--recipient egd@example.com --encrypt > /root/msg.asc'
              )
              out = machine.succeed(
                  "${gpg} --yes --decrypt /root/msg.asc"
              ).strip()
              assert out == "entropy from the ESDM", f"decryption returned {out!r}"

              # Negative control: without the EGD interface the same gpg must
              # fail. Both units have to go - stopping only the server would
              # leave systemd listening with nobody accepting, making clients
              # wait rather than fail. The socket file stays behind (systemd's
              # RemoveOnStop= defaults to no), but with nobody listening the
              # connect is refused, which is what libgcrypt trips over.
              machine.succeed("systemctl stop esdm-server-egd.socket esdm-server.service")
              machine.fail("${gpg} --gen-random 2 32 > /dev/null")

              # ... and it recovers once the interface is back, which also
              # covers the descriptor handover on a restart.
              machine.succeed("systemctl start esdm-server-egd.socket")
              machine.succeed("systemctl start esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              out = machine.succeed("${gpg} --gen-random 2 32 | wc -c").strip()
              assert out == "32", f"gpg --gen-random returned {out} bytes after restart"
            '';
          };

        # OpenSSH served through the EGD OpenSSL RAND provider, with the
        # emphasis on sshd's pre-authentication child: its seccomp filter kills
        # socket, connect, sendto and recvfrom. Serving it requires the EGD
        # client to connect at allocation time - while OpenSSL loads the
        # provider, before the child confines itself - and to then use
        # read/write rather than send/recv. The key exchanges are exercised
        # individually: curve25519 and sntrup761 live inside OpenSSH, while
        # ecdh-sha2-nistp256 and dh-group14-sha256 draw through libcrypto.
        mkEgdOpensshCheck =
          let
            esdm = self.packages.${system}.esdm;
            egdSocket = "/run/esdm-egd.socket";

            # Pin OpenSSL's DRBG and its seed source to the EGD provider.
            # Merely activating it would leave the choice to OpenSSL, and a
            # fallback to the default provider would make this check vacuous -
            # which is what the control at the end rules out.
            egdConf = pkgs.writeTextFile {
              name = "openssl-esdm-egd.cnf";
              text = ''
                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect
                random = random_sect

                [provider_sect]
                esdm = esdm_sect
                default = default_sect

                [default_sect]
                activate = 1

                [esdm_sect]
                activate = 1
                module = ${esdm}/lib/libesdm-egd-provider.so
                egd_socket = ${egdSocket}

                [random_sect]
                random = CTR-DRBG
                properties = provider=esdm-egd
                seed = SEED-SRC
                seed_properties = provider=esdm-egd
              '';
            };

            kexAlgorithms = [
              "sntrup761x25519-sha512@openssh.com"
              "curve25519-sha256"
              "ecdh-sha2-nistp256"
              "diffie-hellman-group14-sha256"
            ];
          in
          pkgs.testers.nixosTest {
            name = "OpenSSH with the ESDM EGD OpenSSL provider";

            nodes.machine =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                systemd.sockets."esdm-server-egd".wantedBy = [ "sockets.target" ];

                services.openssh = {
                  enable = true;
                  settings = {
                    PermitRootLogin = "prohibit-password";
                    LogLevel = "DEBUG1";
                    KexAlgorithms = kexAlgorithms;
                  };
                };

                # sshd and its host key generation draw from the ESDM. Only
                # the server side is wired up here - the client is pointed at
                # the provider per command below, so the two can be told
                # apart.
                systemd.services.sshd.environment.OPENSSL_CONF = "${egdConf}";
                systemd.services.sshd-keygen.environment.OPENSSL_CONF = "${egdConf}";

                environment.systemPackages = [
                  esdm
                  pkgs.openssl.bin
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              machine.wait_for_unit("esdm-server-egd.socket")
              machine.wait_for_unit("esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")
              machine.succeed("OPENSSL_CONF=${egdConf} openssl rand -out /dev/null 32")

              # The host keys were generated by sshd-keygen through the
              # provider - the RSA one goes through libcrypto's RAND.
              machine.wait_for_unit("sshd.service")
              machine.wait_for_open_port(22)
              machine.succeed("test -s /etc/ssh/ssh_host_rsa_key")
              machine.succeed("test -s /etc/ssh/ssh_host_ed25519_key")

              machine.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
              machine.succeed(
                  'OPENSSL_CONF=${egdConf} ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519'
              )
              pubkey = machine.succeed("cat /root/.ssh/id_ed25519.pub").strip()
              machine.succeed(f"echo '{pubkey}' > /root/.ssh/authorized_keys")
              machine.succeed("chmod 600 /root/.ssh/authorized_keys")

              opts = (
                  "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                  "-o IdentitiesOnly=yes -i /root/.ssh/id_ed25519"
              )
              kex_algorithms = ${builtins.toJSON kexAlgorithms}

              # Both ends drawing from the ESDM.
              for kex in kex_algorithms:
                  out = machine.succeed(
                      f"OPENSSL_CONF=${egdConf} ssh {opts} -o KexAlgorithms={kex} "
                      f"root@localhost 'echo ok'"
                  ).strip()
                  assert out == "ok", f"{kex}: unexpected ssh output {out!r}"

              # The same with a plain client, so that only the server side -
              # and with it the sandboxed pre-auth child - is on the ESDM.
              for kex in kex_algorithms:
                  out = machine.succeed(
                      f"ssh {opts} -o KexAlgorithms={kex} root@localhost 'echo ok'"
                  ).strip()
                  assert out == "ok", f"{kex}: unexpected ssh output {out!r}"

              # Nothing was killed by the seccomp filter on the way. This is
              # the assertion that would catch a client reaching for a
              # forbidden syscall inside the sandbox - a lazily opened
              # connection, or send/recv instead of write/read.
              machine.fail("journalctl -b | grep -iE 'sigsys|type=1326'")

              # Control: the sessions above really were served by the ESDM.
              # With it stopped the pinned provider has no source left, so a
              # plain client must now fail to connect - the failure can only
              # come from the server side.
              machine.succeed(
                  "systemctl stop esdm-server-egd.socket esdm-server-priv.socket "
                  "esdm-server-unpriv.socket esdm-server.service"
              )
              machine.fail("OPENSSL_CONF=${egdConf} openssl rand -out /dev/null 32")
              machine.fail(
                  f"ssh {opts} -o KexAlgorithms=ecdh-sha2-nistp256 "
                  "root@localhost 'echo unreachable'"
              )

              # ... and it comes back with the ESDM, which also exercises the
              # provider against a daemon that was restarted underneath it.
              machine.succeed("systemctl start esdm-server-egd.socket")
              machine.succeed("systemctl start esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")
              out = machine.succeed(
                  f"ssh {opts} -o KexAlgorithms=ecdh-sha2-nistp256 "
                  "root@localhost 'echo recovered'"
              ).strip()
              assert out == "recovered", f"unexpected ssh output: {out!r}"
            '';
          };

      in
      {
        # nix fmt
        formatter = pkgs.nixfmt-tree;

        # One check per defined kernel version, e.g.:
        #   nix run .#checks.x86_64-linux.live_6_18.driverInteractive
        #   nix flake check
        checks =
          lib.mapAttrs' (name: kernel: lib.nameValuePair "live_${name}" (mkCheck kernel)) kernels
          // lib.mapAttrs' (name: kernel: lib.nameValuePair "ebpf_${name}" (mkEbpfCheck kernel)) stockKernels
          // {
            # Only for the rolling kernel - see mkEbpfRawCheck on why this is
            # not instantiated per kernel version.
            ebpf_raw = mkEbpfRawCheck stockKernels.latest;

            # Not per kernel version either - see mkEgdCheck.
            egd_gnupg = mkEgdCheck;

            # Nor is the EGD OpenSSL provider kernel specific.
            egd_openssh = mkEgdOpensshCheck;
          };

        packages =
          let
            # gcov occasionally emits a negative branch count for the Botan C++
            # backend (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=68080).
            # gcovr treats that as fatal and produces no report at all, so warn
            # once per affected file and keep the rest of the data.
            gcovrIgnoreParseErrors =
              "--gcov-ignore-parse-errors negative_hits.warn_once_per_file";

            # Turn one of the esdm packages above into a coverage build of
            # itself: instrument with gcov, run "meson test" and export the HTML
            # report as the derivation output.
            #
            #   nix build .#esdm-coverage
            #   xdg-open result/share/doc/esdm/coverage/index.html
            #
            # The tests run unprivileged inside the nix sandbox, so everything
            # needing root (CUSE device files, the RPC and getrandom frontends,
            # the esdm-server driven tests) is skipped and missing from the
            # report; see esdm-coverage-root and -vm for those.
            coverageOf =
              coveragePname: pkg:
              pkg.overrideAttrs (prev: {
              pname = coveragePname;

              nativeBuildInputs = prev.nativeBuildInputs ++ [
                pkgs.gcovr
              ];

              # Coverage needs unoptimized, unstripped objects without LTO: with
              # LTO the arc counters can no longer be attributed to source
              # lines. The address and undefined behaviour sanitizers run
              # alongside, so the same execution also decides whether the code
              # it covered was well defined. Both abort on the first finding
              # (see ASAN_OPTIONS / UBSAN_OPTIONS below), failing the test.
              mesonFlags =
                (builtins.filter (
                  x:
                  (!lib.hasInfix "b_lto" x)
                  && (!lib.hasInfix "b_sanitize" x)
                  && (!lib.hasInfix "optimization" x)
                  && (!lib.hasInfix "strip" x)
                  # replaced below
                  && (x != "-Des_kernel=disabled")
                  && (x != "-Des_jent_kernel=disabled")
                ) prev.mesonFlags)
                ++ [
                  "-Db_coverage=true"
                  "-Db_sanitize=address,undefined"
                  "-Db_lto=false"
                  "-Doptimization=0"
                  "-Dstrip=false"
                  # Several tests drive the ESDM through its test perturbation
                  # hooks and are compiled out without this.
                  "-Dtestmode=enabled"

                  # Every entropy source that can be compiled in. Most disable
                  # themselves at runtime for want of a TPM, a /dev/hwrng, a
                  # token or a patched kernel, but their initialization,
                  # configuration and refusal paths are code like any other.
                  # The eBPF sources are left out on purpose - esdm-coverage-ebpf
                  # covers those, since enabling them changes the credited source.
                  "-Des_kernel=enabled"
                  "-Des_jent_kernel=enabled"
                  "-Des_pkcs11=enabled"

                  # Point the PKCS#11 source at SoftHSM, which needs no
                  # hardware. The path is compile-time only, so without it the
                  # source disables itself at startup. Label and PIN stay unset
                  # - the test installs both at runtime, as the server does from
                  # its RPC handler.
                  "-Des_pkcs11_module_path=${pkgs.softhsm}/lib/softhsm/libsofthsm2.so"
                ];

              # es_jent_kernel reaches the kernel crypto API through libkcapi.
              # es_pkcs11 needs libp11, which is already among the inputs;
              # softhsm supplies the module it loads plus the softhsm2-util
              # the test initializes the token with.
              buildInputs = prev.buildInputs ++ [ pkgs.libkcapi ];
              nativeCheckInputs = (prev.nativeCheckInputs or [ ]) ++ [
                pkgs.softhsm
              ];

              mesonBuildType = "debug";
              dontStrip = true;
              separateDebugInfo = false;

              doCheck = true;
              checkPhase = ''
                runHook preCheck

                # Every ESDM this suite starts loads the SoftHSM module the
                # PKCS#11 source was built against, and SoftHSM logs three
                # errors per start when it finds no configuration - nixpkgs
                # ships none at the path it compiles in. Point it at one of our
                # own so the run stays readable; the PKCS#11 test overrides this
                # with the config of the token it creates.
                mkdir -p "$NIX_BUILD_TOP/softhsm/tokens"
                printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
                  "$NIX_BUILD_TOP/softhsm/tokens" \
                  >"$NIX_BUILD_TOP/softhsm/softhsm2.conf"
                export SOFTHSM2_CONF="$NIX_BUILD_TOP/softhsm/softhsm2.conf"

                # The builder may be busy and is not necessarily fast - give the
                # tests that wait for entropy room before they time out.
                meson test --print-errorlogs --timeout-multiplier 5

                # Turn the .gcda files into the report. gcovr is driven directly
                # rather than through meson's coverage-html target, which offers
                # no way to pass excludes: the tests themselves, the out-of-tree
                # add-ons, esdm-tool's stress drivers and the generated libbpf
                # skeletons all stay out of the report.
                mkdir -p meson-logs/coveragereport
                gcovr \
                  --root .. \
                  --exclude '.*/tests/.*' \
                  --exclude '.*/addon/.*' \
                  --exclude '.*/frontends/tool/stress_.*' \
                  --exclude '.*\.skel\.h' \
                  --exclude-unreachable-branches \
                  ${gcovrIgnoreParseErrors} \
                  --html-details meson-logs/coveragereport/index.html \
                  --html-title 'ESDM ${prev.version} test coverage' \
                  --txt meson-logs/coveragereport/coverage.txt \
                  --print-summary

                runHook postCheck
              '';

              installPhase = ''
                runHook preInstall

                mkdir -p $out/share/doc/esdm/coverage
                cp -r meson-logs/coveragereport/. $out/share/doc/esdm/coverage/

                # Keep the test log next to the report: it records which tests
                # were skipped and therefore which parts of the tree the numbers
                # say nothing about.
                cp meson-logs/testlog.txt $out/share/doc/esdm/coverage/

                runHook postInstall
              '';

              # The output holds a report, not the programs - so there is no
              # esdm-server for the inherited FIPS integrity fixup to sign.
              postFixup = "";

              meta = prev.meta // {
                description = "HTML test coverage report of the ESDM meson test suite";
              };
            });

            # A coverage run packaged as a script instead of a sandboxed build,
            # so it can be started with root privileges:
            #
            #   sudo "$(nix build --no-link --print-out-paths .#esdm-coverage-root)/bin/esdm-coverage-run"
            #
            # As root the tests the sandbox has to skip do run, so the report
            # also covers the frontends and the RPC server. The script works in
            # a temporary directory of its own and never touches a checkout.
            coverageRunnerOf =
              {
                name,
                cov,
                extraRuntimeInputs ? [ ],
              }:
              let
                # Every output of every dependency, not just the one in
                # buildInputs: those carry a selected output (usually "dev") and
                # lib.getLib/getDev hand such a package back unchanged, while
                # headers and libraries live in different outputs - jitterentropy
                # is found with cc.find_library() and needs the shared object.
                deps = lib.concatMap (d: d.all or [ d ]) (
                  cov.buildInputs ++ cov.propagatedBuildInputs
                );
                pkgConfigPath = lib.concatStringsSep ":" (
                  lib.concatMap (d: [
                    "${d}/lib/pkgconfig"
                    "${d}/share/pkgconfig"
                  ]) deps
                );
                # The compiler wrapper is not driven by the stdenv setup hooks
                # here, so the search paths the buildInputs would contribute have
                # to be handed to it explicitly. It reads them from variables
                # carrying its own suffix salt - the unsalted names are what the
                # setup hooks consume, and are ignored by the wrapper itself.
                salt = pkgs.stdenv.cc.suffixSalt;
                cflags = lib.concatMapStringsSep " " (d: "-isystem ${d}/include") deps;
                ldflags = lib.concatMapStringsSep " " (d: "-L${d}/lib") deps;
              in
              pkgs.writeShellApplication {
                inherit name;
                # Order matters: the gcc wrapper has to come before anything that
                # also ships a "cc", or meson would configure the build around a
                # different compiler than the one gcov below is matched to.
                runtimeInputs = [
                  pkgs.meson
                  pkgs.ninja
                  pkgs.pkg-config
                  pkgs.gcovr
                  pkgs.stdenv.cc
                  pkgs.coreutils
                  pkgs.gnugrep
                  # for the "who holds the socket" hint of the preflight check
                  pkgs.iproute2
                  # pkill and umount for the cleanup of a failed run
                  pkgs.procps
                  pkgs.util-linux
                  # softhsm2-util, which the PKCS#11 test initializes its own
                  # token with - without it that test skips
                  pkgs.softhsm
                ]
                ++ extraRuntimeInputs;
                text = ''
                  report_dir="''${1:-$PWD/esdm-coverage-report}"
                  shift || true

                  export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
                  export NIX_CFLAGS_COMPILE_${salt}="${cflags} ''${NIX_CFLAGS_COMPILE_${salt}:-}"
                  export NIX_LDFLAGS_${salt}="${ldflags} ''${NIX_LDFLAGS_${salt}:-}"

                  if [ "$(id -u)" -ne 0 ]; then
                    echo "esdm-coverage-run: not running as root - every test that"
                    echo "  needs an esdm-server, the CUSE device files or the kernel"
                    echo "  entropy interfaces will report itself as skipped, and the"
                    echo "  code behind it will show up as uncovered."
                    echo
                  fi

                  # A test mode ESDM binds these fixed paths, so a leftover one -
                  # or a second coverage run - owns them and this run's clients
                  # connect to it instead. Nothing fails outright, the tests just
                  # wait for their timeout, so say so up front instead.
                  stale=0
                  for sock in /tmp/esdm-rpc-unpriv-testmode.socket \
                              /tmp/esdm-rpc-priv-testmode.socket; do
                    if [ -e "$sock" ]; then
                      echo "esdm-coverage-run: $sock is already there:"
                      ss -xlp 2>/dev/null | grep -F "$sock" || \
                        echo "  (no listener - a stale socket file)"
                      stale=1
                    fi
                  done
                  if [ "$stale" -ne 0 ]; then
                    echo
                    echo "  The test suite binds those paths itself, so it cannot run"
                    echo "  next to whatever holds them. Stop that ESDM (or remove the"
                    echo "  stale files) and try again; set ESDM_COVERAGE_FORCE=1 to"
                    echo "  run anyway."
                    if [ "''${ESDM_COVERAGE_FORCE:-0}" != 1 ]; then
                      exit 1
                    fi
                    echo "  ESDM_COVERAGE_FORCE is set - continuing."
                    echo
                  fi

                  for dev in /dev/tst-random /dev/tst-urandom; do
                    if [ -e "$dev" ]; then
                      echo "esdm-coverage-run: warning: $dev is left over from an" \
                           "interrupted CUSE test run."
                    fi
                  done

                  # The ESDM status segment is a System V singleton keyed by a
                  # fixed ftok() value. One left behind by a root run denies an
                  # unprivileged run write access, and then every test that brings
                  # up an ESDM fails with esdm_init() = -13 - which reads like a
                  # code failure and is not one.
                  if [ "$(id -u)" -ne 0 ]; then
                    ipcs -m 2>/dev/null \
                      | awk '$1 ~ /^0x(6d|65)/ && $3 != "'"$(id -un)"'" {
                               print "esdm-coverage-run: warning: shared memory " \
                                     "segment " $1 " (id " $2 ") belongs to " $3 \
                                     " - ESDM tests will fail with -13 until it " \
                                     "is removed: sudo ipcrm -m " $2 }' || true
                  fi

                  work="$(mktemp -d -t esdm-coverage-XXXXXX)"

                  # shellcheck disable=SC2329  # run from the EXIT trap below
                  cleanup() {
                    # A failed CUSE or RPC test leaves its esdm-server and
                    # frontends holding the fixed socket paths and /dev bind
                    # mounts, which every later test would talk to instead. Match
                    # on the work directory in their command line, so only this
                    # run's processes are hit.
                    pkill -TERM -f "$work" 2>/dev/null || true
                    sleep 2
                    pkill -KILL -f "$work" 2>/dev/null || true

                    # The frontends unmount these themselves when they shut down
                    # cleanly; after a kill they are left behind.
                    if [ "$(id -u)" -eq 0 ]; then
                      for dev in /dev/tst-random /dev/tst-urandom; do
                        umount "$dev" 2>/dev/null || true
                      done
                    fi

                    # Stopping the daemons above is always right; deleting the
                    # evidence is not. A run that failed - or was interrupted
                    # before it wrote a report - is exactly the one whose build
                    # tree and test log are still needed, so keep it and say
                    # where. keep_work is cleared once the report is safely out.
                    if [ "''${keep_work:-1}" = 1 ]; then
                      echo
                      echo "esdm-coverage-run: build tree kept for inspection at" \
                           "$work"
                      echo "  test log: $work/build/meson-logs/testlog.txt"
                      echo "  remove it with: rm -rf $work"
                    else
                      rm -rf "$work"
                    fi
                  }
                  keep_work=1
                  trap cleanup EXIT

                  # The sources come out of the store read-only, and the build
                  # writes the coverage counters next to the objects.
                  cp -r --no-preserve=mode,ownership ${cov.src}/. "$work/source"

                  meson setup "$work/build" "$work/source" \
                    --buildtype=${cov.mesonBuildType} \
                    ${lib.escapeShellArgs cov.mesonFlags}
                  ninja -C "$work/build"

                  # Every ESDM this suite starts loads the SoftHSM module the
                  # PKCS#11 source was built against, and SoftHSM logs three
                  # errors per start when it finds no configuration - nixpkgs
                  # ships none at the path it compiles in. Point it at one of
                  # our own so the run stays readable. Below $work, which the
                  # privileged tests pin across their private /tmp, and which
                  # the chmod below opens up for the daemons that drop
                  # privileges. The PKCS#11 test overrides this with the config
                  # of the token it creates.
                  mkdir -p "$work/softhsm/tokens"
                  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
                    "$work/softhsm/tokens" >"$work/softhsm/softhsm2.conf"
                  export SOFTHSM2_CONF="$work/softhsm/softhsm2.conf"

                  # The esdm-server and the CUSE frontends drop privileges, and
                  # libgcov writes their counters into the build tree as the
                  # dropped user. mktemp's 0700 root owned directory is not even
                  # traversable for them, so those counters would be lost with
                  # "Cannot create directory". Only needed as root, and the
                  # directory is a throwaway that is removed again on exit.
                  if [ "$(id -u)" -eq 0 ]; then
                    chmod -R a+rwX "$work"
                  fi

                  # The chmod above only covers what exists now; the .gcda files
                  # appear during the run. Created 0644 by a root process, the
                  # privilege-dropped ones cannot open them to merge their
                  # counters, so make them 0666 for the duration and the merge
                  # works in either order. The RPC sockets are unaffected - the
                  # server chmod()s them explicitly rather than using the umask.
                  old_umask="$(umask)"
                  if [ "$(id -u)" -eq 0 ]; then
                    umask 0000
                  fi

                  # A failing test still leaves usable counters behind, so the
                  # report is written either way and the failure is reported at
                  # the end.
                  test_status=0
                  meson test -C "$work/build" --print-errorlogs \
                    --timeout-multiplier 5 "$@" || test_status=$?

                  umask "$old_umask"

                  # Get the test log out first: it is the thing needed to explain
                  # a failure, and it must not be lost if the report generation
                  # below is what goes wrong.
                  mkdir -p "$report_dir" "$work/report"
                  cp "$work/build/meson-logs/testlog.txt" "$report_dir/" || true

                  # gcov ships with the compiler itself rather than with its
                  # wrapper, and has to be the one matching the compiler that
                  # produced the notes - so name it instead of searching $PATH.
                  gcovr \
                    --gcov-executable '${pkgs.stdenv.cc.cc}/bin/gcov' \
                    --root "$work/source" \
                    --exclude '.*/tests/.*' \
                    --exclude '.*/addon/.*' \
                    --exclude '.*/frontends/tool/stress_.*' \
                    --exclude '.*\.skel\.h' \
                    --exclude-unreachable-branches \
                    ${gcovrIgnoreParseErrors} \
                    --html-details "$work/report/index.html" \
                    --html-title 'ESDM ${cov.version} test coverage' \
                    --txt "$work/report/coverage.txt" \
                    --print-summary \
                    "$work/build"

                  cp -r "$work/report/." "$report_dir/"
                  chmod -R u+w "$report_dir"

                  echo
                  echo "Coverage report written to $report_dir/index.html"
                  if [ "$test_status" -ne 0 ]; then
                    echo "WARNING: the test run failed (exit $test_status) - see" \
                         "$report_dir/testlog.txt"
                  else
                    # Everything is out and every test passed - nothing left in
                    # the build tree that anybody would want to look at.
                    keep_work=0
                  fi
                  exit "$test_status"
                '';
              };

            # One of the runners above, started inside a VM instead of on the
            # developer's machine, with the report copied back out:
            #
            #   nix build .#esdm-coverage-vm
            #   xdg-open result/coverage/index.html
            #
            # As root the run binds fixed socket paths, creates CUSE device
            # files, writes to the kernel entropy interfaces and leaves daemons
            # behind on failure - in a VM all of that is free of consequence.
            # The VM also carries the patched kernel and its esdm_es module,
            # without which the kernel entropy source disables itself.
            # A package rather than a check on purpose: a full build plus the
            # whole suite under ASan/UBSan in an emulated machine is not work
            # `nix flake check` should be doing.
            coverageVmOf =
              {
                name,
                runner,
                kernel,
                extraConfig ? { },
              }:
              pkgs.testers.nixosTest {
                inherit name;

                # A full build plus a sanitized run of the whole suite, emulated.
                # The default hour is not enough for that.
                globalTimeout = 4 * 60 * 60;

                nodes.machine =
                  { ... }:
                  {
                    imports = [
                      { _module.args.kernel = kernel; }
                      baseModule
                      (
                        { ... }:
                        {
                          # baseModule leaves the daemon disabled (startEsdm =
                          # false), which is what this needs: the suite brings up
                          # test mode ESDMs of its own on fixed socket paths, and
                          # the runner's preflight check refuses to start if a
                          # running server already holds them.

                          # The CUSE frontends reach their device files through
                          # /dev/cuse. Without the module they cannot start, and
                          # every test driving /dev/random through them skips.
                          boot.kernelModules = [ "cuse" ];

                          environment.systemPackages = [ runner ];

                          virtualisation = {
                            # A software TPM, so the TPM 2.0 entropy source has
                            # a /dev/tpmrm0 to talk to. Without one its test
                            # only covers what the source does when the device
                            # is absent, and the command exchange, the response
                            # parsing and the block cache in front of it stay
                            # unreached in the report.
                            tpm.enable = true;
                            # meson runs the suite in parallel, and several
                            # tests spend their time waiting for entropy rather
                            # than on the CPU - cores are what this is short of.
                            cores = 8;
                            # The sanitizer shadow map alongside a parallel run.
                            memorySize = 8192;
                            # The instrumented tree is unoptimized and unstripped
                            # and carries a coverage note next to every object.
                            # The image is sparse, so this is a ceiling rather
                            # than a cost.
                            diskSize = 30 * 1024;
                          };
                        }
                      )
                      extraConfig
                    ];
                  };

                testScript = ''
                  machine.wait_for_unit("multi-user.target")

                  # What the VM is here for. Checked up front: the run takes
                  # long enough that finding out from the report afterwards
                  # would be an expensive way to learn the module is missing.
                  machine.succeed("test -c /dev/esdm_es")

                  machine.succeed("mkdir -p /var/coverage")

                  # TMPDIR puts the build tree on the VM disk sized above; no
                  # timeout, as execute() defaults to 15 minutes and this is a
                  # full build.
                  status, _ = machine.execute(
                      "TMPDIR=/var/tmp ${lib.getExe runner} /var/coverage"
                      " > /var/coverage/coverage-run.log 2>&1",
                      timeout=None,
                  )

                  # A failed suite is recorded in the report rather than
                  # asserted on. The report is what this package exists to
                  # produce, and a failing run is the one whose numbers and test
                  # log are wanted most - asserting here would fail the
                  # derivation, and nix discards $out of a failed build, so
                  # exactly those runs would come back empty. Which tests failed
                  # is in coverage/testlog.txt.
                  machine.succeed(f"echo {status} >/var/coverage/status")
                  machine.copy_from_machine("/var/coverage")

                  if status != 0:
                      print(
                          f"WARNING: the coverage suite failed (exit {status})"
                          " - see coverage/coverage-run.log and"
                          " coverage/testlog.txt in the output"
                      )
                '';
              };
          in
          {
          jitterentropy = pkgs.jitterentropy.overrideAttrs (_: {
            version = "3.7.1";
            src = pkgs.fetchFromGitHub {
              owner = "smuellerDD";
              repo = "jitterentropy-library";
              rev = "8760e08ac3268946aedfcc6fc047dbadb02986ea";
              hash = "sha256-3N1yz+mBSYUIdtAMxKrUV56lE5q2SMfcyRmULfYwcqY=";
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
              fips140 = true;
              # remove later, for testing with NTG.1 capable jitterentropy
              inherit (self.packages.${system}) jitterentropy;
            }).overrideAttrs
              (prev: {
                buildInputs = prev.buildInputs ++ [
                  pkgs.libp11
                  pkgs.json_c
                ];
                mesonFlags =
                  # nixpkgs still knows the combined 'ais2031' option, which
                  # this tree split into 'ais2031_ntg1' and 'ais2031_drg4';
                  # drop the flag it passes and set the successors below.
                  (builtins.filter (
                    x:
                    (!lib.hasInfix "max_threads" x)
                    && (!lib.hasInfix "term-on-signal" x)
                    && (!lib.hasInfix "ais2031" x)
                  ) prev.mesonFlags)
                  ++ lib.optionals debugEsdm [
                    "-Db_sanitize=address,undefined"
                    "-Dstrip=false"
                  ]
                  ++ [
                    "-Des_jent_osr=4"
                    "-Dbotan_drng_type=chacha20"
                    "-Dais2031_ntg1=false"
                    "-Dais2031_drg4=false"
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

          # ESDM with the eBPF-based scheduler and interrupt entropy sources
          # (plus the raw measurement tooling). The eBPF programs only use
          # UAPI headers, so no kernel BTF is needed at build time.
          esdm-ebpf = self.packages.${system}.esdm.overrideAttrs (prev: {
            buildInputs = prev.buildInputs ++ [ pkgs.libbpf ];
            nativeBuildInputs = prev.nativeBuildInputs ++ [
              pkgs.clang
              pkgs.bpftools
            ];
            mesonFlags = prev.mesonFlags ++ [
              "-Des_sched_ebpf=enabled"
              "-Des_irq_ebpf=enabled"
              "-Des_ebpf_testing=enabled"
              "-Des_sched_ebpf_entropy_rate=256"
              "-Des_sched_ebpf_osr=3"
              "-Des_ebpf_testing=enabled"
              "-Dvalidation-helpers=enabled"
            ];
          });


          # ESDM under the German AIS 20/31 3.0 (2024) regime: the NTG.1 seeding
          # strategy and the DRG.4 reseeding limits. Both are off in the package
          # above, so the code behind them - the two-source seeding decision of
          # esdm_es_mgr.c and the capped reseed thresholds of esdm_drng_mgr.c -
          # is compiled out there and cannot be covered.
          #
          # FIPS needs nothing here: fips140 is already set on the base package,
          # and the VM boots with fips=1 (see baseModule), so
          # /proc/sys/crypto/fips_enabled makes fips_enabled() answer true for
          # everything this runs.
          #
          # NTG.1 wants two entropy sources delivering 240 bits each. The base
          # package zeroes the rates of the scheduler, CPU, interrupt and
          # hwrand sources, which leaves the jitter RNG and - through the
          # coverage build's -Des_jent_kernel=enabled - its kernel counterpart
          # as the two that qualify at 256 bits. Should that ever stop being
          # enough, es_jent_ntg1 makes a 3.7.0+ jitter RNG NTG.1 conformant on
          # its own (the jitterentropy pinned above is 3.7.1) and one source
          # then suffices.
          esdm-ais2031 = self.packages.${system}.esdm.overrideAttrs (prev: {
            mesonFlags =
              (builtins.filter (x: !lib.hasInfix "ais2031" x) prev.mesonFlags)
              ++ [
                "-Dais2031_ntg1=true"
                "-Dais2031_drg4=true"
              ];
          });


          # The ESDM under the thread sanitizer, running the meson test suite
          # as its check phase: a race produces data rather than a failing
          # test, so the suite alone says nothing about one. A build of its
          # own - the sanitizer needs the whole program instrumented, and it
          # cannot be linked next to the address sanitizer of the coverage
          # build.
          esdm-tsan = self.packages.${system}.esdm.overrideAttrs (prev: {
            pname = "esdm-tsan";

            mesonFlags =
              (builtins.filter (
                x:
                (!lib.hasInfix "b_lto" x)
                && (!lib.hasInfix "b_sanitize" x)
                && (!lib.hasInfix "optimization" x)
                && (!lib.hasInfix "strip" x)
              ) prev.mesonFlags)
              ++ [
                "-Db_sanitize=thread"
                # The sanitizer needs to see the calls it instruments, and with
                # link time optimization it no longer does reliably.
                "-Db_lto=false"
                # Enough optimization to keep a 10x slower suite bearable,
                # little enough to keep the frames in a report nameable.
                "-Doptimization=1"
                "-Dstrip=false"
                # Compiles in the test perturbation hooks, and shortens the
                # worker intervals so the threads meet during a test.
                "-Dtestmode=enabled"
              ];

            mesonBuildType = "debug";
            dontStrip = true;
            separateDebugInfo = false;

            doCheck = true;
            checkPhase = ''
              runHook preCheck

              # Report every race of a run rather than only the first (the
              # exit code 66 fails the test), with both sides of a lock order
              # inversion.
              export TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1 history_size=7"

              # The sanitizer costs an order of magnitude in run time. The
              # reports are collected from the full log afterwards, as
              # --print-errorlogs only shows the tail of a failing test.
              if ! meson test --print-errorlogs --timeout-multiplier 10; then
                echo
                echo "=== every ThreadSanitizer report of this run ==="
                awk '/^WARNING: ThreadSanitizer/,/^SUMMARY: ThreadSanitizer/' \
                  meson-logs/testlog.txt
                exit 1
              fi

              runHook postCheck
            '';

            # The suite's log next to the binaries it ran.
            postInstall = (prev.postInstall or "") + ''
              mkdir -p $out/share/doc/esdm
              cp meson-logs/testlog.txt $out/share/doc/esdm/tsan-testlog.txt
            '';

            meta = prev.meta // {
              description = "ESDM built with the thread sanitizer, running the meson test suite";
            };
          });

          esdm-coverage = coverageOf "esdm-coverage" self.packages.${system}.esdm;

          # The same, for the build carrying the eBPF entropy sources. A separate
          # report rather than more flags on the one above, because enabling them
          # changes which source is credited (es_sched_ebpf_entropy_rate against
          # a zeroed es_sched), so the numbers should not be pooled. The eBPF
          # programs themselves are not instrumented - clang builds them via a
          # custom_target that meson's b_coverage never reaches - so what the
          # report adds is the userspace side.
          esdm-coverage-ebpf =
            coverageOf "esdm-coverage-ebpf" self.packages.${system}.esdm-ebpf;

          # Likewise its own report rather than more flags on the default one:
          # NTG.1 changes when a DRNG counts as fully seeded and DRG.4 changes
          # how often it reseeds, so the two runs do not exercise the same
          # state machine and their numbers should not be pooled.
          esdm-coverage-ais2031 =
            coverageOf "esdm-coverage-ais2031" self.packages.${system}.esdm-ais2031;


          esdm-coverage-root = coverageRunnerOf {
            name = "esdm-coverage-run";
            cov = self.packages.${system}.esdm-coverage;
          };

          # clang and bpftool are only build time tools of the eBPF variant, so
          # they have to be on the path of the script that does the building -
          # esdm/es_ebpf/meson.build looks both of them up with find_program().
          esdm-coverage-ebpf-root = coverageRunnerOf {
            name = "esdm-coverage-ebpf-run";
            cov = self.packages.${system}.esdm-coverage-ebpf;
            extraRuntimeInputs = [
              pkgs.clang
              pkgs.bpftools
            ];
          };

          esdm-coverage-ais2031-root = coverageRunnerOf {
            name = "esdm-coverage-ais2031-run";
            cov = self.packages.${system}.esdm-coverage-ais2031;
          };

          # The runners above in a VM of their own - see coverageVmOf.
          # Tracking the rolling kernel for the same reason liveIso does: a
          # specific versioned attribute is one nixpkgs bump away from being
          # dropped.
          esdm-coverage-vm = coverageVmOf {
            name = "esdm coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-root;
            kernel = kernels.latest;
          };

          # The AIS 20/31 build on the patched kernel: NTG.1 counts entropy
          # sources, so it wants the kernel ones present rather than disabling
          # themselves for want of /dev/esdm_es.
          esdm-coverage-vm-ais2031 = coverageVmOf {
            name = "esdm AIS 20/31 coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-ais2031-root;
            kernel = kernels.latest;
          };

          # Unlike the ebpf_* checks - where running on a stock kernel is the
          # point, as needing no kernel patches is what the eBPF sources are
          # for - this one takes the patched kernel as well. The eBPF sources
          # are only part of what it covers, and es_kernel next to them needs
          # the module like it does in the run above.
          esdm-coverage-vm-ebpf = coverageVmOf {
            name = "esdm eBPF coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-ebpf-root;
            kernel = kernels.latest;
            extraConfig =
              { lib, ... }:
              {
                # See mkEbpfCheck: the test framework pins clocksource=acpi_pm,
                # which has no vDSO, so the eBPF sources' high resolution timer
                # probe fails and disables both of them before they ever load -
                # leaving the code this variant exists to cover unexecuted.
                boot.kernelParams = lib.mkAfter [ "clocksource=tsc" ];
              };
          };

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
              json_c
              libbpf
              libkcapi
              libselinux
              openssl
              protobufc
              self.packages.${system}.jitterentropy
            ];
            nativeBuildInputs = with pkgs; [
              bpftools
              clang
              cmake
              meson
              ninja
              pkg-config
            ];
            packages = with pkgs; [
              bpftop
              bpftools
              bpftrace
              sp800-90b-entropyassessment
            ];
          };
        };

        # shortcut for development - track the rolling "latest" kernel so this
        # does not break when nixpkgs drops a specific versioned attribute.
        liveIso = self.nixosConfigurations.${system}.live_latest.config.system.build.isoImage;
      }
    );
}
