#!/usr/bin/env python3
#
# Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# Startup-hang regression harness for esdm-server.
#
# Repeatedly starts esdm-server in the foreground and checks that it reaches
# the "RNG correctly initialized" point (init DRNG fully seeded -> operational)
# within a bounded time. The server emits the marker line below to stdout when
# the ESDM_STARTUP_MARKER environment variable is set (see
# esdm_set_operational() in esdm/esdm_es_mgr.c).
#
# Once operational, each iteration also fetches 32 bytes of entropy through
# esdm-tool (exercising the RPC path) and then sends SIGTERM to verify that the
# server shuts down cleanly within a bounded time (default 5s) rather than
# hanging on teardown.
#
# A single failing iteration (the marker not appearing within the timeout, the
# server dying before it, the entropy fetch failing, or the server not shutting
# down cleanly in time) reproduces a startup hang / startup crash / teardown
# hang.
#
# Must be run as root: esdm-server refuses to start otherwise.
#
import argparse
import os
import selectors
import signal
import subprocess
import sys
import time

MARKER = "ESDM_RNG_OPERATIONAL"

# Unix domain sockets esdm-server binds. A hard-killed iteration can leave these
# behind; unlink them before each start so the next bind() does not fail.
DEFAULT_SOCKETS = [
    # ESDM_TESTMODE build (e.g. builddir-tsan)
    "/tmp/esdm-rpc-unpriv-testmode.socket",
    "/tmp/esdm-rpc-priv-testmode.socket",
    # default production paths
    "/var/run/esdm-rpc-unpriv.socket",
    "/var/run/esdm-rpc-priv.socket",
    "/run/esdm-rpc-unpriv.socket",
    "/run/esdm-rpc-priv.socket",
]

BINARY_CANDIDATES = [
    "builddir-tsan/frontends/server/esdm-server",
    "builddir/frontends/server/esdm-server",
]


def find_binary(explicit):
    if explicit:
        if not os.path.isfile(explicit):
            sys.exit(f"esdm-server binary not found: {explicit}")
        return os.path.abspath(explicit)
    for cand in BINARY_CANDIDATES:
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    sys.exit(
        "Could not locate esdm-server; pass --binary <path/to/esdm-server>"
    )


def find_tool(explicit):
    """Locate esdm-tool, by default next to the server in the same build.

    The server lives at <build>/frontends/server/esdm-server, the tool at
    <build>/frontends/tool/esdm-tool, so both share the testmode socket paths
    of that build.
    """
    if explicit:
        if not os.path.isfile(explicit):
            sys.exit(f"esdm-tool binary not found: {explicit}")
        return os.path.abspath(explicit)
    sys.exit(
        "Could not locate esdm-tool next to the server; pass "
        "--tool <path/to/esdm-tool>"
    )


def cleanup_sockets(sockets):
    for s in sockets:
        try:
            os.unlink(s)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def stop_server(proc):
    """Best-effort clean shutdown, escalating to SIGKILL on the session."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()  # SIGTERM -> async-signal-safe exit path
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    # Did not exit in time: kill the whole session to catch any helpers.
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def wait_until_seeded(tool, env, tries):
    """Block until ESDM reports fully seeded via esdm-tool -w.

    esdm-tool checks once per round, sleeping ~1s between rounds, for at most
    `tries` rounds, and also drives seeding by requesting bytes. It exits 0 once
    fully seeded and 1 if the rounds are exhausted first (see
    handle_wait_until_seeded() in frontends/tool/tool_main.c).

    Returns (ok: bool, reason: str).
    """
    argv = [tool, "-w", str(tries)]
    try:
        cp = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=tries + 10,  # ~1s/round plus slack
        )
    except subprocess.TimeoutExpired:
        return False, f"esdm-tool -w {tries} timed out"
    except OSError as e:
        return False, f"esdm-tool failed to run: {e}"

    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", "replace").strip()
        snippet = f": {err}" if err else ""
        return False, (f"esdm-tool -w {tries}: not fully seeded "
                       f"(rc={cp.returncode}){snippet}")
    return True, "ok"


def fetch_entropy(tool, env, nbytes):
    """Fetch nbytes of entropy via esdm-tool (-r, hex formatted).

    Returns (ok: bool, reason: str). Exercises the RPC path against the
    running server.
    """
    argv = [tool, "-r", str(nbytes)]
    try:
        cp = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False, f"esdm-tool -r {nbytes} timed out"
    except OSError as e:
        return False, f"esdm-tool failed to run: {e}"

    out = cp.stdout.decode("utf-8", "replace")
    err = cp.stderr.decode("utf-8", "replace").strip()
    if cp.returncode != 0:
        snippet = f": {err}" if err else ""
        return False, f"esdm-tool -r {nbytes} exited rc={cp.returncode}{snippet}"

    # The random bytes are printed as one line of uppercase hex, two chars per
    # byte (see handle_get_random() in frontends/tool/tool_main.c). Any logging
    # ends up on its own line, so match the line that is exactly nbytes*2 hex
    # digits rather than concatenating everything.
    want = nbytes * 2
    hexdigits = set("0123456789ABCDEFabcdef")
    for line in out.splitlines():
        token = line.strip()
        if len(token) == want and all(c in hexdigits for c in token):
            return True, "ok"
    return False, (f"esdm-tool did not return a {want}-hex-char line "
                   f"(rc={cp.returncode} stdout={out.strip()!r} "
                   f"stderr={err!r})")


def terminate_clean(proc, term_timeout):
    """Send SIGTERM and verify the server shuts down cleanly in time.

    A clean shutdown means the server's signal handler ran and main() returned
    0 within term_timeout seconds. If it does not exit in time (teardown hang)
    or exits with a non-zero status, that is a failure; the process is then
    SIGKILLed so the next iteration can start.

    Returns (ok: bool, reason: str, duration: float).
    """
    if proc.poll() is not None:
        rc = proc.returncode
        return False, f"server already exited before SIGTERM (rc={rc})", 0.0

    start = time.monotonic()
    try:
        proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return False, "server vanished before SIGTERM could be sent", 0.0

    try:
        rc = proc.wait(timeout=term_timeout)
    except subprocess.TimeoutExpired:
        # Teardown hang: did not exit within the allotted window.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return (False,
                f"server did not terminate within {term_timeout:.1f}s of "
                f"SIGTERM (teardown hang)",
                time.monotonic() - start)

    duration = time.monotonic() - start
    if rc != 0:
        # Negative rc means killed by signal -> handler did not run cleanly.
        return False, f"server exited uncleanly after SIGTERM (rc={rc})", duration
    return True, "ok", duration


def run_once(binary, tool, env, timeout, term_timeout, fetch_bytes,
             seed_tries, verbose_server, sockets):
    """Start the server, wait for the operational marker, wait until fully
    seeded, fetch entropy, and verify a clean SIGTERM shutdown.

    Returns (ok: bool, reason: str, output_tail: str).
    """
    cleanup_sockets(sockets)

    argv = [binary, "-f"]
    if verbose_server:
        argv.append("-vvvv")

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        env=env,
        start_new_session=True,  # own session/pgid for reliable teardown
    )

    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)

    buf = bytearray()
    deadline = time.monotonic() + timeout
    marker_ok = False
    ok = False
    reason = "timeout: marker not seen within %.1fs" % timeout

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            events = sel.select(timeout=remaining)
            if not events:
                break  # timed out
            data = os.read(proc.stdout.fileno(), 65536)
            if not data:
                # EOF: server closed stdout (exited) before the marker.
                try:
                    rc = proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    rc = proc.poll()
                reason = f"server exited before marker (rc={rc})"
                break
            buf += data
            if verbose_server:
                print(data.decode('utf-8'), end='')
            if MARKER.encode() in buf:
                marker_ok = True
                reason = "ok"
                break

        if marker_ok:
            # Server is operational: wait until ESDM is fully seeded, then
            # exercise the RPC path by fetching entropy, and finally verify it
            # shuts down cleanly on SIGTERM.
            seed_ok, seed_reason = wait_until_seeded(tool, env, seed_tries)
            if not seed_ok:
                ok = False
                reason = seed_reason
            else:
                fetch_ok, fetch_reason = fetch_entropy(tool, env, fetch_bytes)
                if not fetch_ok:
                    ok = False
                    reason = fetch_reason
                else:
                    term_ok, term_reason, dur = terminate_clean(
                        proc, term_timeout)
                    if term_ok:
                        ok = True
                        reason = f"ok (clean shutdown in {dur:.2f}s)"
                    else:
                        ok = False
                        reason = term_reason
    finally:
        sel.close()
        stop_server(proc)
        # Drain anything still buffered (non-blocking) for diagnostics.
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            while True:
                more = proc.stdout.read()
                if not more:
                    break
                buf += more
        except (OSError, ValueError):
            pass
        try:
            proc.stdout.close()
        except OSError:
            pass

    tail = buf.decode("utf-8", "replace")[-2000:]
    return ok, reason, tail


def main():
    ap = argparse.ArgumentParser(
        description="Repeatedly start esdm-server and verify it reaches the "
        "RNG-operational state within a timeout."
    )
    ap.add_argument("--binary", default=None,
                    help="path to esdm-server (auto-detected if omitted)")
    ap.add_argument("--tool", default=None,
                    help="path to esdm-tool (auto-detected next to the server "
                         "if omitted)")
    ap.add_argument("--iterations", type=int, default=1_000_000,
                    help="number of start/check cycles (default: 1000000)")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="max seconds to wait for the marker (default: 5.0)")
    ap.add_argument("--seed-tries", type=int, default=30,
                    help="rounds esdm-tool -w waits for full seeding, ~1s "
                         "each (default: 30)")
    ap.add_argument("--fetch-bytes", type=int, default=32,
                    help="bytes of entropy to fetch via esdm-tool once "
                         "fully seeded (default: 32)")
    ap.add_argument("--term-timeout", type=float, default=5.0,
                    help="max seconds to wait for a clean SIGTERM shutdown "
                         "(default: 5.0)")
    ap.add_argument("--stop-on-failure", action="store_true",
                    help="abort the loop on the first failing iteration")
    ap.add_argument("--verbose-server", action="store_true",
                    help="run esdm-server with -v (verbose logging)")
    ap.add_argument("--extra-socket", action="append", default=[],
                    help="additional socket path to unlink before each run "
                         "(repeatable)")
    ap.add_argument("--progress-every", type=int, default=100,
                    help="print a progress line every N iterations "
                         "(default: 100)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Must run as root (esdm-server requires it). Use e.g. sudo or su.")

    binary = find_binary(args.binary)
    tool = find_tool(args.tool)
    sockets = DEFAULT_SOCKETS + args.extra_socket

    env = dict(os.environ)
    env["ESDM_STARTUP_MARKER"] = "1"

    print(f"binary      : {binary}")
    print(f"tool        : {tool}")
    print(f"iterations  : {args.iterations}")
    print(f"timeout     : {args.timeout:.1f}s")
    print(f"seed-tries  : {args.seed_tries}")
    print(f"fetch-bytes : {args.fetch_bytes}")
    print(f"term-timeout: {args.term_timeout:.1f}s")
    print(f"marker      : {MARKER}")
    print("-" * 60)

    successes = 0
    failures = 0
    failed_iters = []
    start = time.monotonic()

    try:
        for i in range(1, args.iterations + 1):
            ok, reason, tail = run_once(
                binary, tool, env, args.timeout, args.term_timeout,
                args.fetch_bytes, args.seed_tries, args.verbose_server,
                sockets)
            if ok:
                successes += 1
            else:
                failures += 1
                failed_iters.append(i)
                print(f"[FAIL] iteration {i}: {reason}")
                if tail.strip():
                    print("  --- last output ---")
                    for line in tail.strip().splitlines()[-20:]:
                        print(f"  | {line}")
                    print("  -------------------")
                if args.stop_on_failure:
                    print("Stopping on first failure (--stop-on-failure).")
                    break

            if args.progress_every and i % args.progress_every == 0:
                elapsed = time.monotonic() - start
                rate = i / elapsed if elapsed > 0 else 0.0
                print(f"[{i}/{args.iterations}] ok={successes} "
                      f"fail={failures} "
                      f"({rate:.1f} runs/s, {elapsed:.0f}s elapsed)")
    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    cleanup_sockets(sockets)
    elapsed = time.monotonic() - start
    print("-" * 60)
    print(f"completed : {successes + failures} iterations in {elapsed:.0f}s")
    print(f"successes : {successes}")
    print(f"failures  : {failures}")
    if failed_iters:
        shown = ", ".join(str(x) for x in failed_iters[:50])
        more = "" if len(failed_iters) <= 50 else f", ... (+{len(failed_iters) - 50})"
        print(f"failed at : {shown}{more}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
