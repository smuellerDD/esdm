# Fuzzing the ESDM

The ESDM exchanges bytes with other processes on a handful of surfaces, and all
of them are parsed before anything about the peer is established:

* the **requests** on the unprivileged RPC socket, which every user on the
  machine can connect to, and on the privileged one,
* the **responses** every client parses - the library, the CUSE device files,
  the getrandom server, the OpenSSL provider - which are only as trustworthy as
  the socket they came from,
* the **wire codec** under both, in particular the hand-rolled decoder the
  random calls use instead of the generated protobuf code,
* the **EGD compatibility interface**, an opt-in second socket serving the
  protocol of egd.pl and prngd to legacy consumers, and the **EGD client
  library** on the other end of that socket, which believes a length byte
  about how much random data or how long a PID string follows,
* the **OpenSSL RAND providers**, which are the ESDM loaded into somebody
  else's process: everything a provider is handed comes from libcrypto on one
  side - a number of bytes, an entropy strength, a seed of at least this and at
  most that many bytes, `OSSL_PARAM` arrays whose types and sizes it has to
  check rather than believe - and from the ESDM interface it talks to on the
  other.

Below all of them sits the library, which is also used directly by everything
listed above - so it gets a harness of its own rather than only being reached
through the server. And one harness puts the two sides together: it brings up
the server's real accept loop and worker threads on one side and the client
library on the other, in one process, so an input is a sequence of ordinary
client calls that travel over a socket and come back. That is the only harness
covering the client's packing of a request, and the only one where what the
server does with a request guides a fuzzer working on the calls that produced
it.

| Harness | What one input is | Speed |
| --- | --- | --- |
| `rpc_request_fuzz` | selector byte, then a request - framed by the harness or raw off the socket | slow - a request that parses is served by a live ESDM |
| `rpc_response_fuzz` | selector byte, then a response - framed or raw | fast |
| `rpc_protocol_fuzz` | mode byte, then a message for the codec | fastest - no ESDM, no sockets |
| `rpc_client_fuzz` | a script of client library calls with their arguments | slow - every call is a round trip to a real server |
| `egd_fuzz` | a byte stream and the reads it arrives in | slow - a read command is served by a live ESDM |
| `egd_client_fuzz` | a script of client calls, then the answers an impostor server gives them | slow - every call is a round trip over a socket |
| `esdm_lib_fuzz` | a script of API calls with their arguments | slow - the calls do the work they are asked for |
| `ossl_rng_prov_fuzz` | a script of provider calls with their arguments | slow - every call is a round trip to a real server |
| `ossl_rng_prov_pr_fuzz` | the same, against the prediction resistance build | slowest - each request collects fresh entropy |
| `ossl_seed_src_prov_fuzz` | the same, against the SEED-SRC only build | slow |
| `ossl_egd_prov_fuzz` | a script of provider calls, then the answers an impostor server gives them | slow - every call is a round trip over a socket |
| `ossl_egd_prov_pr_fuzz` | the same, against the prediction resistance build | slow |

`egd_client_fuzz` is the same socket seen from the other side. The harness is
the server: it answers the client's calls with the bytes of the input rather
than with the protocol, cut into the reads they arrive in, so what is fuzzed is
what a consumer of `libesdm_egd_client` is handed when the socket it found is
not the ESDM. The peer in `tests/egd` is not reused for it - that one serves
the protocol correctly with a menu of canned deviations, which is what a test
wants and the opposite of what a fuzzer needs. It binds a socket of its own
named after its process, so several of it may run side by side.

The EGD server one is a stream with no framing above the commands themselves - no
length prefix over a message, no request ID, no error response - so its parser
has nothing to resynchronize on, and a client may split a command across as
many reads as it likes. Its harness therefore fuzzes the reads as well as the
bytes: an input is a sequence of records, each a length byte and that many
bytes, and each record is one read the connection sees. Command by command is
the ordinary case; half a write command followed by the rest of it two reads
later is what the state machine has to survive.

## The OpenSSL providers

A provider is a library loaded into a process that is not ours, and the ESDM
ships five of them: two speaking the RPC protocol (all four RAND algorithms,
and the variant routing every request to the prediction resistance generator),
one offering SEED-SRC alone, and two speaking the EGD protocol (the ordinary
socket and the prediction resistance one). Each gets a harness, because what
differs between them is exactly what the harness looks at: the interface they
reach the ESDM through, whether prediction resistance is a per-request flag or
a property of the socket, and the table of algorithms the operation query hands
back.

The provider is loaded the way libcrypto loads it - `OSSL_PROVIDER_add_builtin()`
and `OSSL_PROVIDER_load()`, so `OSSL_provider_init()` runs with the real core
upcalls and the error stack really works - and a wrapper around the init
function keeps the dispatch table on the way through. The calls then go
straight into that table, which is what lets an input choose arguments no
application would produce: a seed request of `INT_MAX` bits, a minimum length
above the maximum, an `OSSL_PARAM` that claims to be an integer in a buffer of
one byte, a context of `NULL`. One call per input goes through `EVP_RAND` as
well, since that is the path an application takes and it converts arguments on
the way.

The provider is loaded and torn down once per input, so the initialization and
the teardown are fuzzed alongside the calls between them, and each input gets a
peer that has not answered anything yet. For the EGD harnesses that peer is an
impostor: it answers with the tail of the input rather than with the protocol,
in records that are one write each, the same shape `egd_client_fuzz` uses. For
the RPC ones it is a whole ESDM with the server's accept loop and worker
threads, in this process - so those bind the two RPC sockets and, like
`rpc_client_fuzz`, only one of them runs at a time.

## Reaching past the framing

Every RPC surface is guarded by a header the fuzzer would have to guess: a
method index that names a call, a length prefix that agrees with the message
behind it. Left to guess, nearly every input dies there.

So each RPC harness takes both shapes, picked by a bit of the selector byte.
**Framed**: the harness writes the header and the fuzzer's bytes are the
protobuf message, so every input reaches a call. **Raw**: the input is the
buffer as it comes off the socket, so the framing itself is what is fuzzed -
which is where a length prefix that disagrees with its message comes from, and
that is the shape of the bug this found in the client. Neither shape covers the
other, hence both.

The request, client and library harnesses compile the ESDM from its sources
instead of linking the prebuilt library, so the fuzzer is guided by what the
ESDM does with an input rather than only by what the RPC layer in front of it
does.

`rpc_client_fuzz` and the three RPC provider harnesses bind the RPC sockets,
whose paths are fixed at build time, so only one of them can run at a time - no `-jobs`, and not next to anything else
that starts a server, the test suite included: while it runs it *is* a running
ESDM server, and the tests that check what happens without one will fail. It needs no privileges: the server side skips only the
privilege drop, and the privileged calls are refused after their request was
decoded unless the harness happens to run as root, which is the part being
fuzzed either way.

That the paths are fixed also means a machine already running an esdm-server
owns them, and then these harnesses cannot bind: the sockets are there, but
they are somebody else's. They say so and stand down with exit code 77, which
`meson test` reports as a skipped test - the alternative is worse than a
failure, as a harness that carried on would send every call at a socket nobody
is accepting on, spend the client's ten connect attempts of a quarter second
each, and produce a run that looks like it is working while testing nothing.
Stop the esdm-server, or give the run a mount namespace with a private `/run`:

    unshare -r -m -i --propagation private /bin/sh -c \
        'mount -t tmpfs tmpfs /dev/shm; mount -t tmpfs tmpfs /run; exec "$@"' \
        _ build-fuzz/tests/fuzz/rpc_client_fuzz corpus

The same namespace answers the ESDM's status segment and its named semaphores,
which are fixed names as well and are held by a server that has run as root.

## Building

    CC=clang meson setup build-fuzz -Dfuzzing=enabled \
        -Dopenssl-rand-provider=enabled \
        -Db_sanitize=address,undefined -Db_lundef=false
    ninja -C build-fuzz

The provider harnesses come with `openssl-rand-provider`; without it the rest
is built just the same.

`b_lundef=false` is what lets the sanitizer runtime stay undefined in the
shared libraries at link time; without it the link of every library fails.

The option is off by default: it adds the entry points that hand a buffer to
the request and response handling without a connection behind it, which nothing
in production has a use for.

Use the sanitizers. A fuzzer without them only finds the crashes that are fatal
anyway, and the interesting failures here - a length prefix taken on trust, a
payload pointing past the receive buffer - are reads that a plain build gets
away with.

Two things about such a build are worth knowing before a finding is blamed on
the code:

* The harnesses are compiled with `-fno-sanitize=function` where the compiler
  knows the option. protobuf-c hands a call to a closure of a generic type and
  the generated code calls it through the type of the message it carries, which
  is its RPC design rather than anything this tree writes; clang 17 and newer
  check indirect calls against the callee's type and report every one of them.
  Left on, the first one fails the seed replays under `meson test`, which halts
  on the first finding, and a fuzzing run buries a real report under thousands
  of these.
* The rest of the test suite is not built that way and several of its binaries
  compile the same sources they also link, which the address sanitizer reports
  as ODR violations at startup. `ASAN_OPTIONS=detect_odr_violation=0` runs them
  in such a build; the fuzz binaries themselves are unaffected.

With clang each harness is built twice: `<name>_fuzz` is the libFuzzer binary,
`<name>_fuzz_replay` runs the harness without an engine. With a compiler that
has no libFuzzer only the replay binary is built, and everything below except
the fuzzing itself still works.

## Under concurrent load

`rpc_stress_test` is not a fuzzer: it drives the same request path from several
threads at once, which no fuzzer does - it feeds one input at a time. Every
thread sends valid requests across both interfaces and every call they offer,
with garbage interleaved, and each valid request carries a request ID the
answer has to carry back. An answer bearing another thread's ID is a request
that got mixed up on the way, which is what a buffer shared between the worker
threads would look like. It runs in the ordinary test suite, a few seconds of
load; `ESDM_STRESS_THREADS` and `ESDM_STRESS_REQUESTS` turn the same binary
into as long a run as you care to give it:

    ESDM_STRESS_THREADS=16 ESDM_STRESS_REQUESTS=500000 \
        build-fuzz/tests/fuzz/rpc_stress_test

## Running

    mkdir corpus
    build-fuzz/tests/fuzz/rpc_response_fuzz_replay --dump-corpus corpus
    build-fuzz/tests/fuzz/rpc_response_fuzz corpus

Give the slower harnesses time. On four cores of a laptop, with the address and
undefined behaviour sanitizers on, a run of 25 minutes got through 208 million
inputs of the codec harness, 63 million of the response one and 47 thousand of
the EGD server one - the last of those serves every read command from a live
ESDM, which generates the bytes it hands back. The client and library harnesses
are of that order too: their calls do the work they are asked for, and the
client ones wait for an answer over a socket. An hour of those is a short run,
not a long one.

The seeds come from the harness rather than from checked-in files: the request
seeds are built from the service descriptors, so a call added to the protocol
brings its seed along instead of being fuzzed through inputs that never name
it. Dump them into a corpus directory before the first run - they are what gets
the fuzzer past the length and type checks in the first seconds rather than the
first hour.

`ESDM_FUZZ_VERBOSE=1` turns the ESDM logging back on for the harnesses that
have some, which is for looking at one input rather than for fuzzing.

## Reproducing a finding

    build-fuzz/tests/fuzz/rpc_response_fuzz crash-<hash>

The replay binary takes the same file and needs no engine, so a finding can be
run against a build made with any compiler:

    build/tests/fuzz/rpc_response_fuzz_replay crash-<hash>

One caveat for `esdm_lib_fuzz`, `rpc_request_fuzz`, `rpc_client_fuzz` and the
RPC provider harnesses: they bring up one ESDM per process and every input leaves its state behind, so a finding that needs
what an earlier input did may not reproduce from its artifact alone. That is
why an input there is a sequence of calls rather than a single one - what a
crash needs is more likely to be inside it - and why a finding worth keeping
belongs in the seeds, where the sequence is spelled out.

## What is checked

Crashing is not the only failure. A harness also holds the code to what it
promised:

* `rpc_response_fuzz` rejects a response that hands its caller more bytes than
  the response carried. Those bytes come out of the receive buffer, so they are
  whatever sat in it before - for the random calls, data generated for somebody
  else. This is how the missing check on a rejected response header was found,
  and the two `length-beyond-*` seeds keep it found.
* `rpc_protocol_fuzz` holds the hand-rolled encoder and decoder to each other:
  what the decoder accepts, the encoder must be able to write back, and
  decoding that again must yield the same values.
* `rpc_client_fuzz` does the same for every buffer a client call fills, and
  additionally holds a call to the length it was given: a client is handed the
  answer of another process, and how much of it lands in the caller's buffer is
  decided from what that answer says about itself. That is how the answer an
  interrupted call left on the connection was found - the next call reported a
  length that belonged to the abandoned one - and the `abandoned-answer` seed,
  which spells the sequence out, keeps it found.
* `egd_client_fuzz` holds the client to what its header promises: nothing
  written behind the buffer a call was given, no call reporting more bytes than
  it was asked for, and - the one this is really for - a failed transfer
  leaving the buffer cleansed. The protocol lets a peer announce a length and
  then send less, and a partial answer left behind is one the caller cannot
  tell from a complete one. It also requires a PID handed back to be one: the
  answer is text of the peer's choosing, and a number too large for a `pid_t`
  used to be truncated into whatever it became - which is how the
  `get-pid-beyond-pid-t` seed came about, and what keeps it found.
* `esdm_lib_fuzz` hands every call a buffer with a guard behind it and checks
  the guard afterwards, and it requires every call handing back text to
  terminate it inside the buffer it was given - a caller reads that buffer as a
  string, so an unterminated one is a read past the end rather than a short
  answer.
* The provider harnesses hold their provider to the contract of
  `<openssl/core_dispatch.h>`, which is where a bug there would do its damage:
  nothing written behind the buffer a call was given and no `OSSL_PARAM` filled
  past its `data_size`; a `generate()` or `nonce()` that failed leaving no
  partial random data behind, since a caller cannot tell that from a complete
  answer; `get_seed()` handing back either nothing at all or a buffer of at
  least `min_len` and at most `max_len` bytes that really is that large - the
  returned length is what a seed consumer sizes its pool by, so the harness
  reads the whole of it and lets the sanitizer decide; a failed `get_seed()`
  leaving the caller's pointer `NULL` rather than a buffer it would go on to
  free; and the EGD provider bound to the ordinary socket refusing every
  request asking for prediction resistance, rather than serving data that does
  not have the property that was asked for. Holding `enable_locking()` to being
  callable twice is how the leaked lock was found.

## In the test suite

The replay binaries run as ordinary tests (`Fuzz seeds - ...`), so the
harnesses keep compiling and their seeds keep passing between fuzzing runs. A
crash worth keeping should become a seed in the harness that found it.
