#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Prepare raw event time stamps collected with esdm-ebpf-collect for the
# AIS 20/31 statistical test procedures A and B.
#
# The BSI provides a reference implementation of the AIS 20/31 test
# procedures as a Java tool ("AIS31 reference implementation") available at
# https://www.bsi.bund.de - the tool is not redistributable here, so this
# script only converts the collected data into the bit stream format the
# reference implementation consumes and prints usage instructions.
#
# Usage: analyze_ais31.sh <collect.bin> [<output-dir>]

set -eu

COLLECT_BIN="${1:?Usage: $0 <collect.bin> [<output-dir>]}"
OUTDIR="${2:-$(mktemp -d esdm_ais31_XXXXXX)}"

mkdir -p "${OUTDIR}"

# Concatenate the 8 LSBs of the per-CPU delta streams into the byte stream
# assessed as the raw noise source output.
python3 - "${COLLECT_BIN}" "${OUTDIR}" <<'EOF'
import struct
import sys
from collections import defaultdict

infile, outdir = sys.argv[1], sys.argv[2]
per_cpu = defaultdict(list)

with open(infile, "rb") as f:
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            break
        rtype, cpu, ts = struct.unpack("<IIQ", rec)
        if rtype != 3:  # esdm_ebpf_rec_raw
            continue
        per_cpu[cpu].append(ts)

with open(f"{outdir}/ais31_input.bin", "wb") as out:
    n = 0
    for cpu, stamps in sorted(per_cpu.items()):
        deltas = bytes(((b - a) & 0xFF)
                       for a, b in zip(stamps, stamps[1:]))
        out.write(deltas)
        n += len(deltas)

print(f"Wrote {n} bytes to {outdir}/ais31_input.bin")
EOF

cat <<INSTRUCTIONS

Next steps:
 1. Obtain the BSI AIS 20/31 reference implementation.
 2. Run test procedure A (disjoint from startup: tests T0-T5) and test
    procedure B (tests T6-T8) on ${OUTDIR}/ais31_input.bin.
 3. For an NTG.1 claim, document the results together with the SP800-90B
    assessment (analyze_sp80090b.sh) in the entropy report.
INSTRUCTIONS
