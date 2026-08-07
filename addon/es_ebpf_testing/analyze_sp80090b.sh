#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Analyze raw event time stamps collected with esdm-ebpf-collect using the
# NIST SP800-90B entropy assessment tool (ea_non_iid from
# https://github.com/usnistgov/SP800-90B_EntropyAssessment).
#
# The analysis follows the LRNG/ESDM methodology: the time stamp deltas are
# computed per CPU, the 8 (and 4) least significant bits are extracted and
# assessed with the non-IID track. The minimum of all per-CPU estimates is
# the min-entropy per event; the suggested entropy rate applies a safety
# divisor of 2 on top.
#
# Usage: analyze_sp80090b.sh <collect.bin> [<output-dir>]
#
# Environment:
#   EA_NON_IID  Path to the ea_non_iid binary (default: from PATH)

set -eu

COLLECT_BIN="${1:?Usage: $0 <collect.bin> [<output-dir>]}"
OUTDIR="${2:-$(mktemp -d esdm_90b_XXXXXX)}"
EA_NON_IID="${EA_NON_IID:-ea_non_iid}"

if ! command -v "${EA_NON_IID}" >/dev/null 2>&1; then
	echo "error: ea_non_iid not found - build the NIST SP800-90B" >&2
	echo "entropy assessment tool and set EA_NON_IID or PATH" >&2
	exit 1
fi

mkdir -p "${OUTDIR}"

# Split the raw records per CPU and convert the time stamps to delta symbol
# files (8 LSB: one byte per delta, 4 LSB: one byte per delta with 4
# significant bits).
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

total = 0
for cpu, stamps in sorted(per_cpu.items()):
    if len(stamps) < 2:
        continue
    deltas = [(b - a) & 0xFFFFFFFFFFFFFFFF
              for a, b in zip(stamps, stamps[1:])]
    total += len(deltas)
    with open(f"{outdir}/cpu{cpu}_delta_8lsb.bin", "wb") as f8:
        f8.write(bytes(d & 0xFF for d in deltas))
    with open(f"{outdir}/cpu{cpu}_delta_4lsb.bin", "wb") as f4:
        f4.write(bytes(d & 0x0F for d in deltas))

print(f"Prepared {total} deltas from {len(per_cpu)} CPUs")
EOF

# Run the non-IID assessment per CPU and bit width
run_ea() {
	local file="$1" bits="$2"

	# ea_non_iid prints "min(H_original, X * H_bitstring): <value>"
	"${EA_NON_IID}" "${file}" "${bits}" 2>/dev/null |
		awk '/min\(/ { print $NF }' | tail -n 1
}

echo ""
echo "Per-CPU min-entropy estimates (non-IID track):"
printf '%-8s %-24s %-24s\n' "CPU" "H per event (8 LSB)" "H per event (4 LSB)"

min_h=""
for f8 in "${OUTDIR}"/cpu*_delta_8lsb.bin; do
	[ -e "${f8}" ] || continue
	cpu=$(basename "${f8}" | sed 's/cpu\([0-9]*\)_.*/\1/')
	f4="${OUTDIR}/cpu${cpu}_delta_4lsb.bin"

	h8=$(run_ea "${f8}" 8)
	h4=$(run_ea "${f4}" 4)
	printf '%-8s %-24s %-24s\n' "${cpu}" "${h8:-n/a}" "${h4:-n/a}"

	for h in ${h8} ${h4}; do
		if [ -z "${min_h}" ] ||
		   awk -v a="${h}" -v b="${min_h}" 'BEGIN{exit !(a<b)}'; then
			min_h="${h}"
		fi
	done
done

if [ -z "${min_h}" ]; then
	echo "error: no assessment results produced" >&2
	exit 1
fi

# Suggested entropy rate: worst-case per-event min-entropy with a safety
# divisor of 2, expressed as entropy bits per 256 events.
rate=$(awk -v h="${min_h}" 'BEGIN{printf "%d", (h * 256) / 2}')

echo ""
echo "Worst-case min-entropy per event: ${min_h} bits"
echo "Suggested es_*_ebpf_entropy_rate (safety divisor 2): ${rate}"
echo ""
echo "Note: repeat the measurement on every deployment environment (idle"
echo "and under load) and use the minimum of all suggested rates."
