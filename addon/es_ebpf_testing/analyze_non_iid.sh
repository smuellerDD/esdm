#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Example: SP800-90B non-IID assessment of one CPU of an eBPF entropy source.
#
# It drives the three tools the measurement needs:
#
#   esdm-ebpf-collect  writes the raw time between events as decimal ASCII
#   esdm-extractlsb         keeps the least significant bits of each delta and
#                      writes one byte per sample
#   ea_non_iid         estimates the per-event min-entropy (NIST
#                      SP800-90B_EntropyAssessment)
#
# The estimator's output is passed through as it stands - deriving the ESDM
# entropy rate and oversampling rate from it is left to the reader, who has
# to weigh the measurement against the deployment anyway.
#
# One CPU is assessed at a time: the time stamp streams of the individual
# CPUs are separate noise sources and may not be mixed. Repeat for every CPU
# that shall be credited and take the worst result.
#
# THIS IS EXAMPLE TOOLING FOR MEASUREMENT AND VALIDATION. The numbers it
# reports describe the machine it ran on - repeat the measurement in the
# deployment environment, idle and under load, before crediting anything.
#
# Usage: analyze_non_iid.sh [OPTIONS] <output-dir>
#
#   --source sched|irq  Entropy source to assess (default: sched)
#   --cpu N             CPU to assess (default: 0)
#   --events N          Deltas to collect (default: 1000000; the estimator
#                       warns below one million)
#
# Environment:
#   ESDM_EBPF_COLLECT  Path to esdm-ebpf-collect (default: from PATH)
#   EXTRACTLSB         Path to esdm-extractlsb (default: from PATH)
#   EA_NON_IID         Path to ea_non_iid (default: from PATH)

set -eu

SOURCE="sched"
CPU=0
EVENTS=1000000

while [ $# -gt 0 ]; do
	case "$1" in
	--source) SOURCE="${2:?}"; shift 2 ;;
	--cpu) CPU="${2:?}"; shift 2 ;;
	--events) EVENTS="${2:?}"; shift 2 ;;
	--help | -h) sed -n '3,32p' "$0"; exit 0 ;;
	--) shift; break ;;
	-*) echo "error: unknown option $1" >&2; exit 1 ;;
	*) break ;;
	esac
done

OUTDIR="${1:?Usage: $0 [OPTIONS] <output-dir>}"

ESDM_EBPF_COLLECT="${ESDM_EBPF_COLLECT:-esdm-ebpf-collect}"
EXTRACTLSB="${EXTRACTLSB:-esdm-extractlsb}"
EA_NON_IID="${EA_NON_IID:-ea_non_iid}"

for tool in "${ESDM_EBPF_COLLECT}" "${EXTRACTLSB}" "${EA_NON_IID}"; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "error: ${tool} not found - build ESDM with" >&2
		echo "-Des_ebpf_testing=enabled -Dvalidation-helpers=enabled and" >&2
		echo "the NIST SP800-90B_EntropyAssessment tools, or set the" >&2
		echo "ESDM_EBPF_COLLECT / EXTRACTLSB / EA_NON_IID variables" >&2
		exit 1
	fi
done

mkdir -p "${OUTDIR}"
RAW="${OUTDIR}/raw_${SOURCE}_cpu${CPU}.txt"
rm -f "${RAW}"

echo "Collecting ${EVENTS} deltas of CPU ${CPU} from the ${SOURCE} source ..."
"${ESDM_EBPF_COLLECT}" --source "${SOURCE}" --cpu "${CPU}" \
	--events "${EVENTS}" --out "${RAW}"

collected=$(wc -l <"${RAW}")
if [ "${collected}" -lt "${EVENTS}" ]; then
	echo "error: only ${collected} of ${EVENTS} deltas collected" >&2
	exit 1
fi

# The mask selects the bits esdm-extractlsb keeps of every delta - FF for the low
# 8, which is where the timing entropy sits and the width the NIST tools take
# a byte-sized symbol from.
run_ea() {
	local bits="$1" mask="$2"
	local bin="${OUTDIR}/raw_cpu${CPU}_${bits}lsb.bin"
	local log="${OUTDIR}/ea_non_iid_cpu${CPU}_${bits}lsb.log"

	rm -f "${bin}"
	"${EXTRACTLSB}" "${RAW}" "${bin}" "${EVENTS}" "${mask}" >"${log}" 2>&1

	echo ""
	echo "=== ea_non_iid, ${bits} LSB, CPU ${CPU} of the ${SOURCE} source ==="

	# stderr goes into the log along with the output, so a failing run can
	# be told apart from one that simply had nothing to say.
	"${EA_NON_IID}" "${bin}" "${bits}" 2>&1 | tee -a "${log}"
}

run_ea 8 FF

echo ""
echo "The estimate is min(H_original, ...), in bits per event. Take the"
echo "minimum over every CPU and every load profile, and validate it with the"
echo "restart test of SP800-90B section 3.1.4 before crediting anything:"
echo ""
echo "    ./analyze_restart.sh --source ${SOURCE} --cpu ${CPU} <H_I> ${OUTDIR}"
echo ""
echo "Log: ${OUTDIR}/ea_non_iid_cpu${CPU}_8lsb.log"
