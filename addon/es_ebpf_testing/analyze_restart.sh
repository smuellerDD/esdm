#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Example: SP800-90B section 3.1.4 restart test of one CPU of an eBPF entropy
# source.
#
# The test validates the initial estimate H_I - what analyze_non_iid.sh
# measured - against the samples the source delivers immediately after a
# restart, when it has the least state to draw on. It needs a 1000 x 1000
# matrix: 1000 restarts of 1000 samples each. Anything smaller is not a valid
# restart test.
#
# One row is one run of esdm-ebpf-collect. Every run loads and attaches its
# own copy of the eBPF programs, so each row starts from a freshly
# initialized source - zeroed per-CPU state, no previous time stamp and an
# unlearned timer granularity - which is the state the entropy source is in
# when the ESDM server has just started. A restart here is a restart of the
# entropy source, not of the system.
#
# Expect this to take a long time: it is 1000 program loads plus 1000
# collections.
#
# THIS IS EXAMPLE TOOLING FOR MEASUREMENT AND VALIDATION.
#
# Usage: analyze_restart.sh [OPTIONS] <H_I> <output-dir>
#
#   --source sched|irq  Entropy source to assess (default: sched)
#   --cpu N             CPU to assess (default: 0)
#   --restarts N        Matrix rows (default: 1000 - what SP800-90B wants)
#   --samples N         Matrix columns (default: 1000)
#   --bits 8|4          Bits kept per delta; has to match the stream H_I was
#                       measured on (default: 8)
#
# Environment:
#   ESDM_EBPF_COLLECT  Path to esdm-ebpf-collect (default: from PATH)
#   EXTRACTLSB         Path to esdm-extractlsb (default: from PATH)
#   EA_RESTART         Path to ea_restart (default: from PATH)

set -eu

SOURCE="sched"
CPU=0
RESTARTS=1000
SAMPLES=1000
BITS=8

while [ $# -gt 0 ]; do
	case "$1" in
	--source) SOURCE="${2:?}"; shift 2 ;;
	--cpu) CPU="${2:?}"; shift 2 ;;
	--restarts) RESTARTS="${2:?}"; shift 2 ;;
	--samples) SAMPLES="${2:?}"; shift 2 ;;
	--bits) BITS="${2:?}"; shift 2 ;;
	--help | -h) sed -n '3,37p' "$0"; exit 0 ;;
	--) shift; break ;;
	-*) echo "error: unknown option $1" >&2; exit 1 ;;
	*) break ;;
	esac
done

H_I="${1:?Usage: $0 [OPTIONS] <H_I> <output-dir>}"
OUTDIR="${2:?Usage: $0 [OPTIONS] <H_I> <output-dir>}"

ESDM_EBPF_COLLECT="${ESDM_EBPF_COLLECT:-esdm-ebpf-collect}"
EXTRACTLSB="${EXTRACTLSB:-esdm-extractlsb}"
EA_RESTART="${EA_RESTART:-ea_restart}"

case "${BITS}" in
8) MASK="FF" ;;
4) MASK="F" ;;
*) echo "error: --bits must be 8 or 4" >&2; exit 1 ;;
esac

for tool in "${ESDM_EBPF_COLLECT}" "${EXTRACTLSB}" "${EA_RESTART}"; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "error: ${tool} not found - build ESDM with" >&2
		echo "-Des_ebpf_testing=enabled -Dvalidation-helpers=enabled and" >&2
		echo "the NIST SP800-90B_EntropyAssessment tools, or set the" >&2
		echo "ESDM_EBPF_COLLECT / EXTRACTLSB / EA_RESTART variables" >&2
		exit 1
	fi
done

if [ "${RESTARTS}" -ne 1000 ] || [ "${SAMPLES}" -ne 1000 ]; then
	echo "WARNING: SP800-90B section 3.1.4 requires a 1000 x 1000 matrix -" >&2
	echo "a ${RESTARTS} x ${SAMPLES} run supports no entropy claim." >&2
fi

mkdir -p "${OUTDIR}"
MATRIX="${OUTDIR}/restart_${SOURCE}_cpu${CPU}.bin"
ROW_TXT="${OUTDIR}/.restart_row.txt"
ROW_BIN="${OUTDIR}/.restart_row.bin"
LOG="${OUTDIR}/ea_restart_cpu${CPU}.log"

rm -f "${MATRIX}" "${ROW_TXT}" "${ROW_BIN}"
trap 'rm -f "${ROW_TXT}" "${ROW_BIN}"' EXIT

echo "Collecting ${RESTARTS} restarts of ${SAMPLES} samples from CPU ${CPU}"
echo "of the ${SOURCE} source (${BITS} bit symbols) ..."

i=0
while [ "${i}" -lt "${RESTARTS}" ]; do
	rm -f "${ROW_TXT}" "${ROW_BIN}"

	# A fresh program load per row is what makes this a restart test.
	"${ESDM_EBPF_COLLECT}" --source "${SOURCE}" --cpu "${CPU}" \
		--events "${SAMPLES}" --out "${ROW_TXT}" 2>/dev/null

	"${EXTRACTLSB}" "${ROW_TXT}" "${ROW_BIN}" "${SAMPLES}" "${MASK}" \
		>/dev/null

	# A short row would shift every following one, so the matrix ea_restart
	# reads would no longer be the one that was collected.
	got=$(wc -c <"${ROW_BIN}")
	if [ "${got}" -ne "${SAMPLES}" ]; then
		echo "" >&2
		echo "error: restart $((i + 1)) yielded ${got} of ${SAMPLES}" >&2
		echo "samples - is the machine too quiet for this source?" >&2
		exit 1
	fi

	cat "${ROW_BIN}" >>"${MATRIX}"

	i=$((i + 1))
	if [ $((i % 50)) -eq 0 ]; then
		printf '\r  %d/%d restarts' "${i}" "${RESTARTS}"
	fi
done
printf '\r  %d/%d restarts\n' "${RESTARTS}" "${RESTARTS}"

echo ""
echo "=== ea_restart, ${BITS} bit symbols, H_I = ${H_I} ==="
"${EA_RESTART}" "${MATRIX}" "${BITS}" "${H_I}" 2>&1 | tee "${LOG}"

echo ""
echo "Matrix: ${MATRIX}"
echo "Log:    ${LOG}"

# The exit status is the one thing not in the output: ea_restart reports the
# verdict in prose, and a caller should not have to grep for it.
if grep -qi "sanity check failed" "${LOG}"; then
	echo "" >&2
	echo "The restart data is degenerate - rows or columns that repeat." >&2
	echo "The source may not be credited at all." >&2
	exit 1
elif grep -q "Validation Test Passed" "${LOG}"; then
	exit 0
else
	echo "" >&2
	echo "The restart test did not pass: the estimate is not supported by" >&2
	echo "the restart data and may not be used." >&2
	exit 1
fi
