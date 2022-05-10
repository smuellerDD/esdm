#!/bin/bash
#
# Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
# Stress test for parallel reads.

SPEED="./speedtest"

# Count the available CPUs nodes
CPUS=$(lscpu -b -p | grep -v "#" | wc -l)

urandom=0
random=0
wurandom=0
wrandom=0

# Cleanup
cleanup() {
	i=0
	while [ $i -lt $urandom ]
	do
		eval kill=\$dd_urandom_$i
		kill $kill > /dev/null 2>&1
		i=$(($i+1))
	done
	while [ $i -lt $random ]
	do
		eval kill=\$dd_random_$i
		kill $kill > /dev/null 2>&1
		i=$(($i+1))
	done

	rm -f $SPEED
}

init() {
	trap "cleanup; exit $?" 0 1 2 3 15
	gcc -Wall -pedantic -Wextra -Wl,--wrap=getrandom,--wrap=getentropy -lesdm-getrandom -L../../build/frontents/getrandom -o $SPEED ${SPEED}.c
}

init

measure_speed()
{
	local name=$@

	for i in 16 32 64 128 256 512 1024 4096
	do
		if [ -x "$SPEED" ]; then
			speed=$(LD_PRELOAD=../../build/frontends/getrandom/libesdm-getrandom.so $SPEED -b $i | cut -d "|" -f 2)
		else
			speed=$(dd if=$name of=/dev/null bs=$i count=100000 2>&1 | tail -n1 | awk '{print $(NF-1) " " $NF}')
		fi

		echo -e "$name\t$i\t$speed"
	done
}

if ! (ps -efa | grep -v grep | grep -q esdm-cuse-random)
then
	echo "Stress testing misses esdm-cuse-random"
	exit 77
fi
if ! (ps -efa | grep -v grep | grep -q esdm-cuse-urandom)
then
	echo "Stress testing misses esdm-cuse-urandom"
	exit 77
fi


# Start reading on all CPUs
while [ $urandom -lt $CPUS ]
do
	echo "spawn read load on /dev/urandom"
	( measure_speed /dev/urandom ) &
	eval dd_urandom_$urandom=$!
	urandom=$(($urandom+1))
done

# Start reading on all CPUs
while [ $random -lt $CPUS ]
do
	echo "spawn read load on /dev/random"
	( measure_speed /dev/random ) &
	eval dd_random_$random=$!
	random=$(($random+1))
done

# Start writing on all CPUs
while [ $wurandom -lt $CPUS ]
do
	echo "spawn write load on /dev/urandom"
	( dd if=/dev/zero of=/dev/urandom bs=4096 count=10000 > /dev/null 2>&1 ) &
	eval dd_urandom_$urandom=$!
	wurandom=$(($wurandom+1))
done

# Start writing on all CPUs
while [ $wrandom -lt $CPUS ]
do
	echo "spawn write load on /dev/random"
	( dd if=/dev/zero of=/dev/random bs=4096 count=10000 > /dev/null 2>&1 ) &
	eval dd_random_$random=$!
	wrandom=$(($wrandom+1))
done

wait

# Start reading on all CPUs
random=0
while [ $random -lt $CPUS ]
do
	echo "spawn read load on /dev/random"
	( measure_speed /dev/random ) &
	eval dd_random_$random=$!
	random=$(($random+1))
done

wait

ret=0

if ! (ps -efa | grep -v grep | grep -q esdm-cuse-random)
then
	echo "Stress testing causes termination of esdm-cuse-random"
	ret=$(($ret+1))
fi
if ! (ps -efa | grep -v grep | grep -q esdm-cuse-urandom)
then
	echo "Stress testing causes termination of esdm-cuse-urandom"
	ret=$(($ret+1))
fi

if [ $ret -eq 0 ]
then
	echo "Stress testing passed"
fi

exit $ret
