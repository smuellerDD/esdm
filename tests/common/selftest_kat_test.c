/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Tests for the known answer test comparison of selftest_kat.h, which every
 * crypto self test of the ESDM runs its vectors through.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "common_test.h"
#include "selftest_kat.h"

static void test_kat_check(void)
{
	static const uint8_t exp[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t act[sizeof(exp)];

	memcpy(act, exp, sizeof(act));
	CHECK_EQ(esdm_kat_check(act, exp, sizeof(exp)), 0);

	/* A result that differs anywhere is rejected */
	act[0] = (uint8_t)(act[0] ^ 0xff);
	CHECK_EQ(esdm_kat_check(act, exp, sizeof(exp)), -EFAULT);

	memcpy(act, exp, sizeof(act));
	act[sizeof(act) - 1] = (uint8_t)(act[sizeof(act) - 1] ^ 0x01);
	CHECK_EQ(esdm_kat_check(act, exp, sizeof(exp)), -EFAULT);

	/* A comparison that cannot be performed is not a passed test */
	memcpy(act, exp, sizeof(act));
	CHECK_EQ(esdm_kat_check(act, exp, 0), -EINVAL);
	CHECK_EQ(esdm_kat_check(NULL, exp, sizeof(exp)), -EINVAL);
	CHECK_EQ(esdm_kat_check(act, NULL, sizeof(exp)), -EINVAL);
	CHECK_EQ(esdm_kat_check(act, exp, ESDM_KAT_MAX_LEN + 1), -EINVAL);
}

static void test_kat_modify(void)
{
	static const uint8_t in[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t out[sizeof(in)];

	CHECK_EQ(esdm_kat_modify(out, in, sizeof(in)), 0);

	/* The first byte is modified, the rest is the input */
	CHECK(out[0] != in[0], "first byte unchanged: 0x%02x", out[0]);
	CHECK_MEM_EQ(out + 1, in + 1, sizeof(in) - 1);

	CHECK_EQ(esdm_kat_modify(out, in, 0), -EINVAL);
	CHECK_EQ(esdm_kat_modify(NULL, in, sizeof(in)), -EINVAL);
	CHECK_EQ(esdm_kat_modify(out, NULL, sizeof(in)), -EINVAL);
}

static void test_kat_check_differs(void)
{
	static const uint8_t exp[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t act[sizeof(exp)];

	/* The known answer from a modified input is a failure */
	memcpy(act, exp, sizeof(act));
	CHECK_EQ(esdm_kat_check_differs(act, exp, sizeof(exp)), -EFAULT);

	act[0] = (uint8_t)(act[0] ^ 0xff);
	CHECK_EQ(esdm_kat_check_differs(act, exp, sizeof(exp)), 0);

	CHECK_EQ(esdm_kat_check_differs(act, exp, 0), -EINVAL);
	CHECK_EQ(esdm_kat_check_differs(NULL, exp, sizeof(exp)), -EINVAL);
	CHECK_EQ(esdm_kat_check_differs(act, NULL, sizeof(exp)), -EINVAL);
}

/*
 * The two together as a self test uses them: the known answer of the vector,
 * followed by the run over an input whose first byte was modified.
 */
static void test_kat_round_trip(void)
{
	static const uint8_t in[8] = { 0x00, 0x11, 0x22, 0x33,
				       0x44, 0x55, 0x66, 0x77 };
	static const uint8_t exp[8] = { 0xff, 0xee, 0xdd, 0xcc,
					0xbb, 0xaa, 0x99, 0x88 };
	uint8_t mod[sizeof(in)];
	uint8_t act[sizeof(exp)];
	size_t i;

	/* A "computation" that inverts every byte of its input */
	for (i = 0; i < sizeof(in); i++)
		act[i] = (uint8_t)(in[i] ^ 0xff);
	CHECK_EQ(esdm_kat_check(act, exp, sizeof(exp)), 0);

	CHECK_EQ(esdm_kat_modify(mod, in, sizeof(mod)), 0);
	for (i = 0; i < sizeof(mod); i++)
		act[i] = (uint8_t)(mod[i] ^ 0xff);
	CHECK_EQ(esdm_kat_check_differs(act, exp, sizeof(exp)), 0);

	/* An implementation ignoring its input is caught by the second check */
	memcpy(act, exp, sizeof(act));
	CHECK_EQ(esdm_kat_check(act, exp, sizeof(exp)), 0);
	CHECK_EQ(esdm_kat_check_differs(act, exp, sizeof(exp)), -EFAULT);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_kat_check();
	test_kat_modify();
	test_kat_check_differs();
	test_kat_round_trip();

	return common_test_result("selftest_kat");
}
