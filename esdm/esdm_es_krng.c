/*
 * ESDM Fast Entropy Source: Linux kernel RNG
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#define _DEFAULT_SOURCE
#include <errno.h>
#include <limits.h>
#include <sys/random.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include "atomic.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_krng.h"
#include "esdm_es_sched.h"
#include "logger.h"

/*
 * Shall we use select() to wait for an initialization of the kernel RNG or
 * shall we use getrandom(GRNG_NOBLOCK) and adjust the entropy rate
 * accordingly?
 */
#undef ESDM_KRNG_ES_SELECT

#ifdef ESDM_KRNG_ES_SELECT
static uint32_t krng_entropy = 0;
static atomic_t esdm_krng_cancel = ATOMIC_INIT(0);

static void esdm_krng_adjust_entropy(void)
{
	uint32_t entropylevel;

	krng_entropy = esdm_config_es_krng_entropy_rate();

	entropylevel = esdm_krng_properties_entropylevel(krng_entropy);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "Kernel RNG is fully seeded, setting entropy rate to %u bits of entropy\n",
	       entropylevel);

	/* Do not trigger a reseed if the DRNG manger is not available */
	if (!esdm_get_available())
		return 0;

	esdm_drng_force_reseed();
	if (entropylevel)
		esdm_es_add_entropy();
}

/*
 * Initialize the entropy source: set entropy rate to zero and wait until
 * the kernel tells us that sufficient entropy is available on /dev/random
 */
static int esdm_krng_init(void)
{
	struct timeval timeout;
	fd_set fds;
	int ret = 0, fd = -1;

#define DEVRANDOM	"/dev/random"
	fd = open(DEVRANDOM, O_RDONLY);
	if (fd < 0) {
		int errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_ES, "Open of %s failed: %s\n",
		       DEVRANDOM, strerror(errno));
		return -errsv;
	}

	/* Select shall return after 100ms to check for cancel flag. */
	timeout.tv_sec = 0;
	timeout.tv_usec = 100 * 1000;

	FD_ZERO(&fds);
	logger(LOGGER_DEBUG, LOGGER_C_ES, "Polling %s\n", DEVRANDOM);

	/* only /dev/random implements polling */
	do {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		ret = select((fd + 1), &fds, NULL, NULL, &timeout);

		if (ret == -1 && errno != EINTR) {
			logger(LOGGER_ERR, LOGGER_C_ES,
			       "Select returned with error %s\n",
			       strerror(errno));
			break;
		}

		if (ret > 0) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Wakeup call for select on %s\n", DEVRANDOM);
			esdm_krng_adjust_entropy();
			break;
		}

		if (atomic_read(&esdm_krng_cancel))
			break;

	} while (errno == EINTR);

	close(fd);
	return 0;
}

static void esdm_krng_fini(void)
{
	atomic_set(&esdm_krng_cancel, 1);
}

#else /* ESDM_KRNG_ES_SELECT */

static uint32_t krng_entropy = ESDM_KERNEL_RNG_ENTROPY_RATE;

static int esdm_krng_init(void)
{
	/* Do not trigger a reseed if the DRNG manger is not available */
	if (!esdm_get_available())
		return 0;

	esdm_drng_force_reseed();
	if (esdm_config_es_krng_entropy_rate())
		esdm_es_add_entropy();

	return 0;
}

static void esdm_krng_fini(void) { }

#endif /* ESDM_KRNG_ES_SELECT */

/*
 * This function adjusts the entropy level depending on system properties
 */
static uint32_t esdm_krng_properties_entropylevel(uint32_t entropylevel)
{
	/*
	 * If FIPS mode is enabled, we cannot claim that the kernel provides
	 * entropy as the kernel is not SP800-90B compliant.
	 */
	return esdm_config_fips_enabled() ||
	/*
	 * If the scheduler-based entropy source is enabled, the kernel is
	 * claimed to not return any entropy. This is due to the fact that
	 * interrupts may trigger scheduling events. This implies that
	 * interrupts are not independent of interrupts.
	 */
	       esdm_sched_enabled() ? 0 : entropylevel;
}

static uint32_t esdm_krng_entropylevel(uint32_t requested_bits)
{
	uint32_t entropylevel = krng_entropy;

	/*
	 * If a specific entropy value is configured, use it instead of the
	 * heuristic.
	 */
	if (esdm_config_es_krng_entropy_rate() !=
	    ESDM_KERNEL_RNG_ENTROPY_RATE)
		entropylevel = esdm_config_es_krng_entropy_rate();
	return esdm_fast_noise_entropylevel(
		esdm_krng_properties_entropylevel(entropylevel),
		requested_bits);
}

static uint32_t esdm_krng_poolsize(void)
{
	return esdm_krng_entropylevel(esdm_security_strength());
}

static inline ssize_t __getrandom(uint8_t *buffer, size_t bufferlen,
				  unsigned int flags)
{
	ssize_t ret, totallen = 0;

	if (bufferlen > INT_MAX)
		return -EINVAL;

	do {
#ifdef USE_GLIBC_GETRANDOM
		ret = getrandom(buffer, bufferlen, flags);
#else
		ret = syscall(__NR_getrandom, buffer, bufferlen, flags);
#endif
		if (ret > 0) {
			bufferlen -= (size_t)ret;
			buffer += ret;
			totallen += ret;
		}
	} while ((ret > 0 || errno == EINTR) && bufferlen);

	return ((ret < 0) ? -errno : totallen);
}


/*
 * esdm_krng_get() - Get kernel RNG entropy
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 */
static void esdm_krng_get(struct entropy_es *eb_es, uint32_t requested_bits,
			  bool __unused unused)
{
	uint32_t ent_bits = esdm_krng_entropylevel(requested_bits);
	ssize_t ret = __getrandom(eb_es->e, requested_bits >> 3, GRND_NONBLOCK);

	if (ret < 0) {
		if (ret == -EAGAIN) {
			logger(LOGGER_DEBUG, LOGGER_C_ES,
			       "Kernel RNG not yet initialized, implying 0 bits of entropy\n");
		} else {
			logger(LOGGER_WARN, LOGGER_C_ES,
			       "Gathering of random numbers from kernel failed with error: %zd\n",
			       ret);
		}
		eb_es->e_bits = 0;
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "obtained %u bits of entropy from kernel RNG noise source\n",
		       ent_bits);
		eb_es->e_bits = ent_bits;
	}
}

static void esdm_krng_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_krng_poolsize(),
		 esdm_krng_entropylevel(256));
}

struct esdm_es_cb esdm_es_krng = {
	.name			= "KernelRNG",
	.init			= esdm_krng_init,
	.fini			= esdm_krng_fini,
	.monitor_es		= NULL,
	.get_ent		= esdm_krng_get,
	.curr_entropy		= esdm_krng_entropylevel,
	.max_entropy		= esdm_krng_poolsize,
	.state			= esdm_krng_es_state,
	.reset			= NULL,
	.switch_hash		= NULL,
};
