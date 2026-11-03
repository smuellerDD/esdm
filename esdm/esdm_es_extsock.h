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

#ifndef _ESDM_ES_EXTSOCK_H
#define _ESDM_ES_EXTSOCK_H

#include <errno.h>
#include <stdint.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"
#include "visibility.h"

#ifdef ESDM_ES_EXT

/*
 * A provider not there, or lost, is connected to on demand, at most once per
 * this many seconds - nor is a failing provider probed more often
 */
#ifndef ESDM_EXT_RETRY_INTERVAL_SEC
#define ESDM_EXT_RETRY_INTERVAL_SEC 5
#endif

/* The longest a request may take: a DRNG waits for its seed meanwhile */
#ifndef ESDM_EXT_TIMEOUT_MS
#define ESDM_EXT_TIMEOUT_MS 2000
#endif

/*
 * The longest the ESDM status waits for the STATUS of a provider - a seeding
 * waiting behind it still has time for its own request
 */
#ifndef ESDM_EXT_STATUS_TIMEOUT_MS
#define ESDM_EXT_STATUS_TIMEOUT_MS (ESDM_EXT_TIMEOUT_MS / 4)
#endif

/* STATUS is asked for at most once per this many seconds */
#ifndef ESDM_EXT_STATUS_INTERVAL_SEC
#define ESDM_EXT_STATUS_INTERVAL_SEC 5
#endif

extern struct esdm_es_cb esdm_es_extsock;

/**
 * @brief The socket of the provider, in place of the meson option es_ext_path
 *
 * Set before esdm_init() - esdm-server --es_ext - or later, which reconnects
 * at once; "" restores the default. Kept across esdm_fini().
 *
 * @return 0, -EINVAL for a NULL path or one too long, -ENOMEM
 */
DSO_PUBLIC
int esdm_es_ext_set_path(const char *path);

/**
 * @brief A uid accepted for the provider next to root, -1 for root only
 *
 * The ESDM checks the uid of the provider it connects to: whoever creates the
 * socket file could otherwise feed it data credited as entropy. Default: the
 * meson option es_ext_peer_uid; from the next connection on.
 *
 * @return 0, -EINVAL for no uid_t but (uid_t)-1
 */
DSO_PUBLIC
int esdm_es_ext_set_peer_uid(int64_t uid);

#else /* ESDM_ES_EXT */

static inline int esdm_es_ext_set_path(const char *path)
{
	(void)path;
	return -ENOENT;
}

static inline int esdm_es_ext_set_peer_uid(int64_t uid)
{
	(void)uid;
	return -ENOENT;
}

#endif /* ESDM_ES_EXT */

#endif /* _ESDM_ES_EXTSOCK_H */
