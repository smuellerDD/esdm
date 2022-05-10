/*
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

#include "esdm.h"
#include "esdm_es_mgr.h"
#include "esdm_interface_dev_common.h"
#include "esdm_shm_status.h"

DECLARE_WAIT_QUEUE(esdm_write_wait);

/********************************** Helper ***********************************/

void esdm_writer_wakeup(void)
{
	esdm_shm_status_set_need_entropy();
	if (esdm_need_entropy() && thread_queue_sleeper(&esdm_write_wait))
		thread_wake(&esdm_write_wait);
}

/* Is the DRNG seed level too low? */
bool esdm_need_entropy(void)
{
	return (esdm_get_aux_ent() < esdm_write_wakeup_bits);
}
