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

#ifndef _ESDM_ES_PCSC_H
#define _ESDM_ES_PCSC_H

#include "esdm_es_ext.h"

#define ESDM_ES_PCSC_CHALLENGE_LEN 32

/*
 * Set before the init of the source
 *
 * @reader: A part of the name of the reader, NULL for the first one with a card
 * @challenge_len: Bytes asked for with one GET CHALLENGE, 1 to 255
 */
extern struct esdm_es_pcsc_config {
	const char *reader;
	unsigned int challenge_len;
} esdm_es_pcsc_config;

extern const struct esdm_es_ext_plugin esdm_es_pcsc_plugin;

#endif /* _ESDM_ES_PCSC_H */
