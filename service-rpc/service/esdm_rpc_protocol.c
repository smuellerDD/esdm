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

#include <errno.h>
#include <fcntl.h>

#include "buffer.h"
#include "esdm_rpc_protocol.h"

/* Allocate 8-byte aligned memory from thread local storage */
void *esdm_rpc_alloc(void *allocator_data, size_t size)
{
	struct buffer *tlh = allocator_data;
	uint8_t *new = tlh->buf + tlh->consumed;
	uint8_t *new_aligned = ALIGN_PTR_8(new, 8);

	/* Add any potential alignment offset to the required size */
	size += (unsigned long)new_aligned - (unsigned long)new ;

	/* If the size request overflows the available memory, return nothing */
	if (size > (tlh->len - tlh->consumed))
		return NULL;

	/* Adjust the consumed memory indicator */
	tlh->consumed += size;

	/* Return the aligned memory */
	return new_aligned;
}

/*
 * Do not free the thread local storage - at the end of the whole operation
 * the thread-local storage will be cleared anyway.
 */
void esdm_rpc_free(void *allocator_data, void *data)
{
	(void)allocator_data;
	(void)data;
	return;
}

void set_fd_nonblocking(int fd)
{
	int flags = fcntl (fd, F_GETFL);

	if (flags >= 0)
		fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

int
esdm_rpc_proto_get_descriptor(const ProtobufCService *service,
			      const struct esdm_rpc_proto_cs *received_data,
			      const ProtobufCMessageDescriptor **desc)
{
	const struct esdm_rpc_proto_cs_header *header = &received_data->header;
	uint32_t method_index = header->method_index;

	if (method_index >= service->descriptor->n_methods)
		return -EINVAL;

   	*desc = service->descriptor->methods[method_index].input;
	return 0;
}
