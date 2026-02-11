#include "config.h"
#include <common/gossip_store.h>
#include <common/gossip_store_wiregen.h>
#include <unistd.h>

/* We cheat and read first two bytes of message too. */
struct hdr_and_type {
	struct gossip_hdr hdr;
	be16 type;
};
/* Beware padding! */
#define HDR_AND_TYPE_SIZE (sizeof(struct gossip_hdr) + sizeof(u16))

bool gossip_store_readhdr(int gossip_store_fd, size_t off,
			  size_t *len,
			  u32 *timestamp,
			  u16 *flags,
			  u16 *type)
{
	struct hdr_and_type buf;
	int r;

	r = pread(gossip_store_fd, &buf, HDR_AND_TYPE_SIZE, off);
	if (r != HDR_AND_TYPE_SIZE)
		return false;
	if (!(buf.hdr.flags & CPU_TO_BE16(GOSSIP_STORE_COMPLETED_BIT)))
		return false;
	*len = be16_to_cpu(buf.hdr.len);
	if (flags)
		*flags = be16_to_cpu(buf.hdr.flags);
	if (timestamp)
		*timestamp = be32_to_cpu(buf.hdr.timestamp);
	if (type)
		*type = be16_to_cpu(buf.type);
	return true;
}

size_t find_gossip_store_end(int gossip_store_fd, size_t off)
{
	size_t msglen;
	u16 type;

	while (gossip_store_readhdr(gossip_store_fd, off,
				    &msglen, NULL, NULL, &type)) {
		/* Don't swallow end marker! */
		if (type == WIRE_GOSSIP_STORE_ENDED)
			break;

		off += sizeof(struct gossip_hdr) + msglen;
	}
	return off;
}
