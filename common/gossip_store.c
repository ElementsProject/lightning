#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <inttypes.h>
#include <unistd.h>
#include <wire/peer_wire.h>

static bool timestamp_filter(u32 timestamp_min, u32 timestamp_max,
			     u32 timestamp)
{
	/* BOLT #7:
	 *
	 *   - SHOULD send all gossip messages whose `timestamp` is greater or
	 *    equal to `first_timestamp`, and less than `first_timestamp` plus
	 *    `timestamp_range`.
	 */
	/* Note that we turn first_timestamp & timestamp_range into an inclusive range */
	return timestamp >= timestamp_min
		&& timestamp <= timestamp_max;
}

static size_t reopen_gossip_store(int *gossip_store_fd, const u8 *msg)
{
	u64 equivalent_offset;
	int newfd;

	if (!fromwire_gossip_store_ended(msg, &equivalent_offset))
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Bad gossipd GOSSIP_STORE_ENDED msg: %s",
			      tal_hex(tmpctx, msg));

	newfd = open(GOSSIP_STORE_FILENAME, O_RDONLY);
	if (newfd < 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot open %s: %s",
			      GOSSIP_STORE_FILENAME,
			      strerror(errno));

	status_debug("gossip_store at end, new fd moved to %"PRIu64,
		     equivalent_offset);

	close(*gossip_store_fd);
	*gossip_store_fd = newfd;
	return equivalent_offset;
}

u8 *gossip_store_next(const tal_t *ctx,
		      int *gossip_store_fd,
		      u32 timestamp_min, u32 timestamp_max,
		      bool push_only,
		      size_t *off, size_t *end)
{
	u8 *msg = NULL;

	while (!msg) {
		struct gossip_hdr hdr;
		u32 msglen, checksum, timestamp;
		bool push;
		int type, r;

		r = pread(*gossip_store_fd, &hdr, sizeof(hdr), *off);
		if (r != sizeof(hdr))
			return NULL;

		msglen = be32_to_cpu(hdr.len);
		push = (msglen & GOSSIP_STORE_LEN_PUSH_BIT);
		msglen &= GOSSIP_STORE_LEN_MASK;

		/* Skip any deleted entries. */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			*off += r + msglen;
			continue;
		}

		checksum = be32_to_cpu(hdr.crc);
		timestamp = be32_to_cpu(hdr.timestamp);
		msg = tal_arr(ctx, u8, msglen);
		r = pread(*gossip_store_fd, msg, msglen, *off + r);
		if (r != msglen)
			return NULL;

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: bad checksum at offset %zu"
				      ": %s",
				      *off, tal_hex(tmpctx, msg));

		/* Definitely processing it now */
		*off += sizeof(hdr) + msglen;
		if (*off > *end)
			*end = *off;

		type = fromwire_peektype(msg);
		/* end can go backwards in this case! */
		if (type == WIRE_GOSSIP_STORE_ENDED) {
			*off = *end = reopen_gossip_store(gossip_store_fd, msg);
			msg = tal_free(msg);
		/* Ignore gossipd internal messages. */
		} else if (type != WIRE_CHANNEL_ANNOUNCEMENT
			   && type != WIRE_CHANNEL_UPDATE
			   && type != WIRE_NODE_ANNOUNCEMENT) {
			msg = tal_free(msg);
		} else if (!push &&
			 !timestamp_filter(timestamp_min, timestamp_max,
					   timestamp)) {
			msg = tal_free(msg);
		} else if (!push && push_only) {
			msg = tal_free(msg);
		}
	}

	return msg;
}

size_t find_gossip_store_end(int gossip_store_fd, size_t off)
{
	/* We cheat and read first two bytes of message too. */
	struct {
		struct gossip_hdr hdr;
		be16 type;
	} buf;
	int r;

	while ((r = read(gossip_store_fd, &buf,
			 sizeof(buf.hdr) + sizeof(buf.type)))
	       == sizeof(buf.hdr) + sizeof(buf.type)) {
		u32 msglen = be32_to_cpu(buf.hdr.len) & GOSSIP_STORE_LEN_MASK;

		/* Don't swallow end marker! */
		if (buf.type == CPU_TO_BE16(WIRE_GOSSIP_STORE_ENDED))
			break;

		off += sizeof(buf.hdr) + msglen;
		lseek(gossip_store_fd, off, SEEK_SET);
	}
	return off;
}
