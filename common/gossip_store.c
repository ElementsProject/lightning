#include "config.h"
#include <ccan/crc32c/crc32c.h>
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

static bool public_msg_type(enum peer_wire type)
{
	/* This switch statement makes you think about new types as they
	 * are introduced. */
	switch (type) {
	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_WARNING:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_TX_SIGNATURES:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_READY:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_UPDATE_BLOCKHEIGHT:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_ONION_MESSAGE:
#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
#endif
		return false;
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
		return true;
	}

	/* Actually, we do have other (internal) messages. */
	return false;
}

u8 *gossip_store_next(const tal_t *ctx,
		      int *gossip_store_fd,
		      u32 timestamp_min, u32 timestamp_max,
		      bool push_only,
		      bool with_spam,
		      size_t *off, size_t *end)
{
	u8 *msg = NULL;
	size_t initial_off = *off;

	while (!msg) {
		struct gossip_hdr hdr;
		u32 msglen, checksum, timestamp;
		bool push, ratelimited;
		int type, r;

		r = pread(*gossip_store_fd, &hdr, sizeof(hdr), *off);
		if (r != sizeof(hdr))
			return NULL;

		msglen = be32_to_cpu(hdr.len);
		push = (msglen & GOSSIP_STORE_LEN_PUSH_BIT);
		ratelimited = (msglen & GOSSIP_STORE_LEN_RATELIMIT_BIT);
		msglen &= GOSSIP_STORE_LEN_MASK;

		/* Skip any deleted entries. */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			*off += r + msglen;
			continue;
		}

		/* Skip any timestamp filtered */
		timestamp = be32_to_cpu(hdr.timestamp);
		if (!push &&
		    !timestamp_filter(timestamp_min, timestamp_max,
				      timestamp)) {
			*off += r + msglen;
			continue;
		}

		/* Messages can be up to 64k, but we also have internal ones:
		 * 128k is plenty. */
		if (msglen > 128 * 1024)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: oversize msg len %u at"
				      " offset %zu (was at %zu)",
				      msglen, *off, initial_off);

		checksum = be32_to_cpu(hdr.crc);
		msg = tal_arr(ctx, u8, msglen);
		r = pread(*gossip_store_fd, msg, msglen, *off + r);
		if (r != msglen)
			return tal_free(msg);

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: bad checksum at offset %zu"
				      "(was at %zu): %s",
				      *off, initial_off, tal_hex(tmpctx, msg));

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
		} else if (!public_msg_type(type)) {
			msg = tal_free(msg);
		} else if (!push && push_only) {
			msg = tal_free(msg);
		} else if (!with_spam && ratelimited) {
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

	while ((r = pread(gossip_store_fd, &buf,
			 sizeof(buf.hdr) + sizeof(buf.type), off))
	       == sizeof(buf.hdr) + sizeof(buf.type)) {
		u32 msglen = be32_to_cpu(buf.hdr.len) & GOSSIP_STORE_LEN_MASK;

		/* Don't swallow end marker! */
		if (buf.type == CPU_TO_BE16(WIRE_GOSSIP_STORE_ENDED))
			break;

		off += sizeof(buf.hdr) + msglen;
	}
	return off;
}

/* Keep seeking forward until we hit something >= timestamp */
size_t find_gossip_store_by_timestamp(int gossip_store_fd,
				      size_t off,
				      u32 timestamp)
{
	/* We cheat and read first two bytes of message too. */
	struct {
		struct gossip_hdr hdr;
		be16 type;
	} buf;
	int r;

	while ((r = pread(gossip_store_fd, &buf,
			  sizeof(buf.hdr) + sizeof(buf.type), off))
	       == sizeof(buf.hdr) + sizeof(buf.type)) {
		u32 msglen = be32_to_cpu(buf.hdr.len) & GOSSIP_STORE_LEN_MASK;
		u16 type = be16_to_cpu(buf.type);

		/* Don't swallow end marker!  Reset, as they will call
		 * gossip_store_next and reopen file. */
		if (type == WIRE_GOSSIP_STORE_ENDED)
			return 1;

		/* Only to-be-broadcast types have valid timestamps! */
		if (!(be32_to_cpu(buf.hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT)
		    && public_msg_type(type)
		    && be32_to_cpu(buf.hdr.timestamp) >= timestamp) {
			break;
		}

		off += sizeof(buf.hdr) + msglen;
	}
	return off;
}
