#include <assert.h>
#include <ccan/crc/crc.h>
#include <common/gossip_store.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

u8 *gossip_store_next(const tal_t *ctx, struct per_peer_state *pps)
{
	u8 *msg = NULL;

	/* Don't read until we're initialized. */
	if (!pps->gs)
		return NULL;

	while (!msg) {
		struct gossip_hdr hdr;
		u32 msglen, checksum;
		int type;

		if (read(pps->gossip_store_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
			per_peer_state_reset_gossip_timer(pps);
			return NULL;
		}

		/* Skip any deleted entries. */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			/* Skip over it. */
			lseek(pps->gossip_store_fd,
			      be32_to_cpu(hdr.len) & ~GOSSIP_STORE_LEN_DELETED_BIT,
			      SEEK_CUR);
			continue;
		}

		msglen = be32_to_cpu(hdr.len);
		checksum = be32_to_cpu(hdr.crc);
		msg = tal_arr(ctx, u8, msglen);
		if (read(pps->gossip_store_fd, msg, msglen) != msglen)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: can't read len %u"
				      " ~offset %"PRIi64,
				      msglen,
				      (s64)lseek(pps->gossip_store_fd,
						 0, SEEK_CUR));

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: bad checksum offset %"
				      PRIi64": %s",
				      (s64)lseek(pps->gossip_store_fd,
						 0, SEEK_CUR) - msglen,
				      tal_hex(tmpctx, msg));

		/* Ignore gossipd internal messages. */
		type = fromwire_peektype(msg);
		if (type != WIRE_CHANNEL_ANNOUNCEMENT
		    && type != WIRE_CHANNEL_UPDATE
		    && type != WIRE_NODE_ANNOUNCEMENT)
			msg = tal_free(msg);
	}

	return msg;
}

/* newfd is at offset 1.  We need to adjust it to similar offset as our
 * current one. */
void gossip_store_switch_fd(struct per_peer_state *pps,
			    int newfd, u64 offset_shorter)
{
	u64 cur = lseek(pps->gossip_store_fd, SEEK_CUR, 0);

	/* If we're already at end (common), we know where to go in new one. */
	if (cur == lseek(pps->gossip_store_fd, SEEK_END, 0)) {
		status_debug("gossip_store at end, new fd moved to %"PRIu64,
			     cur - offset_shorter);
		assert(cur > offset_shorter);
		lseek(newfd, cur - offset_shorter, SEEK_SET);
	} else if (cur > offset_shorter) {
		/* We're part way through.  Worst case, we should move back by
		 * offset_shorter (that's how much the *end* moved), but in
		 * practice we'll probably end up retransmitting some stuff */
		u64 target = cur - offset_shorter;
		size_t num = 0;

		status_debug("gossip_store new fd moving back %"PRIu64
			     " to %"PRIu64,
			     cur, target);
		cur = 1;
		while (cur < target) {
			u32 msglen;
			struct gossip_hdr hdr;

			if (read(newfd, &hdr, sizeof(hdr)) != sizeof(hdr))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "gossip_store: "
					      "can't read hdr offset %"PRIu64
					      " in new store target %"PRIu64,
					      cur, target);
			/* Skip over it. */
			msglen = (be32_to_cpu(hdr.len)
				  & ~GOSSIP_STORE_LEN_DELETED_BIT);
			cur = lseek(newfd, msglen, SEEK_CUR);
			num++;
		}
		status_debug("gossip_store: skipped %zu records to %"PRIu64,
			     num, cur);
	} else
		status_debug("gossip_store new fd moving back %"PRIu64
			     " to start (offset_shorter=%"PRIu64")",
			     cur, offset_shorter);

	close(pps->gossip_store_fd);
	pps->gossip_store_fd = newfd;
}
