#include <assert.h>
#include <ccan/crc32c/crc32c.h>
#include <common/features.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <wire/peer_wiregen.h>

void gossip_setup_timestamp_filter(struct per_peer_state *pps,
				   u32 first_timestamp,
				   u32 timestamp_range)
{
	/* If this is the first filter, we gossip sync immediately. */
	if (!pps->gs) {
		pps->gs = tal(pps, struct gossip_state);
		pps->gs->next_gossip = time_mono();
	}

	pps->gs->timestamp_min = first_timestamp;
	pps->gs->timestamp_max = first_timestamp + timestamp_range - 1;
	/* Make sure we never leave it on an impossible value. */
	if (pps->gs->timestamp_max < pps->gs->timestamp_min)
		pps->gs->timestamp_max = UINT32_MAX;

	/* BOLT #7:
	 *
	 * The receiver:
	 *   - SHOULD send all gossip messages whose `timestamp` is greater or
	 *     equal to `first_timestamp`, and less than `first_timestamp` plus
	 *     `timestamp_range`.
	 * 	- MAY wait for the next outgoing gossip flush to send these.
	 *   ...
	 *   - SHOULD restrict future gossip messages to those whose `timestamp`
	 *     is greater or equal to `first_timestamp`, and less than
	 *     `first_timestamp` plus `timestamp_range`.
	 */

	/* Restart just after header. */
	lseek(pps->gossip_store_fd, 1, SEEK_SET);
}

static bool timestamp_filter(const struct per_peer_state *pps, u32 timestamp)
{
	/* BOLT #7:
	 *
	 *   - SHOULD send all gossip messages whose `timestamp` is greater or
	 *    equal to `first_timestamp`, and less than `first_timestamp` plus
	 *    `timestamp_range`.
	 */
	/* Note that we turn first_timestamp & timestamp_range into an inclusive range */
	return timestamp >= pps->gs->timestamp_min
		&& timestamp <= pps->gs->timestamp_max;
}

static void undo_read(int fd, int len, size_t wanted)
{
	if (len < 0) {
		/* Grab errno before lseek overrides it */
		const char *err = strerror(errno);
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: failed read @%"PRIu64": %s",
			      (u64)lseek(fd, 0, SEEK_CUR), err);
	}

	/* Shouldn't happen, but some filesystems are not as atomic as
	 * they should be! */
	status_unusual("gossip_store: short read %i of %zu @%"PRIu64,
		       len, wanted, (u64)lseek(fd, 0, SEEK_CUR) - len);
	lseek(fd, -len, SEEK_CUR);
}

u8 *gossip_store_next(const tal_t *ctx, struct per_peer_state *pps)
{
	u8 *msg = NULL;

	/* Don't read until we're initialized. */
	if (!pps->gs)
		return NULL;

	while (!msg) {
		struct gossip_hdr hdr;
		u32 msglen, checksum, timestamp;
		bool push;
		int type, r;

		r = read(pps->gossip_store_fd, &hdr, sizeof(hdr));
		if (r != sizeof(hdr)) {
			/* We expect a 0 read here at EOF */
			if (r != 0)
				undo_read(pps->gossip_store_fd, r, sizeof(hdr));
			per_peer_state_reset_gossip_timer(pps);
			return NULL;
		}

		/* Skip any deleted entries. */
		if (be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_DELETED_BIT) {
			/* Skip over it. */
			lseek(pps->gossip_store_fd,
			      be32_to_cpu(hdr.len) & GOSSIP_STORE_LEN_MASK,
			      SEEK_CUR);
			continue;
		}

		msglen = be32_to_cpu(hdr.len);
		push = (msglen & GOSSIP_STORE_LEN_PUSH_BIT);
		msglen &= GOSSIP_STORE_LEN_MASK;

		checksum = be32_to_cpu(hdr.crc);
		timestamp = be32_to_cpu(hdr.timestamp);
		msg = tal_arr(ctx, u8, msglen);
		r = read(pps->gossip_store_fd, msg, msglen);
		if (r != msglen) {
			undo_read(pps->gossip_store_fd, r, msglen);
			per_peer_state_reset_gossip_timer(pps);
			return NULL;
		}

		if (checksum != crc32c(be32_to_cpu(hdr.timestamp), msg, msglen))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "gossip_store: bad checksum offset %"
				      PRIi64": %s",
				      (s64)lseek(pps->gossip_store_fd,
						 0, SEEK_CUR) - msglen,
				      tal_hex(tmpctx, msg));

		/* Don't send back gossip they sent to us! */
		if (gossip_rcvd_filter_del(pps->grf, msg)) {
			msg = tal_free(msg);
			continue;
		}

		/* Ignore gossipd internal messages. */
		type = fromwire_peektype(msg);
		if (type != WIRE_CHANNEL_ANNOUNCEMENT
		    && type != WIRE_CHANNEL_UPDATE
		    && type != WIRE_NODE_ANNOUNCEMENT)
			msg = tal_free(msg);
		else if (!push && !timestamp_filter(pps, timestamp))
			msg = tal_free(msg);
	}

	return msg;
}

/* newfd is at offset 1.  We need to adjust it to similar offset as our
 * current one. */
void gossip_store_switch_fd(struct per_peer_state *pps,
			    int newfd, u64 offset_shorter)
{
	u64 cur = lseek(pps->gossip_store_fd, 0, SEEK_CUR);

	/* If we're already at end (common), we know where to go in new one. */
	if (cur == lseek(pps->gossip_store_fd, 0, SEEK_END)) {
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
