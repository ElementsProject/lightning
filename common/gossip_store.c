#include "config.h"
#include <assert.h>
#include <ccan/crc32c/crc32c.h>
#include <common/features.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/peer_wire.h>

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

/* Not all the data we expected was there: rewind file */
static void failed_read(int fd, int len)
{
	if (len < 0) {
		/* Grab errno before lseek overrides it */
		const char *err = strerror(errno);
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "gossip_store: failed read @%"PRIu64": %s",
			      (u64)lseek(fd, 0, SEEK_CUR), err);
	}

	lseek(fd, -len, SEEK_CUR);
}

static void reopen_gossip_store(struct per_peer_state *pps,
				const u8 *msg)
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
	lseek(newfd, equivalent_offset, SEEK_SET);

	close(pps->gossip_store_fd);
	pps->gossip_store_fd = newfd;
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
				failed_read(pps->gossip_store_fd, r);
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
			failed_read(pps->gossip_store_fd, r);
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

		type = fromwire_peektype(msg);
		if (type == WIRE_GOSSIP_STORE_ENDED)
			reopen_gossip_store(pps, msg);
		/* Ignore gossipd internal messages. */
		else if (type != WIRE_CHANNEL_ANNOUNCEMENT
		    && type != WIRE_CHANNEL_UPDATE
		    && type != WIRE_NODE_ANNOUNCEMENT)
			msg = tal_free(msg);
		else if (!push && !timestamp_filter(pps, timestamp))
			msg = tal_free(msg);
	}

	return msg;
}
