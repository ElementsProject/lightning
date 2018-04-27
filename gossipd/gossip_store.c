#include "gossip_store.h"

#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_store.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>

#define GOSSIP_STORE_FILENAME "gossip_store"
static u8 gossip_store_version = 0x01;

struct gossip_store {
	int fd;
	u8 version;
};

static void gossip_store_destroy(struct gossip_store *gs)
{
	close(gs->fd);
}

struct gossip_store *gossip_store_new(const tal_t *ctx)
{
	struct gossip_store *gs = tal(ctx, struct gossip_store);
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);

	tal_add_destructor(gs, gossip_store_destroy);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (read(gs->fd, &gs->version, sizeof(gs->version))
	    == sizeof(gs->version)) {
		/* Version match?  All good */
		if (gs->version == gossip_store_version)
			return gs;

		status_unusual("Gossip store version %u not %u: removing",
			       gs->version, gossip_store_version);
		if (ftruncate(gs->fd, 0) != 0)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Truncating store: %s", strerror(errno));
	}
	/* Empty file, write version byte */
	gs->version = gossip_store_version;
	if (write(gs->fd, &gs->version, sizeof(gs->version))
	    != sizeof(gs->version))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing version to store: %s", strerror(errno));
	return gs;
}
/**
 * Write an incoming message to the `gossip_store`
 *
 * @param gs  The gossip_store to write to
 * @param msg The message to write
 * @return The newly created and initialized `gossip_store`
 */
static void gossip_store_append(struct gossip_store *gs, const u8 *msg)
{
	u32 msglen = tal_len(msg);
	beint32_t belen = cpu_to_be32(msglen);

	/* Only give error message once. */
	if (gs->fd == -1)
		return;

	/* FORTIFY_SOURCE gets upset if we don't check return. */
	if (write(gs->fd, &belen, sizeof(belen)) != sizeof(belen) ||
	    write(gs->fd, msg, msglen) != msglen) {
              status_broken("Failed writing to gossip store: %s",
			    strerror(errno));
	      gs->fd = -1;
	}
}

void gossip_store_add_channel_announcement(struct gossip_store *gs, const u8 *gossip_msg, u64 satoshis)
{
	u8 *msg = towire_gossip_store_channel_announcement(NULL, gossip_msg, satoshis);
	gossip_store_append(gs, msg);
	tal_free(msg);
}

void gossip_store_add_channel_update(struct gossip_store *gs,
				     const u8 *gossip_msg)
{
	u8 *msg = towire_gossip_store_channel_update(NULL, gossip_msg);
	gossip_store_append(gs, msg);
	tal_free(msg);
}

void gossip_store_add_node_announcement(struct gossip_store *gs,
					const u8 *gossip_msg)
{
	u8 *msg = towire_gossip_store_node_announcement(NULL, gossip_msg);
	gossip_store_append(gs, msg);
	tal_free(msg);
}

void gossip_store_add_channel_delete(struct gossip_store *gs,
				     const struct short_channel_id *scid)
{
	u8 *msg = towire_gossip_store_channel_delete(NULL, scid);
	gossip_store_append(gs, msg);
	tal_free(msg);
}

void gossip_store_local_add_channel(struct gossip_store *gs,
				    const u8 *add_msg)
{
	u8 *msg = towire_gossip_store_local_add_channel(NULL, add_msg);
	gossip_store_append(gs, msg);
	tal_free(msg);
}


void gossip_store_load(struct routing_state *rstate, struct gossip_store *gs)
{
	beint32_t belen;
	u32 msglen;
	u8 *msg, *gossip_msg;
	u64 satoshis;
	struct short_channel_id scid;
	/* We set/check version byte on creation */
	off_t known_good = 1;
	const char *bad;
	size_t stats[] = {0, 0, 0, 0};

	lseek(gs->fd, known_good, SEEK_SET);
	while (read(gs->fd, &belen, sizeof(belen)) == sizeof(belen)) {
		msglen = be32_to_cpu(belen);
		msg = tal_arr(gs, u8, msglen);

		if (read(gs->fd, msg, msglen) != msglen) {
			status_unusual("gossip_store: truncated file?");
			goto truncate_nomsg;
		}

		if (fromwire_gossip_store_channel_announcement(msg, msg,
							       &gossip_msg,
							       &satoshis)) {
			if (!routing_add_channel_announcement(rstate,
							      gossip_msg,
							      satoshis)) {
				bad = "Bad channel_announcement";
				goto truncate;
			}
			stats[0]++;
		} else if (fromwire_gossip_store_channel_update(msg, msg,
								&gossip_msg)) {
			if (!routing_add_channel_update(rstate, gossip_msg)) {
				bad = "Bad channel_update";
				goto truncate;
			}
			stats[1]++;
		} else if (fromwire_gossip_store_node_announcement(msg, msg,
								   &gossip_msg)) {
			if (!routing_add_node_announcement(rstate, gossip_msg)) {
				bad = "Bad node_announcement";
				goto truncate;
			}
			stats[2]++;
		} else if (fromwire_gossip_store_channel_delete(msg, &scid)) {
			struct chan *c = get_channel(rstate, &scid);
			if (!c) {
				bad = "Bad channel_delete";
				goto truncate;
			}
			tal_free(c);
			stats[3]++;
		} else if (fromwire_gossip_store_local_add_channel(
			       msg, msg, &gossip_msg)) {
			handle_local_add_channel(rstate, gossip_msg);
		} else {
			bad = "Unknown message";
			goto truncate;
		}
		known_good += sizeof(belen) + msglen;
		tal_free(msg);
	}
	goto out;

truncate:
	status_unusual("gossip_store: %s (%s) truncating to %"PRIu64,
		       bad, tal_hex(msg, msg), (u64)1);
truncate_nomsg:
	/* FIXME: We would like to truncate to known_good, except we would
	 * miss channel_delete msgs.  If we put block numbers into the store
	 * as we process them, we can know how far we need to roll back if we
	 * truncate the store */
	if (ftruncate(gs->fd, 1) != 0)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Truncating store: %s", strerror(errno));
out:
	status_trace("gossip_store: Read %zu/%zu/%zu/%zu cannounce/cupdate/nannounce/cdelete from store in %"PRIu64" bytes",
		     stats[0], stats[1], stats[2], stats[3],
		     (u64)known_good);
}
