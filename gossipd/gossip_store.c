#include "gossip_store.h"

#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/status.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_wire.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>

#define GOSSIP_STORE_FILENAME "gossip_store"
static u8 gossip_store_version = 0x01;

struct gossip_store {
	int fd;
	off_t read_pos, write_pos;
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
	gs->read_pos = 1;
	gs->write_pos = lseek(gs->fd, 0, SEEK_END);

	/* Try to read the version, write it if this is a new file, or truncate
	 * if the version doesn't match */
	if (pread(gs->fd, &gs->version, sizeof(gs->version), 0) != 1 ||
	    gs->version != gossip_store_version) {
		status_trace("Truncating gossip_store, either it was empty or "
			     "the version was not supported.");
		gs->version = gossip_store_version;
		gs->write_pos = 1;
		pwrite(gs->fd, &gossip_store_version, sizeof(gossip_store_version), 0);
		ftruncate(gs->fd, gs->write_pos);
	}

	tal_add_destructor(gs, gossip_store_destroy);

	return gs;
}

void gossip_store_append(struct gossip_store *gs, const u8 *msg)
{
	u32 msglen = tal_len(msg);
	beint32_t belen = cpu_to_be32(msglen);

	if (pwrite(gs->fd, &belen, sizeof(belen), gs->write_pos) != sizeof(belen) ||
	    pwrite(gs->fd, msg, msglen, gs->write_pos + sizeof(belen)) != msglen) {
		return;
	} else
		gs->write_pos += sizeof(belen) + msglen;
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

const u8 *gossip_store_read_next(const tal_t *ctx, struct routing_state *rstate,
				 struct gossip_store *gs)
{
	beint32_t belen;
	u32 msglen;
	u8 *msg, *gossip_msg;
	u64 satoshis;
	enum gossip_wire_type type;

	/* Did we already reach the end of the gossip_store? */
	if (gs->read_pos == -1)
		return NULL;

	/* Can we read one message? */
	if (pread(gs->fd, &belen, sizeof(belen), gs->read_pos) != sizeof(belen)) {
		gs->read_pos = -1;
		return NULL;
	}

	msglen = be32_to_cpu(belen);
	msg = tal_arr(ctx, u8, msglen);

	if (!pread(gs->fd, msg, msglen, gs->read_pos + sizeof(belen))) {
		status_trace("Short read from gossip-store, expected lenght %d",
			     msglen);

		/* Reset write_pos to truncate this message and disable future
		 * reads */
		gs->write_pos = gs->read_pos;
		gs->read_pos = -1;
		ftruncate(gs->fd, gs->write_pos);
		return NULL;
	}

	gs->read_pos += sizeof(belen) + msglen;
	type = fromwire_peektype(msg);

	if (type == WIRE_GOSSIP_STORE_CHANNEL_ANNOUNCEMENT) {
		fromwire_gossip_store_channel_announcement(msg, msg, &gossip_msg, &satoshis);
		routing_add_channel_announcement(rstate, gossip_msg, satoshis);

		/* No harm in returning it, it'll get discarded as a duplicate */
		return gossip_msg;
	} else if(type == WIRE_GOSSIP_STORE_CHANNEL_UPDATE) {
		fromwire_gossip_store_channel_update(msg, msg, &gossip_msg);
		routing_add_channel_update(rstate, gossip_msg);
		return gossip_msg;
	}

	return msg;
}
