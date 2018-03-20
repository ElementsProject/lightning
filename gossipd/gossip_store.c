#include "gossip_store.h"

#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/status.h>
#include <fcntl.h>
#include <unistd.h>

#define GOSSIP_STORE_FILENAME "gossip_store"

struct gossip_store {
	int fd;
	off_t read_pos, write_pos;

	/* What was the size of the gossip_store when we started replaying
	 * it? */
	__off_t replaysize;
};

static void gossip_store_destroy(struct gossip_store *gs)
{
	close(gs->fd);
}

struct gossip_store *gossip_store_new(const tal_t *ctx)
{
	struct gossip_store *gs = tal(ctx, struct gossip_store);
	gs->fd = open(GOSSIP_STORE_FILENAME, O_RDWR|O_APPEND|O_CREAT, 0600);
	gs->read_pos = 0;
	gs->write_pos = lseek(gs->fd, 0, SEEK_END);
	gs->replaysize = gs->write_pos;

	tal_add_destructor(gs, gossip_store_destroy);

	return gs;
}

void gossip_store_append(struct gossip_store *gs, const u8 *msg)
{
	u16 msglen = tal_len(msg);
	beint16_t belen = cpu_to_be16(msglen);

	if (pwrite(gs->fd, &belen, sizeof(belen), gs->write_pos) != 2 ||
	    pwrite(gs->fd, msg, msglen, gs->write_pos + 2) != msglen) {
		return;
	} else
		gs->write_pos += 2 + msglen;
}

const u8 *gossip_store_read_next(const tal_t *ctx, struct gossip_store *gs)
{
	beint16_t belen;
	u16 msglen;
	u8 *msg;

	/* Did we already reach the end of the gossip_store? */
	if (gs->read_pos == -1)
		return NULL;

	/* Can we read one message? */
	if (pread(gs->fd, &belen, sizeof(belen), gs->read_pos) != 2) {
		gs->read_pos = -1;
		return NULL;
	}

	msglen = be16_to_cpu(belen);
	msg = tal_arr(ctx, u8, msglen);

	if (!pread(gs->fd, msg, msglen, gs->read_pos + 2)) {
		status_trace("Short read from gossip-store, expected lenght %d",
			     msglen);

		/* Reset write_pos to truncate this message and disable future
		 * reads */
		gs->write_pos = gs->read_pos;
		gs->read_pos = -1;
		ftruncate(gs->fd, gs->write_pos);
	} else
		gs->read_pos += 2 + msglen;

	return msg;
}
