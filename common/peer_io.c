#include "config.h"
#include <ccan/read_write_all/read_write_all.h>
#include <common/cryptomsg.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

void peer_write(struct per_peer_state *pps, const void *msg TAKES)
{
	status_peer_io(LOG_IO_OUT, NULL, msg);

	/* We ignore write errors; we might still have something to read,
	 * so we'd rather fail there. */
	wire_sync_write(pps->peer_fd, msg);
}

u8 *peer_read(const tal_t *ctx, struct per_peer_state *pps)
{
	u8 *msg = wire_sync_read(ctx, pps->peer_fd);
	if (!msg)
		peer_failed_connection_lost();

	status_peer_io(LOG_IO_IN, NULL, msg);

	return msg;
}
