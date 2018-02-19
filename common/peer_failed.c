#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/gen_peer_status_wire.h>
#include <common/gen_status_wire.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <stdarg.h>
#include <unistd.h>

/* We only support one channel per peer anyway */
void peer_failed_(int peer_fd, int gossip_fd,
		  struct crypto_state *cs, u64 gossip_index,
		  const struct channel_id *channel_id,
		  const char *fmt, ...)
{
	va_list ap;
	const char *desc;
	u8 *msg;

 	va_start(ap, fmt);
	desc = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	status_broken("SENT ERROR:%s", desc);
	msg = towire_errorfmt(desc, channel_id, "%s", desc);

	/* This is only best-effort; don't block. */
	io_fd_block(peer_fd, false);
	sync_crypto_write(cs, peer_fd, msg);

	msg = towire_status_peer_error(NULL, channel_id,
				       desc, cs, gossip_index, msg);
	tal_free(desc);
	status_send_fatal(take(msg));
}

/* We're failing because peer sent us an error message */
void peer_failed_received_errmsg(int peer_fd, int gossip_fd,
				 struct crypto_state *cs, u64 gossip_index,
				 const char *desc,
				 const struct channel_id *channel_id)
{
	u8 *msg = towire_status_peer_error(NULL, channel_id,
					   desc, cs, gossip_index, NULL);
	status_send_fatal(take(msg));
}

void peer_failed_connection_lost(void)
{
	status_send_fatal(take(towire_status_peer_connection_lost(NULL)));
}
