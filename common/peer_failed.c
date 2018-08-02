#include <ccan/tal/str/str.h>
#include <common/gen_peer_status_wire.h>
#include <common/gen_status_wire.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <stdarg.h>

/* We only support one channel per peer anyway */
void peer_failed_(int peer_fd, int gossip_fd,
		  struct crypto_state *cs,
		  const struct channel_id *channel_id,
		  const char *fmt, ...)
{
	va_list ap;
	const char *desc;
	u8 *msg;

 	va_start(ap, fmt);
	desc = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	msg = towire_status_peer_error(NULL, channel_id,
				       desc, cs,
				       towire_errorfmt(desc, channel_id,
						       "%s", desc));
	peer_billboard(true, desc);
	tal_free(desc);
	status_send_fatal(take(msg), peer_fd, gossip_fd);
}

/* We're failing because peer sent us an error message */
void peer_failed_received_errmsg(int peer_fd, int gossip_fd,
				 struct crypto_state *cs,
				 const char *desc,
				 const struct channel_id *channel_id)
{
	static const struct channel_id all_channels;
	u8 *msg;

	if (!channel_id)
		channel_id = &all_channels;
	msg = towire_status_peer_error(NULL, channel_id, desc, cs, NULL);
	peer_billboard(true, "Received error from peer: %s", desc);
	status_send_fatal(take(msg), peer_fd, gossip_fd);
}

void peer_failed_connection_lost(void)
{
	status_send_fatal(take(towire_status_peer_connection_lost(NULL)),
			  -1, -1);
}
