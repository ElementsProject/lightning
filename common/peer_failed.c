#include <ccan/tal/str/str.h>
#include <common/gen_peer_status_wire.h>
#include <common/gen_status_wire.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <stdarg.h>

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

	msg = towire_status_peer_error(NULL, channel_id,
				       desc, cs, gossip_index,
				       towire_errorfmt(desc, channel_id,
						       "%s", desc));
	tal_free(desc);
	status_send_fatal(take(msg), peer_fd, gossip_fd);
}

/* We're failing because peer sent us an error message */
void peer_failed_received_errmsg(int peer_fd, int gossip_fd,
				 struct crypto_state *cs, u64 gossip_index,
				 const char *desc,
				 const struct channel_id *channel_id)
{
	u8 *msg = towire_status_peer_error(NULL, channel_id,
					   desc, cs, gossip_index, NULL);
	status_send_fatal(take(msg), peer_fd, gossip_fd);
}

void peer_failed_connection_lost(void)
{
	status_send_fatal(take(towire_status_peer_connection_lost(NULL)),
			  -1, -1);
}
