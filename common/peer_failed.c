#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>

/* We only support one channel per peer anyway */
void peer_failed(int peer_fd, struct crypto_state *cs,
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

	status_fatal_sent_errmsg(take(msg), desc, channel_id);
}
