#include "config.h"
#include <ccan/read_write_all/read_write_all.h>
#include <common/crypto_sync.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/peer_failed.h>
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

void sync_crypto_write(struct per_peer_state *pps, const void *msg TAKES)
{
#if DEVELOPER
	bool post_sabotage = false, post_close;
	int type = fromwire_peektype(msg);
#endif

	status_peer_io(LOG_IO_OUT, NULL, msg);

#if DEVELOPER
	switch (dev_disconnect(type)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(pps->peer_fd, true);
		peer_failed_connection_lost();
	case DEV_DISCONNECT_AFTER:
		post_sabotage = true;
		post_close = true;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		dev_blackhole_fd(pps->peer_fd);
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	case DEV_DISCONNECT_DISABLE_AFTER:
		post_sabotage = true;
		post_close = false;
		break;
	}
#endif
	if (!wire_sync_write(pps->peer_fd, msg))
		peer_failed_connection_lost();

#if DEVELOPER
	if (post_sabotage)
		dev_sabotage_fd(pps->peer_fd, post_close);
#endif
}

/* We're happy for the kernel to batch update and gossip messages, but a
 * commitment message, for example, should be instantly sent.  There's no
 * great way of doing this, unfortunately.
 *
 * Setting TCP_NODELAY on Linux flushes the socket, which really means
 * we'd want to toggle on then off it *after* sending.  But Linux has
 * TCP_CORK.  On FreeBSD, it seems (looking at source) not to, so
 * there we'd want to set it before the send, and reenable it
 * afterwards.  Even if this is wrong on other non-Linux platforms, it
 * only means one extra packet.
 */
void sync_crypto_write_no_delay(struct per_peer_state *pps,
				const void *msg TAKES)
{
	int val;
	int opt;
	const char *optname;
	static bool complained = false;

#ifdef TCP_CORK
	opt = TCP_CORK;
	optname = "TCP_CORK";
#elif defined(TCP_NODELAY)
	opt = TCP_NODELAY;
	optname = "TCP_NODELAY";
#else
#error "Please report platform with neither TCP_CORK nor TCP_NODELAY?"
#endif

	val = 1;
	if (setsockopt(pps->peer_fd, IPPROTO_TCP, opt, &val, sizeof(val)) != 0) {
		/* This actually happens in testing, where we blackhole the fd */
		if (!complained) {
			status_unusual("setsockopt %s=1: %s",
				       optname,
				       strerror(errno));
			complained = true;
		}
	}
	sync_crypto_write(pps, msg);

	val = 0;
	setsockopt(pps->peer_fd, IPPROTO_TCP, opt, &val, sizeof(val));
}

u8 *sync_crypto_read(const tal_t *ctx, struct per_peer_state *pps)
{
	u8 *dec = wire_sync_read(ctx, pps->peer_fd);
	if (!dec)
		peer_failed_connection_lost();

	status_peer_io(LOG_IO_IN, NULL, dec);

	return dec;
}
