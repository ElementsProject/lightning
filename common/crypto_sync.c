#include <ccan/read_write_all/read_write_all.h>
#include <common/crypto_sync.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

void sync_crypto_write(struct crypto_state *cs, int fd, const void *msg TAKES)
{
#if DEVELOPER
	bool post_sabotage = false;
	int type = fromwire_peektype(msg);
#endif
	u8 *enc;

	status_peer_io(LOG_IO_OUT, msg);
	enc = cryptomsg_encrypt_msg(NULL, cs, msg);

#if DEVELOPER
	switch (dev_disconnect(type)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(fd);
		peer_failed_connection_lost();
	case DEV_DISCONNECT_DROPPKT:
		enc = tal_free(enc); /* FALL THRU */
	case DEV_DISCONNECT_AFTER:
		post_sabotage = true;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		dev_blackhole_fd(fd);
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	}
#endif
	if (!write_all(fd, enc, tal_count(enc)))
		peer_failed_connection_lost();
	tal_free(enc);

#if DEVELOPER
	if (post_sabotage)
		dev_sabotage_fd(fd);
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
void sync_crypto_write_no_delay(struct crypto_state *cs, int fd,
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
	if (setsockopt(fd, IPPROTO_TCP, opt, &val, sizeof(val)) != 0) {
		/* This actually happens in testing, where we blackhole the fd */
		if (!complained) {
			status_broken("setsockopt %s=1: %s",
				      optname,
				      strerror(errno));
			complained = true;
		}
	}
	sync_crypto_write(cs, fd, msg);

	val = 0;
	setsockopt(fd, IPPROTO_TCP, opt, &val, sizeof(val));
}

u8 *sync_crypto_read(const tal_t *ctx, struct crypto_state *cs, int fd)
{
	u8 hdr[18], *enc, *dec;
	u16 len;

	if (!read_all(fd, hdr, sizeof(hdr))) {
		status_trace("Failed reading header: %s", strerror(errno));
		peer_failed_connection_lost();
	}

	if (!cryptomsg_decrypt_header(cs, hdr, &len)) {
		status_trace("Failed hdr decrypt with rn=%"PRIu64, cs->rn-1);
		peer_failed_connection_lost();
	}

	enc = tal_arr(ctx, u8, len + 16);
	if (!read_all(fd, enc, tal_count(enc))) {
		status_trace("Failed reading body: %s", strerror(errno));
		peer_failed_connection_lost();
	}

	dec = cryptomsg_decrypt_body(ctx, cs, enc);
	tal_free(enc);
	if (!dec)
		peer_failed_connection_lost();
	else
		status_peer_io(LOG_IO_IN, dec);

	return dec;
}
