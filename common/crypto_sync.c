#include <ccan/read_write_all/read_write_all.h>
#include <common/crypto_sync.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

bool sync_crypto_write(struct crypto_state *cs, int fd, const void *msg TAKES)
{
#if DEVELOPER
	bool post_sabotage = false;
	int type = fromwire_peektype(msg);
#endif
	u8 *enc;
	bool ret;

	status_peer_io(LOG_IO_OUT, msg);
	enc = cryptomsg_encrypt_msg(NULL, cs, msg);

#if DEVELOPER
	switch (dev_disconnect(type)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(fd);
		return false;
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
	ret = write_all(fd, enc, tal_len(enc));
	tal_free(enc);

#if DEVELOPER
	if (post_sabotage)
		dev_sabotage_fd(fd);
#endif
	return ret;
}

u8 *sync_crypto_read(const tal_t *ctx, struct crypto_state *cs, int fd)
{
	u8 hdr[18], *enc, *dec;
	u16 len;

	if (!read_all(fd, hdr, sizeof(hdr))) {
		status_trace("Failed reading header: %s", strerror(errno));
		return NULL;
	}

	if (!cryptomsg_decrypt_header(cs, hdr, &len)) {
		status_trace("Failed hdr decrypt with rn=%"PRIu64, cs->rn-1);
		return NULL;
	}

	enc = tal_arr(ctx, u8, len + 16);
	if (!read_all(fd, enc, tal_len(enc))) {
		status_trace("Failed reading body: %s", strerror(errno));
		return tal_free(enc);
	}

	dec = cryptomsg_decrypt_body(ctx, cs, enc);
	tal_free(enc);
	if (!dec)
		status_trace("Failed body decrypt with rn=%"PRIu64, cs->rn-2);
	else
		status_peer_io(LOG_IO_IN, dec);

	return dec;
}
