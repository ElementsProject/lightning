#include <ccan/read_write_all/read_write_all.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/dev_disconnect.h>
#include <lightningd/status.h>
#include <utils.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

bool sync_crypto_write(struct crypto_state *cs, int fd, const void *msg TAKES)
{
	int type = fromwire_peektype(msg);
	u8 *enc = cryptomsg_encrypt_msg(NULL, cs, msg);
	bool ret;
	bool post_sabotage = false;

	switch (dev_disconnect(type)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(fd);
		return false;
	case DEV_DISCONNECT_DROPPKT:
		enc = tal_free(enc); /* FALL THRU */
	case DEV_DISCONNECT_AFTER:
		post_sabotage = true;
		break;
	default:
		break;
	}
	ret = write_all(fd, enc, tal_len(enc));
	tal_free(enc);

	if (post_sabotage)
		dev_sabotage_fd(fd);
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
		status_trace("Read decrypt %s", tal_hex(trc, dec));
	return dec;
}
