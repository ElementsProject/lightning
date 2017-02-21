#include <ccan/read_write_all/read_write_all.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/cryptomsg.h>
#include <wire/wire_sync.h>

bool sync_crypto_write(struct crypto_state *cs, int fd, const void *msg)
{
	u8 *enc = cryptomsg_encrypt_msg(msg, cs, msg);
	bool ret;

	ret = wire_sync_write(fd, enc);
	tal_free(enc);
	return ret;
}

u8 *sync_crypto_read(const tal_t *ctx, struct crypto_state *cs, int fd)
{
	u8 hdr[18], *enc, *dec;
	u16 len;

	if (!read_all(fd, hdr, sizeof(hdr)))
		return NULL;

	if (!cryptomsg_decrypt_header(cs, hdr, &len))
		return NULL;

	enc = tal_arr(ctx, u8, len);
	if (!read_all(fd, enc, len))
		return tal_free(enc);

	dec = cryptomsg_decrypt_body(ctx, cs, enc);
	tal_free(enc);
	return dec;
}
