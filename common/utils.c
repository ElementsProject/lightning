#include "utils.h"
#include <ccan/list/list.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <locale.h>

secp256k1_context *secp256k1_ctx;
const tal_t *tmpctx;

char *tal_hexstr(const tal_t *ctx, const void *data, size_t len)
{
	char *str = tal_arr(ctx, char, hex_str_size(len));
	hex_encode(data, len, str, hex_str_size(len));
	return str;
}

char *tal_hex(const tal_t *ctx, const tal_t *data)
{
	return tal_hexstr(ctx, data, tal_len(data));
}

u8 *tal_hexdata(const tal_t *ctx, const void *str, size_t len)
{
	u8 *data = tal_arr(ctx, u8, hex_data_size(len));
	if (!hex_decode(str, len, data, hex_data_size(len)))
		return NULL;
	return data;
}

/* Use the POSIX C locale. */
void setup_locale(void)
{
	setlocale(LC_ALL, "C");
	putenv("LC_ALL=C"); /* For exec{l,lp,v,vp}(...) */
}

/* Global temporary convenience context: freed in io loop core. */

/* Initial creation of tmpctx. */
void setup_tmpctx(void)
{
	tmpctx = tal_alloc_(NULL, 0, false, false, "tmpctx");
}

/* Free any children of tmpctx. */
void clean_tmpctx(void)
{
	/* Minor optimization: don't do anything if tmpctx unused. */
	if (tal_first(tmpctx)) {
		tal_free(tmpctx);
		tmpctx = tal_alloc_(NULL, 0, false, false, "tmpctx");
	}
}
