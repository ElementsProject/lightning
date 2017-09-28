#include "utils.h"
#include <ccan/list/list.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>

secp256k1_context *secp256k1_ctx;

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

struct tmpctx {
	struct list_node list;
	const char *file;
	unsigned int line;
};

static struct list_head tmpctxs = LIST_HEAD_INIT(tmpctxs);

static void destroy_tmpctx(struct tmpctx *t)
{
	list_del_from(&tmpctxs, &t->list);
}

tal_t *tal_tmpctx_(const tal_t *ctx, const char *file, unsigned int line)
{
	struct tmpctx *t = tal(ctx, struct tmpctx);
	t->file = file;
	t->line = line;
	list_add_tail(&tmpctxs, &t->list);
	tal_add_destructor(t, destroy_tmpctx);
	return t;
}

const char *tmpctx_any(void)
{
	struct tmpctx *t = list_top(&tmpctxs, struct tmpctx, list);

	if (t)
		return tal_fmt(t, "%s:%u", t->file, t->line);
	return NULL;
}
