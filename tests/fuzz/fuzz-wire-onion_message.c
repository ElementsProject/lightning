#include "config.h"
#include <ccan/mem/mem.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/wire.h>
#include <wire/peer_wire.h>

struct onion_message {
	struct pubkey path_key;
	u8 *onionmsg;
};

static void *encode(const tal_t *ctx, const struct onion_message *s)
{
	return towire_onion_message(ctx, &s->path_key, s->onionmsg);
}

static struct onion_message *decode(const tal_t *ctx, const void *p)
{
	struct onion_message *s = tal(ctx, struct onion_message);

	if (fromwire_onion_message(s, p, &s->path_key, &s->onionmsg))
		return s;
	return tal_free(s);
}

static bool equal(const struct onion_message *x, const struct onion_message *y)
{
	if (memcmp(&x->path_key, &y->path_key, sizeof(x->path_key)) != 0)
		return false;
	return tal_arr_eq(x->onionmsg, y->onionmsg);
}

void run(const u8 *data, size_t size)
{
	test_decode_encode(data, size, WIRE_ONION_MESSAGE,
			   struct onion_message);
}
