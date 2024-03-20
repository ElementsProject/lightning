#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/str/hex/hex.h>
#include <common/utils.h>
#include <wire/wire.h>

char *fmt_privkey(const tal_t *ctx, const struct privkey *secret)
{
	/* Bitcoin appends "01" to indicate the pubkey is compressed. */
	char *str = tal_arr(ctx, char, hex_str_size(sizeof(*secret) + 1));
	hex_encode(secret, sizeof(*secret), str, hex_str_size(sizeof(*secret)));
	strcat(str, "01");
	return str;
}

char *fmt_secret(const tal_t *ctx, const struct secret *secret)
{
	return tal_hexstr(ctx, secret, sizeof(*secret));
}

bool secret_eq_consttime(const struct secret *a, const struct secret *b)
{
	u8 result = 0;
	for (size_t i = 0; i < sizeof(a->data); i++)
		result |= a->data[i] ^ b->data[i];
	return result == 0;
}

void towire_privkey(u8 **pptr, const struct privkey *privkey)
{
	towire_secret(pptr, &privkey->secret);
}

void towire_secret(u8 **pptr, const struct secret *secret)
{
	towire(pptr, secret->data, sizeof(secret->data));
}

void fromwire_secret(const u8 **cursor, size_t *max, struct secret *secret)
{
	fromwire(cursor, max, secret->data, sizeof(secret->data));
}

void fromwire_privkey(const u8 **cursor, size_t *max, struct privkey *privkey)
{
	fromwire_secret(cursor, max, &privkey->secret);
}
