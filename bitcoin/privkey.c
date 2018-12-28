#include "privkey.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>

static char *privkey_to_hexstr(const tal_t *ctx, const struct privkey *secret)
{
	/* Bitcoin appends "01" to indicate the pubkey is compressed. */
	char *str = tal_arr(ctx, char, hex_str_size(sizeof(*secret) + 1));
	hex_encode(secret, sizeof(*secret), str, hex_str_size(sizeof(*secret)));
	strcat(str, "01");
	return str;
}
REGISTER_TYPE_TO_STRING(privkey, privkey_to_hexstr);
REGISTER_TYPE_TO_HEXSTR(secret);

bool secret_eq_consttime(const struct secret *a, const struct secret *b)
{
	u8 result = 0;
	for (size_t i = 0; i < sizeof(a->data); i++)
		result |= a->data[i] ^ b->data[i];
	return result == 0;
}
