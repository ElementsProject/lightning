#include "config.h"
#include <bitcoin/preimage.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <wire/wire.h>

void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage)
{
	fromwire(cursor, max, preimage, sizeof(*preimage));
}

void towire_preimage(u8 **pptr, const struct preimage *preimage)
{
	towire(pptr, preimage, sizeof(*preimage));
}

char *fmt_preimage(const tal_t *ctx, const struct preimage *preimage)
{
	return tal_hexstr(ctx, preimage, sizeof(*preimage));
}

REGISTER_TYPE_TO_STRING(preimage, fmt_preimage);
