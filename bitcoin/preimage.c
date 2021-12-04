#include "config.h"
#include <bitcoin/preimage.h>
#include <wire/wire.h>

void fromwire_preimage(const u8 **cursor, size_t *max, struct preimage *preimage)
{
	fromwire(cursor, max, preimage, sizeof(*preimage));
}

void towire_preimage(u8 **pptr, const struct preimage *preimage)
{
	towire(pptr, preimage, sizeof(*preimage));
}


