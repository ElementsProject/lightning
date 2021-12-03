#include "config.h"
#include <ccan/cast/cast.h>
#include <common/onionreply.h>
#include <common/utils.h>
#include <wire/wire.h>

void towire_onionreply(u8 **cursor, const struct onionreply *r)
{
	towire_u16(cursor, tal_count(r->contents));
	towire_u8_array(cursor, r->contents, tal_count(r->contents));
}

struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = fromwire_tal_arrn(r, cursor, max,
					fromwire_u16(cursor, max));
	if (!*cursor)
		return tal_free(r);
	return r;
}

struct onionreply *dup_onionreply(const tal_t *ctx,
				  const struct onionreply *r TAKES)
{
	struct onionreply *n;

	if (taken(r))
		return cast_const(struct onionreply *, tal_steal(ctx, r));

	n = tal(ctx, struct onionreply);
	n->contents = tal_dup_talarr(n, u8, r->contents);
	return n;
}

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = tal_dup_talarr(r, u8, contents);
	return r;
}
