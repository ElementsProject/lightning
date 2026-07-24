#include "config.h"
#include <ccan/cast/cast.h>
#include <common/onionreply.h>
#include <wire/wire.h>

void towire_onionreply(u8 **cursor, const struct onionreply *r)
{
	towire_u16(cursor, tal_count(r->contents));
	towire_u8_array(cursor, r->contents, tal_count(r->contents));
	if (r->attr_data) {
		towire_u8_array(cursor, r->attr_data->data, ATTR_DATA_SIZE);
	}
}

struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = fromwire_tal_arrn(r, cursor, max,
					fromwire_u16(cursor, max));
	if (*max >= ATTR_DATA_SIZE) {
		r->attr_data = tal(r, struct attribution_data);
		fromwire_u8_array(cursor, max, r->attr_data->data, ATTR_DATA_SIZE);
	} else {
		r->attr_data = NULL;
	}

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
	if (r->attr_data) {
		n->attr_data = tal_dup(n, struct attribution_data, r->attr_data);
	} else {
		n->attr_data = NULL;
	}
	return n;
}

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES, const struct attribution_data *attr_data)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = tal_dup_talarr(r, u8, contents);
	if (attr_data) {
		r->attr_data = tal_dup(r, struct attribution_data, attr_data);
	} else {
		r->attr_data = NULL;
	}
	return r;
}
