#include "config.h"
#include <ccan/cast/cast.h>
#include <common/onionreply.h>
#include <common/utils.h>
#include <wire/wire.h>

void towire_onionreply(u8 **cursor, const struct onionreply *r)
{
	towire_u16(cursor, tal_count(r->contents));
	towire_u8_array(cursor, r->contents, tal_count(r->contents));
	if (r->attr_data) {
		towire_u8_array(cursor, r->attr_data->htlc_hold_time, 80);
		towire_u8_array(cursor, r->attr_data->truncated_hmac, 840);
	}
}

struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = fromwire_tal_arrn(r, cursor, max,
					fromwire_u16(cursor, max));
	if (*max >= 80 + 840) {
		r->attr_data = tal(ctx, struct attribution_data);
		r->attr_data->htlc_hold_time = fromwire_tal_arrn(r, cursor, max, 80);
		r->attr_data->truncated_hmac = fromwire_tal_arrn(r, cursor, max, 840);
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
		n->attr_data = tal(ctx, struct attribution_data);
		n->attr_data->htlc_hold_time = tal_dup_talarr(r, u8, r->attr_data->htlc_hold_time);
		n->attr_data->truncated_hmac = tal_dup_talarr(r, u8, r->attr_data->truncated_hmac);
	} else {
		n->attr_data = NULL;
	}
	return n;
}

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES, const struct attribution_data *attr_data TAKES)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = tal_dup_talarr(r, u8, contents);
	if (attr_data) {
		r->attr_data = tal(ctx, struct attribution_data);
		r->attr_data->htlc_hold_time = tal_dup_talarr(r, u8, attr_data->htlc_hold_time);
		r->attr_data->truncated_hmac = tal_dup_talarr(r, u8, attr_data->truncated_hmac);
	} else {
		r->attr_data = NULL;
	}
	return r;
}
