#include "config.h"
#include <ccan/cast/cast.h>
#include <common/onionreply.h>
#include <common/utils.h>
#include <wire/wire.h>

void towire_onionreply(u8 **cursor, const struct onionreply *r)
{
	towire_u16(cursor, tal_count(r->contents));
	towire_u8_array(cursor, r->contents, tal_count(r->contents));
	if (r->htlc_hold_time && r->truncated_hmac)
		towire_u8_array(cursor, r->htlc_hold_time, 80);
		towire_u8_array(cursor, r->truncated_hmac, 840);
}

struct onionreply *fromwire_onionreply(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = fromwire_tal_arrn(r, cursor, max,
					fromwire_u16(cursor, max));
	if (*max >= 80 + 840) {
		r->htlc_hold_time = fromwire_tal_arrn(r, cursor, max, 80);
		r->truncated_hmac = fromwire_tal_arrn(r, cursor, max, 840);
	} else {
		r->htlc_hold_time = NULL;
		r->truncated_hmac = NULL;
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
	if (r->htlc_hold_time && r->truncated_hmac) {
		n->htlc_hold_time = tal_dup_arr(r, u8, r->htlc_hold_time, 80, 0);
		n->truncated_hmac = tal_dup_arr(r, u8, r->truncated_hmac, 840, 0);
	} else {
		n->htlc_hold_time = NULL;
		n->truncated_hmac = NULL;
	}
	return n;
}

struct onionreply *new_onionreply(const tal_t *ctx, const u8 *contents TAKES, const u8 htlc_hold_time[80] TAKES, const u8 truncated_hmac[840] TAKES)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = tal_dup_talarr(r, u8, contents);
	if (htlc_hold_time && truncated_hmac) {
		r->htlc_hold_time = tal_dup_arr(r, u8, htlc_hold_time, 80, 0);
		r->truncated_hmac = tal_dup_arr(r, u8, truncated_hmac, 840, 0);
	} else {
		r->htlc_hold_time = NULL;
		r->truncated_hmac = NULL;
	}
	return r;
}
