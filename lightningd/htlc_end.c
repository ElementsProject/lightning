#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/tal/tal.h>
#include <daemon/pseudorand.h>
#include <lightningd/htlc_end.h>

size_t hash_htlc_end(const struct htlc_end *e)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	/* peer doesn't move while in this hash, so we just hash pointer. */
	siphash24_update(&ctx, &e->peer, sizeof(e->peer));
	siphash24_u64(&ctx, e->htlc_id);
	siphash24_u8(&ctx, e->which_end);

	return siphash24_done(&ctx);
}

struct htlc_end *find_htlc_end(const struct htlc_end_map *map,
			       const struct peer *peer,
			       u64 htlc_id,
			       enum htlc_end_type which_end)
{
	const struct htlc_end key = { which_end, (struct peer *)peer, htlc_id,
				      0, NULL, NULL };

	return htlc_end_map_get(map, &key);
}

static void remove_htlc_end(struct htlc_end *hend, struct htlc_end_map *map)
{
	htlc_end_map_del(map, hend);
}

void connect_htlc_end(struct htlc_end_map *map, struct htlc_end *hend)
{
	tal_add_destructor2(hend, remove_htlc_end, map);
	htlc_end_map_add(map, hend);
}
