#include "commit_tx.h"
#include "output_to_htlc.h"
#include "peer.h"
#include "peer_internal.h"

/* FIXME: Array makes this O(n^2).  Use a hash table. */
struct wscript_by_wpkh {
	struct htlc *h;
	const u8 *wscript;
	struct sha256 hash;
};

struct htlc_output_map {
	struct wscript_by_wpkh *wpkh;
};

struct htlc_output_map *get_htlc_output_map(const tal_t *ctx,
					    const struct peer *peer,
					    const struct sha256 *rhash,
					    enum side side,
					    unsigned int commit_num)
{
	struct htlc_map_iter it;
	struct htlc *h;
	size_t i;
	struct htlc_output_map *omap = tal(ctx, struct htlc_output_map);

	/* FIXME: use commit_num to filter htlcs. */
	if (side == LOCAL)
		assert(commit_num <= peer->local.commit->commit_num);
	else
		assert(commit_num <= peer->remote.commit->commit_num);

	omap->wpkh = tal_arr(omap, struct wscript_by_wpkh,
			     htlc_map_count(&peer->htlcs));

	for (i = 0, h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		omap->wpkh[i].h = h;
		omap->wpkh[i].wscript = wscript_for_htlc(omap, peer, h, rhash,
							 side);
		sha256(&omap->wpkh[i].hash,
		       omap->wpkh[i].wscript,
		       tal_count(omap->wpkh[i].wscript));
		i++;
	}
	tal_resize(&omap->wpkh, i);
	return omap;
}

static struct wscript_by_wpkh *get_wpkh(struct htlc_output_map *omap,
					const u8 *script)
{
	size_t i;

	if (!is_p2wsh(script))
		return NULL;

	for (i = 0; i < tal_count(omap->wpkh); i++) {
		if (!memcmp(script + 2, omap->wpkh[i].hash.u.u8,
			    sizeof(omap->wpkh[i].hash)))
			return &omap->wpkh[i];
	}
	return NULL;
}

/* Which wscript does this pay to? */
struct htlc *txout_get_htlc(struct htlc_output_map *omap,
			    const u8 *script,
			    const u8 **wscript)
{
	struct wscript_by_wpkh *wpkh = get_wpkh(omap, script);

	if (wpkh) {
		*wscript = wpkh->wscript;
		return wpkh->h;
	}
	return NULL;
}
