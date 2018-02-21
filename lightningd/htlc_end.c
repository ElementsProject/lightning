#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/htlc.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <lightningd/htlc_end.h>
#include <lightningd/log.h>
#include <stdio.h>

size_t hash_htlc_key(const struct htlc_key *k)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	/* channel doesn't move while in this hash, so we just hash pointer. */
	siphash24_update(&ctx, &k->channel, sizeof(k->channel));
	siphash24_u64(&ctx, k->id);

	return siphash24_done(&ctx);
}

struct htlc_in *find_htlc_in(const struct htlc_in_map *map,
			       const struct channel *channel,
			       u64 htlc_id)
{
	const struct htlc_key key = { (struct channel *)channel, htlc_id };
	return htlc_in_map_get(map, &key);
}

static void destroy_htlc_in(struct htlc_in *hend, struct htlc_in_map *map)
{
	htlc_in_map_del(map, hend);
}

void connect_htlc_in(struct htlc_in_map *map, struct htlc_in *hend)
{
	tal_add_destructor2(hend, destroy_htlc_in, map);
	htlc_in_map_add(map, hend);
}

struct htlc_out *find_htlc_out(const struct htlc_out_map *map,
			       const struct channel *channel,
			       u64 htlc_id)
{
	const struct htlc_key key = { (struct channel *)channel, htlc_id };
	return htlc_out_map_get(map, &key);
}

static void destroy_htlc_out(struct htlc_out *hend, struct htlc_out_map *map)
{
	htlc_out_map_del(map, hend);
}

void connect_htlc_out(struct htlc_out_map *map, struct htlc_out *hend)
{
	tal_add_destructor2(hend, destroy_htlc_out, map);
	htlc_out_map_add(map, hend);
}

static void *PRINTF_FMT(2,3)
	corrupt(const char *abortstr, const char *fmt, ...)
{
	if (abortstr) {
		char *p;
		va_list ap;

		va_start(ap, fmt);
		p = tal_vfmt(NULL, fmt, ap);
		fatal("%s:%s\n", abortstr, p);
		va_end(ap);
	}
	return NULL;
}

struct htlc_in *htlc_in_check(const struct htlc_in *hin, const char *abortstr)
{
	if (hin->msatoshi == 0)
		return corrupt(abortstr, "zero msatoshi");
	else if (htlc_state_owner(hin->hstate) != REMOTE)
		return corrupt(abortstr, "invalid state %s",
			       htlc_state_name(hin->hstate));
	else if (hin->failuremsg && hin->preimage)
		return corrupt(abortstr, "Both failuremsg and succeeded");
	else if (hin->failcode != 0 && hin->preimage)
		return corrupt(abortstr, "Both failcode and succeeded");
	else if (hin->failuremsg && (hin->failcode & BADONION))
		return corrupt(abortstr, "Both failed and malformed");

	return cast_const(struct htlc_in *, hin);
}

struct htlc_in *new_htlc_in(const tal_t *ctx,
			    struct channel *channel, u64 id,
			    u64 msatoshi, u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    const struct secret *shared_secret,
			    const u8 *onion_routing_packet)
{
	struct htlc_in *hin = tal(ctx, struct htlc_in);

	hin->dbid = 0;
	hin->key.channel = channel;
	hin->key.id = id;
	hin->msatoshi = msatoshi;
	hin->cltv_expiry = cltv_expiry;
	hin->payment_hash = *payment_hash;
	hin->shared_secret = *shared_secret;
	memcpy(hin->onion_routing_packet, onion_routing_packet,
	       sizeof(hin->onion_routing_packet));

	hin->hstate = RCVD_ADD_COMMIT;
	hin->failcode = 0;
	hin->failuremsg = NULL;
	hin->preimage = NULL;

	return htlc_in_check(hin, "new_htlc_in");
}

struct htlc_out *htlc_out_check(const struct htlc_out *hout,
				const char *abortstr)
{
	if (htlc_state_owner(hout->hstate) != LOCAL)
		return corrupt(abortstr, "invalid state %s",
			       htlc_state_name(hout->hstate));
	else if (hout->failuremsg && hout->preimage)
		return corrupt(abortstr, "Both failed and succeeded");

	return cast_const(struct htlc_out *, hout);
}

/* You need to set the ID, then connect_htlc_out this! */
struct htlc_out *new_htlc_out(const tal_t *ctx,
			      struct channel *channel,
			      u64 msatoshi, u32 cltv_expiry,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in)
{
	struct htlc_out *hout = tal(ctx, struct htlc_out);

        /* Mark this as an as of now unsaved HTLC */
	hout->dbid = 0;

	hout->key.channel = channel;
	hout->key.id = HTLC_INVALID_ID;
	hout->msatoshi = msatoshi;
	hout->cltv_expiry = cltv_expiry;
	hout->payment_hash = *payment_hash;
	memcpy(hout->onion_routing_packet, onion_routing_packet,
	       sizeof(hout->onion_routing_packet));

	hout->hstate = SENT_ADD_HTLC;
	hout->failcode = 0;
	hout->failuremsg = NULL;
	hout->preimage = NULL;

	hout->in = in;

	return htlc_out_check(hout, "new_htlc_out");
}

#if DEVELOPER
void htlc_inmap_mark_pointers_used(struct htable *memtable,
				   const struct htlc_in_map *map)
{
	struct htlc_in *hin;
	struct htlc_in_map_iter it;

	/* memleak can't see inside hash tables, so do them manually */
	for (hin = htlc_in_map_first(map, &it);
	     hin;
	     hin = htlc_in_map_next(map, &it))
		memleak_scan_region(memtable, hin);
}

void htlc_outmap_mark_pointers_used(struct htable *memtable,
				   const struct htlc_out_map *map)
{
	struct htlc_out *hout;
	struct htlc_out_map_iter it;

	/* memleak can't see inside hash tables, so do them manually */
	for (hout = htlc_out_map_first(map, &it);
	     hout;
	     hout = htlc_out_map_next(map, &it))
		memleak_scan_region(memtable, hout);
}
#endif /* DEVELOPER */
