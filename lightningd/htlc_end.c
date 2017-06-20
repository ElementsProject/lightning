#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <daemon/htlc.h>
#include <daemon/log.h>
#include <daemon/pseudorand.h>
#include <lightningd/htlc_end.h>
#include <stdio.h>

size_t hash_htlc_key(const struct htlc_key *k)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	/* peer doesn't move while in this hash, so we just hash pointer. */
	siphash24_update(&ctx, &k->peer, sizeof(k->peer));
	siphash24_u64(&ctx, k->id);

	return siphash24_done(&ctx);
}

struct htlc_in *find_htlc_in(const struct htlc_in_map *map,
			       const struct peer *peer,
			       u64 htlc_id)
{
	const struct htlc_key key = { (struct peer *)peer, htlc_id };
	return htlc_in_map_get(map, &key);
}

static void remove_htlc_in(struct htlc_in *hend, struct htlc_in_map *map)
{
	htlc_in_map_del(map, hend);
}

void connect_htlc_in(struct htlc_in_map *map, struct htlc_in *hend)
{
	tal_add_destructor2(hend, remove_htlc_in, map);
	htlc_in_map_add(map, hend);
}

struct htlc_out *find_htlc_out(const struct htlc_out_map *map,
			       const struct peer *peer,
			       u64 htlc_id)
{
	const struct htlc_key key = { (struct peer *)peer, htlc_id };
	return htlc_out_map_get(map, &key);
}

static void remove_htlc_out(struct htlc_out *hend, struct htlc_out_map *map)
{
	htlc_out_map_del(map, hend);
}

void connect_htlc_out(struct htlc_out_map *map, struct htlc_out *hend)
{
	tal_add_destructor2(hend, remove_htlc_out, map);
	htlc_out_map_add(map, hend);
}

static void *PRINTF_FMT(3,4)
	corrupt(const void *ptr, const char *abortstr, const char *fmt, ...)
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
		return corrupt(hin, abortstr, "zero msatoshi");
	else if (htlc_state_owner(hin->hstate) != REMOTE)
		return corrupt(hin, abortstr, "invalid state %s",
			       htlc_state_name(hin->hstate));
	else if (hin->failuremsg && hin->preimage)
		return corrupt(hin, abortstr, "Both failed and succeeded");
	else if (hin->failuremsg && hin->malformed)
		return corrupt(hin, abortstr, "Both failed and malformed");

	return cast_const(struct htlc_in *, hin);
}

struct htlc_in *new_htlc_in(const tal_t *ctx,
			    struct peer *peer, u64 id,
			    u64 msatoshi, u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    const struct secret *shared_secret,
			    const u8 *onion_routing_packet)
{
	struct htlc_in *hin = tal(ctx, struct htlc_in);

	hin->key.peer = peer;
	hin->key.id = id;
	hin->msatoshi = msatoshi;
	hin->cltv_expiry = cltv_expiry;
	hin->payment_hash = *payment_hash;
	hin->shared_secret = *shared_secret;
	memcpy(hin->onion_routing_packet, onion_routing_packet,
	       sizeof(hin->onion_routing_packet));

	hin->hstate = RCVD_ADD_COMMIT;
	hin->failuremsg = NULL;
	hin->malformed = 0;
	hin->preimage = NULL;

	return htlc_in_check(hin, "new_htlc_in");
}

struct htlc_out *htlc_out_check(const struct htlc_out *hout,
				const char *abortstr)
{
	if (hout->msatoshi == 0)
		return corrupt(hout, abortstr, "zero msatoshi");
	else if (htlc_state_owner(hout->hstate) != LOCAL)
		return corrupt(hout, abortstr, "invalid state %s",
			       htlc_state_name(hout->hstate));
	else if (hout->failuremsg && hout->preimage)
		return corrupt(hout, abortstr, "Both failed and succeeded");
	else if (!hout->in && !hout->pay_command)
		return corrupt(hout, abortstr,
			       "Neither hout->in nor paycommand");

	return cast_const(struct htlc_out *, hout);
}

/* You need to set the ID, then connect_htlc_out this! */
struct htlc_out *new_htlc_out(const tal_t *ctx,
			      struct peer *peer,
			      u64 msatoshi, u32 cltv_expiry,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in,
			      struct pay_command *pc)
{
	struct htlc_out *hout = tal(ctx, struct htlc_out);

	hout->key.peer = peer;
	hout->msatoshi = msatoshi;
	hout->cltv_expiry = cltv_expiry;
	hout->payment_hash = *payment_hash;
	memcpy(hout->onion_routing_packet, onion_routing_packet,
	       sizeof(hout->onion_routing_packet));

	hout->hstate = SENT_ADD_HTLC;
	hout->failuremsg = NULL;
	hout->malformed = 0;
	hout->preimage = NULL;

	hout->in = in;
	hout->pay_command = pc;

	return htlc_out_check(hout, "new_htlc_out");
}
