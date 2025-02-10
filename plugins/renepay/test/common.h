#ifndef LIGHTNING_PLUGINS_RENEPAY_TEST_COMMON_H
#define LIGHTNING_PLUGINS_RENEPAY_TEST_COMMON_H
#include "config.h"
#include <ccan/crc32c/crc32c.h>
#include <common/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wiregen.h>

static const char *print_routes(const tal_t *ctx,
			       struct route **routes)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	char *buff = tal_fmt(ctx, "%zu routes\n", tal_count(routes));
	for (size_t i = 0; i < tal_count(routes); i++) {
		struct amount_msat fee, delivered;

		delivered = route_delivers(routes[i]);
		fee = route_fees(routes[i]);
		tal_append_fmt(&buff, "   %s", fmt_route_path(this_ctx, routes[i]));
		tal_append_fmt(&buff, " prob %.2f, %s delivered with fee %s\n",
			       routes[i]->success_prob,
			       fmt_amount_msat(this_ctx, delivered),
			       fmt_amount_msat(this_ctx, fee));
	}

	tal_free(this_ctx);
	return buff;
}

static void write_to_store(int store_fd, const u8 *msg)
{
	struct gossip_hdr hdr;

	hdr.flags = cpu_to_be16(0);
	hdr.len = cpu_to_be16(tal_count(msg));
	hdr.timestamp = 0;
	hdr.crc = cpu_to_be32(crc32c(be32_to_cpu(hdr.timestamp), msg, tal_count(msg)));
	assert(write(store_fd, &hdr, sizeof(hdr)) == sizeof(hdr));
	assert(write(store_fd, msg, tal_count(msg)) == tal_count(msg));
}

static void add_connection(int store_fd,
			   const struct node_id *from,
			   const struct node_id *to,
			   struct short_channel_id scid,
			   struct amount_msat min,
			   struct amount_msat max,
			   u32 base_fee, s32 proportional_fee,
			   u32 delay,
			   struct amount_sat capacity)
{
	secp256k1_ecdsa_signature dummy_sig;
	struct secret not_a_secret;
	struct pubkey dummy_key;
	u8 *msg;
	const struct node_id *ids[2];

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));
	memset(&not_a_secret, 1, sizeof(not_a_secret));
	pubkey_from_secret(&not_a_secret, &dummy_key);

	if (node_id_cmp(from, to) > 0) {
		ids[0] = to;
		ids[1] = from;
	} else {
		ids[0] = from;
		ids[1] = to;
	}
	msg = towire_channel_announcement(tmpctx, &dummy_sig, &dummy_sig,
					  &dummy_sig, &dummy_sig,
					  /* features */ NULL,
					  &chainparams->genesis_blockhash,
					  scid,
					  ids[0], ids[1],
					  &dummy_key, &dummy_key);
	write_to_store(store_fd, msg);

	msg = towire_gossip_store_channel_amount(tmpctx, capacity);
	write_to_store(store_fd, msg);

	u8 flags = node_id_idx(from, to);

	msg = towire_channel_update(tmpctx,
				    &dummy_sig,
				    &chainparams->genesis_blockhash,
				    scid, 0,
				    ROUTING_OPT_HTLC_MAX_MSAT,
				    flags,
				    delay,
				    min,
				    base_fee,
				    proportional_fee,
				    max);
	write_to_store(store_fd, msg);
}

static void node_id_from_privkey(const struct privkey *p, struct node_id *id)
{
	struct pubkey k;
	pubkey_from_privkey(p, &k);
	node_id_from_pubkey(id, &k);
}


#endif /* LIGHTNING_PLUGINS_RENEPAY_TEST_COMMON_H */
