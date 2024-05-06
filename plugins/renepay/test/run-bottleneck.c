#include "config.h"

#include "../errorcodes.c"
#include "../flow.c"
#include "../mcf.c"
#include "../uncertainty.c"
#include "../disabledmap.c"
#include "../route.c"
#include "../routebuilder.c"

#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <common/gossip_store.h>
#include <common/setup.h>
#include <common/utils.h>
#include <gossipd/gossip_store_wiregen.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wiregen.h>

static u8 empty_map[] = {10};

static const char *print_flows(const tal_t *ctx, const char *desc,
			       const struct gossmap *gossmap,
			       struct chan_extra_map *chan_extra_map,
			       struct flow **flows)
{
	tal_t *this_ctx = tal(ctx, tal_t);
	double tot_prob =
	    flowset_probability(tmpctx, flows, gossmap, chan_extra_map, NULL);
	assert(tot_prob >= 0);
	char *buff = tal_fmt(ctx, "%s: %zu subflows, prob %2lf\n", desc,
			     tal_count(flows), tot_prob);
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct amount_msat fee, delivered;
		tal_append_fmt(&buff, "   ");
		for (size_t j = 0; j < tal_count(flows[i]->path); j++) {
			struct short_channel_id scid =
			    gossmap_chan_scid(gossmap, flows[i]->path[j]);
			tal_append_fmt(&buff, "%s%s", j ? "->" : "",
				       fmt_short_channel_id(this_ctx, scid));
		}
		delivered = flows[i]->amount;
		if (!flow_fee(&fee, flows[i])) {
			abort();
		}
		tal_append_fmt(&buff, " prob %.2f, %s delivered with fee %s\n",
			       flows[i]->success_prob,
			       fmt_amount_msat(this_ctx, delivered),
			       fmt_amount_msat(this_ctx, fee));
	}

	tal_free(this_ctx);
	return buff;
}

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
		tal_append_fmt(&buff, " %s delivered with fee %s\n",
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
	/* We don't actually check these! */
	hdr.crc = 0;
	hdr.timestamp = 0;
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

#define NUM_NODES 8

int main(int argc, char *argv[])
{
	int fd;
	char *gossfile;
	struct gossmap *gossmap;
	struct node_id nodes[NUM_NODES];

	common_setup(argv[0]);
	chainparams = chainparams_for_network("regtest");

	fd = tmpdir_mkstemp(tmpctx, "run-bottleneck.XXXXXX", &gossfile);
	assert(write(fd, empty_map, sizeof(empty_map)) == sizeof(empty_map));

	gossmap = gossmap_load(tmpctx, gossfile, NULL);
	assert(gossmap);

	for (size_t i = 0; i < NUM_NODES; i++) {
		struct privkey tmp;
		memset(&tmp, i+1, sizeof(tmp));
		node_id_from_privkey(&tmp, &nodes[i]);
	}

	/* We will try a payment from 1 to 8, forcing a payment split between
	 * two routes 1->2->4->5->6->8 and 1->3->4->5->7->8.
	 * To force the split the total payment amount will be greater than the
	 * channel 1-2 and 1-3 capacities. Then channel 4--5 will be a common
	 * edge in the payment routes.
	 *
	 * MCF does not handle fees hence if the capacity of 4--5 is enough to
	 * let the entire payment pass, we expect that minflow computes two
	 * routes that are scaled down by get_route algorithm
	 * to fit for the fee constraints.
	 *
	 * +--2--+   +--6--+
	 * |     |   |     |
	 * 1     4---5     8
	 * |     |   |     |
	 * +--3--+   +--7--+
	 *
	 * */
	struct short_channel_id scid;

 	assert(mk_short_channel_id(&scid, 1, 2, 0));
 	add_connection(fd, &nodes[0], &nodes[1], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(60 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(60 * 1000));

	assert(mk_short_channel_id(&scid, 1, 3, 0));
 	add_connection(fd, &nodes[0], &nodes[2], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(60 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(60 * 1000));

	assert(mk_short_channel_id(&scid, 2, 4, 0));
 	add_connection(fd, &nodes[1], &nodes[3], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(mk_short_channel_id(&scid, 3, 4, 0));
 	add_connection(fd, &nodes[2], &nodes[3], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(mk_short_channel_id(&scid, 4, 5, 0));
 	add_connection(fd, &nodes[3], &nodes[4], scid,
 		       AMOUNT_MSAT(0),
		       /* MCF cuts off at 95% of the conditional capacity, for
			* cap = 106k that means only 100.7k sats can be sent
			* through this channel. */
 		       AMOUNT_MSAT(106 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(110 * 1000));

	assert(mk_short_channel_id(&scid, 5, 6, 0));
 	add_connection(fd, &nodes[4], &nodes[5], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 100 * 1000 /* 10% */, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(mk_short_channel_id(&scid, 5, 7, 0));
 	add_connection(fd, &nodes[4], &nodes[6], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 100 * 1000 /* 10% */, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(mk_short_channel_id(&scid, 6, 8, 0));
 	add_connection(fd, &nodes[5], &nodes[7], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(mk_short_channel_id(&scid, 7, 8, 0));
 	add_connection(fd, &nodes[6], &nodes[7], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000));

	assert(gossmap_refresh(gossmap, NULL));
	struct uncertainty *uncertainty = uncertainty_new(tmpctx);
	int skipped_count =
	    uncertainty_update(uncertainty, gossmap);
	assert(skipped_count==0);

	bitmap *disabled = tal_arrz(
 	    tmpctx, bitmap, BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));

	char *errmsg;
 	struct flow **flows;
 	flows =
 	    minflow(tmpctx, gossmap, gossmap_find_node(gossmap, &nodes[0]),
 		    gossmap_find_node(gossmap, &nodes[7]),
		    uncertainty->chan_extra_map, disabled,
 		    /* Half the capacity */
 		    AMOUNT_MSAT(100 * 1000 * 1000),
 		    /* max_fee = */ AMOUNT_MSAT(20 * 1000 * 1000),
 		    /* min probability = */ 0.9,
 		    /* delay fee factor = */ 1e-6,
 		    /* base fee penalty */ 10,
 		    /* prob cost factor = */ 10, &errmsg);

	if (!flows) {
  		printf("Minflow has failed with: %s", errmsg);
  		// assert(0 && "minflow failed");
  	}

 	if(flows)
  	printf("%s\n", print_flows(tmpctx, "Simple minflow", gossmap,
  				   uncertainty->chan_extra_map, flows));

	struct preimage preimage;

	struct amount_msat maxfee = AMOUNT_MSAT(20*1000*1000);
	struct payment_info pinfo;
	pinfo.invstr = NULL;
	pinfo.label = NULL;
	pinfo.description = NULL;
	pinfo.payment_secret = NULL;
	pinfo.payment_metadata = NULL;
	pinfo.routehints = NULL;
	pinfo.destination = nodes[7];
	pinfo.amount = AMOUNT_MSAT(100 * 1000 * 1000);

	assert(amount_msat_add(&pinfo.maxspend, maxfee, pinfo.amount));
	pinfo.maxdelay = 100;
	pinfo.final_cltv = 5;

	pinfo.start_time = time_now();
	pinfo.stop_time = timeabs_add(pinfo.start_time, time_from_sec(10000));

	pinfo.base_fee_penalty = 1e-5;
	pinfo.prob_cost_factor = 1e-5;
	pinfo.delay_feefactor = 1e-6;
	pinfo.min_prob_success = 0.9;
	pinfo.use_shadow = false;

	randombytes_buf(&preimage, sizeof(preimage));
	sha256(&pinfo.payment_hash, &preimage, sizeof(preimage));

	// char hex_preimage[600], hex_sha256[600];
	// assert(hex_encode(preimage.r, sizeof(preimage.r), hex_preimage, sizeof(hex_preimage)));
	// assert(hex_encode(pinfo.payment_hash.u.u8, sizeof(pinfo.payment_hash), hex_sha256, sizeof(hex_sha256)));
	// printf("preimage: %s\npayment_hash: %s\n", hex_preimage, hex_sha256);

	struct disabledmap *disabledmap = disabledmap_new(tmpctx);

	enum jsonrpc_errcode errcode;
	const char *err_msg;

	u64 groupid = 1;
	u64 next_partid=1;

	struct route **routes = get_routes(
		/* ctx */tmpctx,
		/* payment */&pinfo,
		/* source */&nodes[0],
		/* destination */&nodes[7],
		/* gossmap */gossmap,
		/* uncertainty */uncertainty,
		disabledmap,
		/* amount */ pinfo.amount,
		/* feebudget */maxfee,
		&next_partid,
		groupid,
		&errcode,
		&err_msg);

	if (!routes) {
		printf("get_route failed with error %d: %s", errcode, err_msg);
	}
 	if(routes)
  	printf("get_routes: %s\n", print_routes(tmpctx, routes));

	common_shutdown();
}
