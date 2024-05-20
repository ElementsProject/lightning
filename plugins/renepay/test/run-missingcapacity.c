/* Checks that uncertainty_update and get_routes can handle a gossmap where the
 * capacity of some channels are missing.
 *
 * */
#include "config.h"

#include "../disabledmap.c"
#include "../errorcodes.c"
#include "../flow.c"
#include "../mcf.c"
#include "../route.c"
#include "../routebuilder.c"
#include "../uncertainty.c"
#include "common.h"

#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/utils.h>
#include <sodium/randombytes.h>

static u8 empty_map[] = {10};

#define NUM_NODES 4

static void remove_file(char *fname) { assert(!remove(fname)); }

int main(int argc, char *argv[])
{
	int fd;
	char *gossfile;
	struct gossmap *gossmap;
	struct node_id nodes[NUM_NODES];

	common_setup(argv[0]);
	chainparams = chainparams_for_network("regtest");

	fd = tmpdir_mkstemp(tmpctx, "run-missingcapacity.XXXXXX", &gossfile);
	tal_add_destructor(gossfile, remove_file);
	assert(write(fd, empty_map, sizeof(empty_map)) == sizeof(empty_map));

	gossmap = gossmap_load(tmpctx, gossfile, NULL);
	assert(gossmap);

	for (size_t i = 0; i < NUM_NODES; i++) {
		struct privkey tmp;
		memset(&tmp, i+1, sizeof(tmp));
		node_id_from_privkey(&tmp, &nodes[i]);
	}

	/* We will try a payment from 1 to 4.
	 * There are two possible routes 1->2->4 or 1->3->4.
	 * However, we will simulate that we don't have channel 3->4's capacity
	 * in the gossmap (see #7194). We expect that 3->4 it's simply ignored
	 * and only route through 1->2->4 is used.
	 *
	 * +--2--+
	 * |     |
	 * 1     4
	 * |     |
	 * +--3--+
	 *
	 * */
	struct short_channel_id scid;

 	assert(mk_short_channel_id(&scid, 1, 2, 0));
 	add_connection(fd, &nodes[0], &nodes[1], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000),
		       /* add capacity? = */ true);

	assert(mk_short_channel_id(&scid, 2, 4, 0));
 	add_connection(fd, &nodes[1], &nodes[3], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000),
		       /* add capacity? = */ true);

	assert(mk_short_channel_id(&scid, 1, 3, 0));
 	add_connection(fd, &nodes[0], &nodes[2], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000),
		       /* add capacity? = */ true);

	assert(mk_short_channel_id(&scid, 3, 4, 0));
 	add_connection(fd, &nodes[2], &nodes[3], scid,
 		       AMOUNT_MSAT(0),
 		       AMOUNT_MSAT(1000 * 1000 * 1000),
 		       0, 0, 5,
 		       AMOUNT_SAT(1000 * 1000),
		       /* add capacity? = */ false);

	assert(gossmap_refresh(gossmap, NULL));
	struct uncertainty *uncertainty = uncertainty_new(tmpctx);
	int skipped_count =
	    uncertainty_update(uncertainty, gossmap);
	assert(skipped_count==1);

	struct preimage preimage;

	struct amount_msat maxfee = AMOUNT_MSAT(20*1000);
	struct payment_info pinfo;
	pinfo.invstr = NULL;
	pinfo.label = NULL;
	pinfo.description = NULL;
	pinfo.payment_secret = NULL;
	pinfo.payment_metadata = NULL;
	pinfo.routehints = NULL;
	pinfo.destination = nodes[3];
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

	struct disabledmap *disabledmap = disabledmap_new(tmpctx);

	enum jsonrpc_errcode errcode;
	const char *err_msg;

	u64 groupid = 1;
	u64 next_partid=1;

	struct route **routes = get_routes(
		/* ctx */tmpctx,
		/* payment */&pinfo,
		/* source */&nodes[0],
		/* destination */&nodes[3],
		/* gossmap */gossmap,
		/* uncertainty */uncertainty,
		disabledmap,
		/* amount */ pinfo.amount,
		/* feebudget */maxfee,
		&next_partid,
		groupid,
		&errcode,
		&err_msg);

	assert(routes);

	if (!routes) {
		printf("get_route failed with error %d: %s", errcode, err_msg);
	} else {
		printf("get_routes: %s\n", print_routes(tmpctx, routes));
		assert(tal_count(routes) == 1);
		assert(tal_count(routes[0]->hops) == 2);
		assert(node_id_eq(&routes[0]->hops[0].node_id, &nodes[1]));
		assert(node_id_eq(&routes[0]->hops[1].node_id, &nodes[3]));
	}

	common_shutdown();
}

