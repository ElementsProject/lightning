/* Eduardo: testing route_map.
 * */

#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/bigsize.h>
#include <common/channel_id.h>
#include <common/gossip_store.h>
#include <common/node_id.h>
#include <common/setup.h>
#include <common/wireaddr.h>
#include <stdio.h>
#include <assert.h>

#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>

#define RENEPAY_UNITTEST
#include "../flow.c"
#include "../route.c"

static void destroy_route(
		struct route *route,
		struct route_map * map)
{
	printf("calling %s with  %s\n",
		__PRETTY_FUNCTION__,
		fmt_routekey(tmpctx,&route->key));
	route_map_del(map, route);
}

static void valgrind_ok1(void)
{
	const char seed[] = "seed";
	struct sha256 hash;

	sha256(&hash,seed,sizeof(seed));

	tal_t *this_ctx = tal(tmpctx,tal_t);

	struct route_map *map
		= tal(this_ctx, struct route_map);

	route_map_init(map);

	{
		tal_t *local_ctx = tal(this_ctx,tal_t);
		struct routekey key;

		struct route *r1 = new_route(local_ctx, 1, 1, hash,
					     AMOUNT_MSAT(0), AMOUNT_MSAT(0));
		struct route *r2 = new_route(local_ctx, 2, 3, hash,
					     AMOUNT_MSAT(0), AMOUNT_MSAT(0));

		printf("key1 = %s\n", fmt_routekey(local_ctx,&r1->key));
		printf("key1 = %s\n", fmt_routekey(local_ctx,&r2->key));
		printf("key hash 1 = %zu\n", routekey_hash(&r1->key));
		printf("key hash 2 = %zu\n", routekey_hash(&r2->key));

		route_map_add(map,r1); tal_add_destructor2(r1, destroy_route, map);
		route_map_add(map,r2); tal_add_destructor2(r2, destroy_route, map);

		key = routekey(&hash,1,1);
		struct route *q1 = route_map_get(map, &key);
		key = routekey(&hash,2,3);
		struct route *q2 = route_map_get(map, &key);

		assert(routekey_hash(&q1->key)==routekey_hash(&r1->key));
		assert(routekey_hash(&q2->key)==routekey_hash(&r2->key));

		tal_free(local_ctx);
	}

	tal_free(this_ctx);

}
int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	valgrind_ok1();
	common_shutdown();
}

