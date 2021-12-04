#include "config.h"
#include <common/gossmap.h>
#include <devtools/clean_topo.h>

static void visit(struct gossmap *map,
		  struct gossmap_node *n,
		  bool *visited)
{
	visited[gossmap_node_idx(map, n)] = true;

	for (size_t i = 0; i < n->num_chans; i++) {
		int dir;
		struct gossmap_chan *c = gossmap_nth_chan(map, n, i, &dir);
		struct gossmap_node *peer;

		peer = gossmap_nth_node(map, c, !dir);
		if (!visited[gossmap_node_idx(map, peer)])
			visit(map, peer, visited);
	}
}

void clean_topo(struct gossmap *map, bool remove_singles)
{
	struct gossmap_node *n, *next;
	bool *visited;

	/* Remove channels which are not enabled in both dirs. */
	for (struct gossmap_chan *c = gossmap_first_chan(map);
	     c;
	     c = gossmap_next_chan(map, c)) {
		if (!c->half[0].enabled || !c->half[1].enabled) {
			gossmap_remove_chan(map, c);
		}
	}

	if (remove_singles) {
		for (n = gossmap_first_node(map); n; n = next) {
			next = gossmap_next_node(map, n);
			if (n->num_chans == 1)
				gossmap_remove_node(map, n);
		}
	}

	/* Remove isolated nodes (we assume first isn't isolated!) */
	visited = tal_arrz(NULL, bool, gossmap_max_node_idx(map));
	visit(map, gossmap_first_node(map), visited);

	for (n = gossmap_first_node(map); n; n = next) {
		next = gossmap_next_node(map, n);
		if (!visited[gossmap_node_idx(map, n)])
			gossmap_remove_node(map, n);
	}
	tal_free(visited);
}
