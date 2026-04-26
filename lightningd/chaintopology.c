#include "config.h"
#include <ccan/tal/tal.h>
#include <lightningd/chaintopology.h>

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	topo->ld = ld;
	topo->log = log;

	return topo;
}
