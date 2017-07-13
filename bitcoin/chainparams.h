#ifndef LIGHTNING_BITCOIN_CHAINPARAMS_H
#define LIGHTNING_BITCOIN_CHAINPARAMS_H

#include "config.h"
#include <bitcoin/shadouble.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct chainparams {
	const int index;
	const char *network_name;
	const struct sha256_double genesis_blockhash;
	const int rpc_port;
	const char *cli;
	const char *cli_args;
	const u64 dust_limit;

	/* Whether this is a test network or not */
	const bool testnet;
};

/**
 * chainparams_for_network - Look up blockchain parameters by its name
 */
const struct chainparams *chainparams_for_network(const char *network_name);

/**
 * chainparams_by_index - Helper to get a network by its numeric index
 *
 * We may not want to pass the network name through to subdaemons, so
 * we allows lookup by index.
 */
const struct chainparams *chainparams_by_index(const int index);
#endif /* LIGHTNING_BITCOIN_CHAINPARAMS_H */
