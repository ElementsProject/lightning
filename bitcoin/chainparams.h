#ifndef LIGHTNING_BITCOIN_CHAINPARAMS_H
#define LIGHTNING_BITCOIN_CHAINPARAMS_H

#include "config.h"
#include <bitcoin/block.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>
#include <stdbool.h>

struct chainparams {
	const char *network_name;
	const char *bip173_name;
	const struct bitcoin_blkid genesis_blockhash;
	const int rpc_port;
	const char *cli;
	const char *cli_args;
	const struct amount_sat dust_limit;
	const struct amount_sat max_funding;
	const struct amount_msat max_payment;
	const u32 when_lightning_became_cool;

	/* Whether this is a test network or not */
	const bool testnet;
};

/**
 * chainparams_for_network - Look up blockchain parameters by its name
 */
const struct chainparams *chainparams_for_network(const char *network_name);

/**
 * chainparams_by_bip173 - Helper to get a network by its bip173 name
 *
 * This lets us decode BOLT11 addresses.
 */
const struct chainparams *chainparams_by_bip173(const char *bip173_name);

/**
 * chainparams_by_chainhash - Helper to get a network by its genesis blockhash
 */
const struct chainparams *chainparams_by_chainhash(const struct bitcoin_blkid *chain_hash);

#endif /* LIGHTNING_BITCOIN_CHAINPARAMS_H */
