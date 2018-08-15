#ifndef LIGHTNING_BITCOIN_CHAINPARAMS_H
#define LIGHTNING_BITCOIN_CHAINPARAMS_H

#include "config.h"
#include <bitcoin/block.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct chainparams {
	const char *network_name;
	const char *bip173_name;
	const struct bitcoin_blkid genesis_blockhash;
	const int rpc_port;
	const char *cli;
	const char *cli_args;
	const u64 dust_limit;
	const u64 max_funding_satoshi;
	const u64 max_payment_msat;
	const u32 when_lightning_became_cool;
	const u8 p2pkh_version;
	const u8 p2sh_version;

	/* Whether this is a test network or not */
	const bool testnet;
};

/**
 * chainparams_count - Returns the number of supported networks
 */
int chainparams_count(void);

/**
 * chainparams_by_index - Helper to get a network by its numeric index
 */
const struct chainparams *chainparams_by_index(const int index);

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

/**
 * chainparams_by_p2pkh_version: Helper to get a network by its p2pkh version
 */
const struct chainparams *chainparams_by_p2pkh_version(const u8 version);

/**
 * chainparams_by_p2sh_version: Helper to get a network by its p2sh version
 */
const struct chainparams *chainparams_by_p2sh_version(const u8 version);

#endif /* LIGHTNING_BITCOIN_CHAINPARAMS_H */
