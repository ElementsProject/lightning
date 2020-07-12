#ifndef LIGHTNING_BITCOIN_CHAINPARAMS_H
#define LIGHTNING_BITCOIN_CHAINPARAMS_H

#include "config.h"
#include <bitcoin/block.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/bip32.h>
#include <stdbool.h>

#define ELEMENTS_ASSET_LEN 33

struct chainparams {
	const char *network_name;
	const char *bip173_name;
	/*'bip70_name' is corresponding to the 'chain' field of
	 * the API 'getblockchaininfo' */
	const char *bip70_name;
	const struct bitcoin_blkid genesis_blockhash;
	const int rpc_port;
	const char *cli;
	const char *cli_args;
	/* The min numeric version of cli supported */
	const u64 cli_min_supported_version;
	const struct amount_sat dust_limit;
	const struct amount_sat max_funding;
	const struct amount_msat max_payment;
	const u32 when_lightning_became_cool;
	const u8 p2pkh_version;
	const u8 p2sh_version;

	/* Whether this is a test network or not */
	const bool testnet;

	/* Version codes for BIP32 extended keys in libwally-core*/
	const struct bip32_key_version bip32_key_version;
	const bool is_elements;
	const u8 *fee_asset_tag;
};

/**
 * chainparams_for_network - Look up blockchain parameters by its name
 */
const struct chainparams *chainparams_for_network(const char *network_name);

/**
 * chainparams_for_networks - Get blockchain parameters for all known networks,
 *                            as a tal array.
 */
const struct chainparams **chainparams_for_networks(const tal_t *ctx);

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
 * chainparams_get_network_names - Produce a comma-separated list of network names
 */
const char *chainparams_get_network_names(const tal_t *ctx);

#endif /* LIGHTNING_BITCOIN_CHAINPARAMS_H */
