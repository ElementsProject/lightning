#include "chainparams.h"
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <string.h>

const struct chainparams networks[] = {
    {.index = 0,
     .network_name = "bitcoin",
     .bip173_name = "bc",
     .genesis_blockhash = {{{.u.u8 = {0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00}}}},
     .rpc_port = 8332,
     .cli = "bitcoin-cli",
     .cli_args = NULL,
     .dust_limit = 546,
     /* "Lightning Charge Powers Developers & Blockstream Store" */
     .when_lightning_became_cool = 504500,
     .testnet = false},
    {.index = 1,
     .network_name = "regtest",
     .bip173_name = "bcrt",
     .genesis_blockhash = {{{.u.u8 = {0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f}}}},
     .rpc_port = 18332,
     .cli = "bitcoin-cli",
     .cli_args = "-regtest",
     .dust_limit = 546,
     .when_lightning_became_cool = 1,
     .testnet = true},
    {.index = 2,
     .network_name = "testnet",
     .bip173_name = "tb",
     .genesis_blockhash = {{{.u.u8 = {0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00}}}},
     .rpc_port = 18332,
     .cli = "bitcoin-cli",
     .cli_args = "-testnet",
     .dust_limit = 546,
     .testnet = true},
    {.index = 3,
     .network_name = "litecoin",
     .bip173_name = "ltc",
     .genesis_blockhash = {{{.u.u8 = {0xe2, 0xbf, 0x04, 0x7e, 0x7e, 0x5a, 0x19, 0x1a, 0xa4, 0xef, 0x34, 0xd3, 0x14, 0x97, 0x9d, 0xc9, 0x98, 0x6e, 0x0f, 0x19, 0x25, 0x1e, 0xda, 0xba, 0x59, 0x40, 0xfd, 0x1f, 0xe3, 0x65, 0xa7, 0x12 }}}},
     .rpc_port = 9332,
     .cli = "litecoin-cli",
     .cli_args = NULL,
     .dust_limit = 100000,
     .when_lightning_became_cool = 1320000,
     .testnet = false},
    {.index = 4,
     .network_name = "litecoin-testnet",
     .bip173_name = "tltc",
     .genesis_blockhash = {{{.u.u8 = { 0xa0, 0x29, 0x3e, 0x4e, 0xeb, 0x3d, 0xa6, 0xe6, 0xf5, 0x6f, 0x81, 0xed, 0x59, 0x5f, 0x57, 0x88, 0x0d, 0x1a, 0x21, 0x56, 0x9e, 0x13, 0xee, 0xfd, 0xd9, 0x51, 0x28, 0x4b, 0x5a, 0x62, 0x66, 0x49 }}}},
     .rpc_port = 19332,
     .cli = "litecoin-cli",
     .cli_args = "-testnet",
     .dust_limit = 100000,
     .when_lightning_became_cool = 1,
     .testnet = true}
};

const struct chainparams *chainparams_for_network(const char *network_name)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (streq(network_name, networks[i].network_name)) {
			return &networks[i];
		}
	}
	return NULL;
}

const struct chainparams *chainparams_by_index(const int index)
{
	if (index >= ARRAY_SIZE(networks) || index < 0) {
		return NULL;
	} else {
		return &networks[index];
	}
}

const struct chainparams *chainparams_by_bip173(const char *bip173_name)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (streq(bip173_name, networks[i].bip173_name)) {
			return &networks[i];
		}
	}
	return NULL;
}
