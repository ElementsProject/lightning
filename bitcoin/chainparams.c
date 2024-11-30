#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>

/* Version codes for BIP32 extended keys in libwally-core.
 * Stolen from wally_bip32.h in libwally-core*/
#define BIP32_VER_MAIN_PUBLIC  0x0488B21E
#define BIP32_VER_MAIN_PRIVATE 0x0488ADE4
#define BIP32_VER_TEST_PUBLIC  0x043587CF
#define BIP32_VER_TEST_PRIVATE 0x04358394
#define BIP32_VER_SIGT_PUBLIC  0x043587CF
#define BIP32_VER_SIGT_PRIVATE 0x04358394

static u8 liquid_fee_asset[] = {
    0x01, 0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57, 0x34, 0xae,
    0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41, 0x28, 0x29, 0xc0, 0xd0, 0x57,
    0x9f, 0x0a, 0x71, 0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
};

static u8 liquid_regtest_fee_asset[] = {
    0x01, 0x5c, 0xe7, 0xb9, 0x63, 0xd3, 0x7f, 0x8f, 0x2d, 0x51, 0xca,
    0xfb, 0xba, 0x92, 0x8a, 0xaa, 0x9e, 0x22, 0x0b, 0x8b, 0xbc, 0x66,
    0x05, 0x71, 0x49, 0x9c, 0x03, 0x62, 0x8a, 0x38, 0x51, 0xb8, 0xce,
};

const struct chainparams networks[] = {
    {.network_name = "bitcoin",
     .onchain_hrp = "bc",
     .lightning_hrp = "bc",
     .bip70_name = "main",
     .genesis_blockhash = {{{.u.u8 = {0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3,
				      0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
				      0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1,
				      0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
				      0x00, 0x00, 0x00, 0x00}}}},
     .rpc_port = 8332,
     .ln_port = 9735,
     .cli = "bitcoin-cli",
     .cli_args = NULL,
     .cli_min_supported_version = 150000,
     .dust_limit = { 546 },
     /* BOLT #2:
      *
      * The sending node:
      *...
      *   - MUST set `funding_satoshis` to less than 2^24 satoshi.
      */
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     /* "Lightning Charge Powers Developers & Blockstream Store" */
     .when_lightning_became_cool = 504500,
     .p2pkh_version = 0,
     .p2sh_version = 5,
     .testnet = false,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_MAIN_PRIVATE},
     .is_elements = false},
    {.network_name = "regtest",
     .onchain_hrp = "bcrt",
     .lightning_hrp = "bcrt",
     .bip70_name = "regtest",
     .genesis_blockhash = {{{.u.u8 = {0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b,
				      0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb,
				      0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e,
				      0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c,
				      0xf1, 0x88, 0x91, 0x0f}}}},
     .rpc_port = 18443,
     .ln_port = 19846,
     .cli = "bitcoin-cli",
     .cli_args = "-regtest",
     .cli_min_supported_version = 150000,
     .dust_limit = { 546 },
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 111,
     .p2sh_version = 196,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
    {.network_name = "signet",
     .onchain_hrp = "tb",
     .lightning_hrp = "tbs",
     .bip70_name = "signet",
     // 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
     .genesis_blockhash = {{{.u.u8 = {0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80,
				      0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2,
				      0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f,
				      0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81,
				      0x08, 0x00, 0x00, 0x00}}}},
     .rpc_port = 38332,
     .ln_port = 39735,
     .cli = "bitcoin-cli",
     .cli_args = "-signet",
     .cli_min_supported_version = 150000,
     .dust_limit = { 546 },
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 111,
     .p2sh_version = 196,
     .testnet = true,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_SIGT_PUBLIC, .bip32_privkey_version = BIP32_VER_SIGT_PRIVATE},
     .is_elements = false,
    },
    {.network_name = "testnet",
     .onchain_hrp = "tb",
     .lightning_hrp = "tb",
     .bip70_name = "test",
     .genesis_blockhash = {{{.u.u8 = {0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95,
				      0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce,
				      0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84,
				      0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09,
				      0x00, 0x00, 0x00, 0x00}}}},
     .rpc_port = 18332,
     .ln_port = 19735,
     .cli = "bitcoin-cli",
     .cli_args = "-testnet",
     .cli_min_supported_version = 150000,
     .dust_limit = { 546 },
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .p2pkh_version = 111,
     .p2sh_version = 196,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
    {.network_name = "testnet4",
     .onchain_hrp = "tb",
     .lightning_hrp = "tb",
     .bip70_name = "testnet4",
     // 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
     .genesis_blockhash = {{{.u.u8 = {0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3,
				      0x5b, 0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4,
				      0x7f, 0x50, 0xae, 0x72, 0x5a, 0xe2, 0xde,
				      0x53, 0xbc, 0xfb, 0xba, 0xf2, 0x84, 0xda,
				      0x00, 0x00, 0x00, 0x00}}}},
     .rpc_port = 48332,
     .ln_port = 49735,
     .cli = "bitcoin-cli",
     .cli_args = "-testnet4",
     .cli_min_supported_version = 150000,
     .dust_limit = { 546 },
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .p2pkh_version = 111,
     .p2sh_version = 196,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
    {.network_name = "litecoin",
     .onchain_hrp = "ltc",
     .lightning_hrp = "ltc",
     .bip70_name = "main",
     .genesis_blockhash = {{{.u.u8 = {0xe2, 0xbf, 0x04, 0x7e, 0x7e, 0x5a, 0x19,
				      0x1a, 0xa4, 0xef, 0x34, 0xd3, 0x14, 0x97,
				      0x9d, 0xc9, 0x98, 0x6e, 0x0f, 0x19, 0x25,
				      0x1e, 0xda, 0xba, 0x59, 0x40, 0xfd, 0x1f,
				      0xe3, 0x65, 0xa7, 0x12}}}},
     .rpc_port = 9332,
     .ln_port = 9735,
     .cli = "litecoin-cli",
     .cli_args = NULL,
     .cli_min_supported_version = 150000,
     .dust_limit = { 100000 },
     .max_funding = AMOUNT_SAT_INIT(60 * ((1 << 24) - 1)),
     .max_payment = AMOUNT_MSAT_INIT(60 * 0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1320000,
     .p2pkh_version = 48,
     .p2sh_version = 50,
     .testnet = false,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_MAIN_PRIVATE},
     .is_elements = false},
    {.network_name = "litecoin-testnet",
     .onchain_hrp = "tltc",
     .lightning_hrp = "tltc",
     .bip70_name = "test",
     .genesis_blockhash = {{{.u.u8 = {0xa0, 0x29, 0x3e, 0x4e, 0xeb, 0x3d, 0xa6,
				      0xe6, 0xf5, 0x6f, 0x81, 0xed, 0x59, 0x5f,
				      0x57, 0x88, 0x0d, 0x1a, 0x21, 0x56, 0x9e,
				      0x13, 0xee, 0xfd, 0xd9, 0x51, 0x28, 0x4b,
				      0x5a, 0x62, 0x66, 0x49}}}},
     .rpc_port = 19332,
     .ln_port = 9735,
     .cli = "litecoin-cli",
     .cli_args = "-testnet",
     .cli_min_supported_version = 150000,
     .dust_limit = { 100000 },
     .max_funding = AMOUNT_SAT_INIT(60 * ((1 << 24) - 1)),
     .max_payment = AMOUNT_MSAT_INIT(60 * 0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 111,
     .p2sh_version = 58,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
    {.network_name = "liquid-regtest",
     .onchain_hrp = "ert",
     .lightning_hrp = "ert",
     .bip70_name = "liquid-regtest",
     .genesis_blockhash = {{{.u.u8 = {0x9f, 0x87, 0xeb, 0x58, 0x0b, 0x9e, 0x5f,
				      0x11, 0xdc, 0x21, 0x1e, 0x9f, 0xb6, 0x6a,
				      0xbb, 0x36, 0x99, 0x99, 0x90, 0x44, 0xf8,
				      0xfe, 0x14, 0x68, 0x01, 0x16, 0x23, 0x93,
				      0x36, 0x42, 0x86, 0xc6}}}},
     .rpc_port = 19332,
     .ln_port = 20735,
     .cli = "elements-cli",
     .cli_args = "-chain=liquid-regtest",
     .dust_limit = {546},
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 91,
     .p2sh_version = 75,
     .testnet = true,
     .fee_asset_tag = liquid_regtest_fee_asset,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = true},
    {.network_name = "liquid",
     .onchain_hrp = "ex",
     .lightning_hrp = "ex",
     .bip70_name = "liquidv1",
     .genesis_blockhash = {{{.u.u8 = {0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0x0d,
				      0xb2, 0x94, 0x4c, 0xa0, 0x59, 0xa3, 0xa1,
				      0x0e, 0xf6, 0xfd, 0x2e, 0xa6, 0x84, 0xb0,
				      0x68, 0x8d, 0x2c, 0x37, 0x92, 0x96, 0x88,
				      0x8a, 0x20, 0x60, 0x03}}}},
     .rpc_port = 7041,
     .ln_port = 9735,
     .cli = "elements-cli",
     .cli_args = "-chain=liquidv1",
     .dust_limit = {546},
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 57,
     .p2sh_version = 39,
     .testnet = false,
     .fee_asset_tag = liquid_fee_asset,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_MAIN_PRIVATE},
     .is_elements = true},
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

const struct chainparams *chainparams_by_chainhash(const struct bitcoin_blkid *chain_hash)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (bitcoin_blkid_eq(chain_hash, &networks[i].genesis_blockhash)) {
			return &networks[i];
		}
	}
	return NULL;
}

const struct chainparams *chainparams_by_lightning_hrp(const char *lightning_hrp)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (streq(lightning_hrp, networks[i].lightning_hrp)) {
			return &networks[i];
		}
	}
	return NULL;
}

const char *chainparams_get_network_names(const tal_t *ctx)
{
    char *networks_string = tal_strdup(ctx, networks[0].network_name);
    for (size_t i = 1; i < ARRAY_SIZE(networks); ++i)
        tal_append_fmt(&networks_string, ", %s", networks[i].network_name);
    return networks_string;
}

int chainparams_get_ln_port(const struct chainparams *params)
{
	assert(params);
	return params->ln_port;
}
