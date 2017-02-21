#include <bitcoin/base58.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/str/hex/hex.h>
#include <inttypes.h>
#include <stdio.h>
#include <type_to_string.h>
#include <utils.h>
#define SUPERVERBOSE printf
  #include "../funding_tx.c"

#if 0
static struct sha256 sha256_from_hex(const char *hex)
{
	struct sha256 sha256;
	if (strstarts(hex, "0x"))
		hex += 2;
	if (!hex_decode(hex, strlen(hex), &sha256, sizeof(sha256)))
		abort();
	return sha256;
}

static struct privkey privkey_from_hex(const char *hex)
{
	struct privkey pk;
	size_t len;
	if (strstarts(hex, "0x"))
		hex += 2;
	len = strlen(hex);
	if (len == 66 && strends(hex, "01"))
		len -= 2;
	if (!hex_decode(hex, len, &pk, sizeof(pk)))
		abort();
	return pk;
}
#endif

int main(void)
{
	tal_t *tmpctx = tal_tmpctx(NULL);
	struct bitcoin_tx *input, *funding;
	struct sha256_double txid;
	u64 feerate_per_kw;
	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	struct privkey input_privkey;
	struct pubkey inputkey;
	bool testnet;
	unsigned int input_txout;
	u64 input_satoshis;
	u64 funding_satoshis;
	int funding_outnum;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	/* BOLT #3:
	 *
	 * Block 1 coinbase transaction: 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0100f2052a010000001976a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac00000000
	 */
	input = bitcoin_tx_from_hex(tmpctx,
				    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0100f2052a010000001976a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac00000000",
				    strlen("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0100f2052a010000001976a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac00000000"));
	assert(input);

	/* BOLT #3:
	 *    Block 1 coinbase privkey: 6bd078650fcee8444e4e09825227b801a1ca928debb750eb36e6d56124bb20e80101
	 *    # privkey in base58: cRCH7YNcarfvaiY1GWUKQrRGmoezvfAiqHtdRvxe16shzbd7LDMz
	 */
	if (!key_from_base58("cRCH7YNcarfvaiY1GWUKQrRGmoezvfAiqHtdRvxe16shzbd7LDMz", strlen("cRCH7YNcarfvaiY1GWUKQrRGmoezvfAiqHtdRvxe16shzbd7LDMz"),
			     &testnet, &input_privkey, &inputkey))
		abort();
	assert(testnet);
	printf("* Block 1 coinbase privkey: %s01\n",
	       type_to_string(tmpctx, struct privkey, &input_privkey));

	/* BOLT #3:
	 *
	 * The funding transaction is paid to the following keys:
	 *
	 *     local_funding_pubkey: 023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb
	 *     remote_funding_pubkey: 030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1
	 */
	if (!pubkey_from_hexstr("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
				strlen("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
				&local_funding_pubkey))
		abort();
	if (!pubkey_from_hexstr("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
				strlen("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
				&remote_funding_pubkey))
		abort();

	bitcoin_txid(input, &txid);
	input_txout = 0;
	input_satoshis = 5000000000;
	funding_satoshis = 10000000;
	feerate_per_kw = 15000;

	printf("input[0] txid: %s\n", tal_hexstr(tmpctx, &txid, sizeof(txid)));
	printf("input[0] input: %u\n", input_txout);
	printf("input[0] satoshis: %"PRIu64"\n", input_satoshis);
	printf("funding satoshis: %"PRIu64"\n", funding_satoshis);

	funding = funding_tx(tmpctx, &txid, input_txout, input_satoshis,
			     funding_satoshis,
			     &local_funding_pubkey,
			     &remote_funding_pubkey,
			     &inputkey,
			     feerate_per_kw,
			     0);
	funding_outnum = (funding->output[0].amount == funding_satoshis ? 0 : 1);
	printf("# feerate_per_kw: %"PRIu64"\n", feerate_per_kw);
	printf("change satoshis: %"PRIu64"\n",
	       funding->output[!funding_outnum].amount);

	printf("funding output: %u\n", funding_outnum);

	sign_funding_tx(funding, &inputkey, &input_privkey);
	printf("funding tx: %s\n",
	       tal_hex(tmpctx, linearize_tx(tmpctx, funding)));

	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(tmpctx);

	return 0;
}
