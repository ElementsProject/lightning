#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/varint.h>
#include <ccan/err/err.h>
#include <common/addr.h>
#include <common/bech32.h>
#include <common/utils.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <wally_core.h>

static void usage(void)
{
	fprintf(stderr,
		"Usage: bip137-verifysignature message hex-sig [address] [network]\n"
		"If key does not match, signature is not valid!\n");
	exit(1);
}

static char *encode_pubkey_to_p2wpkh_addr(const tal_t *ctx,
					  const struct pubkey *pubkey,
					  const struct chainparams *chain)
{
	char *out;
	const char *hrp;
	struct ripemd160 h160;
        bool ok;
	hrp = chain->onchain_hrp;

	/* out buffer is 73 + strlen(human readable part),
	 * see common/bech32.h*/
	out = tal_arr(ctx, char, 73 + strlen(hrp));
	pubkey_to_hash160(pubkey, &h160);
	ok = segwit_addr_encode(out, hrp, 0, h160.u.u8, sizeof(h160));
        if(!ok)
                tal_free(out);
	return out;
}

int main(int argc, char *argv[])
{
	u8 *sig;
	u8 varint[VARINT_MAX_LEN];
	size_t varintlen, msg_len;
	secp256k1_ecdsa_recoverable_signature rsig;
	struct sha256_ctx sctx = SHA256_INIT;
	struct sha256_double shad;
	struct pubkey reckey;
	const char *addr;
	const struct chainparams *chain = NULL;
	const char *input_chain = NULL, *input_address = NULL;

	setup_locale();
	err_set_progname(argv[0]);
	wally_init(0);
	secp256k1_ctx = wally_get_secp_context();

	if (argc != 3 && argc != 4 && argc != 5)
		usage();
	if (argc > 3)
		input_address = argv[3];
	if (argc > 4)
		input_chain = argv[4];

	sig = tal_hexdata(NULL, argv[2], strlen(argv[2]));
	if (!sig)
		errx(1, "Not a valid hex string");

	if (sig[0] < 39 || sig[0] >= 43)
		errx(1,
		     "Signature header does not correspond to a P2WPKH type");

	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
		secp256k1_ctx, &rsig, sig + 1, sig[0] - 39))
		errx(1, "Signature not parsable");

	sha256_update(&sctx,
		      "\x18"
		      "Bitcoin Signed Message:\n",
		      strlen("\x18"
			     "Bitcoin Signed Message:\n"));
	msg_len = strlen(argv[1]);
	varintlen = varint_put(varint, msg_len);
	sha256_update(&sctx, varint, varintlen);
	sha256_update(&sctx, argv[1], msg_len);
	sha256_double_done(&sctx, &shad);

	if (!secp256k1_ecdsa_recover(secp256k1_ctx, &reckey.pubkey, &rsig,
				     shad.sha.u.u8))
		errx(1, "Signature not recoverable");

	if (input_chain) {
		chain = chainparams_for_network(input_chain);
		if (!chain)
			errx(1, "Invalid network");
	} else {
		/* By default, assume we are verifying a mainnet signature. */
		chain = chainparams_for_network("bitcoin");
	}
	addr = encode_pubkey_to_p2wpkh_addr(NULL, &reckey, chain);
	if (!addr)
		errx(1, "Failed to derive address from recovered key");
	if (input_address) {
		if (!streq(addr, input_address))
			errx(1, "Signature is invalid");
		printf("Signature is valid!\n");
	} else
		printf("Signature claims to be from address %s\n", addr);
	return 0;
}

