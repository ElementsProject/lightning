#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/varint.h>
#include <ccan/err/err.h>
#include <common/bech32.h>
#include <common/utils.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <wally_core.h>

/* FIXME: should we check signatures against addresses instead of keys? */
static void usage(void)
{
	fprintf(stderr, "Usage: bip137-checkmessage message hex-sig [key]\n"
			"If key does not match, signature is not valid!\n");
	exit(1);
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
	const char *keystr;

	setup_locale();
	err_set_progname(argv[0]);
	wally_init(0);
	secp256k1_ctx = wally_get_secp_context();

	if (argc != 3 && argc != 4)
		usage();

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

	keystr = fmt_pubkey(NULL, &reckey);
	if (argv[3]) {
		if (!streq(keystr, argv[3]))
			errx(1, "Signature is invalid");
		printf("Signature is valid!\n");
	} else
		printf("Signature claims to be from key %s\n", keystr);
	return 0;
}

