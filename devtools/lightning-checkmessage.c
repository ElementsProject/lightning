#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <ccan/err/err.h>
#include <common/bech32.h>
#include <common/utils.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <wally_core.h>

/* These tables copied from zbase32 src:
 * copyright 2002-2007 Zooko "Zooko" Wilcox-O'Hearn
 * mailto:zooko@zooko.com
 *
 * Permission is hereby granted to any person obtaining a copy of this work to
 * deal in this work without restriction (including the rights to use, modify,
 * distribute, sublicense, and/or sell copies).
 */

/* revchars: index into this table with the ASCII value of the char.  The result is the value of that quintet. */
static const u8 zbase32_revchars[]={ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 18, 255, 25, 26, 27, 30, 29, 7, 31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 24, 1, 12, 3, 8, 5, 6, 28, 21, 9, 10, 255, 11, 2, 16, 13, 14, 4, 22, 17, 19, 255, 20, 15, 0, 23, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, };

static void usage(void)
{
	fprintf(stderr, "Usage: lightning-checkmessage message zbase32-sig [key]\n"
		"If key does not match, signature is not valid!\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	u8 *u5sig, *u8sig;
	size_t len;
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

	u5sig = tal_arr(NULL, u8, strlen(argv[2]));
	for (size_t i = 0; argv[2][i]; i++) {
		u5sig[i] = zbase32_revchars[(unsigned char)argv[2][i]];
		if (u5sig[i] > 31)
			errx(1, "Not a valid zbase32 string");
	}
	u8sig = tal_arr(NULL, u8, (strlen(argv[2]) * 5 + 7) / 8 + 1);
	len = 0;
	if (!bech32_convert_bits(u8sig, &len, 8, u5sig, strlen(argv[2]), 5, false))
		errx(1, "Invalid string");

	if (len != 65)
		errx(1, "Signature too %s", len < 65 ? "short" : "long");

	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx,
								 &rsig,
								 u8sig + 1,
								 u8sig[0] - 31))
		errx(1, "Signature not parsable");

	sha256_update(&sctx, "Lightning Signed Message:",
		      strlen("Lightning Signed Message:"));
	sha256_update(&sctx, argv[1], strlen(argv[1]));
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
