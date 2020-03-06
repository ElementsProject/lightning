#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/tal.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <common/version.h>
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_arr_label(NULL, char, size, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

int main(int argc, char **argv)
{
	setup_locale();
	const char *method;
	u8 *e2e;
	struct secret *secrets;
	size_t num_secrets;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n\n\tencrypt <payload> <secret>...\n"
			   "\t[un]wrap <payload> <secret>...\n"
			   "\tdecrypt <payload> <secret>...", "Show this message");
	opt_register_version();

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 4)
		errx(1, "You must specify a method, payload and at least 1 secret");

	e2e = tal_hexdata(NULL, argv[2], strlen(argv[2]));
	if (!e2e)
		errx(1, "Bad hex data %s", argv[2]);

	num_secrets = argc - 3;
	secrets = tal_arr(NULL, struct secret, num_secrets);
	for (size_t i = 0; i < num_secrets; i++) {
		if (!hex_decode(argv[3+i], strlen(argv[3+i]),
				&secrets[i], sizeof(secrets[i])))
		errx(1, "Bad hex secret %s", argv[3+i]);
	}

	method = argv[1];
	if (streq(method, "encrypt")) {
		e2e = create_e2e_payload(NULL, e2e, &secrets[num_secrets-1]);
		for (int i = num_secrets - 2; i >= 0; i--)
			e2e = wrap_e2e_payload(NULL, take(e2e), &secrets[i]);
	} else if (streq(method, "wrap") || streq(method, "unwrap")) {
		for (size_t i = 0; i < num_secrets; i++)
			e2e = unwrap_e2e_payload(NULL, take(e2e), &secrets[i]);
	} else if (streq(method, "decrypt")) {
		for (size_t i = 0; i < num_secrets - 1; i++)
			e2e = unwrap_e2e_payload(NULL, take(e2e), &secrets[i]);
		e2e = final_e2e_payload(NULL, e2e, &secrets[num_secrets-1]);
		if (!e2e)
			errx(1, "decryption failed");
	} else
		errx(1, "Unknown method %s", method);

	printf("%s\n", tal_hex(NULL, e2e));
	return 0;
}
