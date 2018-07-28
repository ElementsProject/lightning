#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define NO_ERROR 0
#define ERROR_BAD_DECODE 1
#define ERROR_USAGE 3

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

static char *fmt_time(const tal_t *ctx, u64 time)
{
	/* ctime is not sane.  Take pointer, returns \n in string. */
	time_t t = time;
	const char *p = ctime(&t);

	return tal_fmt(ctx, "%.*s", (int)strcspn(p, "\n"), p);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	const char *method;
	struct bolt11 *b11;
	struct bolt11_field *extra;
	size_t i;
	char *fail, *description = NULL;

	err_set_progname(argv[0]);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<decode> <bolt11>", "Show this message");
	opt_register_arg("--hashed-description", opt_set_charp, opt_show_charp,
			 &description,
			 "Description to check hashed description against");
	opt_register_version();

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);

	method = argv[1];
	if (!method)
		errx(ERROR_USAGE, "Need at least one argument\n%s",
		     opt_usage(argv[0], NULL));

	if (!streq(method, "decode"))
		errx(ERROR_USAGE, "Need decode argument\n%s",
		     opt_usage(argv[0], NULL));

	if (!argv[2])
		errx(ERROR_USAGE, "Need argument\n%s",
		     opt_usage(argv[0], NULL));

	b11 = bolt11_decode(ctx, argv[2], description, &fail);
	if (!b11)
		errx(ERROR_BAD_DECODE, "%s", fail);

	printf("currency: %s\n", b11->chain->bip173_name);
	printf("timestamp: %"PRIu64" (%s)\n",
	       b11->timestamp, fmt_time(ctx, b11->timestamp));
	printf("expiry: %"PRIu64" (%s)\n",
	       b11->expiry, fmt_time(ctx, b11->timestamp + b11->expiry));
	printf("payee: %s\n",
	       type_to_string(ctx, struct pubkey, &b11->receiver_id));
	printf("payment_hash: %s\n",
	       tal_hexstr(ctx, &b11->payment_hash, sizeof(b11->payment_hash)));
        if (b11->msatoshi)
		printf("msatoshi: %"PRIu64"\n", *b11->msatoshi);
        if (b11->description)
                printf("description: '%s'\n", b11->description);
        if (b11->description_hash)
		printf("description_hash: %s\n",
		       tal_hexstr(ctx, b11->description_hash,
				  sizeof(*b11->description_hash)));

	for (i = 0; i < tal_count(b11->fallbacks); i++) {
                struct bitcoin_address pkh;
                struct ripemd160 sh;
                struct sha256 wsh;

		printf("fallback: %s\n", tal_hex(ctx, b11->fallbacks[i]));
                if (is_p2pkh(b11->fallbacks[i], &pkh)) {
			printf("fallback-P2PKH: %s\n",
			       bitcoin_to_base58(ctx, b11->chain->testnet,
						 &pkh));
                } else if (is_p2sh(b11->fallbacks[i], &sh)) {
			printf("fallback-P2SH: %s\n",
			       p2sh_to_base58(ctx,
					      b11->chain->testnet,
					      &sh));
                } else if (is_p2wpkh(b11->fallbacks[i], &pkh)) {
                        char out[73 + strlen(b11->chain->bip173_name)];
                        if (segwit_addr_encode(out, b11->chain->bip173_name, 0,
                                               (const u8 *)&pkh, sizeof(pkh)))
				printf("fallback-P2WPKH: %s\n", out);
                } else if (is_p2wsh(b11->fallbacks[i], &wsh)) {
                        char out[73 + strlen(b11->chain->bip173_name)];
                        if (segwit_addr_encode(out, b11->chain->bip173_name, 0,
                                               (const u8 *)&wsh, sizeof(wsh)))
				printf("fallback-P2WSH: %s\n", out);
                }
        }

	for (i = 0; i < tal_count(b11->routes); i++) {
		printf("route: (node/chanid/fee/expirydelta) ");
		for (size_t n = 0; n < tal_count(b11->routes[i]); n++) {
			printf(" %s/%s/%u/%u/%u",
			       type_to_string(ctx, struct pubkey,
					      &b11->routes[i][n].pubkey),
			       type_to_string(ctx, struct short_channel_id,
					      &b11->routes[i][n].short_channel_id),
			       b11->routes[i][n].fee_base_msat,
			       b11->routes[i][n].fee_proportional_millionths,
			       b11->routes[i][n].cltv_expiry_delta);
		}
		printf("\n");
	}

	list_for_each(&b11->extra_fields, extra, list) {
		char *data = tal_arr(ctx, char, tal_count(extra->data)+1);

		for (i = 0; i < tal_count(extra->data); i++)
			data[i] = bech32_charset[extra->data[i]];

		data[i] = '\0';
		printf("unknown: %c %s\n", extra->tag, data);
	}

	printf("signature: %s\n",
	       type_to_string(ctx, secp256k1_ecdsa_signature, &b11->sig));
	tal_free(ctx);
	return NO_ERROR;
}
