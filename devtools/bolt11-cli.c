#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/features.h>
#include <common/setup.h>
#include <common/version.h>
#include <inttypes.h>
#include <stdio.h>

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

/* pubkey/scid/feebase/feeprop/expiry,... */
static void add_route(struct bolt11 *b11, const char *routestr)
{
	struct route_info *rarr;
	char **rparts = tal_strsplit(tmpctx, routestr, ",", STR_EMPTY_OK);

	rarr = tal_arr(b11->routes, struct route_info, tal_count(rparts)-1);
	for (size_t i = 0; rparts[i]; i++) {
		char **parts = tal_strsplit(tmpctx, rparts[i], "/", STR_EMPTY_OK);
		if (tal_count(parts) != 6)
			errx(ERROR_USAGE,
			     "Bad route %s (expected 5 fields with / separators)",
			     rparts[i]);
		if (!node_id_from_hexstr(parts[0], strlen(parts[0]),
					 &rarr[i].pubkey))
			errx(ERROR_USAGE, "Bad route publey %s", parts[0]);
		if (!short_channel_id_from_str(parts[1], strlen(parts[1]),
					       &rarr[i].short_channel_id))
			errx(ERROR_USAGE, "Bad route scid %s", parts[1]);
		rarr[i].fee_base_msat = atol(parts[2]);
		rarr[i].fee_proportional_millionths = atol(parts[3]);
		rarr[i].cltv_expiry_delta = atol(parts[4]);
	}
	tal_arr_expand(&b11->routes, rarr);
}

static char *fmt_time(const tal_t *ctx, u64 time)
{
	/* ctime is not sane.  Take pointer, returns \n in string. */
	time_t t = time;
	const char *p = ctime(&t);

	return tal_fmt(ctx, "%.*s", (int)strcspn(p, "\n"), p);
}

static bool sign_b11(const u5 *u5bytes,
		     const u8 *hrpu8,
		     secp256k1_ecdsa_recoverable_signature *rsig,
		     struct privkey *privkey)
{
	struct hash_u5 hu5;
	char *hrp;
	struct sha256 sha;

	hrp = tal_dup_arr(NULL, char, (char *)hrpu8, tal_count(hrpu8), 1);
	hrp[tal_count(hrpu8)] = '\0';

	hash_u5_init(&hu5, hrp);
	hash_u5(&hu5, u5bytes, tal_count(u5bytes));
	hash_u5_done(&hu5, &sha);
	tal_free(hrp);

        if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, rsig,
                                              (const u8 *)&sha,
                                              privkey->secret.data,
                                              NULL, NULL))
		abort();

	return true;
}

static void encode(const tal_t *ctx,
		   struct privkey *privkey,
		   char *fields[])
{
	struct bolt11 *b11 = talz(ctx, struct bolt11);
	struct pubkey me;
	bool explicit_n = false;

	b11->timestamp = time_now().ts.tv_sec;
	b11->chain = chainparams_for_network("regtest");
	b11->expiry = 3600;
	b11->min_final_cltv_expiry = DEFAULT_FINAL_CLTV_DELTA;
	list_head_init(&b11->extra_fields);

	if (!pubkey_from_privkey(privkey, &me))
		errx(ERROR_USAGE, "Invalid privkey!");
	node_id_from_pubkey(&b11->receiver_id, &me);

	while (*fields) {
		const char *eq = strchr(*fields, '=');
		const char *fname, *val;
		char *endp;
		unsigned long fieldnum;

		if (!eq)
			errx(ERROR_USAGE, "Field name must have =: %s", *fields);

		fname = tal_strndup(ctx, *fields, eq - *fields);
		val = eq + 1;

		if (streq(fname, "currency")) {
			b11->chain = chainparams_by_lightning_hrp(val);
			if (!b11->chain)
				errx(ERROR_USAGE, "Unknown currency %s", val);
		} else if (streq(fname, "amount")) {
			b11->msat = tal(b11, struct amount_msat);
			if (!parse_amount_msat(b11->msat, val, strlen(val)))
				errx(ERROR_USAGE, "Invalid amount %s", val);
		} else if (streq(fname, "timestamp")) {
			b11->timestamp = strtoul(val, &endp, 10);
			if (!b11->timestamp || *endp != '\0')
				errx(ERROR_USAGE, "Invalid amount %s", val);
		/* Allow raw numbered fields */
		} else if ((fieldnum = strtoul(fname, &endp, 10)) != 0
			   && fieldnum < 256) {
			struct bolt11_field *extra = tal(b11, struct bolt11_field);
			extra->tag = fieldnum;
			extra->data = tal_hexdata(extra, val, strlen(val));
			if (!extra->data)
				errx(ERROR_USAGE, "Invalid hex %s", val);
			list_add_tail(&b11->extra_fields, &extra->list);
		} else {
			if (strlen(fname) != 1)
				errx(ERROR_USAGE, "Unknown field %s", fname);
			switch (*fname) {
			case 'p':
				if (!hex_decode(val, strlen(val),
						&b11->payment_hash, sizeof(b11->payment_hash)))
					errx(ERROR_USAGE, "Invalid payment_hash %s", val);
				break;
			case 's':
				b11->payment_secret = tal(b11, struct secret);
				if (!hex_decode(val, strlen(val),
						b11->payment_secret, sizeof(*b11->payment_secret)))
					errx(ERROR_USAGE, "Invalid payment_secret %s", val);
				break;
			case 'd':
				b11->description = val;
				break;
			case 'm':
				b11->metadata = tal_hexdata(b11, val, strlen(val));
				if (!b11->metadata)
					errx(ERROR_USAGE, "Invalid metadata %s", val);
				break;
			case 'n':
				explicit_n = streq(val, "true");
				break;
			case 'h':
				b11->description_hash = tal(b11, struct sha256);
				if (!hex_decode(val, strlen(val),
						b11->description_hash, sizeof(*b11->description_hash)))
					errx(ERROR_USAGE, "Invalid description hash %s", val);
				break;
			case 'x':
				b11->expiry = atol(val);
				break;
			case 'c':
				b11->min_final_cltv_expiry = atol(val);
				break;
			case 'r':
				if (!b11->routes)
					b11->routes = tal_arr(b11, struct route_info *, 0);
				add_route(b11, val);
				break;
			case '9':
				b11->features = tal_hexdata(b11, val, strlen(val));
				if (!b11->features)
					errx(ERROR_USAGE, "Invalid hex features %s", val);
				break;
			case 'f':
				errx(ERROR_USAGE, "FIXME: `f` unsupported!");
			default:
				errx(ERROR_USAGE, "Unknown letter %s", fname);
			}
		}
		fields++;
	}

	printf("%s\n", bolt11_encode(tmpctx, b11, explicit_n, sign_b11, privkey));
}

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal(NULL, char);
	const char *method;
	struct bolt11 *b11;
	struct bolt11_field *extra;
	char *fail, *description = NULL;

	common_setup(argv[0]);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<decode> <bolt11> OR\n"
			   "<encode> <privkey> [<field>=...]*",
			   "Show this message");
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

	if (streq(method, "encode")) {
		struct privkey privkey;

		if (!argv[2]
		    || !hex_decode(argv[2], strlen(argv[2]), &privkey, sizeof(privkey)))
			errx(ERROR_USAGE, "Need valid <privkey>\n%s",
			     opt_usage(argv[0], NULL));
		encode(ctx, &privkey, argv + 3);
		tal_free(ctx);
		common_shutdown();
		return NO_ERROR;
	}

	if (!streq(method, "decode"))
		errx(ERROR_USAGE, "Need encode or decode argument\n%s",
		     opt_usage(argv[0], NULL));

	if (!argv[2])
		errx(ERROR_USAGE, "Need argument\n%s",
		     opt_usage(argv[0], NULL));

	b11 = bolt11_decode(ctx, argv[2], NULL, description, NULL, &fail);
	if (!b11)
		errx(ERROR_BAD_DECODE, "%s", fail);

	printf("currency: %s\n", b11->chain->lightning_hrp);
	printf("timestamp: %"PRIu64" (%s)\n",
	       b11->timestamp, fmt_time(ctx, b11->timestamp));
	printf("expiry: %"PRIu64" (%s)\n",
	       b11->expiry, fmt_time(ctx, b11->timestamp + b11->expiry));
	printf("payee: %s\n",
	       fmt_node_id(ctx, &b11->receiver_id));
	printf("payment_hash: %s\n",
	       tal_hexstr(ctx, &b11->payment_hash, sizeof(b11->payment_hash)));
	printf("min_final_cltv_expiry: %u\n", b11->min_final_cltv_expiry);
        if (b11->msat) {
		printf("msatoshi: %"PRIu64"\n", b11->msat->millisatoshis); /* Raw: raw int for backwards compat */
		printf("amount_msat: %s\n",
		       fmt_amount_msat(tmpctx, *b11->msat));
	}
        if (b11->description)
                printf("description: '%s'\n", b11->description);
        if (b11->description_hash)
		printf("description_hash: %s\n",
		       tal_hexstr(ctx, b11->description_hash,
				  sizeof(*b11->description_hash)));
	if (b11->payment_secret)
		printf("payment_secret: %s\n",
		       tal_hexstr(ctx, b11->payment_secret,
				  sizeof(*b11->payment_secret)));
	if (tal_bytelen(b11->features)) {
		printf("features:");
		for (size_t i = 0; i < tal_bytelen(b11->features) * CHAR_BIT; i++) {
			if (feature_is_set(b11->features, i))
				printf(" %zu", i);
		}
		printf("\n");
	}
	for (size_t i = 0; i < tal_count(b11->fallbacks); i++) {
                struct bitcoin_address pkh;
                struct ripemd160 sh;
                struct sha256 wsh;
                const u8 *fallback = b11->fallbacks[i];
                const size_t fallback_len = tal_bytelen(fallback);

		printf("fallback: %s\n", tal_hex(ctx, fallback));
                if (is_p2pkh(fallback, fallback_len, &pkh)) {
			printf("fallback-P2PKH: %s\n",
			       bitcoin_to_base58(ctx, b11->chain,
						 &pkh));
                } else if (is_p2sh(fallback, fallback_len, &sh)) {
			printf("fallback-P2SH: %s\n",
			       p2sh_to_base58(ctx,
					      b11->chain,
					      &sh));
                } else if (is_p2wpkh(fallback, fallback_len, &pkh)) {
                        char out[73 + strlen(b11->chain->onchain_hrp)];
                        if (segwit_addr_encode(out, b11->chain->onchain_hrp, 0,
                                               (const u8 *)&pkh, sizeof(pkh)))
				printf("fallback-P2WPKH: %s\n", out);
                } else if (is_p2wsh(fallback, fallback_len, &wsh)) {
                        char out[73 + strlen(b11->chain->onchain_hrp)];
                        if (segwit_addr_encode(out, b11->chain->onchain_hrp, 0,
                                               (const u8 *)&wsh, sizeof(wsh)))
				printf("fallback-P2WSH: %s\n", out);
                }
        }

	for (size_t i = 0; i < tal_count(b11->routes); i++) {
		printf("route: (node/chanid/fee/expirydelta) ");
		for (size_t n = 0; n < tal_count(b11->routes[i]); n++) {
			printf(" %s/%s/%u/%u/%u",
			       fmt_node_id(ctx,
					   &b11->routes[i][n].pubkey),
			       fmt_short_channel_id(ctx,
						    b11->routes[i][n].short_channel_id),
			       b11->routes[i][n].fee_base_msat,
			       b11->routes[i][n].fee_proportional_millionths,
			       b11->routes[i][n].cltv_expiry_delta);
		}
		printf("\n");
	}

	if (b11->metadata)
		printf("metadata: %s\n",
		       tal_hex(ctx, b11->metadata));

	list_for_each(&b11->extra_fields, extra, list) {
		char *data = tal_arr(ctx, char, tal_count(extra->data)+1);
		size_t i;

		for (i = 0; i < tal_count(extra->data); i++)
			data[i] = bech32_charset[extra->data[i]];

		data[i] = '\0';
		printf("unknown: %c %s\n", extra->tag, data);
	}

	printf("signature: %s\n",
	       fmt_secp256k1_ecdsa_signature(ctx, &b11->sig));
	tal_free(ctx);
	common_shutdown();
	return NO_ERROR;
}
