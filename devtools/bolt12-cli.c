#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/iso4217.h>
#include <common/setup.h>
#include <common/version.h>
#include <inttypes.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <time.h>

#define NO_ERROR 0
#define ERROR_BAD_DECODE 1
#define ERROR_USAGE 3

static bool well_formed = true;

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

static bool must_str(bool expected, const char *complaint, const char *fieldname)
{
	if (!expected) {
		fprintf(stderr, "%s %s\n", complaint, fieldname);
		well_formed = false;
		return false;
	}
	return true;
}

#define must_have(obj, field) \
	must_str((obj)->field != NULL, "Missing", stringify(field))
#define must_not_have(obj, field) \
	must_str((obj)->field == NULL, "Unnecessary", stringify(field))

static void print_offer_chains(const struct bitcoin_blkid *chains)
{
	printf("offer_chains:");
	for (size_t i = 0; i < tal_count(chains); i++) {
		printf(" %s", fmt_bitcoin_blkid(tmpctx, &chains[i]));
	}
	printf("\n");
}

static void print_hex(const char *fieldname, const u8 *bin)
{
	printf("%s: %s\n", fieldname, tal_hex(tmpctx, bin));
}


static void print_invreq_chain(const struct bitcoin_blkid *chain)
{
	printf("invreq_chain: %s\n",
	       fmt_bitcoin_blkid(tmpctx, chain));
}

static bool print_offer_amount(const struct bitcoin_blkid *chains,
			       const char *iso4217, u64 amount)
{
	const char *currency;
	unsigned int minor_unit;
	bool ok = true;

	/* BOLT-offers #12:
	 * - if a specific minimum `offer_amount` is required for successful payment:
	 *   - MUST set `offer_amount` to the amount expected (per item).
	 *   - if the currency for `offer_amount` is that of all entries in `chains`:
	 *     - MUST specify `amount` in multiples of the minimum lightning-payable unit
	 *       (e.g. milli-satoshis for bitcoin).
	 *   - otherwise:
	 *     - MUST specify `offer_currency` `iso4217` as an ISO 4712 three-letter code.
	 *     - MUST specify `offer_amount` in the currency unit adjusted by the ISO 4712
	 *       exponent (e.g. USD cents).
	 *   - MUST set `offer_description` to a complete description of the purpose
	 *       of the payment.
	 * - otherwise:
	 *   - MUST NOT set `offer_amount`
	 *   - MUST NOT set `offer_currency`
	 *   - MAY set `offer_description`
	 */
	if (!iso4217) {
		if (tal_count(chains) == 0)
			currency = "bc";
		else {
			const struct chainparams *ch;

			ch = chainparams_by_chainhash(&chains[0]);
			if (!ch) {
				currency = tal_fmt(tmpctx, "UNKNOWN CHAINHASH %s",
						   fmt_bitcoin_blkid(tmpctx,
								     &chains[0]));
				ok = false;
			} else
				currency = ch->lightning_hrp;
		}
		minor_unit = 11;
	} else {
		const struct iso4217_name_and_divisor *iso;
		iso = find_iso4217(iso4217, tal_bytelen(iso4217));
		if (iso) {
			minor_unit = iso->minor_unit;
			currency = iso->name;
		} else {
			minor_unit = 0;
			currency = tal_fmt(tmpctx, "%.*s (UNKNOWN CURRENCY)",
					   (int)tal_bytelen(iso4217), iso4217);
			ok = false;
		}
	}

	if (!minor_unit)
		printf("offer_amount: %"PRIu64"%s\n", amount, currency);
	else {
		u64 minor_div = 1;
		for (size_t i = 0; i < minor_unit; i++)
			minor_div *= 10;
		printf("offer_amount: %"PRIu64".%.*"PRIu64"%s\n",
		       amount / minor_div, minor_unit, amount % minor_div,
		       currency);
	}

	return ok;
}

static bool print_utf8(const char *fieldname, const char *description)
{
	bool valid = utf8_check(description, tal_bytelen(description));
	printf("%s: %.*s%s\n", fieldname,
	       (int)tal_bytelen(description), description,
	       valid ? "" : "(INVALID UTF-8)");
	return valid;
}

static void print_node_id(const char *fieldname, const struct pubkey *node_id)
{
	printf("%s: %s\n",
	       fieldname, fmt_pubkey(tmpctx, node_id));
}

static void print_u64(const char *fieldname, u64 max)
{
	printf("%s: %"PRIu64"\n", fieldname, max);
}

static bool print_recurrance(const struct recurrence *recurrence,
			     const struct recurrence_paywindow *paywindow,
			     const u32 *limit,
			     const struct recurrence_base *base)
{
	const char *unit;
	bool ok = true;

	/* BOLT-offers-recurrence #12:
	 * Thus, each offer containing a recurring payment has:
	 * 1. A `time_unit` defining 0 (seconds), 1 (days), 2 (months),
	 *    3 (years).
	 * 2. A `period`, defining how often (in `time_unit`) it has to be paid.
	 * 3. An optional `recurrence_limit` of total payments to be paid.
	 * 4. An optional `recurrence_base`:
	 *    * `basetime`, defining when the first period starts
	 *       in seconds since 1970-01-01 UTC.
	 *    * `start_any_period` if non-zero, meaning you don't have to start
	 *       paying at the period indicated by `basetime`, but can use
	 *       `recurrence_start` to indicate what period you are starting at.
	 * 5. An optional `recurrence_paywindow`:
	 *    * `seconds_before`, defining how many seconds prior to the start of
	 *       the period a payment will be accepted.
	 *    * `proportional_amount`, if set indicating that a payment made
	 *       during the period itself will be charged proportionally to the
	 *       remaining time in the period (e.g. 150 seconds into a 1500
	 *       second period gives a 10% discount).
	 *    * `seconds_after`, defining how many seconds after the start of the
	 *       period a payment will be accepted.
	 *   If this field is missing, payment will be accepted during the prior
	 *   period and the paid-for period.
	 */
	switch (recurrence->time_unit) {
	case 0:
		unit = "seconds";
		break;
	case 1:
		unit = "days";
		break;
	case 2:
		unit = "months";
		break;
	case 3:
		unit = "years";
		break;
	default:
		fprintf(stderr, "recurrence: unknown time_unit %u", recurrence->time_unit);
		unit = "";
		ok = false;
	}
	printf("offer_recurrence: every %u %s", recurrence->period, unit);
	if (limit)
		printf(" limit %u", *limit);
	if (base) {
		printf(" start %"PRIu64" (%s)",
		       base->basetime,
		       fmt_time(tmpctx, base->basetime));
		if (base->start_any_period)
			printf(" (can start any period)");
	}
	if (paywindow) {
		printf(" paywindow -%u to +%u",
		       paywindow->seconds_before, paywindow->seconds_after);
		if (paywindow->proportional_amount)
			printf(" (pay proportional)");
	}
	printf("\n");

	return ok;
}

static void print_abstime(const char *fieldname, u64 expiry)
{
	printf("%s: %"PRIu64" (%s)\n", fieldname,
	       expiry, fmt_time(tmpctx, expiry));
}

static void print_features(const char *fieldname, const u8 *features)
{
	printf("%s:", fieldname);
	for (size_t i = 0; i < tal_bytelen(features) * CHAR_BIT; i++) {
		if (feature_is_set(features, i))
			printf(" %zu", i);
	}
	printf("\n");
}

static bool print_blindedpaths(const char *fieldname,
			       struct blinded_path **paths,
			       struct blinded_payinfo **blindedpay)
{
	size_t bp_idx = 0;

	for (size_t i = 0; i < tal_count(paths); i++) {
		struct onionmsg_hop **p = paths[i]->path;
		printf("%s %zu/%zu: blinding %s ",
		       fieldname,
		       i, tal_count(paths),
		       fmt_pubkey(tmpctx, &paths[i]->blinding));
		printf("first_node_id %s ",
		       fmt_sciddir_or_pubkey(tmpctx, &paths[i]->first_node_id));
		printf("path ");
		for (size_t j = 0; j < tal_count(p); j++) {
			printf(" %s:%s",
			       fmt_pubkey(tmpctx,
					      &p[j]->blinded_node_id),
			       tal_hex(tmpctx, p[j]->encrypted_recipient_data));
			if (blindedpay) {
				if (bp_idx < tal_count(blindedpay))
					printf("fee=%u/%u,cltv=%u,features=%s",
					       blindedpay[bp_idx]->fee_base_msat,
					       blindedpay[bp_idx]->fee_proportional_millionths,
					       blindedpay[bp_idx]->cltv_expiry_delta,
					       tal_hex(tmpctx,
						       blindedpay[bp_idx]->features));
				bp_idx++;
			}
		}
		printf("\n");
	}
	if (blindedpay && tal_count(blindedpay) != bp_idx) {
		fprintf(stderr, "Expected %zu blindedpay fields, got %zu\n",
			bp_idx, tal_count(blindedpay));
		return false;
	}
	return true;
}

static bool print_signature(const char *messagename,
			    const char *fieldname,
			    const struct tlv_field *fields,
			    const struct pubkey *node_id,
			    const struct bip340sig *sig)
{
	struct sha256 m, shash;

	/* No key, it's already invalid */
	if (!node_id)
		return false;

	merkle_tlv(fields, &m);
	sighash_from_merkle(messagename, fieldname, &m, &shash);
	if (!check_schnorr_sig(&shash, &node_id->pubkey, sig)) {
		fprintf(stderr, "%s: INVALID\n", fieldname);
		return false;
	}
	printf("%s: %s\n",
	       fieldname,
	       fmt_bip340sig(tmpctx, sig));
	return true;
}

static void print_recurrence_counter(const u32 *recurrence_counter,
				     const u32 *recurrence_start)
{
	printf("invreq_recurrence_counter: %u", *recurrence_counter);
	if (recurrence_start)
		printf(" (start +%u)", *recurrence_start);
	printf("\n");
}

static bool print_recurrence_counter_with_base(const u32 *recurrence_counter,
					       const u32 *recurrence_start,
					       const u64 *recurrence_base)
{
	if (!recurrence_base) {
		fprintf(stderr, "Missing recurrence_base\n");
		return false;
	}
	printf("invreq_recurrence_counter: %u", *recurrence_counter);
	if (recurrence_start)
		printf(" (start +%u)", *recurrence_start);
	printf(" (base %"PRIu64")\n", *recurrence_base);
	return true;
}

static void print_hash(const char *fieldname, const struct sha256 *hash)
{
	printf("%s: %s\n",
	       fieldname, fmt_sha256(tmpctx, hash));
}

static void print_relative_expiry(u64 *created_at, u32 *relative)
{
	/* Ignore if already malformed */
	if (!created_at)
		return;

	/* BOLT-offers #12:
	 * - if `invoice_relative_expiry` is present:
	 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *     is greater than `invoice_created_at` plus `seconds_from_creation`.
	 *  - otherwise:
	 *    - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *      is greater than `invoice_created_at` plus 7200.
	 */
	if (!relative)
		printf("invoice_relative_expiry: %u (%s) (default)\n",
		       BOLT12_DEFAULT_REL_EXPIRY,
		       fmt_time(tmpctx, *created_at + BOLT12_DEFAULT_REL_EXPIRY));
	else
		printf("invoice_relative_expiry: %u (%s)\n", *relative,
		       fmt_time(tmpctx, *created_at + *relative));
}

static void print_fallbacks(struct fallback_address **fallbacks)
{
	for (size_t i = 0; i < tal_count(fallbacks); i++) {
		/* FIXME: format properly! */
		printf("invocice_fallbacks: %u %s\n",
		       fallbacks[i]->version,
		       tal_hex(tmpctx, fallbacks[i]->address));
	}
}

static void print_msat(const char *fieldname, u64 amount)
{
	printf("%s: %s\n", fieldname, fmt_amount_msat(tmpctx, amount_msat(amount)));
}

static bool print_extra_fields(const struct tlv_field *fields)
{
	bool ok = true;

	for (size_t i = 0; i < tal_count(fields); i++) {
		if (fields[i].meta)
			continue;
		if (fields[i].numtype % 2 == 0) {
			printf("UNKNOWN EVEN field %"PRIu64": %s\n",
			       fields[i].numtype,
			       tal_hexstr(tmpctx, fields[i].value, fields[i].length));
			ok = false;
		} else {
			printf("Unknown field %"PRIu64": %s\n",
			       fields[i].numtype,
			       tal_hexstr(tmpctx, fields[i].value, fields[i].length));
		}
	}
	return ok;
}

static u64 get_offer_type(const char *name)
{
	u64 val;
	char *endptr;
	struct name_map {
		const char *name;
		u64 val;
	} map[] = {
		/* BOLT-offers #12:
		 * 1. `tlv_stream`: `offer`
		 * 2. types:
		 *     1. type: 2 (`offer_chains`)
		 *     2. data:
		 *         * [`...*chain_hash`:`chains`]
		 *     1. type: 4 (`offer_metadata`)
		 *     2. data:
		 *         * [`...*byte`:`data`]
		 *     1. type: 6 (`offer_currency`)
		 *     2. data:
		 *         * [`...*utf8`:`iso4217`]
		 *     1. type: 8 (`offer_amount`)
		 *     2. data:
		 *         * [`tu64`:`amount`]
		 *     1. type: 10 (`offer_description`)
		 *     2. data:
		 *         * [`...*utf8`:`description`]
		 *     1. type: 12 (`offer_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 14 (`offer_absolute_expiry`)
		 *     2. data:
		 *         * [`tu64`:`seconds_from_epoch`]
		 *     1. type: 16 (`offer_paths`)
		 *     2. data:
		 *         * [`...*blinded_path`:`paths`]
		 *     1. type: 18 (`offer_issuer`)
		 *     2. data:
		 *         * [`...*utf8`:`issuer`]
		 *     1. type: 20 (`offer_quantity_max`)
		 *     2. data:
		 *         * [`tu64`:`max`]
		 *     1. type: 22 (`offer_issuer_id`)
		 *     2. data:
		 *         * [`point`:`node_id`]
		 */
		{ "offer_chains", 2 },
		{ "offer_metadata", 4 },
		{ "offer_currency", 6 },
		{ "offer_amount", 8 },
		{ "offer_description", 10 },
		{ "offer_features", 12 },
		{ "offer_absolute_expiry", 14 },
		{ "offer_paths", 16 },
		{ "offer_issuer", 18 },
		{ "offer_quantity_max", 20 },
		{ "offer_issuer_id", 22 },
		/* BOLT-offers #12:
		 * 1. `tlv_stream`: `invoice_request`
		 * 2. types:
		 *     1. type: 0 (`invreq_metadata`)
		 *     2. data:
		 *         * [`...*byte`:`blob`]
		 *     1. type: 2 (`offer_chains`)
		 *     2. data:
		 *         * [`...*chain_hash`:`chains`]
		 *     1. type: 4 (`offer_metadata`)
		 *     2. data:
		 *         * [`...*byte`:`data`]
		 *     1. type: 6 (`offer_currency`)
		 *     2. data:
		 *         * [`...*utf8`:`iso4217`]
		 *     1. type: 8 (`offer_amount`)
		 *     2. data:
		 *         * [`tu64`:`amount`]
		 *     1. type: 10 (`offer_description`)
		 *     2. data:
		 *         * [`...*utf8`:`description`]
		 *     1. type: 12 (`offer_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 14 (`offer_absolute_expiry`)
		 *     2. data:
		 *         * [`tu64`:`seconds_from_epoch`]
		 *     1. type: 16 (`offer_paths`)
		 *     2. data:
		 *         * [`...*blinded_path`:`paths`]
		 *     1. type: 18 (`offer_issuer`)
		 *     2. data:
		 *         * [`...*utf8`:`issuer`]
		 *     1. type: 20 (`offer_quantity_max`)
		 *     2. data:
		 *         * [`tu64`:`max`]
		 *     1. type: 22 (`offer_issuer_id`)
		 *     2. data:
		 *         * [`point`:`node_id`]
		 *     1. type: 80 (`invreq_chain`)
		 *     2. data:
		 *         * [`chain_hash`:`chain`]
		 *     1. type: 82 (`invreq_amount`)
		 *     2. data:
		 *         * [`tu64`:`msat`]
		 *     1. type: 84 (`invreq_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 86 (`invreq_quantity`)
		 *     2. data:
		 *         * [`tu64`:`quantity`]
		 *     1. type: 88 (`invreq_payer_id`)
		 *     2. data:
		 *         * [`point`:`key`]
		 *     1. type: 89 (`invreq_payer_note`)
		 *     2. data:
		 *         * [`...*utf8`:`note`]
		 *     1. type: 90 (`invreq_paths`)
		 *     2. data:
		 *         * [`...*blinded_path`:`paths`]
		 *     1. type: 240 (`signature`)
		 *     2. data:
		 *         * [`bip340sig`:`sig`]
		 */
		 { "invreq_metadata", 0 },
		 { "invreq_chain", 80 },
		 { "invreq_amount", 82 },
		 { "invreq_features", 84 },
		 { "invreq_quantity", 86 },
		 { "invreq_payer_id", 88 },
		 { "invreq_payer_note", 89 },
		 { "invreq_paths", 90 },
		 { "signature", 240 },
		/* BOLT-offers #12:
		 * 1. `tlv_stream`: `invoice`
		 * 2. types:
		 *     1. type: 0 (`invreq_metadata`)
		 *     2. data:
		 *         * [`...*byte`:`blob`]
		 *     1. type: 2 (`offer_chains`)
		 *     2. data:
		 *         * [`...*chain_hash`:`chains`]
		 *     1. type: 4 (`offer_metadata`)
		 *     2. data:
		 *         * [`...*byte`:`data`]
		 *     1. type: 6 (`offer_currency`)
		 *     2. data:
		 *         * [`...*utf8`:`iso4217`]
		 *     1. type: 8 (`offer_amount`)
		 *     2. data:
		 *         * [`tu64`:`amount`]
		 *     1. type: 10 (`offer_description`)
		 *     2. data:
		 *         * [`...*utf8`:`description`]
		 *     1. type: 12 (`offer_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 14 (`offer_absolute_expiry`)
		 *     2. data:
		 *         * [`tu64`:`seconds_from_epoch`]
		 *     1. type: 16 (`offer_paths`)
		 *     2. data:
		 *         * [`...*blinded_path`:`paths`]
		 *     1. type: 18 (`offer_issuer`)
		 *     2. data:
		 *         * [`...*utf8`:`issuer`]
		 *     1. type: 20 (`offer_quantity_max`)
		 *     2. data:
		 *         * [`tu64`:`max`]
		 *     1. type: 22 (`offer_issuer_id`)
		 *     2. data:
		 *         * [`point`:`node_id`]
		 *     1. type: 80 (`invreq_chain`)
		 *     2. data:
		 *         * [`chain_hash`:`chain`]
		 *     1. type: 82 (`invreq_amount`)
		 *     2. data:
		 *         * [`tu64`:`msat`]
		 *     1. type: 84 (`invreq_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 86 (`invreq_quantity`)
		 *     2. data:
		 *         * [`tu64`:`quantity`]
		 *     1. type: 88 (`invreq_payer_id`)
		 *     2. data:
		 *         * [`point`:`key`]
		 *     1. type: 89 (`invreq_payer_note`)
		 *     2. data:
		 *         * [`...*utf8`:`note`]
		 *     1. type: 160 (`invoice_paths`)
		 *     2. data:
		 *         * [`...*blinded_path`:`paths`]
		 *     1. type: 162 (`invoice_blindedpay`)
		 *     2. data:
		 *         * [`...*blinded_payinfo`:`payinfo`]
		 *     1. type: 164 (`invoice_created_at`)
		 *     2. data:
		 *         * [`tu64`:`timestamp`]
		 *     1. type: 166 (`invoice_relative_expiry`)
		 *     2. data:
		 *         * [`tu32`:`seconds_from_creation`]
		 *     1. type: 168 (`invoice_payment_hash`)
		 *     2. data:
		 *         * [`sha256`:`payment_hash`]
		 *     1. type: 170 (`invoice_amount`)
		 *     2. data:
		 *         * [`tu64`:`msat`]
		 *     1. type: 172 (`invoice_fallbacks`)
		 *     2. data:
		 *         * [`...*fallback_address`:`fallbacks`]
		 *     1. type: 174 (`invoice_features`)
		 *     2. data:
		 *         * [`...*byte`:`features`]
		 *     1. type: 176 (`invoice_node_id`)
		 *     2. data:
		 *         * [`point`:`node_id`]
		 *     1. type: 240 (`signature`)
		 *     2. data:
		 *         * [`bip340sig`:`sig`]
		 */
		 { "invoice_paths", 160 },
		 { "invoice_blindedpay", 162 },
		 { "invoice_created_at", 164 },
		 { "invoice_relative_expiry", 166 },
		 { "invoice_payment_hash", 168 },
		 { "invoice_amount", 170 },
		 { "invoice_fallbacks", 172 },
		 { "invoice_features", 174 },
		 { "invoice_node_id", 176 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
		if (streq(map[i].name, name))
			return map[i].val;
	}

	/* Numeric value */
	val = strtoul(name, &endptr, 0);
	if (*endptr)
		errx(1, "Unknown value %s", name);
	return val;
}

static u8 *get_tlv_val(const tal_t *ctx, const char *val)
{
	u8 *data = tal_hexdata(ctx, val, strlen(val));
	if (data)
		return data;
	/* Literal string */
	return tal_dup_arr(ctx, u8, (u8 *)val, strlen(val), 0);
}

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal(NULL, char);
	const char *method;
	char *hrp;
	u8 *data;
	char *fail;
	bool to_hex = false;

	common_setup(argv[0]);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "decode|decodehex <bolt12>\n"
			   "encodehex <hrp> <hexstr>...\n"
			   "encode <hrp> [<tlvname> <tlvval>]...",
			   "Show this message");
	opt_register_version();

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);

	method = argv[1];
	if (!method)
		errx(ERROR_USAGE, "Need at least one argument\n%s",
		     opt_usage(argv[0], NULL));

	if (streq(method, "encodehex")) {
		char *nospaces;

		if (argc < 4)
			errx(ERROR_USAGE, "Need hrp and hexstr...\n%s",
			     opt_usage(argv[0], NULL));
		nospaces = tal_arr(ctx, char, 0);
		for (size_t i = 3; i < argc; i++) {
			const char *src;

			for (src = argv[i]; *src; src++) {
				if (cisspace(*src))
					continue;
				tal_arr_expand(&nospaces, *src);
			}
		}
		data = tal_hexdata(ctx, nospaces, tal_bytelen(nospaces));
		if (!data)
			errx(ERROR_USAGE, "Invalid hexstr\n%s",
			     opt_usage(argv[0], NULL));
		printf("%s\n", to_bech32_charset(ctx, argv[2], data));
		goto out;
	}
	if (streq(method, "encode")) {
		data = tal_arr(ctx, u8, 0);

		/* We encode literally, to make it possible to create invalid ones for
		 * testing! */
		for (size_t i = 3; i < argc; i += 2) {
			u64 tlvtype = get_offer_type(argv[i]);
			u8 *tlvval = get_tlv_val(ctx, argv[i+1]);
			towire_bigsize(&data, tlvtype);
			towire_bigsize(&data, tal_bytelen(tlvval));
			towire(&data, tlvval, tal_bytelen(tlvval));
		}
		printf("%s\n", to_bech32_charset(ctx, argv[2], data));
		goto out;
	}

	if (streq(method, "decode"))
		to_hex = false;
	else if (streq(method, "decodehex"))
		to_hex = true;
	else
		errx(ERROR_USAGE,
		     "Need encodehex/decode/decodehex argument\n%s",
		     opt_usage(argv[0], NULL));

	if (!argv[2])
		errx(ERROR_USAGE, "Need argument\n%s",
		     opt_usage(argv[0], NULL));

	if (!from_bech32_charset(ctx, argv[2], strlen(argv[2]), &hrp, &data))
		errx(ERROR_USAGE, "Bad bech32 string\n%s",
		     opt_usage(argv[0], NULL));

	if (to_hex) {
		const u8 *cursor = data;
		size_t max = tal_bytelen(data);

		printf("%s %s\n", hrp, tal_hex(ctx, data));
		/* Now break down each element */
		while (max) {
			bigsize_t len;
			const u8 *s = cursor;
			fromwire_bigsize(&cursor, &max);
			if (!cursor)
				errx(ERROR_BAD_DECODE, "Bad type");
			printf("%s ", tal_hexstr(ctx, s, cursor - s));

			s = cursor;
			len = fromwire_bigsize(&cursor, &max);
			if (!cursor)
				errx(ERROR_BAD_DECODE, "Bad len");
			printf("%s ", tal_hexstr(ctx, s, cursor - s));
			s = cursor;
			fromwire(&cursor, &max, NULL, len);
			if (!cursor)
				errx(ERROR_BAD_DECODE, "Bad value");
			printf("%s\n", tal_hexstr(ctx, s, cursor - s));
		}
		goto out;
	}

	if (streq(hrp, "lno")) {
		struct sha256 offer_id;
		const struct tlv_offer *offer
			= offer_decode(ctx, argv[2], strlen(argv[2]),
				       NULL, NULL, &fail);
		if (!offer)
			errx(ERROR_BAD_DECODE, "Bad offer: %s", fail);

		offer_offer_id(offer, &offer_id);
		print_hash("offer_id", &offer_id);
		if (offer->offer_chains)
			print_offer_chains(offer->offer_chains);
		if (offer->offer_amount)
			well_formed &= print_offer_amount(offer->offer_chains,
							  offer->offer_currency,
							  *offer->offer_amount);
		if (offer->offer_description)
			well_formed &= print_utf8("offer_description", offer->offer_description);
		/* BOLT-offers #12:
		 *   - if `offer_amount` is set and `offer_description` is not set:
		 *     - MUST NOT respond to the offer.
		 */
		if (offer->offer_amount && !offer->offer_description) {
			fprintf(stderr, "Missing offer_description (with offer_amount)\n");
			well_formed = false;
		}
		if (offer->offer_features)
			print_features("offer_features", offer->offer_features);
		if (offer->offer_absolute_expiry)
			print_abstime("offer_absolute_expiry", *offer->offer_absolute_expiry);
		if (offer->offer_paths)
			print_blindedpaths("offer_paths", offer->offer_paths, NULL);
		if (offer->offer_issuer)
			well_formed &= print_utf8("offer_issuer", offer->offer_issuer);
		if (offer->offer_quantity_max)
			print_u64("offer_quantity_max", *offer->offer_quantity_max);
		if (offer->offer_issuer_id)
			print_node_id("offer_issuer_id", offer->offer_issuer_id);
		/* BOLT-offers #12:
		 *
		 *   - if neither `offer_issuer_id` nor `offer_paths` are set:
		 *     - MUST NOT respond to the offer.
		 */
		if (!offer->offer_issuer_id && !offer->offer_paths) {
			fprintf(stderr, "Missing offer_issuer_id and offer_paths\n");
			well_formed = false;
		}
		if (offer->offer_recurrence)
			well_formed &= print_recurrance(offer->offer_recurrence,
							offer->offer_recurrence_paywindow,
							offer->offer_recurrence_limit,
							offer->offer_recurrence_base);
		if (!print_extra_fields(offer->fields))
			well_formed = false;
	} else if (streq(hrp, "lnr")) {
		struct sha256 offer_id, invreq_id;
		const struct tlv_invoice_request *invreq
			= invrequest_decode(ctx, argv[2], strlen(argv[2]),
					    NULL, NULL, &fail);
		if (!invreq)
			errx(ERROR_BAD_DECODE, "Bad invreq: %s", fail);

		if (invreq->offer_issuer_id) {
			invreq_offer_id(invreq, &offer_id);
			print_hash("offer_id", &offer_id);
		}
		invreq_invreq_id(invreq, &invreq_id);
		print_hash("invreq_id", &invreq_id);

		/* FIXME: We can do more intra-field checking! */
		if (must_have(invreq, invreq_metadata))
			print_hex("invreq_metadata", invreq->invreq_metadata);
		if (invreq->offer_chains)
			print_offer_chains(invreq->offer_chains);
		if (invreq->offer_amount)
			well_formed &= print_offer_amount(invreq->offer_chains,
							  invreq->offer_currency,
							  *invreq->offer_amount);
		if (must_have(invreq, offer_description))
			well_formed &= print_utf8("offer_description", invreq->offer_description);
		if (invreq->offer_features)
			print_features("offer_features", invreq->offer_features);
		if (invreq->offer_absolute_expiry)
			print_abstime("offer_absolute_expiry", *invreq->offer_absolute_expiry);
		if (invreq->offer_paths)
			print_blindedpaths("offer_paths", invreq->offer_paths, NULL);
		if (invreq->offer_issuer)
			well_formed &= print_utf8("offer_issuer", invreq->offer_issuer);
		if (invreq->offer_quantity_max)
			print_u64("offer_quantity_max", *invreq->offer_quantity_max);
		if (invreq->offer_issuer_id)
			print_node_id("offer_issuer_id", invreq->offer_issuer_id);
		if (invreq->offer_recurrence)
			well_formed &= print_recurrance(invreq->offer_recurrence,
							invreq->offer_recurrence_paywindow,
							invreq->offer_recurrence_limit,
							invreq->offer_recurrence_base);
		if (invreq->invreq_chain)
			print_invreq_chain(invreq->invreq_chain);
		if (invreq->invreq_amount)
			print_msat("invreq_amount", *invreq->invreq_amount);
		if (invreq->invreq_features)
			print_features("invreq_features", invreq->invreq_features);
		if (invreq->invreq_quantity)
			print_u64("invreq_quantity", *invreq->invreq_quantity);
		if (must_have(invreq, invreq_payer_id))
			print_node_id("invreq_payer_id", invreq->invreq_payer_id);
		if (invreq->invreq_payer_note)
			well_formed &= print_utf8("invreq_payer_note", invreq->invreq_payer_note);
		if (invreq->invreq_recurrence_counter) {
			print_recurrence_counter(invreq->invreq_recurrence_counter,
						 invreq->invreq_recurrence_start);
		} else {
			must_not_have(invreq, invreq_recurrence_start);
		}
		if (invreq->invreq_paths)
			print_blindedpaths("invreq_paths", invreq->invreq_paths, NULL);
		if (must_have(invreq, signature)) {
			well_formed = print_signature("invoice_request",
						      "signature",
						      invreq->fields,
						      invreq->invreq_payer_id,
						      invreq->signature);
		}
		if (!print_extra_fields(invreq->fields))
			well_formed = false;
	} else if (streq(hrp, "lni")) {
		struct sha256 offer_id, invreq_id;
		const struct tlv_invoice *invoice
			= invoice_decode(ctx, argv[2], strlen(argv[2]),
					 NULL, NULL, &fail);
		if (!invoice)
			errx(ERROR_BAD_DECODE, "Bad invoice: %s", fail);

		if (invoice->invreq_payer_id) {
			if (invoice->offer_issuer_id) {
				invoice_offer_id(invoice, &offer_id);
				print_hash("offer_id", &offer_id);
			}
			invoice_invreq_id(invoice, &invreq_id);
			print_hash("invreq_id", &invreq_id);
		}

		/* FIXME: We can do more intra-field checking! */
		if (must_have(invoice, invreq_metadata))
			print_hex("invreq_metadata", invoice->invreq_metadata);
		if (invoice->offer_chains)
			print_offer_chains(invoice->offer_chains);
		if (invoice->offer_amount)
			well_formed &= print_offer_amount(invoice->offer_chains,
							  invoice->offer_currency,
							  *invoice->offer_amount);
		if (must_have(invoice, offer_description))
			well_formed &= print_utf8("offer_description", invoice->offer_description);
		if (invoice->offer_features)
			print_features("offer_features", invoice->offer_features);
		if (invoice->offer_absolute_expiry)
			print_abstime("offer_absolute_expiry", *invoice->offer_absolute_expiry);
		if (invoice->offer_paths)
			print_blindedpaths("offer_paths", invoice->offer_paths, NULL);
		if (invoice->offer_issuer)
			well_formed &= print_utf8("offer_issuer", invoice->offer_issuer);
		if (invoice->offer_quantity_max)
			print_u64("offer_quantity_max", *invoice->offer_quantity_max);
		if (invoice->offer_issuer_id)
			print_node_id("offer_issuer_id", invoice->offer_issuer_id);
		if (invoice->offer_recurrence)
			well_formed &= print_recurrance(invoice->offer_recurrence,
							invoice->offer_recurrence_paywindow,
							invoice->offer_recurrence_limit,
							invoice->offer_recurrence_base);
		if (invoice->invreq_chain)
			print_invreq_chain(invoice->invreq_chain);
		if (invoice->invreq_amount)
			print_msat("invreq_amount", *invoice->invreq_amount);
		if (invoice->invreq_features)
			print_features("invreq_features", invoice->invreq_features);
		if (invoice->invreq_quantity)
			print_u64("invreq_quantity", *invoice->invreq_quantity);
		if (must_have(invoice, invreq_payer_id))
			print_node_id("invreq_payer_id", invoice->invreq_payer_id);
		if (invoice->invreq_payer_note)
			well_formed &= print_utf8("invreq_payer_note", invoice->invreq_payer_note);
		if (invoice->invreq_recurrence_counter) {
			well_formed &= print_recurrence_counter_with_base(invoice->invreq_recurrence_counter,
									  invoice->invreq_recurrence_start,
									  invoice->invoice_recurrence_basetime);
		} else {
			must_not_have(invoice, invreq_recurrence_start);
		}
		if (invoice->invreq_paths)
			print_blindedpaths("invreq_paths", invoice->invreq_paths, NULL);
		if (must_have(invoice, invoice_paths))
			print_blindedpaths("invoice_paths",
					   invoice->invoice_paths,
					   invoice->invoice_blindedpay);
		if (must_have(invoice, invoice_created_at))
			print_abstime("invoice_created_at",
				      *invoice->invoice_created_at);
		print_relative_expiry(invoice->invoice_created_at,
				      invoice->invoice_relative_expiry);
		if (must_have(invoice, invoice_payment_hash))
			print_hash("invoice_payment_hash", invoice->invoice_payment_hash);
		if (must_have(invoice, invoice_amount))
			print_msat("invoice_amount", *invoice->invoice_amount);
		if (invoice->invoice_fallbacks)
			print_fallbacks(invoice->invoice_fallbacks);
		if (invoice->invoice_features)
			print_features("invoice_features", invoice->invoice_features);
		if (must_have(invoice, invoice_node_id))
			print_node_id("invoice_node_id", invoice->invoice_node_id);
		if (must_have(invoice, signature))
			well_formed &= print_signature("invoice", "signature",
						       invoice->fields,
						       invoice->invoice_node_id,
						       invoice->signature);
		if (!print_extra_fields(invoice->fields))
			well_formed = false;
	} else
		errx(ERROR_BAD_DECODE, "Unknown prefix %s", hrp);

out:
	tal_free(ctx);
	common_shutdown();

	if (well_formed)
		return NO_ERROR;
	else
		return ERROR_BAD_DECODE;
}
