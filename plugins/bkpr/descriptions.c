#include "config.h"

#include <bitcoin/tx.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/descriptions.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* We keep two hashes; one for UTXO descriptions, one for payment_hashes */
struct utxo_desc {
	struct bitcoin_outpoint outp;
	const char *desc;
};

struct payment_hash_desc {
	struct sha256 payment_hash;
	const char *desc;
};

static size_t hash_utxo(const struct bitcoin_outpoint *outp)
{
	return siphash24(siphash_seed(), outp->txid.shad.sha.u.u8,
			 sizeof(outp->txid.shad.sha.u.u8)) + outp->n;
}

static const struct bitcoin_outpoint *utxo_key(const struct utxo_desc *utxodesc)
{
	return &utxodesc->outp;
}

static bool utxo_key_eq(const struct utxo_desc *utxodesc,
			const struct bitcoin_outpoint *outp)
{
	return bitcoin_outpoint_eq(&utxodesc->outp, outp);
}

HTABLE_DEFINE_NODUPS_TYPE(struct utxo_desc,
			  utxo_key,
			  hash_utxo,
			  utxo_key_eq,
			  utxo_desc_htable);

static size_t hash_payment_hash(const struct sha256 *h)
{
	return siphash24(siphash_seed(), h->u.u8, sizeof(h->u.u8));
}

static const struct sha256 *payment_hash_key(const struct payment_hash_desc *phd)
{
	return &phd->payment_hash;
}

static bool payment_hash_key_eq(const struct payment_hash_desc *phd,
				const struct sha256 *h)
{
	return sha256_eq(&phd->payment_hash, h);
}

HTABLE_DEFINE_NODUPS_TYPE(struct payment_hash_desc,
			  payment_hash_key,
			  hash_payment_hash,
			  payment_hash_key_eq,
			  payment_hash_desc_htable);


/* We keep descriptions in memory and datastore */
struct descriptions {
	struct utxo_desc_htable *by_utxo;
	struct payment_hash_desc_htable *by_payment_hash;
};

static const char *ds_desc_utxo_path(const tal_t *ctx,
				     const struct bitcoin_outpoint *outp)
{
	return tal_fmt(ctx, "bookkeeper/description/utxo/%s", fmt_bitcoin_outpoint(tmpctx, outp));
}

static void utxo_desc_datastore_update(struct command *cmd,
				       const struct utxo_desc *utxo_desc)
{
	const char *path = ds_desc_utxo_path(tmpctx, &utxo_desc->outp);

	jsonrpc_set_datastore_binary(cmd, path,
				     utxo_desc->desc, strlen(utxo_desc->desc),
				     "create-or-replace",
				     ignore_datastore_reply, NULL, NULL);
}

static const char *ds_desc_payment_hash_path(const tal_t *ctx,
						    const struct sha256 *payment_hash)
{
	return tal_fmt(ctx, "bookkeeper/description/payment/%s",
		       fmt_sha256(tmpctx, payment_hash));
}

static void payment_hash_desc_datastore_update(struct command *cmd,
					       const struct payment_hash_desc *phd)
{
	const char *path = ds_desc_payment_hash_path(tmpctx, &phd->payment_hash);
	jsonrpc_set_datastore_binary(cmd, path, phd->desc, strlen(phd->desc),
				     "create-or-replace",
				     ignore_datastore_reply, NULL, NULL);
}

static struct payment_hash_desc *
new_payment_hash_description(struct descriptions *descriptions,
			     const struct sha256 *payment_hash,
			     const char *desc TAKES)
{
	struct payment_hash_desc *phd;

	phd = payment_hash_desc_htable_get(descriptions->by_payment_hash, payment_hash);
	if (phd) {
		tal_free(phd->desc);
		phd->desc = tal_strdup(phd, desc);
	} else {
		phd = tal(descriptions->by_payment_hash, struct payment_hash_desc);
		phd->payment_hash = *payment_hash;
		phd->desc = tal_strdup(phd, desc);
		payment_hash_desc_htable_add(descriptions->by_payment_hash, phd);
	}
	return phd;
}

void add_payment_hash_description(struct command *cmd,
				  struct bkpr *bkpr,
				  const struct sha256 *payment_hash,
				  const char *desc TAKES)
{
	struct payment_hash_desc *phd;

	phd = new_payment_hash_description(bkpr->descriptions,
					   payment_hash, desc);
	payment_hash_desc_datastore_update(cmd, phd);
}

static struct utxo_desc *
new_utxo_description(struct descriptions *descriptions,
		     const struct bitcoin_outpoint *outpoint,
		     const char *desc TAKES)
{
	struct utxo_desc *ud;

	ud = utxo_desc_htable_get(descriptions->by_utxo, outpoint);
	if (ud) {
		tal_free(ud->desc);
		ud->desc = tal_strdup(ud, desc);
	} else {
		ud = tal(descriptions->by_utxo, struct utxo_desc);
		ud->outp = *outpoint;
		ud->desc = tal_strdup(ud, desc);
		utxo_desc_htable_add(descriptions->by_utxo, ud);
	}
	return ud;
}

void add_utxo_description(struct command *cmd,
			  struct bkpr *bkpr,
			  const struct bitcoin_outpoint *outpoint,
			  const char *desc TAKES)
{
	struct utxo_desc *ud;

	ud = new_utxo_description(bkpr->descriptions, outpoint, desc);
	utxo_desc_datastore_update(cmd, ud);
}

static void memleak_scan_utxo_desc_htable(struct htable *memtable,
					  struct utxo_desc_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

static void memleak_scan_payment_hash_desc_htable(struct htable *memtable,
						  struct payment_hash_desc_htable *ht)
{
	memleak_scan_htable(memtable, &ht->raw);
}

/* To avoid JSON encoding/decoding, we use hex encoding directly */
static char *json_cstr_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	char *result;
	size_t hexlen, rawlen;
	hexlen = tok->end - tok->start;
	rawlen = hex_data_size(hexlen);

	result = tal_arr(ctx, char, rawlen + 1);
	if (!hex_decode(buffer + tok->start, hexlen, result, rawlen))
		return tal_free(result);

	result[rawlen] = '\0';
	return result;
}

struct descriptions *init_descriptions(const tal_t *ctx,
				       struct command *init_cmd)
{
	struct descriptions *descriptions = tal(ctx, struct descriptions);
	struct json_out *params;
	const jsmntok_t *result, *datastore, *t;
	size_t i;
	const char *buf;

	descriptions->by_utxo = tal(descriptions, struct utxo_desc_htable);
	utxo_desc_htable_init(descriptions->by_utxo);
	memleak_add_helper(descriptions->by_utxo, memleak_scan_utxo_desc_htable);

	descriptions->by_payment_hash = tal(descriptions, struct payment_hash_desc_htable);
	payment_hash_desc_htable_init(descriptions->by_payment_hash);
	memleak_add_helper(descriptions->by_payment_hash, memleak_scan_payment_hash_desc_htable);

	/* Load everything under "bookkeeper/description/utxo" */
	params = json_out_new(tmpctx);
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "description");
	json_out_addstr(params, NULL, "utxo");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const jsmntok_t *keytok, *hextok;
		const char *desc_str;
		struct bitcoin_outpoint outp;

		keytok = json_get_member(buf, t, "key");
		if (keytok->size != 4)
			continue;

		/* ["bookkeeper", "description", "utxo", <key>] */
		hextok = json_get_member(buf, t, "hex");
		desc_str = json_cstr_from_hex(tmpctx, buf, hextok);
		if (!json_to_outpoint(buf, keytok + 4, &outp)) {
			plugin_log(init_cmd->plugin, LOG_BROKEN,
				   "Invalid outpoint desc for %.*s",
				   json_tok_full_len(keytok),
				   json_tok_full(buf, keytok));
			continue;
		}
		new_utxo_description(descriptions, &outp, take(desc_str));
	}

	/* Load everything under "bookkeeper/description/payment" */
	params = json_out_new(tmpctx);
	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bookkeeper");
	json_out_addstr(params, NULL, "description");
	json_out_addstr(params, NULL, "payment");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      params, &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const jsmntok_t *keytok, *hextok;
		const char *desc_str;
		struct sha256 ph;

		keytok = json_get_member(buf, t, "key");
		if (keytok->size != 4)
			continue;

		/* ["bookkeeper", "description", "payment", <key>] */
		hextok = json_get_member(buf, t, "hex");
		desc_str = json_cstr_from_hex(tmpctx, buf, hextok);
		if (!json_to_sha256(buf, keytok + 4, &ph)) {
			plugin_log(init_cmd->plugin, LOG_BROKEN,
				   "Invalid payment hash desc for %.*s",
				   json_tok_full_len(keytok),
				   json_tok_full(buf, keytok));
			continue;
		}
		new_payment_hash_description(descriptions, &ph, take(desc_str));
	}

	return descriptions;
}

const char *chain_event_description(const struct bkpr *bkpr,
				    const struct chain_event *ce)
{
	const struct utxo_desc *ud;

	/* We only put descriptions on the *credit* events */
	if (amount_msat_is_zero(ce->credit))
		return NULL;

	ud = utxo_desc_htable_get(bkpr->descriptions->by_utxo, &ce->outpoint);
	return ud ? ud->desc : NULL;
}

const char *channel_event_description(const struct bkpr *bkpr,
				      const struct channel_event *ce)
{
	const struct payment_hash_desc *phd;

	if (!ce->payment_id)
		return NULL;

	phd = payment_hash_desc_htable_get(bkpr->descriptions->by_payment_hash,
					   ce->payment_id);
	return phd ? phd->desc : NULL;
}
