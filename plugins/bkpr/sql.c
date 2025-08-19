#include "config.h"

#include <common/json_stream.h>
#include <plugins/bkpr/blockheights.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/sql.h>
#include <plugins/libplugin.h>

const jsmntok_t *sql_req(const tal_t *ctx,
			 struct command *cmd,
			 const char **buf,
			 const char *fmt, ...)
{
	va_list ap;
	const jsmntok_t *ret;

	va_start(ap, fmt);
	ret = sql_reqv(ctx, cmd, buf, fmt, ap);
	va_end(ap);
	return ret;
}

const jsmntok_t *sql_reqv(const tal_t *ctx,
			  struct command *cmd,
			  const char **buf,
			  const char *fmt, va_list ap)
{
	struct json_out *params;

	params = json_out_obj(NULL, "query", take(tal_vfmt(NULL, fmt, ap)));

	return jsonrpc_request_sync(ctx, cmd, "sql", take(params), buf);
}

static struct channel_event **channel_events(const tal_t *ctx,
					     const char *buf,
					     const jsmntok_t *result)
{
	struct channel_event **evs;
	size_t i;
	const jsmntok_t *row, *rows = json_get_member(buf, result, "rows");

	evs = tal_arr(ctx, struct channel_event *, rows->size);
	json_for_each_arr(i, row, rows) {
		bool ok = true;
		struct channel_event *ev;
		u64 created_index;
		const char *account_name;
		const char *primary_tag;
		struct amount_msat credit, debit, fees;
		struct sha256 *payment_id, payment_hash;
		u64 part_id, timestamp;

		const jsmntok_t *val = row + 1;
		assert(row->size == 9);
		ok &= json_to_u64(buf, val, &created_index);
		val = json_next(val);
		account_name = json_strdup(NULL, buf, val);
		val = json_next(val);
		primary_tag = json_strdup(NULL, buf, val);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &credit);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &debit);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &fees);
		val = json_next(val);
		if (json_tok_is_null(buf, val))
			payment_id = NULL;
		else {
			ok &= json_to_sha256(buf, val, &payment_hash);
			payment_id = &payment_hash;
		}
		val = json_next(val);
		if (json_tok_is_null(buf, val))
			part_id = 0;
		else {
			ok &= json_to_u64(buf, val, &part_id);
		}
		val = json_next(val);
		ok &= json_to_u64(buf, val, &timestamp);
		assert(ok);
		ev = new_channel_event(evs,
				       take(primary_tag),
				       credit, debit, fees,
				       payment_id,
				       part_id,
				       timestamp);
		ev->acct_name = tal_steal(ev, account_name);
		ev->db_id = created_index;
		evs[i] = ev;
	}
	return evs;
}

static struct chain_event **chain_events(const tal_t *ctx,
					 const struct bkpr *bkpr,
					 const char *buf,
					 const jsmntok_t *result)
{
	struct chain_event **evs;
	size_t i;
	const jsmntok_t *row, *rows = json_get_member(buf, result, "rows");

	evs = tal_arr(ctx, struct chain_event *, rows->size);
	json_for_each_arr(i, row, rows) {
		bool ok = true;
		struct chain_event *ev = tal(evs, struct chain_event);
		int flag;

		const jsmntok_t *val = row + 1;
		assert(row->size == 14);
		ok &= json_to_u64(buf, val, &ev->db_id);
		val = json_next(val);
		ev->acct_name = json_strdup(ev, buf, val);
		val = json_next(val);
		if (json_tok_is_null(buf, val))
			ev->origin_acct = NULL;
		else
			ev->origin_acct = json_strdup(ev, buf, val);
		val = json_next(val);
		ev->tag = json_strdup(ev, buf, val);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &ev->credit);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &ev->debit);
		val = json_next(val);
		ok &= json_to_msat(buf, val, &ev->output_value);
		val = json_next(val);
		ok &= json_to_u64(buf, val, &ev->timestamp);
		val = json_next(val);
		ok &= json_to_u32(buf, val, &ev->blockheight);
		val = json_next(val);
		ok &= json_to_outpoint(buf, val, &ev->outpoint);
		/* We may know better! */
		if (ev->blockheight == 0)
			ev->blockheight = find_blockheight(bkpr, &ev->outpoint.txid);
		val = json_next(val);
		if (json_tok_is_null(buf, val))
			ev->spending_txid = NULL;
		else {
			ev->spending_txid = tal(ev, struct bitcoin_txid);
			ok &= json_to_txid(buf, val, ev->spending_txid);
		}
		val = json_next(val);
		if (json_tok_is_null(buf, val))
			ev->payment_id = NULL;
		else {
			ev->payment_id = tal(ev, struct sha256);
			ok &= json_to_sha256(buf, val, ev->payment_id);
		}
		val = json_next(val);
		/* These are 0/1 not true/false */
		ok &= json_to_int(buf, val, &flag);
		ev->stealable = flag;
		val = json_next(val);
		/* These are 0/1 not true/false */
		ok &= json_to_int(buf, val, &flag);
		ev->splice_close = flag;
		assert(ok);
		evs[i] = ev;
	}
	return evs;
}

struct channel_event **
channel_events_from_sql(const tal_t *ctx,
			struct command *cmd,
			const char *fmt, ...)
{
	va_list ap;
	const jsmntok_t *toks;
	const char *buf;

	va_start(ap, fmt);
	toks = sql_reqv(tmpctx, cmd, &buf, fmt, ap);
	va_end(ap);

	return channel_events(ctx, buf, toks);
}

struct chain_event **
chain_events_from_sql(const tal_t *ctx,
		      const struct bkpr *bkpr,
		      struct command *cmd,
		      const char *fmt, ...)
{
	va_list ap;
	const jsmntok_t *toks;
	const char *buf;

	va_start(ap, fmt);
	toks = sql_reqv(tmpctx, cmd, &buf, fmt, ap);
	va_end(ap);

	return chain_events(ctx, bkpr, buf, toks);
}

const char *sql_string(const tal_t *ctx, const char *str)
{
	char *ret;
	size_t out;

	if (!strchr(str, '\''))
		return str;

	/* Worst case size */
	ret = tal_arr(ctx, char, strlen(str) * 2 + 1);
	out = 0;
	for (size_t in = 0; str[in]; in++) {
		ret[out++] = str[in];
		if (str[in] == '\'')
			ret[out++] = str[in];
	}
	ret[out] = '\0';
	return ret;
}
