#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/iso4217.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/incomestmt.h>
#include <plugins/bkpr/report.h>
#include <plugins/libplugin.h>

/* This is a zero, but treated specially if tested with ? */
static const char ZERO_AMOUNT[] = "0";

static const char *report_fmt_acct_name(const tal_t *ctx UNNEEDED,
					const struct bkpr *bkpr UNNEEDED,
					const struct income_event *e)
{
	return e->acct_name;
}

static const char *report_fmt_tag(const tal_t *ctx UNNEEDED,
				  const struct bkpr *bkpr UNNEEDED,
				  const struct income_event *e)
{
	return e->tag;
}

static const char *report_fmt_desc(const tal_t *ctx UNNEEDED,
				   const struct bkpr *bkpr UNNEEDED,
				   const struct income_event *e)
{
	return e->desc;
}

static const char *report_fmt_credit(const tal_t *ctx,
				     const struct bkpr *bkpr UNNEEDED,
				     const struct income_event *e)
{
	if (amount_msat_is_zero(e->credit))
		return ZERO_AMOUNT;
	return fmt_amount_msat_btc(ctx, e->credit, false);
}

static const char *report_fmt_debit(const tal_t *ctx,
				    const struct bkpr *bkpr UNNEEDED,
				    const struct income_event *e)
{
	if (amount_msat_is_zero(e->debit))
		return ZERO_AMOUNT;
	return fmt_amount_msat_btc(ctx, e->debit, false);
}

static const char *report_fmt_fees(const tal_t *ctx,
				   const struct bkpr *bkpr UNNEEDED,
				   const struct income_event *e)
{
	if (amount_msat_is_zero(e->fees))
		return ZERO_AMOUNT;
	return fmt_amount_msat_btc(ctx, e->fees, false);
}

static const char *report_fmt_localtime(const tal_t *ctx,
					const struct bkpr *bkpr UNNEEDED,
					const struct income_event *e)
{
	time_t t = e->timestamp;
	struct tm tm;
	char buf[100];

	localtime_r(&t, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
	return tal_strdup(ctx, buf);
}

static const char *report_fmt_utctime(const tal_t *ctx,
				      const struct bkpr *bkpr UNNEEDED,
				      const struct income_event *e)
{
	time_t t = e->timestamp;
	struct tm tm;
	char buf[100];

	gmtime_r(&t, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
	return tal_strdup(ctx, buf);
}

static const char *report_fmt_outpoint(const tal_t *ctx,
				       const struct bkpr *bkpr UNNEEDED,
				       const struct income_event *e)
{
	if (!e->outpoint)
		return NULL;
	return fmt_bitcoin_outpoint(ctx, e->outpoint);
}

static const char *report_fmt_txid(const tal_t *ctx,
				   const struct bkpr *bkpr UNNEEDED,
				   const struct income_event *e)
{
	if (!e->txid)
		return NULL;
	return fmt_bitcoin_txid(ctx, e->txid);
}

static const char *report_fmt_payment_id(const tal_t *ctx,
					 const struct bkpr *bkpr UNNEEDED,
					 const struct income_event *e)
{
	if (!e->payment_id)
		return NULL;
	return fmt_sha256(ctx, e->payment_id);
}

static const char *report_fmt_bkpr_currency(const tal_t *ctx UNNEEDED,
					    const struct bkpr *bkpr,
					    const struct income_event *e UNNEEDED)
{
	return bkpr->currency ? bkpr->currency->name : NULL;
}

static const char *report_fmt_bkpr_currencyrate(const tal_t *ctx UNNEEDED,
						const struct bkpr *bkpr,
						const struct income_event *e)
{
	return currencyrate_str(ctx, bkpr, e->timestamp, NULL);
}

static const char *report_fmt_credit_debit(const tal_t *ctx,
					   const struct bkpr *bkpr UNNEEDED,
					   const struct income_event *e)
{
	if (!amount_msat_is_zero(e->credit))
		return tal_fmt(ctx, "+%s",
			       fmt_amount_msat_btc(tmpctx, e->credit, false));
	if (!amount_msat_is_zero(e->debit))
		return tal_fmt(ctx, "-%s",
			       fmt_amount_msat_btc(tmpctx, e->debit, false));
	return ZERO_AMOUNT;
}

static const char *report_fmt_currency_credit(const tal_t *ctx,
					      const struct bkpr *bkpr,
					      const struct income_event *e)
{
	return currencyrate_str(ctx, bkpr, e->timestamp, &e->credit);
}

static const char *report_fmt_currency_debit(const tal_t *ctx,
					     const struct bkpr *bkpr,
					     const struct income_event *e)
{
	return currencyrate_str(ctx, bkpr, e->timestamp, &e->debit);
}

static const char *report_fmt_currency_credit_debit(const tal_t *ctx,
						    const struct bkpr *bkpr,
						    const struct income_event *e)
{
	const char *s;

	if (!amount_msat_is_zero(e->credit)) {
		s = currencyrate_str(tmpctx, bkpr, e->timestamp, &e->credit);
		return s ? tal_fmt(ctx, "+%s", s) : NULL;
	}
	if (!amount_msat_is_zero(e->debit)) {
		s = currencyrate_str(tmpctx, bkpr, e->timestamp, &e->debit);
		return s ? tal_fmt(ctx, "-%s", s) : NULL;
	}
	return "0";
}

struct report_tag {
	const char *name;
	const char *(*fmt)(const tal_t *ctx,
			   const struct bkpr *bkpr,
			   const struct income_event *e);
};

static const struct report_tag report_tags[] = {
	{ "account", report_fmt_acct_name },
	{ "tag", report_fmt_tag },
	{ "description", report_fmt_desc },
	{ "credit", report_fmt_credit },
	{ "debit", report_fmt_debit },
	{ "fees", report_fmt_fees },
	{ "localtime", report_fmt_localtime },
	{ "utctime", report_fmt_utctime },
	{ "outpoint", report_fmt_outpoint },
	{ "txid", report_fmt_txid },
	{ "payment_id", report_fmt_payment_id },
	{ "bkpr-currency", report_fmt_bkpr_currency },
	{ "currencyrate", report_fmt_bkpr_currencyrate },
	{ "creditdebit", report_fmt_credit_debit },
	{ "currencycredit", report_fmt_currency_credit },
	{ "currencydebit", report_fmt_currency_debit },
	{ "currencycreditdebit", report_fmt_currency_credit_debit },
};

static const struct report_tag *
find_report_tag(const char *name, size_t len)
{
	for (size_t i = 0; i < ARRAY_SIZE(report_tags); i++) {
		if (memeqstr(name, len, report_tags[i].name))
			return &report_tags[i];
	}
	return NULL;
}

struct report_format {
	/* Produces a string: NULL means simply copy. */
	const char *(**fmt)(const tal_t *ctx,
			    const struct bkpr *bkpr,
			    const struct income_event *e);
	const char **str;
	/* If fmt returns non-NULL (and non-ZERO_AMOUNT), evaluate these instead of the value. */
	struct report_format **ifset;
	/* If fmt returns NULL (or ZERO_AMOUNT when either ifset/ifnotset is non-NULL), evaluate these. */
	struct report_format **ifnotset;
};

static void add_literal(struct report_format *f,
			const char **start, const char *end)
{
	if (*start != end) {
		tal_arr_expand(&f->fmt, NULL);
		tal_arr_expand(&f->str,
			       tal_strndup(f->str, *start, end - *start));
		tal_arr_expand(&f->ifset, NULL);
		tal_arr_expand(&f->ifnotset, NULL);
		*start = end;
	}
}

/* alt_term is a secondary loop terminator (in addition to term); '\0' means none. */
static struct report_format *
parse_report_format(const tal_t *ctx,
		    const char **start,
		    char term,
		    char alt_term,
		    const char **err)
{
	const char *p;
	struct report_format *f;

	f = tal(ctx, struct report_format);
	f->fmt = tal_arr(f, typeof(*f->fmt), 0);
	f->str = tal_arr(f, const char *, 0);
	f->ifset = tal_arr(f, struct report_format *, 0);
	f->ifnotset = tal_arr(f, struct report_format *, 0);

	p = *start;
	while (*p != term && !(alt_term && *p == alt_term)) {
		struct report_format *ifset, *ifnotset;
		const struct report_tag *rt;

		if (*p == '\0') {
			*err = tal_fmt(ctx, "Unterminated tag");
			return tal_free(f);
		}

		if (*p != '{') {
			p++;
			continue;
		}

		/* Escaped '{{' => literal '{' */
		if (p[1] != term && p[1] == '{') {
			char *lit;

			lit = tal_strndup(f->str, *start, p - *start);
			lit = tal_strcat(tmpctx, take(lit), "{");
			tal_arr_expand(&f->fmt, NULL);
			tal_arr_expand(&f->str, lit);
			tal_arr_expand(&f->ifset, NULL);
			tal_arr_expand(&f->ifnotset, NULL);
			p += 2;
			*start = p;
			continue;
		}

		/* Emit preceding literal, if any. */
		add_literal(f, start, p);

		const char *endtag = p + 1 + strcspn(p+1, "?:}");
		if (*endtag == '\0') {
			*err = tal_fmt(ctx, "Unterminated tag %s", p + 1);
			return tal_free(f);
		}

		rt = find_report_tag(p + 1, endtag - (p + 1));
		if (!rt) {
			*err = tal_fmt(ctx,
				       "Unknown tag %.*s",
				       (int)(endtag - (p + 1)), p + 1);
			return tal_free(f);
		}

		ifset = ifnotset = NULL;
		if (*endtag == '?') {
			/* Parse if-set, which ends at ':' or '}' */
			*start = endtag + 1;
			ifset = parse_report_format(f, start, '}', ':', err);
			if (!ifset) {
				tal_steal(ctx, *err);
				return tal_free(f);
			}
			if (**start == ':') {
				/* Parse if-not-set */
				(*start)++;
				ifnotset = parse_report_format(f, start, '}', '\0', err);
				if (!ifnotset) {
					tal_steal(ctx, *err);
					return tal_free(f);
				}
			}
			/* Consume final '}' */
			(*start)++;
		} else if (*endtag == ':') {
			/* Only if-not-set */
			*start = endtag + 1;
			ifnotset = parse_report_format(f, start, '}', '\0', err);
			if (!ifnotset) {
				tal_steal(ctx, *err);
				return tal_free(f);
			}
			/* Consume final '}' */
			(*start)++;
		} else {
			assert(*endtag == '}');
			*start = endtag + 1;
		}

		tal_arr_expand(&f->fmt, rt->fmt);
		tal_arr_expand(&f->str, NULL);
		tal_arr_expand(&f->ifset, ifset);
		tal_arr_expand(&f->ifnotset, ifnotset);

		p = *start;
	}

	add_literal(f, start, p);
	return f;
}

struct command_result *param_report_format(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   struct report_format **format)
{
	const char *err, *start;
	struct command_result *ret;

	ret = param_escaped_string(cmd, name, buffer, tok, &start);
	if (ret)
		return ret;

	*format = parse_report_format(cmd, &start, '\0', '\0', &err);
	if (!*format)
		return command_fail_badparam(cmd, name, buffer, tok, err);

	return NULL;
}

struct command_result *param_escape_format(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum escape_format **escape)
{
	*escape = tal(cmd, enum escape_format);
	if (json_tok_streq(buffer, tok, "csv")) {
		**escape = REPORT_FMT_CSV;
	} else if (json_tok_streq(buffer, tok, "none")) {
		**escape = REPORT_FMT_NONE;
	} else
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be `csv` or `none`");
	return NULL;
}

static char *escape_value(const tal_t *ctx,
			  const char *val TAKES,
			  enum escape_format esc)
{
	bool needs_quotes = false;
	char *ret, *out;
	const char *p;

	switch (esc) {
	case REPORT_FMT_NONE:
		return tal_strdup(ctx, val);

	case REPORT_FMT_CSV:
		for (p = val; *p; p++) {
			if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
				needs_quotes = true;
				break;
			}
		}

		if (!needs_quotes)
			return tal_strdup(ctx, val);

		/* Worst case: doubling length plus " around plus nul term */
		ret = tal_arr(ctx, char, 2 + strlen(val) * 2 + 1);
		out = ret;
		*(out++) = '"';
		/* Quotes get doubled */
		for (p = val; *p; p++) {
			if (*p == '"')
				*(out++) = '"';
			*(out++) = *p;
		}
		*(out++) = '"';
		*(out++) = '\0';
		if (taken(val))
			tal_free(val);
		return ret;
	}
	abort();
}

static char *format_event(const tal_t *ctx,
			  const struct report_format *fmt,
			  enum escape_format esc,
			  const struct bkpr *bkpr,
			  const struct income_event *e)
{
	char *out = tal_strdup(ctx, "");

	for (size_t i = 0; i < tal_count(fmt->fmt); i++) {
		const char *v;

		if (fmt->fmt[i] == NULL) {
			assert(fmt->str[i] != NULL);
			out = tal_strcat(ctx, take(out), fmt->str[i]);
			continue;
		}

		v = fmt->fmt[i](tmpctx, bkpr, e);
		/* Treat ZERO_AMOUNT as absent when there are conditionals. */
		if (v == ZERO_AMOUNT && (fmt->ifset[i] || fmt->ifnotset[i]))
			v = NULL;

		if (v) {
			if (fmt->ifset[i]) {
				out = tal_strcat(ctx, take(out),
						 format_event(tmpctx, fmt->ifset[i], esc, bkpr, e));
			} else {
				out = tal_strcat(ctx, take(out),
						 escape_value(tmpctx, v, esc));
			}
			continue;
		}

		if (fmt->ifnotset[i]) {
			out = tal_strcat(ctx, take(out),
					 format_event(tmpctx, fmt->ifnotset[i], esc, bkpr, e));
		}
	}

	return out;
}

struct command_result *do_bkpr_report(struct command *cmd,
				      struct report_info *info)
{
	const struct bkpr *bkpr = bkpr_of(cmd->plugin);
	struct income_event **events;
	struct json_stream *js;

	events = list_income_events(tmpctx, bkpr, cmd,
				    *info->start_time,
				    *info->end_time,
				    true);

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "report");
	for (size_t i = 0; i < tal_count(info->headers); i++)
		json_add_string(js, NULL, info->headers[i]);
	for (size_t i = 0; i < tal_count(events); i++) {
		char *line;

		line = format_event(tmpctx, info->format, *info->escapes,
				    bkpr, events[i]);
		json_add_string(js, NULL, line);
	}
	json_array_end(js);
	/* Tell cli this is simple enough to be formatted flat for humans */
	json_add_string(js, "format-hint", "simple");
	return command_finished(cmd, js);
}
