#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/runes.h>
#include <wallet/wallet.h>

struct usage {
	/* If you really issue more than 2^32 runes, they'll share ratelimit buckets */
	u32 id;
	u32 counter;
};

static u64 usage_id(const struct usage *u)
{
	return u->id;
}

static size_t id_hash(u64 id)
{
	return siphash24(siphash_seed(), &id, sizeof(id));
}

static bool usage_eq_id(const struct usage *u, u64 id)
{
	return u->id == id;
}
HTABLE_DEFINE_TYPE(struct usage, usage_id, id_hash, usage_eq_id, usage_table);

struct cond_info {
	const struct runes *runes;
	const struct node_id *peer;
	const char *buf;
	const char *method;
	const jsmntok_t *params;
	STRMAP(const jsmntok_t *) cached_params;
	struct usage *usage;
};

/* This is lightningd->runes */
struct runes {
	struct lightningd *ld;
	struct rune *master;
	u64 next_unique_id;
	struct rune_blacklist *blacklist;
	struct usage_table *usage_table;
};

const char *rune_is_ours(struct lightningd *ld, const struct rune *rune)
{
	return rune_is_derived(ld->runes->master, rune);
}

#if DEVELOPER
static void memleak_help_usage_table(struct htable *memtable,
				     struct usage_table *usage_table)
{
	memleak_scan_htable(memtable, &usage_table->raw);
}
#endif /* DEVELOPER */

/* Every minute we forget entries. */
static void flush_usage_table(struct runes *runes)
{
	tal_free(runes->usage_table);
	runes->usage_table = tal(runes, struct usage_table);
	usage_table_init(runes->usage_table);
	memleak_add_helper(runes->usage_table, memleak_help_usage_table);

	notleak(new_reltimer(runes->ld->timers, runes, time_from_sec(60), flush_usage_table, runes));
}

static const char *rate_limit_check(const tal_t *ctx,
				    const struct runes *runes,
				    const struct rune *rune,
				    const struct rune_altern *alt,
				    struct cond_info *cinfo)
{
	unsigned long r;
	char *endp;
	if (alt->condition != '=')
		return "rate operator must be =";

	r = strtoul(alt->value, &endp, 10);
	if (endp == alt->value || *endp || r == 0 || r >= UINT32_MAX)
		return "malformed rate";

	/* We cache this: we only add usage counter if whole rune succeeds! */
	if (!cinfo->usage) {
		cinfo->usage = usage_table_get(runes->usage_table, atol(rune->unique_id));
		if (!cinfo->usage) {
			cinfo->usage = tal(runes->usage_table, struct usage);
			cinfo->usage->id = atol(rune->unique_id);
			cinfo->usage->counter = 0;
			usage_table_add(runes->usage_table, cinfo->usage);
		}
	}

	/* >= becuase if we allow this, counter will increment */
	if (cinfo->usage->counter >= r)
		return tal_fmt(ctx, "Rate of %lu per minute exceeded", r);

	return NULL;
}

/* We need to initialize master runes secret early, so db can use rune_is_ours */
struct runes *runes_early_init(struct lightningd *ld)
{
	const u8 *msg;
	struct runes *runes = tal(ld, struct runes);
	const u8 *data;
	struct secret secret;

	/* Runes came out of commando, hence the derivation key is 'commando' */
	data = tal_dup_arr(tmpctx, u8, (u8 *)"commando", strlen("commando"), 0);
	msg = hsm_sync_req(tmpctx, ld, towire_hsmd_derive_secret(tmpctx, data));
	if (!fromwire_hsmd_derive_secret_reply(msg, &secret))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	runes->ld = ld;
	runes->master = rune_new(runes, secret.data, ARRAY_SIZE(secret.data), NULL);

	return runes;
}

void runes_finish_init(struct runes *runes)
{
	struct lightningd *ld = runes->ld;

	runes->next_unique_id = db_get_intvar(ld->wallet->db, "runes_uniqueid", 0);
	runes->blacklist = wallet_get_runes_blacklist(runes, ld->wallet);

	/* Initialize usage table and start flush timer. */
	runes->usage_table = NULL;
	flush_usage_table(runes);
}

struct rune_and_string {
	const char *runestr;
	struct rune *rune;
};

static struct command_result *param_rune(struct command *cmd, const char *name,
					 const char * buffer, const jsmntok_t *tok,
					 struct rune_and_string **rune_and_string)
{
	*rune_and_string = tal(cmd, struct rune_and_string);
	(*rune_and_string)->runestr = json_strdup(*rune_and_string, buffer, tok);
	(*rune_and_string)->rune = rune_from_base64(cmd, (*rune_and_string)->runestr);
	if (!(*rune_and_string)->rune)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be base64 string");

	return NULL;
}

static struct command_result *param_params(struct command *cmd, const char *name,
					 const char * buffer, const jsmntok_t *tok,
					 const jsmntok_t **params)
{
	if (tok->type != JSMN_OBJECT && tok->type != JSMN_ARRAY) {
		return command_fail_badparam(cmd, name, buffer, tok, "must be object or array");
	}
	*params = tok;
	return NULL;
}

/* The unique id is embedded with a special restriction with an empty field name */
static bool is_unique_id(struct rune_restr **restrs, unsigned int index)
{
	/* must be the first restriction */
	if (index != 0)
		return false;

	/* Must be the only alternative */
	if (tal_count(restrs[index]->alterns) != 1)
		return false;

	/* Must have an empty field name */
	return streq(restrs[index]->alterns[0]->fieldname, "");
}

static char *rune_altern_to_english(const tal_t *ctx, const struct rune_altern *alt)
{
	const char *cond_str;
	switch (alt->condition) {
		case RUNE_COND_IF_MISSING:
			return tal_strcat(ctx, alt->fieldname, " is missing");
		case RUNE_COND_EQUAL:
			cond_str = "equal to";
			break;
		case RUNE_COND_NOT_EQUAL:
			cond_str = "unequal to";
			break;
		case RUNE_COND_BEGINS:
			cond_str = "starts with";
			break;
		case RUNE_COND_ENDS:
			cond_str = "ends with";
			break;
		case RUNE_COND_CONTAINS:
			cond_str = "contains";
			break;
		case RUNE_COND_INT_LESS:
			cond_str = "<";
			break;
		case RUNE_COND_INT_GREATER:
			cond_str = ">";
			break;
		case RUNE_COND_LEXO_BEFORE:
			cond_str = "sorts before";
			break;
		case RUNE_COND_LEXO_AFTER:
			cond_str = "sorts after";
			break;
		case RUNE_COND_COMMENT:
			return tal_fmt(ctx, "comment: %s %s", alt->fieldname, alt->value);
	}
	return tal_fmt(ctx, "%s %s %s", alt->fieldname, cond_str, alt->value);
}

static char *json_add_alternative(const tal_t *ctx,
				  struct json_stream *js,
				  const char *fieldname,
				  struct rune_altern *alternative)
{
	char *altern_english;
	altern_english = rune_altern_to_english(ctx, alternative);
	json_object_start(js, fieldname);
	json_add_string(js, "fieldname", alternative->fieldname);
	json_add_string(js, "value", alternative->value);
	json_add_stringn(js, "condition", (char *)&alternative->condition, 1);
	json_add_string(js, "english", altern_english);
	json_object_end(js);
	return altern_english;
}

static bool is_rune_blacklisted(const struct runes *runes, const struct rune *rune)
{
	u64 uid;

	/* Every rune *we produce* has a unique_id which is a number, but
	 * it's legal to have a rune without one. */
	if (rune->unique_id == NULL) {
		return false;
	}
	uid = atol(rune->unique_id);
	for (size_t i = 0; i < tal_count(runes->blacklist); i++) {
		if (runes->blacklist[i].start <= uid && runes->blacklist[i].end >= uid) {
			return true;
		}
	}
	return false;
}

static void join_strings(char **base, const char *connector, char *append)
{
	if (streq(*base, "")) {
		*base = append;
	} else {
		tal_append_fmt(base, " %s %s", connector, append);
	}
}

static struct command_result *json_add_rune(struct lightningd *ld,
					    struct json_stream *js,
					    const char *fieldname,
					    const char *runestr,
					    const struct rune *rune,
					    bool stored)
{
	char *rune_english;
	rune_english = "";
	json_object_start(js, fieldname);
	json_add_string(js, "rune", runestr);
	if (!stored) {
		json_add_bool(js, "stored", false);
	}
	if (is_rune_blacklisted(ld->runes, rune)) {
		json_add_bool(js, "blacklisted", true);
	}
	if (rune_is_ours(ld, rune) != NULL) {
		json_add_bool(js, "our_rune", false);
	}
	json_add_string(js, "unique_id", rune->unique_id);
	json_array_start(js, "restrictions");
	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		char *restr_english;
		restr_english = "";
		/* Already printed out the unique id */
		if (is_unique_id(rune->restrs, i)) {
			continue;
		}
		json_object_start(js, NULL);
		json_array_start(js, "alternatives");
		for (size_t j = 0; j < tal_count(rune->restrs[i]->alterns); j++) {
			join_strings(&restr_english, "OR",
				     json_add_alternative(tmpctx, js, NULL, rune->restrs[i]->alterns[j]));
		}
		json_array_end(js);
		json_add_string(js, "english", restr_english);
		json_object_end(js);
		join_strings(&rune_english, "AND", restr_english);
	}
	json_array_end(js);
	json_add_string(js, "restrictions_as_english", rune_english);
	json_object_end(js);
	return NULL;
}

static struct command_result *json_showrunes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct json_stream *response;
	struct rune_and_string *ras;

	if (!param(cmd, buffer, params,
		   p_opt("rune", param_rune, &ras), NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "runes");
	if (ras) {
		long uid = atol(ras->rune->unique_id);
		const char *from_db = wallet_get_rune(tmpctx, cmd->ld->wallet, uid);

		/* We consider it stored iff this is exactly stored */
		json_add_rune(cmd->ld, response, NULL, ras->runestr, ras->rune,
			      from_db && streq(from_db, ras->runestr));
	} else {
		const char **strs = wallet_get_runes(cmd, cmd->ld->wallet);
		for (size_t i = 0; i < tal_count(strs); i++) {
			const struct rune *r = rune_from_base64(cmd, strs[i]);
			json_add_rune(cmd->ld, response, NULL, strs[i], r, true);
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command showrunes_command = {
	"showrunes",
	"utility",
	json_showrunes,
	"Show the list of runes or decode an optional {rune}."
};
AUTODATA(json_command, &showrunes_command);

static struct rune_restr **readonly_restrictions(const tal_t *ctx)
{
	struct rune_restr **restrs = tal_arr(ctx, struct rune_restr *, 2);

	/* Any list*, get*, or summary:
	 *  method^list|method^get|method=summary
	 */
	restrs[0] = rune_restr_new(restrs);
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_BEGINS,
						   "list")));
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_BEGINS,
						   "get")));
	rune_restr_add_altern(restrs[0],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_EQUAL,
						   "summary")));
	/* But not listdatastore!
	 *  method/listdatastore
	 */
	restrs[1] = rune_restr_new(restrs);
	rune_restr_add_altern(restrs[1],
			      take(rune_altern_new(NULL,
						   "method",
						   RUNE_COND_NOT_EQUAL,
						   "listdatastore")));

	return restrs;
}

static struct rune_altern *rune_altern_from_json(const tal_t *ctx,
						 const char *buffer,
						 const jsmntok_t *tok)
{
	struct rune_altern *alt;
	size_t condoff;
	/* We still need to unescape here, for \\ -> \.  JSON doesn't
	 * allow unnecessary \ */
	const char *unescape;
	struct json_escape *e = json_escape_string_(tmpctx,
						    buffer + tok->start,
						    tok->end - tok->start);
	unescape = json_escape_unescape(tmpctx, e);
	if (!unescape)
		return NULL;

	condoff = rune_altern_fieldname_len(unescape, strlen(unescape));
	if (!rune_condition_is_valid(unescape[condoff]))
		return NULL;

	alt = tal(ctx, struct rune_altern);
	alt->fieldname = tal_strndup(alt, unescape, condoff);
	alt->condition = unescape[condoff];
	alt->value = tal_strdup(alt, unescape + condoff + 1);
	return alt;
}

static struct rune_restr *rune_restr_from_json(struct command *cmd,
						   const tal_t *ctx,
					       const char *buffer,
					       const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;
	struct rune_restr *restr;

	/* \| is not valid JSON, so they use \\|: undo it! */
	if (cmd->ld->deprecated_apis && tok->type == JSMN_STRING) {
		const char *unescape;
		struct json_escape *e = json_escape_string_(tmpctx,
							    buffer + tok->start,
							    tok->end - tok->start);
		unescape = json_escape_unescape(tmpctx, e);
		if (!unescape)
			return NULL;
		return rune_restr_from_string(ctx, unescape, strlen(unescape));
	}

	restr = tal(ctx, struct rune_restr);
	/* FIXME: after deprecation removed, allow singletons again! */
	if (tok->type != JSMN_ARRAY)
		return NULL;

	restr->alterns = tal_arr(restr, struct rune_altern *, tok->size);
	json_for_each_arr(i, t, tok) {
		restr->alterns[i] = rune_altern_from_json(restr->alterns,
							  buffer, t);
		if (!restr->alterns[i])
			return tal_free(restr);
	}
	return restr;
}

static struct command_result *param_restrictions(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct rune_restr ***restrs)
{
	if (json_tok_streq(buffer, tok, "readonly"))
		*restrs = readonly_restrictions(cmd);
	else if (tok->type == JSMN_ARRAY) {
		size_t i;
		const jsmntok_t *t;

		*restrs = tal_arr(cmd, struct rune_restr *, tok->size);
		json_for_each_arr(i, t, tok) {
			(*restrs)[i] = rune_restr_from_json(cmd, *restrs, buffer, t);
			if (!(*restrs)[i]) {
				return command_fail_badparam(cmd, name, buffer, t,
							     "not a valid restriction (should be array)");
			}
		}
	} else {
		*restrs = tal_arr(cmd, struct rune_restr *, 1);
		(*restrs)[0] = rune_restr_from_json(cmd, *restrs, buffer, tok);
		if (!(*restrs)[0])
			return command_fail_badparam(cmd, name, buffer, tok,
						     "not a valid restriction (should be array)");
	}
	return NULL;
}

static struct command_result *reply_with_rune(struct command *cmd,
					      const char *buf UNUSED,
					      const jsmntok_t *result UNUSED,
					      struct rune *rune)
{
	struct json_stream *js = json_stream_success(cmd);

	json_add_string(js, "rune", rune_to_base64(tmpctx, rune));
	json_add_string(js, "unique_id", rune->unique_id);

	if (tal_count(rune->restrs) <= 1) {
		json_add_string(js, "warning_unrestricted_rune", "WARNING: This rune has no restrictions! Anyone who has access to this rune could drain funds from your node. Be careful when giving this to apps that you don't trust. Consider using the restrictions parameter to only allow access to specific rpc methods.");
	}
	return command_success(cmd, js);
}

static struct command_result *json_createrune(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct rune_and_string *ras;
	struct rune_restr **restrs;

	if (!param(cmd, buffer, params,
		   p_opt("rune", param_rune, &ras),
		   p_opt("restrictions", param_restrictions, &restrs),
		   NULL))
		return command_param_failed();

	if (ras != NULL ) {
		for (size_t i = 0; i < tal_count(restrs); i++)
			rune_add_restr(ras->rune, restrs[i]);
		return reply_with_rune(cmd, NULL, NULL, ras->rune);
	}

	ras = tal(cmd, struct rune_and_string);
	ras->rune = rune_derive_start(cmd, cmd->ld->runes->master,
		tal_fmt(tmpctx, "%"PRIu64, cmd->ld->runes->next_unique_id ? cmd->ld->runes->next_unique_id : 0));
	ras->runestr = rune_to_base64(tmpctx, ras->rune);

	for (size_t i = 0; i < tal_count(restrs); i++)
		rune_add_restr(ras->rune, restrs[i]);

	/* Insert into DB*/
	wallet_rune_insert(cmd->ld->wallet, ras->rune);
	cmd->ld->runes->next_unique_id = cmd->ld->runes->next_unique_id + 1;
	db_set_intvar(cmd->ld->wallet->db, "runes_uniqueid", cmd->ld->runes->next_unique_id);
	return reply_with_rune(cmd, NULL, NULL, ras->rune);
}

static const struct json_command creatrune_command = {
	"createrune",
	"utility",
	json_createrune,
	"Create or restrict an optional {rune} with optional {restrictions} and returns {rune}"
};
AUTODATA(json_command, &creatrune_command);

static const struct json_command invokerune_command = {
	"invokerune",
	"utility",
	json_createrune,
	"Invoke or restrict an optional {rune} with optional {restrictions} and returns {rune}"
};
AUTODATA(json_command, &invokerune_command);

static void blacklist_merge(struct rune_blacklist *blacklist,
			    const struct rune_blacklist *entry)
{
	if (entry->start < blacklist->start) {
		blacklist->start = entry->start;
	}
	if (entry->end > blacklist->end) {
		blacklist->end = entry->end;
	}
}

static bool blacklist_before(const struct rune_blacklist *first,
			     const struct rune_blacklist *second)
{
	// Is it before with a gap
	return (first->end + 1) < second->start;
}

static struct command_result *list_blacklist(struct command *cmd)
{
	struct json_stream *js = json_stream_success(cmd);
	json_array_start(js, "blacklist");
	for (size_t i = 0; i < tal_count(cmd->ld->runes->blacklist); i++) {
		json_object_start(js, NULL);
		json_add_u64(js, "start", cmd->ld->runes->blacklist[i].start);
		json_add_u64(js, "end", cmd->ld->runes->blacklist[i].end);
		json_object_end(js);
	}
	json_array_end(js);
	return command_success(cmd, js);
}

static struct command_result *json_blacklistrune(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	u64 *start, *end;
	struct rune_blacklist *entry, *newblacklist;

	if (!param(cmd, buffer, params,
		   p_opt("start", param_u64, &start), p_opt("end", param_u64, &end), NULL))
		return command_param_failed();

	if (end && !start) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Can not specify end without start");
	}
	if (!start) {
		return list_blacklist(cmd);
	}
	if (!end) {
		end = start;
	}
	entry = tal(cmd, struct rune_blacklist);
	entry->start = *start;
	entry->end = *end;

	newblacklist = tal_arr(cmd->ld->runes, struct rune_blacklist, 0);

	for (size_t i = 0; i < tal_count(cmd->ld->runes->blacklist); i++) {
		/* if new entry if already merged just copy the old list */
		if (entry == NULL) {
			tal_arr_expand(&newblacklist, cmd->ld->runes->blacklist[i]);
			continue;
		}
		/* old list has not reached the entry yet, so we are just copying it */
		if (blacklist_before(&(cmd->ld->runes->blacklist)[i], entry)) {
			tal_arr_expand(&newblacklist, cmd->ld->runes->blacklist[i]);
			continue;
		}
		/* old list has passed the entry, time to put the entry in */
		if (blacklist_before(entry, &(cmd->ld->runes->blacklist)[i])) {
			tal_arr_expand(&newblacklist, *entry);
			tal_arr_expand(&newblacklist, cmd->ld->runes->blacklist[i]);
			wallet_insert_blacklist(cmd->ld->wallet, entry);
			// mark entry as copied
			entry = NULL;
			continue;
		}
		/* old list overlaps combined into the entry we are adding */
		blacklist_merge(entry, &(cmd->ld->runes->blacklist)[i]);
		wallet_delete_blacklist(cmd->ld->wallet, &(cmd->ld->runes->blacklist)[i]);
	}
	if (entry != NULL) {
		tal_arr_expand(&newblacklist, *entry);
		wallet_insert_blacklist(cmd->ld->wallet, entry);
	}

	tal_free(cmd->ld->runes->blacklist);
	cmd->ld->runes->blacklist = newblacklist;
	return list_blacklist(cmd);
}

static const struct json_command blacklistrune_command = {
	"blacklistrune",
	"utility",
	json_blacklistrune,
	"Blacklist a rune or range of runes by taking an optional {start} and an optional {end} and returns {blacklist} array containing {start}, {end}"
};
AUTODATA(json_command, &blacklistrune_command);

static const struct json_command destroyrune_command = {
	"destroyrune",
	"utility",
	json_blacklistrune,
	"Destroy a rune or range of runes by taking an optional {start} and an optional {end} and returns {blacklist} array containing {start}, {end}"
};
AUTODATA(json_command, &destroyrune_command);

static const char *check_condition(const tal_t *ctx,
				   const struct rune *rune,
				   const struct rune_altern *alt,
				   struct cond_info *cinfo)
{
	const jsmntok_t *ptok;

	if (streq(alt->fieldname, "time")) {
		return rune_alt_single_int(ctx, alt, time_now().ts.tv_sec);
	} else if (streq(alt->fieldname, "id")) {
		const char *id = node_id_to_hexstr(tmpctx, cinfo->peer);
		return rune_alt_single_str(ctx, alt, id, strlen(id));
	} else if (streq(alt->fieldname, "method")) {
		return rune_alt_single_str(ctx, alt,
					   cinfo->method, strlen(cinfo->method));
	} else if (streq(alt->fieldname, "pnum")) {
		return rune_alt_single_int(ctx, alt, (cinfo && cinfo->params) ? cinfo->params->size : 0);
	} else if (streq(alt->fieldname, "rate")) {
		return rate_limit_check(ctx, cinfo->runes, rune, alt, cinfo);
	}

	/* Rest are params looksup: generate this once! */
	if (cinfo->params && strmap_empty(&cinfo->cached_params)) {
		const jsmntok_t *t;
		size_t i;

		if (cinfo->params->type == JSMN_OBJECT) {
			json_for_each_obj(i, t, cinfo->params) {
				char *pmemname = tal_fmt(tmpctx,
							 "pname%.*s",
							 t->end - t->start,
							 cinfo->buf + t->start);
				size_t off = strlen("pname");
				/* Remove punctuation! */
				for (size_t n = off; pmemname[n]; n++) {
					if (cispunct(pmemname[n]))
						continue;
					pmemname[off++] = pmemname[n];
				}
				pmemname[off++] = '\0';
				strmap_add(&cinfo->cached_params, pmemname, t+1);
			}
		} else if (cinfo->params->type == JSMN_ARRAY) {
			json_for_each_arr(i, t, cinfo->params) {
				char *pmemname = tal_fmt(tmpctx, "parr%zu", i);
				strmap_add(&cinfo->cached_params, pmemname, t);
			}
		}
	}

	ptok = strmap_get(&cinfo->cached_params, alt->fieldname);
	if (!ptok)
		return rune_alt_single_missing(ctx, alt);

	/* Pass through valid integers as integers. */
	if (ptok->type == JSMN_PRIMITIVE) {
		s64 val;

		if (json_to_s64(cinfo->buf, ptok, &val)) {
			return rune_alt_single_int(ctx, alt, val);
		}

		/* Otherwise, treat it as a string (< and > will fail with
		 * "is not an integer field") */
	}
	return rune_alt_single_str(ctx, alt,
				   cinfo->buf + ptok->start,
				   ptok->end - ptok->start);
}

static struct command_result *json_checkrune(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	const jsmntok_t *methodparams;
	struct cond_info cinfo;
	struct rune_and_string *ras;
	struct node_id *nodeid;
	struct json_stream *js;
	const char *err, *method;

	if (!param(cmd, buffer, params,
		   p_req("rune", param_rune, &ras),
		   p_req("nodeid", param_node_id, &nodeid),
		   p_req("method", param_string, &method),
		   p_opt("params", param_params, &methodparams),
		   NULL))
		return command_param_failed();

	if (is_rune_blacklisted(cmd->ld->runes, ras->rune))
		return command_fail(cmd, RUNE_BLACKLISTED, "Not authorized: Blacklisted rune");

	cinfo.runes = cmd->ld->runes;
	cinfo.peer = nodeid;
	cinfo.buf = buffer;
	cinfo.method = method;
	cinfo.params = methodparams;
	/* We will populate it in rate_limit_check if required. */
	cinfo.usage = NULL;
	strmap_init(&cinfo.cached_params);

	err = rune_is_ours(cmd->ld, ras->rune);
	if (err) {
		return command_fail(cmd, RUNE_NOT_AUTHORIZED, "Not authorized: %s", err);
	}

	err = rune_test(tmpctx, cmd->ld->runes->master, ras->rune, check_condition, &cinfo);
	strmap_clear(&cinfo.cached_params);

	/* Just in case they manage to make us speak non-JSON, escape! */
	if (err) {
		err = json_escape(tmpctx, err)->s;
		return command_fail(cmd, RUNE_NOT_PERMITTED, "Not permitted: %s", err);
	}

	/* If it succeeded, *now* we increment any associated usage counter. */
	if (cinfo.usage)
		cinfo.usage->counter++;

	js = json_stream_success(cmd);
	json_add_bool(js, "valid", true);
	return command_success(cmd, js);
}

static const struct json_command checkrune_command = {
	"checkrune",
	"utility",
	json_checkrune,
	"Checks rune for validity with required {nodeid}, {rune}, {method} and optional {params} and returns {valid: true} or error message"
};
AUTODATA(json_command, &checkrune_command);
