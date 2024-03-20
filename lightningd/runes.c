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
#include <common/overflows.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/runes.h>
#include <wallet/wallet.h>

static const u64 sec_per_nsec = 1000000000;

struct cond_info {
	const struct runes *runes;
	const struct node_id *peer;
	const char *buf;
	const char *method;
	struct timeabs now;
	const jsmntok_t *params;
	STRMAP(const jsmntok_t *) cached_params;
};

/* This is lightningd->runes */
struct runes {
	struct lightningd *ld;
	struct rune *master;
	u64 next_unique_id;
	struct rune_blacklist *blacklist;
};

const char *rune_is_ours(struct lightningd *ld, const struct rune *rune)
{
	return rune_is_derived(ld->runes->master, rune);
}

/* Convert unique_id string to u64.  We only expect this to fail when we're
 * dealing with runes from elsewhere (i.e. param_rune) */
static bool unique_id_num(const struct rune *rune, u64 *num)
{
	unsigned long long l;
	char *end;

	if (!rune->unique_id)
		return false;
	l = strtoull(rune->unique_id, &end, 0);
	if (*end)
		return false;

	/* sqlite3 only does signed 64 bits, so don't exceed 63 bits. */
	if (l > INT64_MAX)
		return false;

	*num = l;
	return true;
}

u64 rune_unique_id(const struct rune *rune)
{
	u64 num;

	/* Any of our runes must have valid unique ids! */
	if (!unique_id_num(rune, &num))
		abort();
	return num;
}

static const char *last_time_check(const struct rune *rune,
				    struct cond_info *cinfo,
					u64 n_sec)
{
	u64 diff;
	struct timeabs last_used;

	if (!wallet_get_rune(tmpctx, cinfo->runes->ld->wallet, atol(rune->unique_id), &last_used)) {
		/* FIXME: If we do not know the rune, per does not work */
		return NULL;
	}
	if (time_before(cinfo->now, last_used)) {
		last_used = cinfo->now;
	}

	diff = time_to_nsec(time_between(cinfo->now, last_used));
	if (diff < n_sec) {
		return "too soon";
	}
	return NULL;
}

static const char *per_time_check(const tal_t *ctx,
				    const struct runes *runes,
				    const struct rune *rune,
				    const struct rune_altern *alt,
				    struct cond_info *cinfo)
{
	u64 r, multiplier;
	char *endp;

	if (alt->condition != '=')
		return "per operator must be =";

	r = strtoul(alt->value, &endp, 10);
	if (endp == alt->value || r == 0 || r >= UINT32_MAX)
		return "malformed per";
	if (streq(endp, "") || streq(endp, "sec")) {
		multiplier = sec_per_nsec;
	} else if (streq(endp, "nsec")) {
		multiplier = 1;
	} else if (streq(endp, "usec")) {
		multiplier = 1000;
	} else if (streq(endp, "msec")) {
		multiplier = 1000000;
	} else if (streq(endp, "min")) {
		multiplier = 60 * sec_per_nsec;
	} else if (streq(endp, "hour")) {
		multiplier = 60 * 60 * sec_per_nsec;
	} else if (streq(endp, "day")) {
		multiplier = 24 * 60 * 60 * sec_per_nsec;
	} else {
		return "malformed suffix";
	}
	if (mul_overflows_u64(r, multiplier)) {
		return "per overflow";
	}
	return last_time_check(rune, cinfo, r * multiplier);
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

	return last_time_check(rune, cinfo, 60 * sec_per_nsec / r);
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

	runes->next_unique_id = wallet_get_rune_next_unique_id(runes, ld->wallet);
	runes->blacklist = wallet_get_runes_blacklist(runes, ld->wallet);
}

struct rune_and_string {
	const char *runestr;
	struct rune *rune;
};

static struct command_result *param_rune(struct command *cmd, const char *name,
					 const char * buffer, const jsmntok_t *tok,
					 struct rune_and_string **rune_and_string)
{
	u64 uid;

	*rune_and_string = tal(cmd, struct rune_and_string);
	(*rune_and_string)->runestr = json_strdup(*rune_and_string, buffer, tok);
	(*rune_and_string)->rune = rune_from_base64(cmd, (*rune_and_string)->runestr);
	if (!(*rune_and_string)->rune)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be base64 string");
	/* We always create runes with integer unique ids: accept no less! */
	if (!unique_id_num((*rune_and_string)->rune, &uid))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should have valid numeric unique_id");

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

static char *fmt_cond(const tal_t *ctx,
		      const struct rune_altern *alt,
		      const char *cond_str)
{
	return tal_fmt(ctx, "%s %s %s", alt->fieldname, cond_str, alt->value);
}

static char *rune_altern_to_english(const tal_t *ctx, const struct rune_altern *alt)
{
	switch (alt->condition) {
		case RUNE_COND_IF_MISSING:
			return tal_strcat(ctx, alt->fieldname, " is missing");
		case RUNE_COND_EQUAL:
			return fmt_cond(ctx, alt, "equal to");
		case RUNE_COND_NOT_EQUAL:
			return fmt_cond(ctx, alt, "unequal to");
		case RUNE_COND_BEGINS:
			return fmt_cond(ctx, alt, "starts with");
		case RUNE_COND_ENDS:
			return fmt_cond(ctx, alt, "ends with");
		case RUNE_COND_CONTAINS:
			return fmt_cond(ctx, alt, "contains");
		case RUNE_COND_INT_LESS:
			return fmt_cond(ctx, alt, "<");
		case RUNE_COND_INT_GREATER:
			return fmt_cond(ctx, alt, ">");
		case RUNE_COND_LEXO_BEFORE:
			return fmt_cond(ctx, alt, "sorts before");
		case RUNE_COND_LEXO_AFTER:
			return fmt_cond(ctx, alt, "sorts after");
		case RUNE_COND_COMMENT:
			return tal_fmt(ctx, "comment: %s %s", alt->fieldname, alt->value);
	}

	abort();
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
	uid = rune_unique_id(rune);
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
					    bool stored,
					    struct timeabs last_used)
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
	if (last_used.ts.tv_sec != 0) {
		json_add_timeabs(js, "last_used", last_used);
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
		u64 uid = rune_unique_id(ras->rune);
		struct timeabs last_used;
		const char *from_db = wallet_get_rune(tmpctx, cmd->ld->wallet, uid, &last_used);

		/* This is how we indicate no timestamp: */
		if (!from_db)
			last_used.ts.tv_sec = 0;
		/* We consider it stored iff this is exactly stored */
		json_add_rune(cmd->ld, response, NULL, ras->runestr, ras->rune,
			      from_db && streq(from_db, ras->runestr), last_used);
	} else {
		struct timeabs *last_used;
		const char **strs = wallet_get_runes(cmd, cmd->ld->wallet, &last_used);
		for (size_t i = 0; i < tal_count(strs); i++) {
			const struct rune *r = rune_from_base64(cmd, strs[i]);
			json_add_rune(cmd->ld, response, NULL, strs[i], r, true, last_used[i]);
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

	/* don't let them add empty fieldnames */
	if (streq(alt->fieldname, ""))
		return tal_free(alt);
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
	if (tok->type == JSMN_STRING
	    && command_deprecated_in_ok(cmd, "restrictions.string",
					"v23.05", "v24.02")) {
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
				      tal_fmt(tmpctx, "%"PRIu64,
					      cmd->ld->runes->next_unique_id));
	ras->runestr = rune_to_base64(tmpctx, ras->rune);

	for (size_t i = 0; i < tal_count(restrs); i++)
		rune_add_restr(ras->rune, restrs[i]);

	/* Insert into DB*/
	wallet_rune_insert(cmd->ld->wallet, ras->rune);
	cmd->ld->runes->next_unique_id = cmd->ld->runes->next_unique_id + 1;
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

	if (!param_check(cmd, buffer, params,
			 p_opt("start", param_u64, &start), p_opt("end", param_u64, &end), NULL))
		return command_param_failed();

	if (end && !start) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Can not specify end without start");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

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
		return rune_alt_single_int(ctx, alt, cinfo->now.ts.tv_sec);
	} else if (streq(alt->fieldname, "id")) {
		if (cinfo->peer) {
			const char *id = fmt_node_id(tmpctx, cinfo->peer);
			return rune_alt_single_str(ctx, alt, id, strlen(id));
		}
		return rune_alt_single_missing(ctx, alt);
	} else if (streq(alt->fieldname, "method")) {
		if (cinfo->method) {
			return rune_alt_single_str(ctx, alt,
						   cinfo->method, strlen(cinfo->method));
		}
		return rune_alt_single_missing(ctx, alt);
	} else if (streq(alt->fieldname, "pnum")) {
		return rune_alt_single_int(ctx, alt, (cinfo && cinfo->params) ? cinfo->params->size : 0);
	} else if (streq(alt->fieldname, "rate")) {
		return rate_limit_check(ctx, cinfo->runes, rune, alt, cinfo);
	} else if (streq(alt->fieldname, "per")) {
		return per_time_check(ctx, cinfo->runes, rune, alt, cinfo);
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

static void update_rune_usage_time(struct runes *runes,
						 struct rune *rune, struct timeabs now)
{
	/* FIXME: we could batch DB access if this is too slow */
	wallet_rune_update_last_used(runes->ld->wallet, rune, now);
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
		   p_opt("nodeid", param_node_id, &nodeid),
		   p_opt("method", param_string, &method),
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
	cinfo.now = time_now();
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

	update_rune_usage_time(cmd->ld->runes, ras->rune, cinfo.now);

	js = json_stream_success(cmd);
	json_add_bool(js, "valid", true);
	return command_success(cmd, js);
}

static const struct json_command checkrune_command = {
	"checkrune",
	"utility",
	json_checkrune,
	"Checks rune for validity with required {rune} and optional {nodeid}, {method}, {params} and returns {valid: true} or error message"
};
AUTODATA(json_command, &checkrune_command);
