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
#include <common/type_to_string.h>
#include <db/exec.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/runes.h>
#include <wallet/wallet.h>

/* This is lightningd->runes */
struct runes {
	struct rune *master;
	u64 next_unique_id;
	struct rune_blacklist *blacklist;
};

struct runes *runes_init(struct lightningd *ld)
{
	const u8 *msg;
	struct runes *runes = tal(ld, struct runes);
	const u8 *data;
	struct secret secret;

	runes->next_unique_id = db_get_intvar(ld->wallet->db, "runes_uniqueid", 0);
	runes->blacklist = wallet_get_runes_blacklist(runes, ld->wallet);

	/* Runes came out of commando, hence the derivation key is 'commando' */
	data = tal_dup_arr(tmpctx, u8, (u8 *)"commando", strlen("commando"), 0);
	msg = hsm_sync_req(tmpctx, ld, towire_hsmd_derive_secret(tmpctx, data));
	if (!fromwire_hsmd_derive_secret_reply(msg, &secret))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	runes->master = rune_new(runes, secret.data, ARRAY_SIZE(secret.data), NULL);

	return runes;
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
	if (rune_is_derived(ld->runes->master, rune)) {
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

static struct command_result *json_listrunes(struct command *cmd,
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
		bool in_db = (wallet_get_rune(tmpctx, cmd->ld->wallet, uid) != NULL);
		json_add_rune(cmd->ld, response, NULL, ras->runestr, ras->rune, in_db);
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

static const struct json_command listrunes_command = {
	"listrunes",
	"utility",
	json_listrunes,
	"List a rune or list/decode an optional {rune}."
};
AUTODATA(json_command, &listrunes_command);

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
