#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
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
