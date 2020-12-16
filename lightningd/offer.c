#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>
#include <wire/wire_sync.h>

static void json_populate_offer(struct json_stream *response,
				const struct sha256 *offer_id,
				const char *b12,
				const struct json_escape *label,
				enum offer_status status)
{
	json_add_sha256(response, "offer_id", offer_id);
	json_add_bool(response, "active", offer_status_active(status));
	json_add_bool(response, "single_use", offer_status_single(status));
	json_add_string(response, "bolt12", b12);
	json_add_bool(response, "used", status == OFFER_USED);
	if (label)
		json_add_escaped_string(response, "label", label);
}

static struct command_result *param_b12_offer(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct tlv_offer **offer)
{
	char *fail;
	*offer = offer_decode_nosig(cmd, buffer + tok->start,
				    tok->end - tok->start,
				    cmd->ld->our_features, chainparams, &fail);
	if (!*offer)
		return command_fail_badparam(cmd, name, buffer, tok, fail);
	if ((*offer)->signature)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must be unsigned offer");
	return NULL;
}

static void hsm_sign_b12_offer(struct lightningd *ld,
			       const struct sha256 *merkle,
			       struct bip340sig *sig)
{
	u8 *msg;

	msg = towire_hsmd_sign_bolt12(NULL, "offer", "signature", merkle, NULL);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
        if (!fromwire_hsmd_sign_bolt12_reply(msg, sig))
		fatal("HSM gave bad sign_offer_reply %s",
		      tal_hex(msg, msg));
}

static struct command_result *json_createoffer(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct json_stream *response;
	struct json_escape *label;
	struct tlv_offer *offer;
	struct sha256 merkle;
	const char *b12str;
	bool *single_use;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_req("bolt12", param_b12_offer, &offer),
		   p_opt("label", param_label, &label),
		   p_opt_def("single_use", param_bool, &single_use, false),
		   NULL))
		return command_param_failed();

	if (*single_use)
		status = OFFER_SINGLE_USE;
	else
		status = OFFER_MULTIPLE_USE;
 	merkle_tlv(offer->fields, &merkle);
	offer->signature = tal(offer, struct bip340sig);
	hsm_sign_b12_offer(cmd->ld, &merkle, offer->signature);
	b12str = offer_encode(cmd, offer);
	if (!wallet_offer_create(cmd->ld->wallet, &merkle, b12str, label,
				 status)) {
		return command_fail(cmd,
				    OFFER_ALREADY_EXISTS,
				    "Duplicate offer");
	}

	response = json_stream_success(cmd);
	json_populate_offer(response, &merkle, b12str, label, status);
	return command_success(cmd, response);
}

static const struct json_command createoffer_command = {
	"createoffer",
	"payment",
	json_createoffer,
	"Create and sign an offer {bolt12} with and optional {label}."
};
AUTODATA(json_command, &createoffer_command);

static struct command_result *json_listoffers(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct sha256 *offer_id;
	struct json_stream *response;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	bool *active_only;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_opt("offer_id", param_sha256, &offer_id),
		   p_opt_def("active_only", param_bool, &active_only, false),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "offers");
	if (offer_id) {
		b12 = wallet_offer_find(tmpctx, wallet, offer_id, &label,
					&status);
		if (b12 && offer_status_active(status) >= *active_only) {
			json_object_start(response, NULL);
			json_populate_offer(response,
					    offer_id, b12, label, status);
			json_object_end(response);
		}
	} else {
		struct db_stmt *stmt;
		struct sha256 id;

		for (stmt = wallet_offer_id_first(cmd->ld->wallet, &id);
		     stmt;
		     stmt = wallet_offer_id_next(cmd->ld->wallet, stmt, &id)) {
			b12 = wallet_offer_find(tmpctx, wallet, &id,
						&label, &status);
			if (offer_status_active(status) >= *active_only) {
				json_object_start(response, NULL);
				json_populate_offer(response,
						    &id, b12, label, status);
				json_object_end(response);
			}
		}
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listoffers_command = {
	"listoffers",
	"payment",
	json_listoffers,
	"If {offer_id} is set, show that."
	" Otherwise, if {showdisabled} is true, list all, otherwise just non-disabled ones."
};
AUTODATA(json_command, &listoffers_command);

static struct command_result *json_disableoffer(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *offer_id;
	struct wallet *wallet = cmd->ld->wallet;
	const char *b12;
	const struct json_escape *label;
	enum offer_status status;

	if (!param(cmd, buffer, params,
		   p_req("offer_id", param_sha256, &offer_id),
		   NULL))
		return command_param_failed();

	b12 = wallet_offer_find(tmpctx, wallet, offer_id, &label, &status);
	if (!b12)
		return command_fail(cmd, LIGHTNINGD, "Unknown offer");

	if (!offer_status_active(status))
		return command_fail(cmd, OFFER_ALREADY_DISABLED,
				    "offer is not active");
	status = wallet_offer_disable(wallet, offer_id, status);

	response = json_stream_success(cmd);
	json_populate_offer(response, offer_id, b12, label, status);
	return command_success(cmd, response);
}

static const struct json_command disableoffer_command = {
	"disableoffer",
	"payment",
	json_disableoffer,
	"Disable offer {offer_id}",
};
AUTODATA(json_command, &disableoffer_command);
