/* Dealing with reserving UTXOs */
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>
#include <wallet/walletrpc.h>

static bool was_reserved(enum output_status oldstatus,
			 const u32 *reserved_til,
			 u32 current_height)
{
	if (oldstatus != output_state_reserved)
		return false;

	return *reserved_til > current_height;
}

static void json_add_reservestatus(struct json_stream *response,
				   const struct utxo *utxo,
				   enum output_status oldstatus,
				   u32 old_res,
				   u32 current_height)
{
	json_object_start(response, NULL);
	json_add_txid(response, "txid", &utxo->txid);
	json_add_u32(response, "vout", utxo->outnum);
	json_add_bool(response, "was_reserved",
		      was_reserved(oldstatus, &old_res, current_height));
	json_add_bool(response, "reserved",
		      is_reserved(utxo, current_height));
	if (utxo->reserved_til)
		json_add_u32(response, "reserved_to_block",
			     *utxo->reserved_til);
	json_object_end(response);
}

static struct command_result *json_reserveinputs(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;
	struct utxo **utxos = tal_arr(cmd, struct utxo *, 0);
	bool *exclusive;
	u32 current_height;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   p_opt_def("exclusive", param_bool, &exclusive, true),
		   NULL))
		return command_param_failed();

	current_height = get_block_height(cmd->ld->topology);
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo)
			continue;
		if (*exclusive && is_reserved(utxo, current_height)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already reserved",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		}
		if (utxo->status == output_state_spent)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s:%u already spent",
					    type_to_string(tmpctx,
							   struct bitcoin_txid,
							   &utxo->txid),
					    utxo->outnum);
		tal_arr_expand(&utxos, utxo);
	}

	response = json_stream_success(cmd);
	json_array_start(response, "reservations");
	for (size_t i = 0; i < tal_count(utxos); i++) {
		enum output_status oldstatus;
		u32 old_res;

		oldstatus = utxos[i]->status;
		old_res = utxos[i]->reserved_til ? *utxos[i]->reserved_til : 0;

		if (!wallet_reserve_utxo(cmd->ld->wallet,
					 utxos[i],
					 current_height)) {
			fatal("Unable to reserve %s:%u!",
			      type_to_string(tmpctx,
					     struct bitcoin_txid,
					     &utxos[i]->txid),
			      utxos[i]->outnum);
		}
		json_add_reservestatus(response, utxos[i], oldstatus, old_res,
				       current_height);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command reserveinputs_command = {
	"reserveinputs",
	"bitcoin",
	json_reserveinputs,
	"Reserve utxos (or increase their reservation)",
	false
};
AUTODATA(json_command, &reserveinputs_command);

static struct command_result *json_unreserveinputs(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct json_stream *response;
	struct wally_psbt *psbt;

	if (!param(cmd, buffer, params,
		   p_req("psbt", param_psbt, &psbt),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_array_start(response, "reservations");
	for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
		struct bitcoin_txid txid;
		struct utxo *utxo;
		enum output_status oldstatus;
		u32 old_res;

		wally_tx_input_get_txid(&psbt->tx->inputs[i], &txid);
		utxo = wallet_utxo_get(cmd, cmd->ld->wallet,
				       &txid, psbt->tx->inputs[i].index);
		if (!utxo || utxo->status != output_state_reserved)
			continue;

		oldstatus = utxo->status;
		old_res = *utxo->reserved_til;

		wallet_unreserve_utxo(cmd->ld->wallet,
				      utxo,
				      get_block_height(cmd->ld->topology));

		json_add_reservestatus(response, utxo, oldstatus, old_res,
				       get_block_height(cmd->ld->topology));
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command unreserveinputs_command = {
	"unreserveinputs",
	"bitcoin",
	json_unreserveinputs,
	"Unreserve utxos (or at least, reduce their reservation)",
	false
};
AUTODATA(json_command, &unreserveinputs_command);
