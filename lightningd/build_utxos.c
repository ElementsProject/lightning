#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/structeq/structeq.h>
#include <daemon/jsonrpc.h>
#include <lightningd/build_utxos.h>
#include <lightningd/lightningd.h>
#include <utils.h>
#include <wally_bip32.h>

struct tracked_utxo {
	struct list_node list;

	/* Currently being used for a connection. */
	bool reserved;

	struct utxo utxo;
};

static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct ext_key ext;
	struct sha256 h;
	struct ripemd160 p2sh;
	struct pubkey pubkey;
	u8 *redeemscript;

	if (ld->bip32_max_index == BIP32_INITIAL_HARDENED_CHILD) {
		command_fail(cmd, "Keys exhausted ");
		return;
	}

	if (bip32_key_from_parent(ld->bip32_base, ld->bip32_max_index,
				  BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
		command_fail(cmd, "Keys generation failure");
		return;
	}

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey.pubkey,
				       ext.pub_key, sizeof(ext.pub_key))) {
		command_fail(cmd, "Key parsing failure");
		return;
	}

	redeemscript = bitcoin_redeem_p2wpkh(cmd, &pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&p2sh, h.u.u8, sizeof(h));

	ld->bip32_max_index++;

	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, cmd->dstate->testnet, &p2sh));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
	"Get a new address to fund a channel",
	"Returns {address} a p2sh address"
};
AUTODATA(json_command, &newaddr_command);

/* FIXME: This is very slow with lots of inputs! */
static bool can_spend(struct lightningd *ld, const u8 *script,
		      u32 *index, bool *output_is_p2sh)
{
	struct ext_key ext;
	u32 i;

	/* If not one of these, can't be for us. */
	if (is_p2sh(script))
		*output_is_p2sh = true;
	else if (is_p2wpkh(script))
		*output_is_p2sh = false;
	else
		return false;

	for (i = 0; i < ld->bip32_max_index; i++) {
		u8 *s;

		if (bip32_key_from_parent(ld->bip32_base, i,
					  BIP32_FLAG_KEY_PUBLIC, &ext)
		    != WALLY_OK) {
			abort();
		}
		s = scriptpubkey_p2wpkh_derkey(ld, ext.pub_key);
		if (*output_is_p2sh) {
			u8 *p2sh = scriptpubkey_p2sh(ld, s);
			tal_free(s);
			s = p2sh;
		}
		if (scripteq(s, script)) {
			tal_free(s);
			*index = i;
			return true;
		}
		tal_free(s);
	}
	return false;
}

static void json_addfunds(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *txtok;
	struct bitcoin_tx *tx;
	int output;
	size_t txhexlen, num_utxos = 0;
	u64 total_satoshi = 0;

	if (!json_get_params(buffer, params, "tx", &txtok, NULL)) {
		command_fail(cmd, "Need tx sending to address from newaddr");
		return;
	}

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(cmd, buffer + txtok->start, txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	/* Find an output we know how to spend. */
	for (output = 0; output < tal_count(tx->output); output++) {
		struct tracked_utxo *utxo;
		u32 index;
		bool is_p2sh;

		if (!can_spend(ld, tx->output[output].script, &index, &is_p2sh))
			continue;

		utxo = tal(ld, struct tracked_utxo);
		utxo->utxo.keyindex = index;
		utxo->utxo.is_p2sh = is_p2sh;
		utxo->utxo.amount = tx->output[output].amount;
		bitcoin_txid(tx, &utxo->utxo.txid);
		utxo->utxo.outnum = output;
		utxo->reserved = false;
		list_add_tail(&ld->utxos, &utxo->list);
		total_satoshi += utxo->utxo.amount;
		num_utxos++;
	}

	if (!num_utxos) {
		command_fail(cmd, "No usable outputs");
		return;
	}

	json_object_start(response, NULL);
	json_add_num(response, "outputs", num_utxos);
	json_add_u64(response, "satoshis", total_satoshi);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command addfunds_command = {
	"addfunds",
	json_addfunds,
	"Add funds for lightningd to spend to create channels, using {tx}",
	"Returns how many {outputs} it can use and total {satoshis}"
};
AUTODATA(json_command, &addfunds_command);

static void unreserve_utxo(struct lightningd *ld, const struct utxo *unres)
{
	struct tracked_utxo *utxo;

	list_for_each(&ld->utxos, utxo, list) {
		if (unres->outnum != utxo->utxo.outnum
		    || !structeq(&unres->txid, &utxo->utxo.txid))
			continue;
		assert(utxo->reserved);
		assert(unres->amount == utxo->utxo.amount);
		assert(unres->keyindex == utxo->utxo.keyindex);
		assert(unres->is_p2sh == utxo->utxo.is_p2sh);
		utxo->reserved = false;
		return;
	}
	abort();
}

struct utxo *build_utxos(const tal_t *ctx,
			 struct lightningd *ld, u64 satoshi_out,
			 u32 feerate_per_kw, u64 dust_limit,
			 u64 *change_amount, u32 *change_keyindex)
{
	size_t i = 0;
	struct utxo *utxos = tal_arr(ctx, struct utxo, 0);
	struct tracked_utxo *utxo;
	/* We assume two outputs for the weight. */
	u64 satoshi_in = 0, weight = (4 + (8 + 22) * 2 + 4) * 4;

	list_for_each(&ld->utxos, utxo, list) {
		u64 fee;

		if (utxo->reserved)
			continue;

		tal_resize(&utxos, i+1);
		utxos[i] = utxo->utxo;
		utxo->reserved = true;

		/* Add this input's weight. */
		weight += (32 + 4 + 4) * 4;
		if (utxos[i].is_p2sh)
			weight += 22 * 4;

		satoshi_in += utxos[i].amount;

		fee = weight * feerate_per_kw / 1000;
		if (satoshi_in >= fee + satoshi_out) {
			/* We simply eliminate change if it's dust. */
			*change_amount = satoshi_in - (fee + satoshi_out);
			if (*change_amount < dust_limit)
				*change_amount = 0;
			else
				*change_keyindex = ld->bip32_max_index++;

			return utxos;
		}
		i++;
	}

	/* Failed, unmark them all. */
	for (i = 0; i < tal_count(utxos); i++)
		unreserve_utxo(ld, &utxos[i]);

	return tal_free(utxos);
}
