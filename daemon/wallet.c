/* Poor man's wallet.
 *  Needed because bitcoind doesn't (yet) produce segwit outputs, and we need
 *  such outputs for our anchor tx to make it immalleable.
 */
#include "bitcoin/base58.h"
#include "bitcoin/privkey.h"
#include "bitcoin/script.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "db.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "wallet.h"
#include <ccan/structeq/structeq.h>
#include <sodium/randombytes.h>

struct wallet {
	struct list_node list;
	struct privkey privkey;
	struct pubkey pubkey;
	struct ripemd160 p2sh;
};

bool restore_wallet_address(struct lightningd_state *dstate,
			    const struct privkey *privkey)
{
	struct wallet *w = tal(dstate, struct wallet);
	u8 *redeemscript;
	struct sha256 h;

	w->privkey = *privkey;
	if (!pubkey_from_privkey(&w->privkey, &w->pubkey))
		return false;

	redeemscript = bitcoin_redeem_p2wpkh(w, &w->pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&w->p2sh, h.u.u8, sizeof(h));

	list_add_tail(&dstate->wallet, &w->list);
	tal_free(redeemscript);
	return true;
}

static void new_keypair(struct privkey *privkey, struct pubkey *pubkey)
{
	do {
		randombytes_buf(privkey->secret, sizeof(privkey->secret));
	} while (!pubkey_from_privkey(privkey, pubkey));
}

static struct wallet *find_by_pubkey(struct lightningd_state *dstate,
				     const struct pubkey *walletkey)
{
	struct wallet *w;

	list_for_each(&dstate->wallet, w, list) {
		if (pubkey_eq(walletkey, &w->pubkey))
			return w;
	}
	return NULL;
}

bool wallet_add_signed_input(struct lightningd_state *dstate,
			     const struct pubkey *walletkey,
			     struct bitcoin_tx *tx,
			     unsigned int input_num)
{
	u8 *redeemscript;
	secp256k1_ecdsa_signature sig;
	struct wallet *w = find_by_pubkey(dstate, walletkey);

	assert(input_num < tal_count(tx->input));
	if (!w)
		return false;

	redeemscript = bitcoin_redeem_p2wpkh(tx, &w->pubkey);

	sign_tx_input(tx, input_num,
		      redeemscript,
		      p2wpkh_scriptcode(redeemscript, &w->pubkey),
		      &w->privkey,
		      &w->pubkey,
		      &sig);

	bitcoin_witness_p2sh_p2wpkh(tx->input,
				    &tx->input[input_num],
				    &sig,
				    &w->pubkey);
	tal_free(redeemscript);
	return true;
}

bool wallet_can_spend(struct lightningd_state *dstate,
		      const struct bitcoin_tx_output *output,
		      struct pubkey *walletkey)
{
	struct ripemd160 h;
	struct wallet *w;

	if (!is_p2sh(output->script))
		return NULL;

	memcpy(&h, output->script + 2, 20);
	list_for_each(&dstate->wallet, w, list) {
		if (structeq(&h, &w->p2sh)) {
			*walletkey = w->pubkey;
			return true;
		}
	}
	return false;
}

static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct wallet *w = tal(cmd->dstate, struct wallet);
	u8 *redeemscript;
	struct sha256 h;

	new_keypair(&w->privkey, &w->pubkey);
	redeemscript = bitcoin_redeem_p2wpkh(cmd, &w->pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&w->p2sh, h.u.u8, sizeof(h));

	list_add_tail(&cmd->dstate->wallet, &w->list);
	db_add_wallet_privkey(cmd->dstate, &w->privkey);

	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, cmd->dstate->testnet, &w->p2sh));
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
