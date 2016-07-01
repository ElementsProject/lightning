/* Poor man's wallet.
 *  Needed because bitcoind doesn't (yet) produce segwit outputs, and we need
 *  such outputs for our anchor tx to make it immalleable.
 */
#include "bitcoin/base58.h"
#include "bitcoin/privkey.h"
#include "bitcoin/script.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "wallet.h"
#include <ccan/structeq/structeq.h>
#include <openssl/rand.h>

struct wallet {
	struct list_node list;
	struct privkey privkey;
	struct pubkey pubkey;
	struct ripemd160 p2sh;
};

static void new_keypair(struct lightningd_state *dstate,
			struct privkey *privkey, struct pubkey *pubkey)
{
	do {
		if (RAND_bytes(privkey->secret, sizeof(privkey->secret)) != 1)
			fatal("Could not get random bytes for privkey");
	} while (!pubkey_from_privkey(dstate->secpctx, privkey, pubkey));
}

void wallet_add_signed_input(struct lightningd_state *dstate,
			     const struct wallet *w,
			     struct bitcoin_tx *tx,
			     unsigned int input_num)
{
	u8 *redeemscript;
	struct bitcoin_signature sig;
	assert(input_num < tx->input_count);

	redeemscript = bitcoin_redeem_p2wpkh(tx, dstate->secpctx, &w->pubkey);

	sig.stype = SIGHASH_ALL;
	sign_tx_input(dstate->secpctx, tx, input_num,
		      redeemscript, tal_count(redeemscript),
		      p2wpkh_scriptcode(redeemscript, dstate->secpctx,
					&w->pubkey),
		      &w->privkey,
		      &w->pubkey,
		      &sig.sig);

	bitcoin_witness_p2sh_p2wpkh(tx->input, dstate->secpctx,
				    &tx->input[input_num],
				    &sig,
				    &w->pubkey);
	tal_free(redeemscript);
}

struct wallet *wallet_can_spend(struct lightningd_state *dstate,
				const struct bitcoin_tx_output *output)
{
	struct ripemd160 h;
	struct wallet *w;

	if (!is_p2sh(output->script, output->script_length))
		return NULL;

	memcpy(&h, output->script + 2, 20);
	list_for_each(&dstate->wallet, w, list) {
		if (structeq(&h, &w->p2sh))
			return w;
	}
	return NULL;
}
	
static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);	
	struct wallet *w = tal(cmd->dstate, struct wallet);
	u8 *redeemscript;
	struct sha256 h;

	new_keypair(cmd->dstate, &w->privkey, &w->pubkey);
	redeemscript = bitcoin_redeem_p2wpkh(cmd, cmd->dstate->secpctx,
					     &w->pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&w->p2sh, h.u.u8, sizeof(h));

	list_add_tail(&cmd->dstate->wallet, &w->list);
	
	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, cmd->dstate->config.testnet,
				       &w->p2sh));
	json_object_end(response);
	command_success(cmd, response);
}

const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
	"Get a new address to fund a channel",
	"Returns {address} a p2sh address"
};
