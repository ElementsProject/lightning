#ifndef LIGHTNING_COMMON_FUNDING_TX_H
#define LIGHTNING_COMMON_FUNDING_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <wire/gen_peer_wire.h>

struct bitcoin_tx;
struct ext_key;
struct privkey;
struct pubkey;
struct utxo;

/**
 * funding_tx: create a P2WSH funding transaction for a channel.
 * @ctx: context to tal from.
 * @chainparams: (in) the params for the resulting transaction.
 * @outnum: (out) txout (0 or 1) which is the funding output.
 * @utxomap: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @funding: (in) satoshis to output.
 * @local_fundingkey: (in) local key for 2of2 funding output.
 * @remote_fundingkey: (in) remote key for 2of2 funding output.
 * @change: (in) amount to send as change.
 * @changekey: (in) key to send change to (only used if change_satoshis != 0).
 * @bip32_base: (in) bip32 base for key derivation, or NULL.
 *
 * If bip32_base is supplied, scriptSig will be added for p2sh inputs: this
 * means our signing code will fail, but txid will be correct.  If NULL,
 * the txid will be incorrect, by signing will succeed.
 *
 * This is done because all other txs have no scriptSig (being pure Segwit)
 * so our signature code simply asserts there's no scriptsig (which would
 * have to be removed for signing anyway).  The funding transaction is
 * a special case because of the P2SH inputs.
 */
struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      struct amount_sat funding,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      struct amount_sat change,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base);

#if EXPERIMENTAL_FEATURES
/**
 * funding_tx: create a P2WSH funding transaction for a channel.
 * @ctx: context to tal from.
 * @chainparams: (in) the params for the resulting transaction.
 * @outnum: (out) txout which is the funding output.
 * @feerate_kw_funding: (in) feerate for the funding transaction
 * @opener_funding: (in/out) funding amount contributed by opener
 * @accepter_funding: (in) funding amount contributed by accepter
 * @opener_inputs: (in) inputs from the opener
 * @accepter_inputs: (in) inputs from the accepter
 * @opener_outputs: (in) outputs for the opener
 * @accepter_outputs: (in) outputs for the accepter
 * @local_fundingkey: (in) local key for 2of2 funding output.
 * @remote_fundingkey: (in) remote key for 2of2 funding output.
 * @total_funding: (out) total funding amount for this transaction
 * @opener_change: (out) change amount for opener
 * @input_map: (out) ordering of inputs, after being sorted.
 */
struct bitcoin_tx *dual_funding_funding_tx(const tal_t *ctx,
	                                   const struct chainparams *chainparams,
				           u16 *outnum,
					   u32 feerate_kw_funding,
				           struct amount_sat *opener_funding,
					   struct amount_sat accepter_funding,
				           struct input_info **opener_inputs,
				           struct input_info **accepter_inputs,
					   struct output_info **opener_outputs,
					   struct output_info **accepter_outputs,
				           const struct pubkey *local_fundingkey,
				           const struct pubkey *remote_fundingkey,
					   struct amount_sat *total_funding,
					   struct amount_sat *opener_change,
					   const void **input_map);
#endif /* EXPERIMENTAL_FEATURES */
#endif /* LIGHTNING_COMMON_FUNDING_TX_H */
