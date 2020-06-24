#ifndef LIGHTNING_COMMON_WITHDRAW_TX_H
#define LIGHTNING_COMMON_WITHDRAW_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>

struct bitcoin_tx;
struct ext_key;
struct privkey;
struct pubkey;
struct bitcoin_address;
struct utxo;

/**
 * withdraw_tx - Create a p2pkh withdrawal transaction
 *
 * @ctx: context to tal from.
 * @chainparams: (in) the params for the created transaction.
 * @allow_rbf: (in) bool to signal whether to flag the sequence as RBF'able
 * @utxos: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @outputs: (in) tal_arr of bitcoin_tx_output, scriptPubKeys with amount to send to.
 * @bip32_base: (in) bip32 base for key derivation, or NULL.
 * @nlocktime: (in) the value to set as the transaction's nLockTime.
 */
struct bitcoin_tx *withdraw_tx(const tal_t *ctx,
			       const struct chainparams *chainparams,
			       bool allow_rbf,
			       const struct utxo **utxos,
			       struct bitcoin_tx_output **outputs,
			       const struct ext_key *bip32_base,
			       u32 nlocktime);

#endif /* LIGHTNING_COMMON_WITHDRAW_TX_H */
