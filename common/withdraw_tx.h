#ifndef LIGHTNING_COMMON_WITHDRAW_TX_H
#define LIGHTNING_COMMON_WITHDRAW_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

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
 * @utxos: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @destination: (in) tal_arr of u8, scriptPubKey to send to.
 * @amount: (in) satoshis to send to the destination
 * @changekey: (in) key to send change to (only used if change_satoshis != 0).
 * @changesat: (in) amount to send as change.
 * @bip32_base: (in) bip32 base for key derivation, or NULL.
 */
struct bitcoin_tx *withdraw_tx(const tal_t *ctx,
			       const struct utxo **utxos,
			       u8 *destination,
			       const u64 withdraw_amount,
			       const struct pubkey *changekey,
			       const u64 changesat,
			       const struct ext_key *bip32_base);

#endif /* LIGHTNING_COMMON_WITHDRAW_TX_H */
