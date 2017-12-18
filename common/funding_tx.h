#ifndef LIGHTNING_COMMON_FUNDING_TX_H
#define LIGHTNING_COMMON_FUNDING_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_tx;
struct ext_key;
struct privkey;
struct pubkey;
struct utxo;

/**
 * funding_tx: create a P2WSH funding transaction for a channel.
 * @ctx: context to tal from.
 * @outnum: (out) txout (0 or 1) which is the funding output.
 * @utxomap: (in/out) tal_arr of UTXO pointers to spend (permuted to match)
 * @funding_satoshis: (in) satoshis to output.
 * @local_fundingkey: (in) local key for 2of2 funding output.
 * @remote_fundingkey: (in) remote key for 2of2 funding output.
 * @change_satoshis: (in) amount to send as change.
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
			      u16 *outnum,
			      const struct utxo **utxomap,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      u64 change_satoshis,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base);
#endif /* LIGHTNING_COMMON_FUNDING_TX_H */
