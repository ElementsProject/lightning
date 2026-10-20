#ifndef LIGHTNING_COMMON_CHANNEL_CONFIG_H
#define LIGHTNING_COMMON_CHANNEL_CONFIG_H
#include "config.h"
#include <common/amount.h>

/* BOLT #2:
 *
 * 1. type: 32 (`open_channel`)
 * 2. data:
 *    * [`chain_hash`:`chain_hash`]
 *    * [`32*byte`:`temporary_channel_id`]
 *    * [`u64`:`funding_satoshis`]
 *    * [`u64`:`push_msat`]
 *    * [`u64`:`dust_limit_satoshis`]
 *    * [`u64`:`max_htlc_value_in_flight_msat`]
 *    * [`u64`:`channel_reserve_satoshis`]
 *    * [`u64`:`htlc_minimum_msat`]
 *    * [`u32`:`feerate_per_kw`]
 *    * [`u16`:`to_self_delay`]
 *    * [`u16`:`max_accepted_htlcs`]
 */
/* BOLT #2:
 *
 * 1. type: 33 (`accept_channel`)
 * 2. data:
 *    * [`32*byte`:`temporary_channel_id`]
 *    * [`u64`:`dust_limit_satoshis`]
 *    * [`u64`:`max_htlc_value_in_flight_msat`]
 *    * [`u64`:`channel_reserve_satoshis`]
 *    * [`u64`:`htlc_minimum_msat`]
 *    * [`u32`:`minimum_depth`]
 *    * [`u16`:`to_self_delay`]
 *    * [`u16`:`max_accepted_htlcs`]
 */
struct channel_config {
	/* Database ID */
	u64 id;
	/* BOLT #2:
	 *
	 * `dust_limit_satoshis` is the threshold below which outputs should
	 * not be generated for this node's commitment or HTLC transaction */
	struct amount_sat dust_limit;

	/* BOLT #2:
	 *
	 * `max_htlc_value_in_flight_msat` is a cap on total value of
	 * outstanding HTLCs offered by the remote node, which allows the
	 * local node to limit its exposure to HTLCs */
	struct amount_msat max_htlc_value_in_flight;

	/* BOLT #2:
	 *
	 * `channel_reserve_satoshis` is the minimum amount that the other
	 * node is to keep as a direct payment. */
	struct amount_sat channel_reserve;

	/* BOLT #2:
	 *
	 * `htlc_minimum_msat` indicates the smallest value HTLC this node
	 * will accept.
	 */
	struct amount_msat htlc_minimum;

	/* BOLT #2:
	 *
	 * `to_self_delay` is the number of blocks that the other node's
	 * to-self outputs must be delayed, using `OP_CHECKSEQUENCEVERIFY`
	 * delays */
	u16 to_self_delay;

	/* BOLT #2:
	 *
	 * similarly, `max_accepted_htlcs` limits the number of outstanding
	 * HTLCs the remote node can offer. */
	u16 max_accepted_htlcs;

	/* BOLT-TBD #X
	 *
	 * maximum dust exposure allowed for this channel
	 */
	struct amount_msat max_dust_htlc_exposure_msat;
};

/* Bounds on the peer's dust_limit_satoshis, checked at negotiation.
 * max_dust_htlc_exposure_msat above caps trimmed HTLCs; this caps the
 * dust limit itself, so our balance output can't be trimmed too. */

/* BOLT #3:
 *
 * Bitcoin Core defines the following dust thresholds:
 *
 * - pay to pubkey hash (p2pkh): 546 satoshis
 * - pay to script hash (p2sh): 540 satoshis
 * - pay to witness pubkey hash (p2wpkh): 294 satoshis
 * - pay to witness script hash (p2wsh): 330 satoshis
 * - pay to anchor (p2a): 240 satoshis
 * - unknown segwit versions: 354 satoshis
 * - `OP_RETURN` outputs: these are never dust
 */
#define MIN_REMOTE_DUST_LIMIT AMOUNT_SAT(354)

#define MAX_REMOTE_DUST_LIMIT AMOUNT_SAT(5000)

void towire_channel_config(u8 **pptr, const struct channel_config *config);
void fromwire_channel_config(const u8 **ptr, size_t *max,
			     struct channel_config *config);
#endif /* LIGHTNING_COMMON_CHANNEL_CONFIG_H */
