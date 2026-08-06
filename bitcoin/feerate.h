#ifndef LIGHTNING_BITCOIN_FEERATE_H
#define LIGHTNING_BITCOIN_FEERATE_H
#include "config.h"
#include <ccan/build_assert/build_assert.h>
#include <common/amount.h>

/* bitcoind considers 250 satoshi per kw to be the minimum acceptable fee:
 * less than this won't even relay.
 */
#define BITCOIND_MINRELAYTXFEE_PER_KW 250
/*
 * But bitcoind uses vbytes (ie. (weight + 3) / 4) for this
 * calculation, rather than weight, meaning we can disagree since we do
 * it sanely (as specified in BOLT #3).
 */
#define FEERATE_BITCOIND_SEES(feerate, weight) \
	(((feerate) * (weight)) / 1000 * 1000 / ((weight) + 3))
/* ie. fee = (feerate * weight) // 1000
 * bitcoind needs (worst-case): fee * 1000 / (weight + 3) >= 250
 *
 * (feerate * weight) // 1000 * 1000 // (weight + 3) >= 250
 *
 * The feerate needs to be higher for lower weight, and our minimum tx weight
 * is 464 (version (4) + count_tx_in (1) + tx_in (32 + 4 + 1 + 4) +
 * count_tx_out (1) + amount (8) + P2WSH (1 + 1 + 32) + witness 1 + 1 + <sig>
 * + 1 + <key>).  Assume it's 400 to give a significant safety margin (it
 * only makes 1 difference in the result anyway).
 */
#define MINIMUM_TX_WEIGHT 400

/*
 * This formula is satisfied by a feerate of 253 (hand-search).
 */
#define FEERATE_FLOOR 253

/*
 * Sanity ceiling on any feerate estimate entering lightningd (sat/kw).
 * This is a sanity bound rather than a policy limit: an estimate above it
 * means a broken fee source rather than an expensive mempool, so it sits
 * far above anything the real chain has ever seen (4000 sat/vB, several
 * times the historical peak).  Clamping on the way in keeps every
 * downstream feerate calculation working on a plausible number.
 */
#define FEERATE_CEILING 1000000

/*
 * The most we are ever willing to pay ourselves (sat/kw).
 *
 * Unlike FEERATE_CEILING this *is* a policy limit, and the two are
 * deliberately an order of magnitude apart because they answer different
 * questions.  FEERATE_CEILING bounds what we let a peer drive us to: their
 * estimator being broken is not by itself worth dropping a channel over, so
 * it only has to exclude the absurd.  This one bounds what we propose with
 * our own money, where we can simply decline: 400 sat/vB is around 0.011 BTC
 * for a bare anchor commitment, which we would rather not spend by accident.
 */
#define MAX_OUR_FEERATE_PER_KW 100000

enum feerate_style {
	FEERATE_PER_KSIPA,
	FEERATE_PER_KBYTE
};

static inline u32 feerate_floor_check(void)
{
	/* Assert that bitcoind will see this as above minRelayTxFee */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR, MINIMUM_TX_WEIGHT)
		     >= BITCOIND_MINRELAYTXFEE_PER_KW);
	/* And a lesser value won't do */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR-1, MINIMUM_TX_WEIGHT)
		     < BITCOIND_MINRELAYTXFEE_PER_KW);
	/* And I'm right about it being OK for larger txs, too */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR, (MINIMUM_TX_WEIGHT*2))
		     >= BITCOIND_MINRELAYTXFEE_PER_KW);

	return FEERATE_FLOOR;
}

u32 feerate_from_style(u32 feerate, enum feerate_style style);
u32 feerate_to_style(u32 feerate_perkw, enum feerate_style style);
const char *feerate_style_name(enum feerate_style style);

#endif /* LIGHTNING_BITCOIN_FEERATE_H */
