/* Error enums separated out for easy autogen of names*/
#ifndef LIGHTNING_CHANNELD_FULL_CHANNEL_ERROR_H
#define LIGHTNING_CHANNELD_FULL_CHANNEL_ERROR_H
#include "config.h"

enum channel_add_err {
	/* All OK! */
	CHANNEL_ERR_ADD_OK,
	/* Bad expiry value */
	CHANNEL_ERR_INVALID_EXPIRY,
	/* Not really a failure, if expected: it's an exact duplicate. */
	CHANNEL_ERR_DUPLICATE,
	/* Same ID, but otherwise different. */
	CHANNEL_ERR_DUPLICATE_ID_DIFFERENT,
	/* Would exceed the specified max_htlc_value_in_flight_msat */
	CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED,
	/* Can't afford it */
	CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED,
	/* HTLC is below htlc_minimum_msat */
	CHANNEL_ERR_HTLC_BELOW_MINIMUM,
	/* HTLC would push past max_accepted_htlcs */
	CHANNEL_ERR_TOO_MANY_HTLCS,
	/* HTLC would push dusted-htlcs above max_dust_htlc_exposure_msat */
	CHANNEL_ERR_DUST_FAILURE,
};

enum channel_remove_err {
	/* All OK! */
	CHANNEL_ERR_REMOVE_OK,
	/* No such HTLC. */
	CHANNEL_ERR_NO_SUCH_ID,
	/* Already have fulfilled it */
	CHANNEL_ERR_ALREADY_FULFILLED,
	/* Preimage doesn't hash to value. */
	CHANNEL_ERR_BAD_PREIMAGE,
	/* HTLC is not committed */
	CHANNEL_ERR_HTLC_UNCOMMITTED,
	/* HTLC is not committed and prior revoked on both sides */
	CHANNEL_ERR_HTLC_NOT_IRREVOCABLE
};

#endif /* LIGHTNING_CHANNELD_FULL_CHANNEL_ERROR_H */
