#ifndef LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H
#define LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H

#include "config.h"
#include <ccan/short_types/short_types.h>

struct amount_msat;
struct bitcoin_txid;

struct onchain_fee {

	/* db_id of account this event belongs to */
	u64 acct_db_id;

	/* Transaction that we're recording fees for */
	struct bitcoin_txid txid;

	/* Total amount of onchain fees we paid for this txid */
	struct amount_msat amount;

	/* What token are fees? */
	char *currency;
};

#endif /* LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H */
