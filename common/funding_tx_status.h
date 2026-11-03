#ifndef LIGHTNING_COMMON_FUNDING_TX_STATUS_H
#define LIGHTNING_COMMON_FUNDING_TX_STATUS_H
#include "config.h"

/* This is a DB ENUM!!!, please do not change the numbering of any
 * already defined elements (adding is ok) */
enum funding_tx_status {
	/* Never observed broadcast (or observed, but not yet accepted
	 * into our bitcoind's mempool) */
	FUNDING_TX_STATUS_UNKNOWN = 0,
	/* Our bitcoind accepted it into its mempool */
	FUNDING_TX_STATUS_MEMPOOL = 1,
	/* Seen in a scanned block */
	FUNDING_TX_STATUS_CONFIRMED = 2,
};

#endif /* LIGHTNING_COMMON_FUNDING_TX_STATUS_H */
