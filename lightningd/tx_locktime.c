#include <common/pseudorand.h>
#include <lightningd/tx_locktime.h>

/* Cribbed from bitcoind's wallet.cpp GetLocktimeForNewTransaction */
u32 locktime_for_new_tx(struct chain_topology *topology)
{
	u32 locktime;

	if (!topology_synced(topology))
		return 0;

	locktime = topology->tip->height;

        /* Occasionally randomly pick a locktime even further back, so
         * that transactions that are delayed after signing for whatever reason,
         * e.g. high-latency mix networks and some CoinJoin implementations, have
         * better privacy. */
	if (pseudorand(10) == 0) {
		locktime = locktime - pseudorand(100);
		if (locktime < 0)
			locktime = 0;
	}

	assert(locktime <= topology->tip->height);
	assert(locktime < LOCKTIME_THRESHOLD);
	return locktime;
}
