#ifndef LIGHTNING_CHANNELD_INFLIGHT_H
#define LIGHTNING_CHANNELD_INFLIGHT_H

#include "config.h"
#include <bitcoin/tx.h>
#include <common/amount.h>

struct inflight {
	struct bitcoin_outpoint outpoint;
	struct amount_sat amnt;
	struct amount_sat local_funding;
};

#endif /* LIGHTNING_CHANNELD_INFLIGHT_H */
