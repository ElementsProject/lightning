#include "config.h"
#include <ccan/ccan/mem/mem.h>
#include <common/lease_rates.h>
#include <wire/peer_wire.h>

bool lease_rates_empty(struct lease_rates *rates)
{
	if (!rates)
		return true;

	/* FIXME: why can't i do memeqzero? */
	return rates->funding_weight == 0
		&& rates->channel_fee_max_base_msat == 0
		&& rates->channel_fee_max_proportional_thousandths == 0
		&& rates->lease_fee_base_sat == 0
		&& rates->lease_fee_basis == 0;
}
