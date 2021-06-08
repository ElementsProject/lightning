#include "config.h"
#include <ccan/ccan/mem/mem.h>
#include <common/amount.h>
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

bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates,
					struct amount_msat amt)
{
	rates->channel_fee_max_base_msat = amt.millisatoshis; /* Raw: conversion */
	return rates->channel_fee_max_base_msat == amt.millisatoshis; /* Raw: comparsion */
}

bool lease_rates_set_lease_fee_sat(struct lease_rates *rates,
				   struct amount_sat amt)
{
	rates->lease_fee_base_sat = amt.satoshis; /* Raw: conversion */
	return rates->lease_fee_base_sat == amt.satoshis; /* Raw: comparsion */
}
