#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <common/billboard.h>
#include <common/utils.h>

char *billboard_message(const tal_t *ctx,
			const bool channel_ready[NUM_SIDES],
			const bool have_sigs[NUM_SIDES],
			const bool shutdown_sent[NUM_SIDES],
			u32 depth_togo,
			size_t num_htlcs)
{
	const char *funding_status, *announce_status,
		*shutdown_status COMPILER_WANTS_INIT("gcc 8.3.0");

	if (channel_ready[LOCAL] && channel_ready[REMOTE])
		funding_status = "Channel ready for use.";
	else if (!channel_ready[LOCAL] && !channel_ready[REMOTE])
		funding_status = tal_fmt(ctx,
					"Funding needs %d more"
					" confirmations to be ready.",
					depth_togo);
	else if (channel_ready[LOCAL] && !channel_ready[REMOTE])
		funding_status = "We've confirmed channel ready, they haven't yet.";
	else {
		assert(!channel_ready[LOCAL] && channel_ready[REMOTE]);
		funding_status = "They've confirmed channel ready, we haven't yet.";
	}

	if (have_sigs) {
		if (have_sigs[LOCAL] && have_sigs[REMOTE])
			announce_status = " Channel announced.";
		else if (have_sigs[LOCAL] && !have_sigs[REMOTE])
			announce_status = " Waiting for their"
					  " announcement signatures.";
		else if (!have_sigs[LOCAL] && have_sigs[REMOTE])
			announce_status = " They need our announcement"
					  " signatures.";
		else {
			assert(!have_sigs[LOCAL] && !have_sigs[REMOTE]);
			announce_status = "";
		}
	} else
		announce_status = "";

	if (!shutdown_sent[LOCAL] && !shutdown_sent[REMOTE])
		shutdown_status = "";
	else if (!shutdown_sent[LOCAL] && shutdown_sent[REMOTE])
		shutdown_status = " They've sent shutdown, waiting for ours";
	else if (shutdown_sent[LOCAL] && !shutdown_sent[REMOTE])
		shutdown_status = " We've send shutdown, waiting for theirs";
	else if (shutdown_sent[LOCAL] && shutdown_sent[REMOTE]) {
		if (num_htlcs)
			shutdown_status = tal_fmt(ctx,
						  " Shutdown messages"
						  " exchanged, waiting for"
						  " %zu HTLCs to complete.",
						  num_htlcs);
		else
			shutdown_status = tal_fmt(ctx,
						  " Shutdown messages"
						  " exchanged.");
	}

	return tal_fmt(ctx, "%s%s%s", funding_status,
		       announce_status, shutdown_status);
}
