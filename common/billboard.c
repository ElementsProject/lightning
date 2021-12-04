#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <common/billboard.h>
#include <common/utils.h>

char *billboard_message(const tal_t *ctx,
			const bool funding_locked[NUM_SIDES],
			const bool have_sigs[NUM_SIDES],
			const bool shutdown_sent[NUM_SIDES],
			u32 depth_togo,
			size_t num_htlcs)
{
	const char *funding_status, *announce_status,
		*shutdown_status COMPILER_WANTS_INIT("gcc 8.3.0");

	if (funding_locked[LOCAL] && funding_locked[REMOTE])
		funding_status = "Funding transaction locked.";
	else if (!funding_locked[LOCAL] && !funding_locked[REMOTE])
		funding_status = tal_fmt(ctx,
					"Funding needs %d more"
					" confirmations for lockin.",
					depth_togo);
	else if (funding_locked[LOCAL] && !funding_locked[REMOTE])
		funding_status = "We've confirmed funding, they haven't yet.";
	else if (!funding_locked[LOCAL] && funding_locked[REMOTE])
		funding_status = "They've confirmed funding, we haven't yet.";

	if (have_sigs) {
		if (have_sigs[LOCAL] && have_sigs[REMOTE])
			announce_status = " Channel announced.";
		else if (have_sigs[LOCAL] && !have_sigs[REMOTE])
			announce_status = " Waiting for their"
					  " announcement signatures.";
		else if (!have_sigs[LOCAL] && have_sigs[REMOTE])
			announce_status = " They need our announcement"
					  " signatures.";
		else if (!have_sigs[LOCAL] && !have_sigs[REMOTE])
			announce_status = "";
	} else
		announce_status = "";

	if (!shutdown_sent[LOCAL] && !shutdown_sent[REMOTE])
		shutdown_status = "";
	else if (!shutdown_sent[LOCAL] && shutdown_sent[REMOTE])
		shutdown_status = " We've send shutdown, waiting for theirs";
	else if (shutdown_sent[LOCAL] && !shutdown_sent[REMOTE])
		shutdown_status = " They've sent shutdown, waiting for ours";
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
