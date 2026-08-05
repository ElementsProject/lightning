#ifndef LIGHTNING_COMMON_SPLICE_SCRIPT_H
#define LIGHTNING_COMMON_SPLICE_SCRIPT_H

#include "config.h"
#include <common/channel_id.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/splice_script_errors.h>

struct splice_script_error {
	enum splice_script_error_type type;
	size_t script_index; /* where in `script` was error found */
	char *message;
	const char *phase;
};

/* Outputs a multiline helpful compiler error for the user. */
char *fmt_splice_script_compiler_error(const tal_t *ctx,
				       const char *script,
				       struct splice_script_error *error);

/* You are responsible for filling this in for every channel the
 * node has. If you would like a peer that has no channels to be queryable by
 * the script, include it here with a NULL channel. */
struct splice_script_chan {
	struct node_id node_id;
	struct channel_id *chan_id;
};

/* If the script parses successfully, you will receive an array of these */
struct splice_script_result {
	/* Lease request info */
	struct amount_sat lease_sat;
	u32 lease_max_ppm;

	/* Funds going in to destination (just one) */
	struct amount_sat in_sat;
	u32 in_ppm;

	/* Destination (just one) */
	struct channel_id *channel_id;
	struct node_id *peer_id; /* Open new channel if set */
	char *bitcoin_address;
	bool onchain_wallet;

	/* Funds coming out of destination (just one) */
	struct amount_sat out_sat;
	u32 out_ppm; /* UINT32_MAX means "max available from channel" */

	/* If set, this `in_sat` and `out_sat` wont be set. Instead at the point
	 * our channel's funds are known (after `stfu`). At this point `in_sat`
	 * and `out_sat` must be set so that the resulting channel balance is
	 * `balance_ppm`.
	 * in_sat = max(0, balance_ppm * chan_size - sats_owed)
	 * out_sat = max(0, (1000000 - balance_ppm) * chan_size - sats_owed) */
	u32 balance_ppm;

	/* Open new channel parameters */
	u32 commit_feerate_per_kw;
	bool private_channel;
	char *close_to_address;

	/* If true, this 'destination' pays the fee. Only one destination may
	 * do so. If feerate_per_kw is non-zero, it will be used for feerate. */
	bool pays_fee;
	u32 feerate_per_kw;
};

/* Parses `script` taking `channels` into account. The result is returned into
 * `result` or an error is returned. */
struct splice_script_error *parse_splice_script(const tal_t *ctx,
						const char *script,
						struct splice_script_chan **channels,
						struct splice_script_result ***result);

void splice_to_json(const tal_t *ctx,
		    struct splice_script_result **splice,
		    struct json_stream *js);

bool json_to_splice(const tal_t *ctx, const char *buffer, const jsmntok_t *tok,
		    struct splice_script_result ***result);

/* Convenience methods for printing out compiled scripts */
char *splice_to_string(const tal_t *ctx, struct splice_script_result *splice);
char *splicearr_to_string(const tal_t *ctx, struct splice_script_result **splice);

#endif /* LIGHTNING_COMMON_SPLICE_SCRIPT_H */
