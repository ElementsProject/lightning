#ifndef LIGHTNING_COMMON_SPLICE_SCRIPT_H
#define LIGHTNING_COMMON_SPLICE_SCRIPT_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <common/channel_id.h>
#include <common/json_stream.h>
#include <common/node_id.h>

enum splice_script_error_type {
	INTERNAL_ERROR,
	INVALID_TOKEN,
	DEBUG_DUMP,
	TOO_MANY_PIPES,
	TOO_MANY_ATS,
	TOO_MANY_COLONS,
	TOO_MANY_PLUS,
	TOO_MANY_MINUS,
	INVALID_NODEID,
	INVALID_CHANID,
	WRONG_NUM_SEGMENT_CHUNKS,
	MISSING_ARROW,
	NO_MATCHING_NODES,
	INVALID_INDEX,
	CHAN_INDEX_ON_WILDCARD_NODE,
	CHAN_INDEX_NOT_FOUND,
	CHANQUERY_TYPEERROR,
	NODE_ID_MULTIMATCH,
	NODE_ID_CHAN_OVERMATCH,
	CHAN_ID_MULTIMATCH,
	CHAN_ID_NODE_OVERMATCH,
	NODE_ID_NO_UNUSED,
	DOUBLE_MIDDLE_OP,
	MISSING_MIDDLE_OP,
	MISSING_AMOUNT_OP,
	MISSING_AMOUNT_OR_WILD_OP,
	CANNOT_PARSE_SAT_AMNT,
	ZERO_AMOUNTS,
	IN_AND_OUT_AMOUNTS,
	MISSING_PERCENT,
	LEASE_AMOUNT_ZERO,
	CHANNEL_ID_UNRECOGNIZED,
	DUPLICATE_CHANID,
	INVALID_MIDDLE_OP,
	INSUFFICENT_FUNDS,
	PERCENT_IS_ZERO,
	WILDCARD_IS_ZERO,
	INVALID_PERCENT,
	LEFT_PERCENT_OVER_100,
	LEFT_FEE_NOT_NEGATIVE,
	RIGHT_FEE_NOT_POSITIVE,
	MISSING_FEESTR,
	DUPLICATE_FEESTR,
	TOO_MUCH_DECIMAL,
	INVALID_FEERATE,
};

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

struct splice_script_chan {
	struct node_id node_id;
	struct channel_id chan_id;
};

struct splice_script_result {
	/* Lease request info */
	struct amount_sat lease_sat;
	u32 lease_max_ppm;

	/* Funds going in to destination (just one) */
	struct amount_sat in_sat;
	u32 in_ppm;

	/* Destination (just one) */
	struct channel_id *channel_id;
	char *bitcoin_address;
	bool onchain_wallet;

	/* Funds coming out of destination (just one) */
	struct amount_sat out_sat;
	u32 out_ppm; /* UINT32_MAX means "max available from channel" */

	/* If true, this 'destination' pays the fee. Only one destination may
	 * do so. If feerate_per_kw is non-zero, it will be used for feerate. */
	bool pays_fee;
	u32 feerate_per_kw;
};

struct splice_script_error *parse_splice_script(const tal_t *ctx,
						const char *script,
						struct splice_script_chan **channels,
						struct splice_script_result ***result);

void splice_to_json(const tal_t *ctx,
		    struct splice_script_result **splice,
		    struct json_stream *js);

bool json_to_splice(const tal_t *ctx, const char *buffer, const jsmntok_t *tok,
		    struct splice_script_result ***result);

char *splice_to_string(const tal_t *ctx, struct splice_script_result *splice);
char *splicearr_to_string(const tal_t *ctx, struct splice_script_result **splice);

#endif /* LIGHTNING_COMMON_SPLICE_SCRIPT_H */
