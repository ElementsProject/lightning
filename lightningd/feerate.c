#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/htlc_tx.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/feerate.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/watchman.h>
#include <math.h>

const char *feerate_name(enum feerate feerate)
{
	switch (feerate) {
	case FEERATE_OPENING: return "opening";
	case FEERATE_MUTUAL_CLOSE: return "mutual_close";
	case FEERATE_UNILATERAL_CLOSE: return "unilateral_close";
	case FEERATE_DELAYED_TO_US: return "delayed_to_us";
	case FEERATE_HTLC_RESOLUTION: return "htlc_resolution";
	case FEERATE_PENALTY: return "penalty";
	case FEERATE_MIN: return "min_acceptable";
	case FEERATE_MAX: return "max_acceptable";
	}
	abort();
}

struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style)
{
	*style = tal(cmd, enum feerate_style);
	if (json_tok_streq(buffer, tok,
			   feerate_style_name(FEERATE_PER_KSIPA))) {
		**style = FEERATE_PER_KSIPA;
		return NULL;
	} else if (json_tok_streq(buffer, tok,
				  feerate_style_name(FEERATE_PER_KBYTE))) {
		**style = FEERATE_PER_KBYTE;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be '%s' or '%s', not '%.*s'",
			    name,
			    feerate_style_name(FEERATE_PER_KSIPA),
			    feerate_style_name(FEERATE_PER_KBYTE),
			    json_tok_full_len(tok), json_tok_full(buffer, tok));
}

/* This can set **feerate to 0, if it's unknown. */
static struct command_result *param_feerate_unchecked(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      u32 **feerate)
{
	*feerate = tal(cmd, u32);

	if (json_tok_streq(buffer, tok, "opening")) {
		**feerate = opening_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "mutual_close")) {
		**feerate = mutual_close_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "penalty")) {
		**feerate = penalty_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_close")) {
		**feerate = unilateral_feerate(cmd->ld, false);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_anchor_close")) {
		**feerate = unilateral_feerate(cmd->ld, true);
		return NULL;
	}

	/* We used SLOW, NORMAL, and URGENT as feerate targets previously,
	 * and many commands rely on this syntax now.
	 * It's also really more natural for an user interface. */
	if (json_tok_streq(buffer, tok, "slow")) {
		**feerate = feerate_for_deadline(cmd->ld, 100);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "normal")) {
		**feerate = feerate_for_deadline(cmd->ld, 12);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "urgent")) {
		**feerate = feerate_for_deadline(cmd->ld, 6);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "minimum")) {
		**feerate = get_feerate_floor(cmd->ld);
		return NULL;
	}

	/* Can specify number of blocks as a target */
	if (json_tok_endswith(buffer, tok, "blocks")) {
		jsmntok_t base = *tok;
		base.end -= strlen("blocks");
		u32 numblocks;

		if (!json_to_number(buffer, &base, &numblocks)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' should be an integer not '%.*s'",
					    name, base.end - base.start,
					    buffer + base.start);
		}
		**feerate = feerate_for_deadline(cmd->ld, numblocks);
		return NULL;
	}

	/* It's a number... */
	tal_free(*feerate);
	return param_feerate_val(cmd, name, buffer, tok, feerate);
}

struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate)
{
	struct command_result *ret;

	ret = param_feerate_unchecked(cmd, name, buffer, tok, feerate);
	if (ret)
		return ret;

	if (**feerate == 0)
		return command_fail(cmd, BCLI_NO_FEE_ESTIMATES,
				    "Cannot estimate fees (yet)");

	return NULL;
}

struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw)
{
	jsmntok_t base = *tok;
	enum feerate_style style;
	unsigned int num;

	if (json_tok_endswith(buffer, tok,
			      feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KBYTE));
	} else if (json_tok_endswith(buffer, tok,
				     feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KSIPA));
	} else
		style = FEERATE_PER_KBYTE;

	if (!json_to_number(buffer, &base, &num)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be an integer with optional perkw/perkb, not '%.*s'",
				    name, base.end - base.start,
				    buffer + base.start);
	}

	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = feerate_from_style(num, style);
	if (**feerate_per_kw < FEERATE_FLOOR)
		**feerate_per_kw = FEERATE_FLOOR;
	return NULL;
}

/* Mutual recursion via timer. */
/* Fee polling: lightningd polls bitcoind for fee estimates every 30 seconds.
 * bwatch only reports blockheight via block_processed; it does not call
 * estimatefees. */
struct fee_poll {
	struct lightningd *ld;
	struct oneshot *timer;
};

static void start_fee_estimate(struct fee_poll *fp);
static void schedule_fee_estimate(struct fee_poll *fp);

bool unknown_feerates(const struct lightningd *ld)
{
	return tal_count(ld->watchman->feerates[0]) == 0;
}

static u32 interp_feerate(const struct feerate_est *rates, u32 blockcount)
{
	const struct feerate_est *before = NULL, *after = NULL;

	/* Find before and after. */
	const size_t num_feerates = tal_count(rates);
	for (size_t i = 0; i < num_feerates; i++) {
		if (rates[i].blockcount <= blockcount) {
			before = &rates[i];
		} else if (rates[i].blockcount > blockcount && !after) {
			after = &rates[i];
		}
	}
	/* No estimates at all? */
	if (!before && !after)
		return 0;
	/* We don't extrapolate. */
	if (!before && after)
		return after->rate;
	if (before && !after)
		return before->rate;

	/* Interpolate, eg. blockcount 10, rate 15000, blockcount 20, rate 5000.
	 * At 15, rate should be 10000.
	 * 15000 + (15 - 10) / (20 - 10) * (15000 - 5000)
	 * 15000 + 5 / 10 * 10000
	 * => 10000
	 */
	/* Don't go backwards though! */
	if (before->rate < after->rate)
		return before->rate;

	return before->rate
		- ((u64)(blockcount - before->blockcount)
		   * (before->rate - after->rate)
		   / (after->blockcount - before->blockcount));

}

u32 feerate_for_deadline(const struct lightningd *ld, u32 blockcount)
{
	u32 rate = interp_feerate(ld->watchman->feerates[0], blockcount);

	/* 0 is a special value, meaning "don't know" */
	if (rate && rate < ld->watchman->feerate_floor)
		rate = ld->watchman->feerate_floor;
	return rate;
}

u32 smoothed_feerate_for_deadline(const struct lightningd *ld,
				  u32 blockcount)
{
	/* Note: we cap it at feerate_floor when we smooth */
	return interp_feerate(ld->watchman->smoothed_feerates, blockcount);
}

/* feerate_for_deadline, but really lowball for distant targets */
u32 feerate_for_target(const struct lightningd *ld, u64 deadline)
{
	u64 blocks, blockheight;

	blockheight = get_block_height(ld->topology);

	/* Past deadline?  Want it now. */
	if (blockheight > deadline)
		return feerate_for_deadline(ld, 1);

	blocks = deadline - blockheight;

	/* Over 200 blocks, we *always* use min fee! */
	if (blocks > 200)
		return FEERATE_FLOOR;
	/* Over 100 blocks, use min fee bitcoind will accept */
	if (blocks > 100)
		return get_feerate_floor(ld);

	return feerate_for_deadline(ld, blocks);
}

/* Mixes in fresh feerate rate into old smoothed values, modifies rate */
static void smooth_one_feerate(const struct lightningd *ld,
			       struct feerate_est *rate)
{
	/* Smoothing factor alpha for simple exponential smoothing. The goal is to
	 * have the feerate account for 90 percent of the values polled in the last
	 * 2 minutes. */
	double alpha = 1 - pow(0.1, (double)BITCOIND_POLL_SECONDS / 120);
	u32 old_feerate, feerate_smooth;

	/* We don't call this unless we had a previous feerate */
	old_feerate = smoothed_feerate_for_deadline(ld, rate->blockcount);
	assert(old_feerate);

	feerate_smooth = rate->rate * alpha + old_feerate * (1 - alpha);

	/* But to avoid updating forever, only apply smoothing when its
	 * effect is more then 10 percent */
	if (abs((int)rate->rate - (int)feerate_smooth) > (0.1 * rate->rate))
		rate->rate = feerate_smooth;

	if (rate->rate < get_feerate_floor(ld))
		rate->rate = get_feerate_floor(ld);

	if (rate->rate != feerate_smooth)
		log_debug(ld->log,
			  "Feerate estimate for %u blocks set to %u (was %u)",
			  rate->blockcount, rate->rate, feerate_smooth);
}

static bool feerates_differ(const struct feerate_est *a,
			    const struct feerate_est *b)
{
	const size_t num_feerates = tal_count(a);
	if (num_feerates != tal_count(b))
		return true;
	for (size_t i = 0; i < num_feerates; i++) {
		if (a[i].blockcount != b[i].blockcount)
			return true;
		if (a[i].rate != b[i].rate)
			return true;
	}
	return false;
}

/* In case the plugin does weird stuff! */
static bool different_blockcounts(struct lightningd *ld,
				  const struct feerate_est *old,
				  const struct feerate_est *new)
{
	const size_t num_feerates = tal_count(old);
	if (num_feerates != tal_count(new)) {
		log_unusual(ld->log,
			    "Presented with %zu feerates this time (was %zu!)",
			    tal_count(new), num_feerates);
		return true;
	}
	for (size_t i = 0; i < num_feerates; i++) {
		if (old[i].blockcount != new[i].blockcount) {
			log_unusual(ld->log,
				    "Presented with feerates"
				    " for blockcount %u, previously %u",
				    new[i].blockcount, old[i].blockcount);
			return true;
		}
	}
	return false;
}

void update_feerates(struct lightningd *ld,
		     u32 feerate_floor,
		     const struct feerate_est *rates TAKES)
{
	struct feerate_est *new_smoothed;
	bool changed;
	struct watchman *wm = ld->watchman;

	wm->feerate_floor = feerate_floor;

	/* Don't bother updating if we got no feerates; we'd rather have
	 * historical ones, if any. */
	if (tal_count(rates) == 0)
		return;

	/* If the feerate blockcounts differ, don't average, just override */
	if (wm->feerates[0] && different_blockcounts(ld, wm->feerates[0], rates)) {
		for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++)
			wm->feerates[i] = tal_free(wm->feerates[i]);
		wm->smoothed_feerates = tal_free(wm->smoothed_feerates);
	}

	/* Move down historical rates, insert these */
	tal_free(wm->feerates[FEE_HISTORY_NUM-1]);
	memmove(wm->feerates + 1, wm->feerates,
		sizeof(wm->feerates[0]) * (FEE_HISTORY_NUM-1));
	wm->feerates[0] = tal_dup_talarr(wm, struct feerate_est, rates);
	changed = feerates_differ(wm->feerates[0], wm->feerates[1]);

	/* Use this as basis of new smoothed ones. */
	new_smoothed = tal_dup_talarr(wm, struct feerate_est, wm->feerates[0]);

	/* If there were old smoothed feerates, incorporate those */
	if (tal_count(wm->smoothed_feerates) != 0) {
		const size_t num_new = tal_count(new_smoothed);
		for (size_t i = 0; i < num_new; i++)
			smooth_one_feerate(ld, &new_smoothed[i]);
	}
	changed |= feerates_differ(wm->smoothed_feerates, new_smoothed);
	tal_free(wm->smoothed_feerates);
	wm->smoothed_feerates = new_smoothed;

	if (changed)
		notify_feerate_change(ld);
}

static void update_feerates_and_reschedule(struct lightningd *ld,
					   u32 feerate_floor,
					   const struct feerate_est *rates TAKES,
					   struct fee_poll *fp)
{
	update_feerates(ld, feerate_floor, rates);
	schedule_fee_estimate(fp);
}

static void start_fee_estimate(struct fee_poll *fp)
{
	fp->timer = NULL;
	bitcoind_estimate_fees(fp, fp->ld->bitcoind,
			       update_feerates_and_reschedule, fp);
}

static void schedule_fee_estimate(struct fee_poll *fp)
{
	fp->timer = new_reltimer(fp->ld->timers, fp,
				 time_from_sec(BITCOIND_POLL_SECONDS),
				 start_fee_estimate, fp);
}

void start_fee_polling(struct lightningd *ld)
{
	struct fee_poll *fp = tal(ld, struct fee_poll);
	fp->ld = ld;
	fp->timer = NULL;
	ld->fee_poll = fp;
	start_fee_estimate(fp);
}

struct rate_conversion {
	u32 blockcount;
};

static struct rate_conversion conversions[] = {
	[FEERATE_OPENING] = { 12 },
	[FEERATE_MUTUAL_CLOSE] = { 100 },
	[FEERATE_UNILATERAL_CLOSE] = { 6 },
	[FEERATE_DELAYED_TO_US] = { 12 },
	[FEERATE_HTLC_RESOLUTION] = { 6 },
	[FEERATE_PENALTY] = { 12 },
};

u32 opening_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_OPENING];
	return feerate_for_deadline(ld,
				    conversions[FEERATE_OPENING].blockcount);
}

u32 mutual_close_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_MUTUAL_CLOSE];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_MUTUAL_CLOSE].blockcount);
}

u32 unilateral_feerate(struct lightningd *ld, bool option_anchors)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_UNILATERAL_CLOSE];

	if (option_anchors) {
		/* We can lowball fee, since we can CPFP with anchors */
		u32 feerate = feerate_for_deadline(ld, 100);
		if (!feerate)
			return 0; /* Don't know */
		/* We still need to get into the mempool, so use 5 sat/byte */
		if (feerate < 1250)
			return 1250;
		return feerate;
	}

	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_UNILATERAL_CLOSE].blockcount)
		* ld->config.commit_fee_percent / 100;
}

u32 delayed_to_us_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_DELAYED_TO_US];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_DELAYED_TO_US].blockcount);
}

u32 htlc_resolution_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_HTLC_RESOLUTION];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_HTLC_RESOLUTION].blockcount);
}

u32 penalty_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_PENALTY];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_PENALTY].blockcount);
}

u32 get_feerate_floor(const struct lightningd *ld)
{
	return ld->watchman->feerate_floor;
}

u32 feerate_min(struct lightningd *ld, bool *unknown)
{
	const struct watchman *wm = ld->watchman;
	u32 min;

	if (unknown)
		*unknown = false;

        /* We allow the user to ignore the fee limits,
	 * although this comes with inherent risks.
	 *
	 * By enabling this option, users are explicitly
	 * made aware of the potential dangers.
	 * There are situations, such as the one described in [1],
	 * where it becomes necessary to bypass the fee limits to resolve
	 * issues like a stuck channel.
	 *
	 * BTW experimental-anchors feature provides a solution to this problem.
	 *
	 * [1] https://github.com/ElementsProject/lightning/issues/6362
	 * */
	min = 0xFFFFFFFF;
	for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++) {
		const size_t num_feerates = tal_count(wm->feerates[i]);
		for (size_t j = 0; j < num_feerates; j++) {
			if (wm->feerates[i][j].rate < min)
				min = wm->feerates[i][j].rate;
		}
	}
	if (min == 0xFFFFFFFF) {
		if (unknown)
			*unknown = true;
		min = 0;
	}

	/* FIXME: This is what bcli used to do: halve the slow feerate! */
	min /= 2;

	/* We can't allow less than feerate_floor, since that won't relay */
	if (min < get_feerate_floor(ld))
		return get_feerate_floor(ld);
	return min;
}

u32 feerate_max(struct lightningd *ld, bool *unknown)
{
	const struct watchman *wm = ld->watchman;
	u32 max = 0;

	if (unknown)
		*unknown = false;

	for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++) {
		const size_t num_feerates = tal_count(wm->feerates[i]);
		for (size_t j = 0; j < num_feerates; j++) {
			if (wm->feerates[i][j].rate > max)
				max = wm->feerates[i][j].rate;
		}
	}
	if (!max) {
		if (unknown)
			*unknown = true;
		return UINT_MAX;
	}
	return max * ld->config.max_fee_multiplier;
}

u32 default_locktime(const struct lightningd *ld)
{
	u32 locktime, current_height = get_block_height(ld->topology);

	/* Setting the locktime to the next block to be mined has multiple
	 * benefits:
	 * - anti fee-snipping (even if not yet likely)
	 * - less distinguishable transactions (with this we create
	 *   general-purpose transactions which looks like bitcoind:
	 *   native segwit, nlocktime set to tip, and sequence set to
	 *   0xFFFFFFFD by default. Other wallets are likely to implement
	 *   this too).
	 */
	locktime = current_height;

	/* Eventually fuzz it too. */
	if (locktime > 100 && pseudorand(10) == 0)
		locktime -= pseudorand(100);

	return locktime;
}

static struct command_result *json_feerates(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct json_stream *response;
	enum feerate_style *style;
	u32 rate;

	if (!param(cmd, buffer, params,
		   p_req("style", param_feerate_style, &style),
		   NULL))
		return command_param_failed();

	const size_t num_feerates = tal_count(ld->watchman->feerates[0]);

	response = json_stream_success(cmd);
	if (!num_feerates)
		json_add_string(response, "warning_missing_feerates",
				"Some fee estimates unavailable: bitcoind startup?");

	json_object_start(response, feerate_style_name(*style));
	rate = opening_feerate(ld);
	if (rate)
		json_add_num(response, "opening", feerate_to_style(rate, *style));
	rate = mutual_close_feerate(ld);
	if (rate)
		json_add_num(response, "mutual_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(ld, false);
	if (rate)
		json_add_num(response, "unilateral_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(ld, true);
	if (rate)
		json_add_num(response, "unilateral_anchor_close",
			     feerate_to_style(rate, *style));
	rate = penalty_feerate(ld);
	if (rate)
		json_add_num(response, "penalty",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(ld, true);
	if (rate) {
		rate += ld->config.feerate_offset;
		if (rate > feerate_max(ld, NULL))
			rate = feerate_max(ld, NULL);
		json_add_num(response, "splice",
			     feerate_to_style(rate, *style));
	}

	json_add_u64(response, "min_acceptable",
		     feerate_to_style(feerate_min(ld, NULL), *style));
	json_add_u64(response, "max_acceptable",
		     feerate_to_style(feerate_max(ld, NULL), *style));
	json_add_u64(response, "floor",
		     feerate_to_style(get_feerate_floor(ld), *style));

	json_array_start(response, "estimates");
	assert(tal_count(ld->watchman->smoothed_feerates) == num_feerates);
	for (size_t i = 0; i < num_feerates; i++) {
		json_object_start(response, NULL);
		json_add_num(response, "blockcount",
			     ld->watchman->feerates[0][i].blockcount);
		json_add_u64(response, "feerate",
			     feerate_to_style(ld->watchman->feerates[0][i].rate, *style));
		json_add_u64(response, "smoothed_feerate",
			     feerate_to_style(ld->watchman->smoothed_feerates[i].rate,
					      *style));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);

	if (num_feerates) {
		/* It actually is negotiated per-channel... */
		bool anchor_outputs
			= feature_offered(ld->our_features->bits[INIT_FEATURE],
					  OPT_ANCHOR_OUTPUTS_DEPRECATED)
			|| feature_offered(ld->our_features->bits[INIT_FEATURE],
					   OPT_ANCHORS_ZERO_FEE_HTLC_TX);

		json_object_start(response, "onchain_fee_estimates");
		/* eg 020000000001016f51de645a47baa49a636b8ec974c28bdff0ac9151c0f4eda2dbe3b41dbe711d000000001716001401fad90abcd66697e2592164722de4a95ebee165ffffffff0240420f00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cdb73f890000000000160014c2ccab171c2a5be9dab52ec41b825863024c54660248304502210088f65e054dbc2d8f679de3e40150069854863efa4a45103b2bb63d060322f94702200d3ae8923924a458cffb0b7360179790830027bb6b29715ba03e12fc22365de1012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf00000000 == weight 702 */
		json_add_num(response, "opening_channel_satoshis",
			     opening_feerate(ld) * 702 / 1000);
		/* eg. 02000000000101afcfac637d44d4e0df52031dba55b18d3f1bd79ad4b7ebbee964f124c5163dc30100000000ffffffff02400d03000000000016001427213e2217b4f56bd19b6c8393dc9f61be691233ca1f0c0000000000160014071c49cad2f420f3c805f9f6b98a57269cb1415004004830450221009a12b4d5ae1d41781f79bedecfa3e65542b1799a46c272287ba41f009d2e27ff0220382630c899207487eba28062f3989c4b656c697c23a8c89c1d115c98d82ff261014730440220191ddf13834aa08ea06dca8191422e85d217b065462d1b405b665eefa0684ed70220252409bf033eeab3aae89ae27596d7e0491bcc7ae759c5644bced71ef3cccef30147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae00000000 == weight 673 */
		json_add_u64(response, "mutual_close_satoshis",
			     mutual_close_feerate(ld) * 673 / 1000);
		/* eg. 02000000000101c4fecaae1ea940c15ec502de732c4c386d51f981317605bbe5ad2c59165690ab00000000009db0e280010a2d0f00000000002200208d290003cedb0dd00cd5004c2d565d55fc70227bf5711186f4fa9392f8f32b4a0400483045022100952fcf8c730c91cf66bcb742cd52f046c0db3694dc461e7599be330a22466d790220740738a6f9d9e1ae5c86452fa07b0d8dddc90f8bee4ded24a88fe4b7400089eb01483045022100db3002a93390fc15c193da57d6ce1020e82705e760a3aa935ebe864bd66dd8e8022062ee9c6aa7b88ff4580e2671900a339754116371d8f40eba15b798136a76cd150147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae9a3ed620 == weight 598 */
		/* Or, with anchors:
		 * 02000000000101dc824e8e880f90f397a74f89022b4d58f8c36ebc4fffc238bd525bd11f5002a501000000009db0e280044a010000000000002200200e1a08b3da3bea6a7a77315f95afcd589fe799af46cf9bfb89523172814050e44a01000000000000220020be7935a77ca9ab70a4b8b1906825637767fed3c00824aa90c988983587d6848878e001000000000022002009fa3082e61ca0bd627915b53b0cb8afa467248fa4dc95141f78b96e9c98a8ed245a0d000000000022002091fb9e7843a03e66b4b1173482a0eb394f03a35aae4c28e8b4b1f575696bd793040047304402205c2ea9cf6f670e2f454c054f9aaca2d248763e258e44c71675c06135fd8f36cb02201b564f0e1b3f1ea19342f26e978a4981675da23042b4d392737636738c3514da0147304402205fcd2af5b724cbbf71dfa07bd14e8018ce22c08a019976dc03d0f545f848d0a702203652200350cadb464a70a09829d09227ed3da8c6b8ef5e3a59b5eefd056deaae0147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae9b3ed620 1112 */
		if (anchor_outputs)
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(ld, true) * 1112 / 1000);
		else
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(ld, false) * 598 / 1000);
		json_add_u64(response, "unilateral_close_nonanchor_satoshis",
			     unilateral_feerate(ld, false) * 598 / 1000);

		json_add_u64(response, "htlc_timeout_satoshis",
			     htlc_timeout_fee(htlc_resolution_feerate(ld),
					      false, false).satoshis /* Raw: estimate */);
		json_add_u64(response, "htlc_success_satoshis",
			     htlc_success_fee(htlc_resolution_feerate(ld),
					      false, false).satoshis /* Raw: estimate */);
		json_object_end(response);
	}

	return command_success(cmd, response);
}

static const struct json_command feerates_command = {
	"feerates",
	json_feerates,
};
AUTODATA(json_command, &feerates_command);

static struct command_result *json_parse_feerate(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	u32 *feerate;

	if (!param(cmd, buffer, params,
		   p_req("feerate", param_feerate, &feerate),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_add_num(response, feerate_style_name(FEERATE_PER_KSIPA),
		     feerate_to_style(*feerate, FEERATE_PER_KSIPA));
	return command_success(cmd, response);
}

static const struct json_command parse_feerate_command = {
	"parsefeerate",
	json_parse_feerate,
};
AUTODATA(json_command, &parse_feerate_command);
