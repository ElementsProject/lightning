#ifndef LIGHTNING_LIGHTNINGD_FEERATE_H
#define LIGHTNING_LIGHTNINGD_FEERATE_H
#include "config.h"
#include <bitcoin/feerate.h>
#include <common/json_parse_simple.h>
#include <common/utils.h>

struct command;
struct lightningd;

/* We keep the last three in case there are outliers (for min/max) */
#define FEE_HISTORY_NUM 3

/* Our plugins give us a series of blockcount, feerate pairs. */
struct feerate_est {
	u32 blockcount;
	u32 rate;
};

enum feerate {
	/* DO NOT REORDER: force-feerates uses this order! */
	FEERATE_OPENING,
	FEERATE_MUTUAL_CLOSE,
	FEERATE_UNILATERAL_CLOSE,
	FEERATE_DELAYED_TO_US,
	FEERATE_HTLC_RESOLUTION,
	FEERATE_PENALTY,
	FEERATE_MIN,
	FEERATE_MAX,
};
#define NUM_FEERATES (FEERATE_MAX+1)

const char *feerate_name(enum feerate feerate);

/* Extract a feerate style. */
struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style);

/* Extract a feerate with optional style suffix. */
struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw);

/* This also accepts names like "slow" etc */
struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate);

/* Get the minimum feerate that bitcoind will accept */
u32 get_feerate_floor(const struct lightningd *ld);

/* Has our feerate estimation failed altogether? */
bool unknown_feerates(const struct lightningd *ld);

/* Get feerate estimate for getting a tx in this many blocks */
u32 feerate_for_deadline(const struct lightningd *ld, u32 blockcount);
u32 smoothed_feerate_for_deadline(const struct lightningd *ld, u32 blockcount);

/* Get feerate to hit this *block number*. */
u32 feerate_for_target(const struct lightningd *ld, u64 deadline);

/* Get range of feerates to insist other side abide by for normal channels.
 * If we have to guess, sets *unknown to true, otherwise false. */
u32 feerate_min(struct lightningd *ld, bool *unknown);
u32 feerate_max(struct lightningd *ld, bool *unknown);

/* These return 0 if unknown */
u32 opening_feerate(struct lightningd *ld);
u32 mutual_close_feerate(struct lightningd *ld);
u32 unilateral_feerate(struct lightningd *ld, bool option_anchors);
u32 delayed_to_us_feerate(struct lightningd *ld);
u32 htlc_resolution_feerate(struct lightningd *ld);
u32 penalty_feerate(struct lightningd *ld);

/* Usually we set nLocktime to tip (or recent) like bitcoind does */
u32 default_locktime(const struct lightningd *ld);

/* Feed a fresh feerate sample into the smoothing/history machinery. */
void update_feerates(struct lightningd *ld,
		     u32 feerate_floor,
		     const struct feerate_est *rates TAKES,
		     void *arg);

/* Start polling bitcoind for fee estimates every 30s */
void start_fee_polling(struct lightningd *ld);

/* In channel_control.c */
void notify_feerate_change(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_FEERATE_H */
