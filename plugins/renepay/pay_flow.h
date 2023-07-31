#ifndef LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H
#define LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H
#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <ccan/short_types/short_types.h>
#include <common/utils.h>
#include <plugins/renepay/debug.h>
#include <plugins/renepay/flow.h>
#include <plugins/renepay/payment.h>

/* This is like a struct flow, but independent of gossmap, and contains
 * all we need to actually send the part payment. */
struct pay_flow {
	/* So we can be an independent object for callbacks. */
	struct payment * payment;

	// TODO(eduardo): remove this, unnecessary
	int attempt;

	/* Information to link this flow to a unique sendpay. */
	struct payflow_key
	{
		// TODO(eduardo): pointer or value?
		struct sha256 *payment_hash;
		u64 groupid;
		u64 partid;
	} key;

	/* The series of channels and nodes to traverse. */
	struct short_channel_id *path_scids;
	struct node_id *path_nodes;
	int *path_dirs;
	/* CLTV delays for each hop */
	u32 *cltv_delays;
	/* The amounts at each step */
	struct amount_msat *amounts;
	/* Probability estimate (0-1) */
	double success_prob;
};

static inline struct payflow_key
payflow_key(struct sha256 *hash, u64 groupid, u64 partid)
{
	struct payflow_key k= {hash,groupid,partid};
	return k;
}

static inline const char* fmt_payflow_key(
		const tal_t *ctx,
		const struct payflow_key * k)
{
	char *str = tal_fmt(
		ctx,
		"key: groupid=%ld, partid=%ld, payment_hash=%s",
		k->groupid,k->partid,
		type_to_string(ctx,struct sha256,k->payment_hash));
	return str;
}


static inline const struct payflow_key
payflow_get_key(const struct pay_flow * pf)
{
	return pf->key;
}

static inline size_t payflow_key_hash(const struct payflow_key k)
{
	return k.payment_hash->u.u32[0] ^ (k.groupid << 32) ^ k.partid;
}

static inline bool payflow_key_equal(struct pay_flow const *pf,
				      const struct payflow_key k)
{
	return pf->key.partid==k.partid && pf->key.groupid==k.groupid
		&& sha256_eq(pf->key.payment_hash,k.payment_hash);
}

HTABLE_DEFINE_TYPE(struct pay_flow,
		   payflow_get_key, payflow_key_hash, payflow_key_equal,
		   payflow_map);


struct pay_flow **get_payflows(struct renepay * renepay,
			       struct amount_msat amount,
			       struct amount_msat feebudget,
			       bool unlikely_ok,
			       bool is_entire_payment,
			       char const ** err_msg);

void commit_htlc_payflow(
		struct chan_extra_map *chan_extra_map,
		const struct pay_flow *flow);

void remove_htlc_payflow(
		struct chan_extra_map *chan_extra_map,
		struct pay_flow *flow);

const char *flow_path_to_str(const tal_t *ctx, const struct pay_flow *flow);

const char* fmt_payflows(const tal_t *ctx,
			 struct pay_flow ** flows);

/* How much does this flow deliver to destination? */
struct amount_msat payflow_delivered(const struct pay_flow *flow);

/* Removes amounts from payment and frees flow pointer.
 * A possible destructor for flow would remove HTLCs from the
 * uncertainty_network and remove the flow from any data structure. */
struct pay_flow* payflow_fail(struct pay_flow *flow);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H */
