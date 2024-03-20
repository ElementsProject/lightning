#ifndef LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H
#define LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H
#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <ccan/short_types/short_types.h>
#include <common/utils.h>
#include <plugins/renepay/flow.h>
#include <plugins/renepay/payment.h>

/* There are several states a payment can be in */
enum pay_flow_state {
	/* Created, but not sent to sendpay */
	PAY_FLOW_NOT_STARTED,
	/* Normally, here */
	PAY_FLOW_IN_PROGRESS,
	/* Failed: we've fed the data back to the uncertainly network. */
	PAY_FLOW_FAILED,
	/* Failed from the final node, so give up: see ->final_error. */
	PAY_FLOW_FAILED_FINAL,
	/* Failed, but still updating gossip. */
	PAY_FLOW_FAILED_GOSSIP_PENDING,
	/* Succeeded: see ->payment_preimage. */
	PAY_FLOW_SUCCESS,
};
#define NUM_PAY_FLOW (PAY_FLOW_SUCCESS + 1)

/* This is like a struct flow, but independent of gossmap, and contains
 * all we need to actually send the part payment. */
struct pay_flow {
	/* Linked from payment->flows */
	struct list_node list;

	enum pay_flow_state state;
	/* Iff state == PAY_FLOW_SUCCESS */
	const struct preimage *payment_preimage;
	/* Iff state == PAY_FAILED_FINAL */
	enum jsonrpc_errcode final_error;
	const char *final_msg;

	/* So we can be an independent object for callbacks. */
	struct payment * payment;

	/* Information to link this flow to a unique sendpay. */
	struct payflow_key
	{
		struct sha256 payment_hash;
		u64 groupid;
		u64 partid;
	} key;

	/* The series of channels and nodes to traverse. */
	struct short_channel_id_dir *path_scidds;
	struct node_id *path_nodes;
	/* CLTV delays for each hop */
	u32 *cltv_delays;
	/* The amounts at each step */
	struct amount_msat *amounts;
	/* Probability estimate (0-1) */
	double success_prob;
};

static inline struct payflow_key
payflow_key(const struct sha256 *hash, u64 groupid, u64 partid)
{
	struct payflow_key k= {*hash,groupid,partid};
	return k;
}

static inline const char* fmt_payflow_key(
		const tal_t *ctx,
		const struct payflow_key * k)
{
	char *str = tal_fmt(
		ctx,
		"key: groupid=%"PRIu64", partid=%"PRIu64", payment_hash=%s",
		k->groupid,k->partid,
		fmt_sha256(ctx, &k->payment_hash));
	return str;
}


static inline const struct payflow_key *
payflow_get_key(const struct pay_flow * pf)
{
	return &pf->key;
}

static inline size_t payflow_key_hash(const struct payflow_key *k)
{
	return k->payment_hash.u.u32[0] ^ (k->groupid << 32) ^ k->partid;
}

static inline bool payflow_key_equal(const struct pay_flow *pf,
				     const struct payflow_key *k)
{
	return pf->key.partid==k->partid && pf->key.groupid==k->groupid
		&& sha256_eq(&pf->key.payment_hash, &k->payment_hash);
}

HTABLE_DEFINE_TYPE(struct pay_flow,
		   payflow_get_key, payflow_key_hash, payflow_key_equal,
		   payflow_map);

/* Add one or more IN_PROGRESS pay_flow to payment.  Return NULL if we did,
 * otherwise an error message (and sets *ecode). */
const char *add_payflows(const tal_t *ctx,
			 struct payment *payment,
			 struct amount_msat amount,
			 struct amount_msat feebudget,
			 bool is_entire_payment,
			 enum jsonrpc_errcode *ecode);

/* Each payflow is eventually terminated by one of these.
 *
 * To make sure you deal with flows, they return a special type.
 */

/* We've been notified that a pay_flow has failed */
struct pf_result *pay_flow_failed(struct pay_flow *pf STEALS);
/* We've been notified that a pay_flow has failed, payment is done. */
struct pf_result *pay_flow_failed_final(struct pay_flow *pf STEALS,
					enum jsonrpc_errcode final_error,
					const char *final_msg TAKES);
/* We've been notified that a pay_flow has failed, adding gossip. */
struct pf_result *pay_flow_failed_adding_gossip(struct pay_flow *pf STEALS);
/* We've finished adding gossip. */
struct pf_result *pay_flow_finished_adding_gossip(struct pay_flow *pf STEALS);
/* We've been notified that a pay_flow has succeeded. */
struct pf_result *pay_flow_succeeded(struct pay_flow *pf STEALS,
				     const struct preimage *preimage);

/* Formatting helpers */
const char *flow_path_to_str(const tal_t *ctx, const struct pay_flow *flow);

/* How much does this flow deliver to destination? */
struct amount_msat payflow_delivered(const struct pay_flow *flow);

/* At what cost? */
struct amount_msat payflow_fee(const struct pay_flow *flow);

#endif /* LIGHTNING_PLUGINS_RENEPAY_PAY_FLOW_H */
