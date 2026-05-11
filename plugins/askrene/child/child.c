#include "config.h"
#include <assert.h>
#include <ccan/json_out/json_out.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <plugins/askrene/child/child.h>
#include <plugins/askrene/child/child_log.h>
#include <plugins/askrene/child/flow.h>
#include <plugins/askrene/child/mcf.h>
#include <plugins/askrene/child/route_query.h>

struct hop {
	/* Via this channel */
	struct short_channel_id_dir scidd;
	/* Nodes at each end */
	struct node_id node_in, node_out;
	/* This is amount the node needs (including fees) */
	struct amount_msat amount_in;
	/* ... to send this amount */
	struct amount_msat amount_out;
	/* This is the delay, including delay across node */
	u32 cltv_value_in;
	/* This is the delay, out from node. */
	u32 cltv_value_out;
};

/* A single route. */
struct route {
	/* Actual path to take */
	struct hop *hops;
	/* Probability estimate (0-1) */
	double success_prob;
};

static const struct hop *final_hop(const struct hop *hops)
{
	assert(tal_count(hops) > 0);

	return &hops[tal_count(hops) - 1];
}

static const char *fmt_route(const tal_t *ctx, const struct route *route)
{
	char *str = tal_strdup(ctx, "");
	const struct hop *final = final_hop(route->hops);

	for (size_t i = 0; i < tal_count(route->hops); i++) {
		tal_append_fmt(&str, "%s/%u %s -> ",
			       fmt_amount_msat(tmpctx, route->hops[i].amount_in),
			       route->hops[i].cltv_value_in,
			       fmt_short_channel_id_dir(tmpctx, &route->hops[i].scidd));
	}
	tal_append_fmt(&str, "%s/%u (prob=%0.3f%%)",
		       fmt_amount_msat(tmpctx, final->amount_out),
		       final->cltv_value_out,
		       route->success_prob * 100);
	return str;
}

/* Convert back into routes, with delay and other information fixed */
static struct route **convert_flows_to_routes(const tal_t *ctx,
					      const struct route_query *rq,
					      u32 finalcltv,
					      struct flow **flows,
					      bool include_fees)
{
	struct route **routes = tal_arr(ctx, struct route *, tal_count(flows));

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct route *r;
		struct amount_msat msat;
		u32 cltv_value;

		routes[i] = r = tal(routes, struct route);
		r->success_prob = flow_probability(flows[i], rq);
		r->hops = tal_arr(r, struct hop, tal_count(flows[i]->path));

		msat = flows[i]->delivers;
		cltv_value = finalcltv;

		/* Fill in backwards to calculate delay */
		for (int j = tal_count(flows[i]->path) - 1; j >= 0; j--) {
			struct hop *hop = &r->hops[j];
			struct gossmap_node *n;
			const struct half_chan *h = flow_edge(flows[i], j);

			hop->cltv_value_out = cltv_value;
			cltv_value += h->delay;
			hop->cltv_value_in = cltv_value;

			hop->scidd.scid = gossmap_chan_scid(rq->gossmap,
							    flows[i]->path[j]);
			hop->scidd.dir = flows[i]->dirs[j];
			n = gossmap_nth_node(rq->gossmap,
					     flows[i]->path[j],
					     flows[i]->dirs[j]);
			gossmap_node_get_id(rq->gossmap, n, &hop->node_in);
			n = gossmap_nth_node(rq->gossmap,
					     flows[i]->path[j],
					     !flows[i]->dirs[j]);
			gossmap_node_get_id(rq->gossmap, n, &hop->node_out);
		}

		if (!include_fees) {
			/* Fill in backwards to calc amount */
			for (int j = tal_count(flows[i]->path) - 1; j >= 0;
			     j--) {
				struct hop *hop = &r->hops[j];
				const struct half_chan *h =
				    flow_edge(flows[i], j);

				hop->amount_out = msat;
				if (!amount_msat_add_fee(&msat, h->base_fee,
							 h->proportional_fee))
					abort();
				hop->amount_in = msat;
			}
		} else {
			/* Compute fees forward */
			for (int j = 0; j < tal_count(flows[i]->path); j++) {
				struct hop *hop = &r->hops[j];
				const struct half_chan *h =
				    flow_edge(flows[i], j);

				hop->amount_in = msat;
                                msat = amount_msat_sub_fee(msat, h->base_fee,
							   h->proportional_fee);
				hop->amount_out = msat;
			}
		}

		child_log(tmpctx, LOG_INFORM, "Flow %zu/%zu: %s",
			  i, tal_count(flows), fmt_route(tmpctx, r));
	}

	return routes;
}

static void json_add_getroutes(struct json_stream *js,
			       struct route **routes,
			       double probability)
{
	json_add_u64(js, "probability_ppm", (u64)(probability * 1000000));
	json_array_start(js, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		const struct hop *final = final_hop(routes[i]->hops);
		json_object_start(js, NULL);
		json_add_u64(js, "probability_ppm",
			     (u64)(routes[i]->success_prob * 1000000));
		json_add_amount_msat(js, "amount_msat", final->amount_out);
		json_add_u32(js, "final_cltv", final->cltv_value_out);
		json_array_start(js, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			const struct hop *hop = &routes[i]->hops[j];
			json_object_start(js, NULL);
			json_add_short_channel_id_dir(
			    js, "short_channel_id_dir", hop->scidd);
			json_add_node_id(js, "node_id_in", &hop->node_in);
			json_add_node_id(js, "node_id_out", &hop->node_out);
			json_add_amount_msat(js, "amount_in_msat", hop->amount_in);
			json_add_amount_msat(js, "amount_out_msat", hop->amount_out);
			json_add_u32(js, "cltv_in", hop->cltv_value_in);
			json_add_u32(js, "cltv_out", hop->cltv_value_out);

			json_add_node_id(js, "next_node_id", &hop->node_out);
			json_add_amount_msat(js, "amount_msat", hop->amount_in);
			json_add_u32(js, "delay", hop->cltv_value_in);
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
}


static struct route_query *new_route_query(const tal_t *ctx,
					   const struct gossmap *gossmap,
					   const char *cmd_id,
					   const struct layer **layers,
					   const s8 *biases,
					   const struct additional_cost_htable *additional_costs,
					   struct reserve_htable *reserved,
					   fp16_t *capacities TAKES)
{
	struct route_query *rq = tal(ctx, struct route_query);

	rq->gossmap = gossmap;
	rq->cmd_id = tal_strdup(rq, cmd_id);
	rq->layers = layers;
	rq->biases = biases;
	rq->additional_costs = additional_costs;
	rq->reserved = reserved;
	rq->capacities = tal_dup_talarr(rq, fp16_t, capacities);
	rq->disabled_chans =
	    tal_arrz(rq, bitmap,
		     2 * BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));

	return rq;
}

void run_child(const struct gossmap *gossmap,
	       const struct layer **layers,
	       const s8 *biases,
	       const struct additional_cost_htable *additional_costs,
	       struct reserve_htable *reserved,
	       fp16_t *capacities TAKES,
	       bool single_path,
	       struct timemono deadline,
	       const struct gossmap_node *srcnode,
	       const struct gossmap_node *dstnode,
	       struct amount_msat amount, struct amount_msat maxfee,
	       u32 finalcltv, u32 maxdelay, size_t maxparts,
              bool include_fees,
	       const char *cmd_id,
	       struct json_filter *cmd_filter,
	       int replyfd)
{
	double probability;
	struct flow **flows;
	struct route **routes;
	const char *err, *p;
	size_t len;
	struct route_query *rq;
	enum jsonrpc_errcode ecode;

	/* We exit below, so we don't bother freeing this */
	rq = new_route_query(NULL, gossmap, cmd_id, layers,
			     biases, additional_costs,
			     reserved, capacities);
	if (single_path) {
		err = single_path_routes(rq, rq, deadline, srcnode, dstnode,
					 amount, maxfee, finalcltv,
					 maxdelay, &flows, &probability, &ecode);
	} else {
		err = default_routes(rq, rq, deadline, srcnode, dstnode,
				     amount, maxfee, finalcltv, maxdelay,
				     maxparts, &flows, &probability, &ecode);
	}
	if (err) {
		write_all(replyfd, &ecode, sizeof(ecode));
		write_all(replyfd, err, strlen(err));
		/* Non-zero exit tells parent this is an error string. */
		exit(1);
	}

	/* otherwise we continue */
	assert(tal_count(flows) > 0);
	child_log(tmpctx, LOG_DBG, "Final answer has %zu flows",
		  tal_count(flows));

	/* convert flows to routes */
	routes = convert_flows_to_routes(rq, rq, finalcltv, flows, include_fees);
	assert(tal_count(routes) == tal_count(flows));

	/* output the results */
	struct json_stream *js = new_json_stream(tmpctx, NULL, NULL);
	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_id(js, cmd_id);
	json_object_start(js, "result");
	if (cmd_filter)
		json_stream_attach_filter(js, cmd_filter);
	json_add_getroutes(js, routes, probability);

	/* Detach filter before it complains about closing object it never saw */
	if (cmd_filter) {
		err = json_stream_detach_filter(tmpctx, js);
		if (err)
			json_add_string(js, "warning_parameter_filter", err);
	}
	/* "result" object */
	json_object_end(js);
	/* Global object */
	json_object_end(js);
	json_stream_close(js, NULL);

	p = json_out_contents(js->jout, &len);
	if (!write_all(replyfd, p, len))
		abort();
	exit(0);
}

