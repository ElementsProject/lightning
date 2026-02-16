#include "config.h"
#include <assert.h>
#include <ccan/json_out/json_out.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <common/utils.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/child/child_log.h>
#include <plugins/askrene/child/entry.h>
#include <plugins/askrene/child/flow.h>
#include <plugins/askrene/child/mcf.h>
#include <unistd.h>

/* Temporary hack */
bool am_child = false;

/* A single route. */
struct route {
	/* Actual path to take */
	struct route_hop *hops;
	/* Probability estimate (0-1) */
	double success_prob;
};

static const char *fmt_route(const tal_t *ctx,
			     const struct route *route,
			     struct amount_msat delivers,
			     u32 final_cltv)
{
	char *str = tal_strdup(ctx, "");

	for (size_t i = 0; i < tal_count(route->hops); i++) {
		struct short_channel_id_dir scidd;
		scidd.scid = route->hops[i].scid;
		scidd.dir = route->hops[i].direction;
		tal_append_fmt(&str, "%s/%u %s -> ",
			       fmt_amount_msat(tmpctx, route->hops[i].amount),
			       route->hops[i].delay,
			       fmt_short_channel_id_dir(tmpctx, &scidd));
	}
	tal_append_fmt(&str, "%s/%u",
		       fmt_amount_msat(tmpctx, delivers), final_cltv);
	return str;
}

/* Convert back into routes, with delay and other information fixed */
static struct route **convert_flows_to_routes(const tal_t *ctx,
					      struct route_query *rq,
					      u32 finalcltv,
					      struct flow **flows,
					      struct amount_msat **amounts,
					      bool include_fees)
{
	struct route **routes;
	routes = tal_arr(ctx, struct route *, tal_count(flows));
	*amounts = tal_arr(ctx, struct amount_msat, tal_count(flows));

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct route *r;
		struct amount_msat msat;
		u32 delay;

		routes[i] = r = tal(routes, struct route);
		r->success_prob = flow_probability(flows[i], rq);
		r->hops = tal_arr(r, struct route_hop, tal_count(flows[i]->path));

		msat = flows[i]->delivers;
		delay = finalcltv;

		if (!include_fees) {
			/* Fill in backwards to calc amount and delay */
			for (int j = tal_count(flows[i]->path) - 1; j >= 0;
			     j--) {
				struct route_hop *rh = &r->hops[j];
				struct gossmap_node *far_end;
				const struct half_chan *h =
				    flow_edge(flows[i], j);

				if (!amount_msat_add_fee(&msat, h->base_fee,
							 h->proportional_fee))
					plugin_err(rq->plugin,
						   "Adding fee to amount");
				delay += h->delay;

				rh->scid = gossmap_chan_scid(rq->gossmap,
							     flows[i]->path[j]);
				rh->direction = flows[i]->dirs[j];
				far_end = gossmap_nth_node(rq->gossmap,
							   flows[i]->path[j],
							   !flows[i]->dirs[j]);
				gossmap_node_get_id(rq->gossmap, far_end,
						    &rh->node_id);
				rh->amount = msat;
				rh->delay = delay;
			}
		        (*amounts)[i] = flows[i]->delivers;
		} else {
			/* Fill in backwards to calc delay */
			for (int j = tal_count(flows[i]->path) - 1; j >= 0;
			     j--) {
				struct route_hop *rh = &r->hops[j];
				struct gossmap_node *far_end;
				const struct half_chan *h =
				    flow_edge(flows[i], j);

				delay += h->delay;

				rh->scid = gossmap_chan_scid(rq->gossmap,
							     flows[i]->path[j]);
				rh->direction = flows[i]->dirs[j];
				far_end = gossmap_nth_node(rq->gossmap,
							   flows[i]->path[j],
							   !flows[i]->dirs[j]);
				gossmap_node_get_id(rq->gossmap, far_end,
						    &rh->node_id);
				rh->delay = delay;
			}
			/* Compute fees forward */
			for (int j = 0; j < tal_count(flows[i]->path); j++) {
				struct route_hop *rh = &r->hops[j];
				const struct half_chan *h =
				    flow_edge(flows[i], j);

				rh->amount = msat;
                                msat = amount_msat_sub_fee(msat, h->base_fee,
							   h->proportional_fee);
			}
		        (*amounts)[i] = msat;
		}

		child_log(tmpctx, LOG_INFORM, "Flow %zu/%zu: %s",
			  i, tal_count(flows),
			  fmt_route(tmpctx, r, (*amounts)[i], finalcltv));
	}

	return routes;
}

static void json_add_getroutes(struct json_stream *js,
			       struct route **routes,
			       const struct amount_msat *amounts,
			       double probability,
			       u32 final_cltv)
{
	json_add_u64(js, "probability_ppm", (u64)(probability * 1000000));
	json_array_start(js, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		json_object_start(js, NULL);
		json_add_u64(js, "probability_ppm",
			     (u64)(routes[i]->success_prob * 1000000));
		json_add_amount_msat(js, "amount_msat", amounts[i]);
		json_add_u32(js, "final_cltv", final_cltv);
		json_array_start(js, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			struct short_channel_id_dir scidd;
			const struct route_hop *r = &routes[i]->hops[j];
			json_object_start(js, NULL);
			scidd.scid = r->scid;
			scidd.dir = r->direction;
			json_add_short_channel_id_dir(
			    js, "short_channel_id_dir", scidd);
			json_add_node_id(js, "next_node_id", &r->node_id);
			json_add_amount_msat(js, "amount_msat", r->amount);
			json_add_u32(js, "delay", r->delay);
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
}


/* Returns fd to child */
int fork_router_child(struct route_query *rq,
		      bool single_path,
		      struct timemono deadline,
		      const struct gossmap_node *srcnode,
		      const struct gossmap_node *dstnode,
		      struct amount_msat amount, struct amount_msat maxfee,
		      u32 finalcltv, u32 maxdelay,
		      bool include_fees,
		      const char *cmd_id,
		      struct json_filter *cmd_filter,
		      int *log_fd,
		      int *child_pid)
{
	int replyfds[2], logfds[2];
	double probability;
	struct flow **flows;
	struct route **routes;
	struct amount_msat *amounts;
	const char *err, *p;
	size_t len;

	if (pipe(replyfds) != 0)
		return -1;
	if (pipe(logfds) != 0) {
		close_noerr(replyfds[0]);
		close_noerr(replyfds[1]);
		return -1;
	}
	*child_pid = fork();
	if (*child_pid < 0) {
		close_noerr(replyfds[0]);
		close_noerr(replyfds[1]);
		close_noerr(logfds[0]);
		close_noerr(logfds[1]);
		return -1;
	}
	if (*child_pid != 0) {
		close(logfds[1]);
		close(replyfds[1]);
		*log_fd = logfds[0];
		return replyfds[0];
	}

	/* We are the child.  Run the algo */
	close(logfds[0]);
	close(replyfds[0]);
	set_child_log_fd(logfds[1]);
	am_child = true;
	if (single_path) {
		err = single_path_routes(rq, rq, deadline, srcnode, dstnode,
					 amount, maxfee, finalcltv,
					 maxdelay, &flows, &probability);
	} else {
		err = default_routes(rq, rq, deadline, srcnode, dstnode,
				     amount, maxfee, finalcltv, maxdelay,
				     &flows, &probability);
	}
	if (err) {
		write_all(replyfds[1], err, strlen(err));
		/* Non-zero exit tells parent this is an error string. */
		exit(1);
	}

	/* otherwise we continue */
	assert(tal_count(flows) > 0);
	child_log(tmpctx, LOG_DBG, "Final answer has %zu flows",
		  tal_count(flows));

	/* convert flows to routes */
	routes = convert_flows_to_routes(rq, rq, finalcltv, flows,
					 &amounts, include_fees);
	assert(tal_count(routes) == tal_count(flows));
	assert(tal_count(amounts) == tal_count(flows));

	/* output the results */
	struct json_stream *js = new_json_stream(tmpctx, NULL, NULL);
	json_object_start(js, NULL);
	json_add_string(js, "jsonrpc", "2.0");
	json_add_id(js, cmd_id);
	json_object_start(js, "result");
	if (cmd_filter)
		json_stream_attach_filter(js, cmd_filter);
	json_add_getroutes(js, routes, amounts, probability, finalcltv);

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
	if (!write_all(replyfds[1], p, len))
		abort();
	exit(0);
}

