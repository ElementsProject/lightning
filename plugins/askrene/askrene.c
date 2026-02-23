/* All your payment questions answered!
 *
 * This powerful oracle combines data from the network, and then
 * determines optimal routes.
 *
 * When you feed it information, these are remembered as "layers", so you
 * can ask questions with (or without) certain layers.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/clock_time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/route.h>
#include <common/status_wiregen.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/child/additional_costs.h>
#include <plugins/askrene/child/child.h>
#include <plugins/askrene/child/child_log.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>
#include <sys/wait.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

struct router_child {
	/* Inside askrene->children */
	struct list_node list;
	struct command *cmd;
	struct timemono start;
	int pid;
	struct io_conn *log_conn;
	struct io_conn *reply_conn;

	/* A whole msg read in for logging */
	u8 *log_msg;

	/* How much we've read so far */
	char *reply_buf;
	size_t reply_bytes;

	/* How much we just read (populated by io_read_partial) */
	size_t this_reply_len;
};

static bool have_layer(const char **layers, const char *name)
{
	for (size_t i = 0; i < tal_count(layers); i++) {
		if (streq(layers[i], name))
			return true;
	}
	return false;
}

/* A direction, either "in" or "out", internally handled as a boolean. */
static struct command_result *param_direction(struct command *cmd,
                                              const char *name,
                                              const char *buffer,
                                              const jsmntok_t *tok,
                                              bool **out_direction)
{
	const char *value;
	struct command_result *ret =
	    param_string(cmd, name, buffer, tok, &value);
	if (ret)
		return ret;

	*out_direction = tal(cmd, bool);
	if (streq(value, "in"))
		**out_direction = false;
	else if (streq(value, "out"))
		**out_direction = true;
	else {
		tal_free(value);
		return command_fail_badparam(
		    cmd, name, buffer, tok,
		    "Expected either in or out values.");
	}

	tal_free(value);
	return NULL;
}

/* Valid, known layers */
static struct command_result *param_layer_names(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						const char ***arr)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array");

	*arr = tal_arr(cmd, const char *, tok->size);
	json_for_each_arr(i, t, tok) {
		if (t->type != JSMN_STRING)
			return command_fail_badparam(cmd, name, buffer, t,
						     "should be a string");
		(*arr)[i] = json_strdup(*arr, buffer, t);

		/* Must be a known layer name */
		if (streq((*arr)[i], "auto.localchans")
		    || streq((*arr)[i], "auto.no_mpp_support")
		    || streq((*arr)[i], "auto.sourcefree")
		    || streq((*arr)[i], "auto.include_fees"))
			continue;
		if (!find_layer(get_askrene(cmd->plugin), (*arr)[i])) {
			return command_fail_badparam(cmd, name, buffer, t,
						     "unknown layer");
		}
	}
	return NULL;
}

static struct command_result *param_known_layer(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct layer **layer)
{
	const char *layername;
	struct command_result *ret = param_string(cmd, name, buffer, tok, &layername);
	if (ret)
		return ret;

	*layer = find_layer(get_askrene(cmd->plugin), layername);
	tal_free(layername);
	if (!*layer)
		return command_fail_badparam(cmd, name, buffer, tok, "Unknown layer");
	return NULL;
}

static struct command_result *parse_reserve_hop(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct reserve_hop *rhop)
{
	const char *err;
	const char *layername = NULL;

	err = json_scan(tmpctx, buffer, tok, "{short_channel_id_dir:%,amount_msat:%,layer?:%}",
			JSON_SCAN(json_to_short_channel_id_dir, &rhop->scidd),
			JSON_SCAN(json_to_msat, &rhop->amount),
			JSON_SCAN_TAL(tmpctx, json_strdup, &layername));
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);
	if (layername) {
		rhop->layer = find_layer(get_askrene(cmd->plugin), layername);
		if (!rhop->layer)
			return command_fail_badparam(cmd, name, buffer, tok, "Unknown layer");
	} else
		rhop->layer = NULL;

	return NULL;
}

static struct command_result *param_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct reserve_hop **path)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*path = tal_arr(cmd, struct reserve_hop, tok->size);
	json_for_each_arr(i, t, tok) {
		struct command_result *ret;

		ret = parse_reserve_hop(cmd, name, buffer, t, &(*path)[i]);
		if (ret)
			return ret;
	}
	return NULL;
}

static fp16_t *get_capacities(const tal_t *ctx,
			      struct plugin *plugin, struct gossmap *gossmap)
{
	fp16_t *caps;
	struct gossmap_chan *c;

	caps = tal_arrz(ctx, fp16_t, gossmap_max_chan_idx(gossmap));

	for (c = gossmap_first_chan(gossmap);
	     c;
	     c = gossmap_next_chan(gossmap, c)) {
		struct amount_msat cap;

		cap = gossmap_chan_get_capacity(gossmap, c);
		/* Pessimistic: round down! */
		caps[gossmap_chan_idx(gossmap, c)]
			= u64_to_fp16(cap.millisatoshis/1000, false); /* Raw: fp16 */
	}
	return caps;
}

/* If we're the payer, we don't add delay or fee to our own outgoing
 * channels.  This wouldn't be right if we looped back through ourselves,
 * but we won't. */
/* FIXME: We could cache this until gossmap/layer changes... */
static struct layer *source_free_layer(const tal_t *ctx,
				       struct askrene *askrene,
				       const struct node_id *source,
				       struct gossmap_localmods *localmods)
{
	/* We apply existing localmods so we see *all* channels */
	struct gossmap *gossmap = askrene->gossmap;
	const struct gossmap_node *srcnode;
	const struct amount_msat zero_base_fee = AMOUNT_MSAT(0);
	const u16 zero_delay = 0;
	const u32 zero_prop_fee = 0;
	struct layer *layer = new_temp_layer(ctx, askrene, "auto.sourcefree");

	/* We apply this so we see any created channels */
	gossmap_apply_localmods(gossmap, localmods);

	/* If we're not in map, we complain later */
	srcnode = gossmap_find_node(gossmap, source);

	for (size_t i = 0; srcnode && i < srcnode->num_chans; i++) {
		struct short_channel_id_dir scidd;
		const struct gossmap_chan *c;

		c = gossmap_nth_chan(gossmap, srcnode, i, &scidd.dir);
		scidd.scid = gossmap_chan_scid(gossmap, c);
		layer_add_update_channel(layer, &scidd,
					 NULL, NULL, NULL,
					 &zero_base_fee, &zero_prop_fee,
					 &zero_delay);
	}
	gossmap_remove_localmods(gossmap, localmods);

	return layer;
}

/* We're going to abuse MCF, and take the largest flow it gives and ram everything
 * through it.  This is more effective if there's at least a *chance* that can handle
 * the full amount.
 *
 * It's far from perfect, but I have very little sympathy: if you want
 * to receive amounts reliably, enable MPP.
 */
static struct layer *remove_small_channel_layer(const tal_t *ctx,
						struct askrene *askrene,
						struct amount_msat min_amount,
						struct gossmap_localmods *localmods)
{
	struct layer *layer = new_temp_layer(ctx, askrene, "auto.no_mpp_support");
	struct gossmap *gossmap = askrene->gossmap;
	struct gossmap_chan *c;

	/* We apply this so we see any created channels */
	gossmap_apply_localmods(gossmap, localmods);

	for (c = gossmap_first_chan(gossmap); c; c = gossmap_next_chan(gossmap, c)) {
		struct short_channel_id_dir scidd;
		if (amount_msat_greater_eq(gossmap_chan_get_capacity(gossmap, c),
					   min_amount))
			continue;

		scidd.scid = gossmap_chan_scid(gossmap, c);
		/* Layer will disable this in both directions */
		for (scidd.dir = 0; scidd.dir < 2; scidd.dir++) {
			const bool enabled = false;
			layer_add_update_channel(layer, &scidd, &enabled,
						 NULL, NULL, NULL, NULL, NULL);
		}
	}
	gossmap_remove_localmods(gossmap, localmods);

	return layer;
}

PRINTF_FMT(4, 5)
static const char *cmd_log(const tal_t *ctx,
			   struct command *cmd,
			   enum log_level level,
			   const char *fmt,
			   ...)
{
	va_list args;
	const char *msg;

	va_start(args, fmt);
	msg = tal_vfmt(ctx, fmt, args);
	va_end(args);

	plugin_notify_message(cmd, level, "%s", msg);

	/* Notifications already get logged at debug. Otherwise reduce
	 * severity. */
	if (level != LOG_DBG)
		plugin_log(cmd->plugin,
			   level == LOG_BROKEN ? level : level - 1,
			   "%s: %s", cmd->id, msg);
	return msg;
}

enum algorithm {
	/* Min. Cost Flow by successive shortests paths. */
	ALGO_DEFAULT,
	/* Algorithm that finds the optimal routing solution constrained to a
	 * single path. */
	ALGO_SINGLE_PATH,
};

static struct command_result *
param_algorithm(struct command *cmd, const char *name, const char *buffer,
		const jsmntok_t *tok, enum algorithm **algo)
{
	const char *algo_str = json_strdup(cmd, buffer, tok);
	*algo = tal(cmd, enum algorithm);
	if (streq(algo_str, "default"))
		**algo = ALGO_DEFAULT;
	else if (streq(algo_str, "single-path"))
		**algo = ALGO_SINGLE_PATH;
	else
		return command_fail_badparam(cmd, name, buffer, tok,
					     "unknown algorithm");
	return NULL;
}

struct getroutes_info {
	/* We keep this around in askrene->waiting if we're busy */
	struct list_node list;
	struct command *cmd;
	struct node_id source, dest;
	struct amount_msat amount, maxfee;
	u32 finalcltv, maxdelay;
	/* algorithm selection, only dev */
	enum algorithm dev_algo;
	const char **layers;
	struct additional_cost_htable *additional_costs;
	/* Non-NULL if we are told to use "auto.localchans" */
	struct layer *local_layer;
	u32 maxparts;
};

/* Gather layers, clear capacities where layers contains info */
static const struct layer **apply_layers(const tal_t *ctx,
					 struct askrene *askrene,
					 struct command *cmd,
					 const struct node_id *source,
					 struct amount_msat amount,
					 struct gossmap_localmods *localmods,
					 const char **layernames,
					 const struct layer *local_layer,
					 fp16_t *capacities)
{
	const struct layer **layers = tal_arr(ctx, const struct layer *, 0);
	/* Layers must exist, but might be special ones! */
	for (size_t i = 0; i < tal_count(layernames); i++) {
		const struct layer *l = find_layer(askrene, layernames[i]);
		if (!l) {
			if (streq(layernames[i], "auto.localchans")) {
				cmd_log(tmpctx, cmd, LOG_DBG, "Adding auto.localchans");
				l = local_layer;
			} else if (streq(layernames[i], "auto.no_mpp_support")) {
				cmd_log(tmpctx, cmd, LOG_DBG, "Adding auto.no_mpp_support, sorry");
				l = remove_small_channel_layer(layernames, askrene, amount, localmods);
			} else if (streq(layernames[i], "auto.include_fees")) {
				cmd_log(tmpctx, cmd, LOG_DBG, "Adding auto.include_fees");
				/* This layer takes effect when converting flows
				 * into routes. */
				continue;
			} else {
				assert(streq(layernames[i], "auto.sourcefree"));
				cmd_log(tmpctx, cmd, LOG_DBG, "Adding auto.sourcefree");
				l = source_free_layer(layernames, askrene, source, localmods);
			}
		}

		tal_arr_expand(&layers, l);
		/* FIXME: Implement localmods_merge, and cache this in layer? */
		layer_add_localmods(l, askrene->gossmap, localmods);

		/* Clear any entries in capacities array if we
		 * override them (incl local channels) */
		layer_clear_overridden_capacities(l, askrene->gossmap, capacities);
	}
	return layers;
}

static struct command_result *reap_child(struct router_child *child)
{
	int child_status;
	struct timerel time_delta;
	const char *err;

	waitpid(child->pid, &child_status, 0);
	time_delta = timemono_between(time_mono(), child->start);

	/* log the time of computation */
	cmd_log(tmpctx, child->cmd, LOG_DBG, "get_routes %s %" PRIu64 " ms",
		WEXITSTATUS(child_status) != 0 ? "failed after" : "completed in",
		time_to_msec(time_delta));

	if (WIFSIGNALED(child_status)) {
		err = tal_fmt(tmpctx, "child died with signal %u",
			      WTERMSIG(child_status));
		goto fail_broken;
	}

	/* This is how it indicates an error message */
	if (WEXITSTATUS(child_status) != 0 && child->reply_bytes) {
		err = tal_strndup(child, child->reply_buf, child->reply_bytes);
		goto fail;
	}
	if (child->reply_bytes == 0) {
		err = tal_fmt(child, "child produced no output (exited %i)?",
			      WEXITSTATUS(child_status));
		goto fail_broken;
	}

	/* Frees child, since it's a child of cmd */
	return command_finish_rawstr(child->cmd,
				     child->reply_buf, child->reply_bytes);

fail_broken:
	plugin_log(child->cmd->plugin, LOG_BROKEN, "%s", err);
fail:
	assert(err);
	/* Frees child, since it's a child of cmd */
	return command_fail(child->cmd, PAY_ROUTE_NOT_FOUND, "%s", err);
}

/* Last one out finalizes */
static void log_closed(struct io_conn *conn, struct router_child *child)
{
	child->log_conn = NULL;
	if (child->reply_conn == NULL)
		reap_child(child);
}

static void reply_closed(struct io_conn *conn, struct router_child *child)
{
	child->reply_conn = NULL;
	if (child->log_conn == NULL)
		reap_child(child);
}

static struct io_plan *log_msg_in(struct io_conn *conn,
				  struct router_child *child)
{
	enum log_level level;
	char *entry;
	struct node_id *peer;

	if (fromwire_status_log(tmpctx, child->log_msg, &level, &peer, &entry))
		cmd_log(tmpctx, child->cmd, level, "%s", entry);
	else {
		cmd_log(tmpctx, child->cmd, LOG_BROKEN,
			"unexpected non-log message %s",
			tal_hex(tmpctx, child->log_msg));
	}
	return io_read_wire(conn, child, &child->log_msg, log_msg_in, child);
}

static struct io_plan *child_log_init(struct io_conn *conn,
				      struct router_child *child)
{
	io_set_finish(conn, log_closed, child);
	return io_read_wire(conn, child, &child->log_msg, log_msg_in, child);
}

static size_t remaining_read_len(const struct router_child *child)
{
	return tal_bytelen(child->reply_buf) - child->reply_bytes;
}

static struct io_plan *child_reply_in(struct io_conn *conn,
				      struct router_child *child)
{
	child->reply_bytes += child->this_reply_len;
	if (remaining_read_len(child) < 64)
		tal_resize(&child->reply_buf, tal_bytelen(child->reply_buf) * 2);
	return io_read_partial(conn,
			       child->reply_buf + child->reply_bytes,
			       remaining_read_len(child),
			       &child->this_reply_len,
			       child_reply_in, child);
}

static struct io_plan *child_reply_init(struct io_conn *conn,
					struct router_child *child)
{
	io_set_finish(conn, reply_closed, child);
	child->reply_buf = tal_arr(child, char, 64);
	child->reply_bytes = 0;
	child->this_reply_len = 0;
	return child_reply_in(conn, child);
}

static void destroy_router_child(struct router_child *child)
{
	list_del(&child->list);
}

static struct command_result *do_getroutes(struct command *cmd,
					   struct gossmap_localmods *localmods,
					   struct getroutes_info *info)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	const struct gossmap_node *me;
	bool include_fees;
	const char *err;
	struct timemono deadline;
	int replyfds[2], logfds[2];
	struct router_child *child;
	const struct layer **layers;
	s8 *biases;
	fp16_t *capacities;

	/* update the gossmap */
	if (gossmap_refresh(askrene->gossmap)) {
		/* FIXME: gossmap_refresh callbacks to we can update in place */
		tal_free(askrene->capacities);
		askrene->capacities =
		    get_capacities(askrene, askrene->plugin, askrene->gossmap);
	}

	capacities = tal_dup_talarr(cmd, fp16_t, askrene->capacities);

	/* We also eliminate any local channels we *know* are dying.
	 * Most channels get 12 blocks grace in case it's a splice,
	 * but if it's us, we know about the splice already. */
	me = gossmap_find_node(askrene->gossmap, &askrene->my_id);
	if (me) {
		for (size_t i = 0; i < me->num_chans; i++) {
			struct short_channel_id_dir scidd;
			const struct gossmap_chan *c = gossmap_nth_chan(askrene->gossmap,
									me, i, NULL);
			if (!gossmap_chan_is_dying(askrene->gossmap, c))
				continue;

			scidd.scid = gossmap_chan_scid(askrene->gossmap, c);
			/* Disable both directions */
			for (scidd.dir = 0; scidd.dir < 2; scidd.dir++) {
				bool enabled = false;
				gossmap_local_updatechan(localmods,
							 &scidd,
							 &enabled,
							 NULL, NULL, NULL, NULL, NULL);
			}
		}
	}

	/* apply selected layers to the localmods */
	layers = apply_layers(cmd, askrene, cmd,
			      &info->source, info->amount, localmods,
			      info->layers, info->local_layer, capacities);

	/* Clear scids with reservations, too, so we don't have to look up
	 * all the time! */
	reserves_clear_capacities(askrene->reserved, askrene->gossmap,
				  capacities);

	/* we temporarily apply localmods */
	gossmap_apply_localmods(askrene->gossmap, localmods);

	/* localmods can add channels, so we need to allocate biases array
	 * *afterwards* */
	biases = tal_arrz(cmd, s8, gossmap_max_chan_idx(askrene->gossmap) * 2);

	/* Note any channel biases */
	for (size_t i = 0; i < tal_count(layers); i++)
		layer_apply_biases(layers[i], askrene->gossmap, biases);

	/* checkout the source */
	const struct gossmap_node *srcnode =
	    gossmap_find_node(askrene->gossmap, &info->source);
	if (!srcnode) {
		err = cmd_log(tmpctx, cmd, LOG_INFORM,
			     "Unknown source node %s",
			     fmt_node_id(tmpctx, &info->source));
		goto fail;
	}

	/* checkout the destination */
	const struct gossmap_node *dstnode =
	    gossmap_find_node(askrene->gossmap, &info->dest);
	if (!dstnode) {
		err = cmd_log(tmpctx, cmd, LOG_INFORM,
			     "Unknown destination node %s",
			     fmt_node_id(tmpctx, &info->dest));
		goto fail;
	}

	/* auto.no_mpp_support layer overrides any choice of algorithm. */
	if (have_layer(info->layers, "auto.no_mpp_support") &&
	    info->dev_algo != ALGO_SINGLE_PATH) {
		info->dev_algo = ALGO_SINGLE_PATH;
		cmd_log(tmpctx, cmd, LOG_DBG,
		       "Layer no_mpp_support is active we switch to a "
		       "single path algorithm.");
	}
	if (info->maxparts == 1 &&
	    info->dev_algo != ALGO_SINGLE_PATH) {
		info->dev_algo = ALGO_SINGLE_PATH;
		cmd_log(tmpctx, cmd, LOG_DBG,
		       "maxparts == 1: switching to a single path algorithm.");
	}

	include_fees = have_layer(info->layers, "auto.include_fees");

	child = tal(cmd, struct router_child);
	child->start = time_mono();
	deadline = timemono_add(child->start,
				time_from_sec(askrene->route_seconds));

	if (pipe(replyfds) != 0) {
		err = tal_fmt(tmpctx, "failed to create pipes: %s", strerror(errno));
		goto fail_broken;
	}
	if (pipe(logfds) != 0) {
		err = tal_fmt(tmpctx, "failed to create pipes: %s", strerror(errno));
		close_noerr(replyfds[0]);
		close_noerr(replyfds[1]);
		goto fail_broken;
	}
	child->pid = fork();
	if (child->pid < 0) {
		err = tal_fmt(tmpctx, "failed to fork: %s", strerror(errno));
		close_noerr(replyfds[0]);
		close_noerr(replyfds[1]);
		close_noerr(logfds[0]);
		close_noerr(logfds[1]);
		goto fail_broken;
	}

	if (child->pid == 0) {
		/* We are the child.  Run the algo */
		close(logfds[0]);
		close(replyfds[0]);
		set_child_log_fd(logfds[1]);

		/* Make sure we don't stomp over plugin fds, even if we have a bug */
		for (int i = 0; i < min_u64(logfds[1], replyfds[1]); i++) {
			/* stderr is maintained */
			if (i != 2)
				close(i);
		}

		/* Does not return! */
		run_child(askrene->gossmap,
			  layers,
			  biases,
			  info->additional_costs,
			  askrene->reserved,
			  take(capacities),
			  info->dev_algo == ALGO_SINGLE_PATH,
			  deadline, srcnode, dstnode, info->amount,
			  info->maxfee, info->finalcltv, info->maxdelay, info->maxparts,
			  include_fees,
			  cmd->id, cmd->filter, replyfds[1]);
		abort();
	}

	close(logfds[1]);
	close(replyfds[1]);

	/* We don't need this any more. */
	gossmap_remove_localmods(askrene->gossmap, localmods);
	child->reply_conn = io_new_conn(child, replyfds[0],
					child_reply_init, child);
	child->log_conn = io_new_conn(child, logfds[0], child_log_init, child);
	child->cmd = cmd;

	list_add_tail(&askrene->children, &child->list);
	tal_add_destructor(child, destroy_router_child);
	return command_still_pending(cmd);

fail_broken:
	plugin_log(cmd->plugin, LOG_BROKEN, "%s", err);
fail:
	assert(err);
	gossmap_remove_localmods(askrene->gossmap, localmods);
	return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "%s", err);
 }

static void add_localchan(struct gossmap_localmods *mods,
			  const struct node_id *self,
			  const struct node_id *peer,
			  const struct short_channel_id_dir *scidd,
			  struct amount_msat capacity_msat,
			  struct amount_msat htlcmin,
			  struct amount_msat htlcmax,
			  struct amount_msat spendable,
			  struct amount_msat max_total_htlc,
			  struct amount_msat fee_base,
			  u32 fee_proportional,
			  u16 cltv_delta,
			  bool enabled,
			  const char *buf,
			  const jsmntok_t *chantok,
			  struct getroutes_info *info)
{
	u32 feerate;
	const char *opener;
	const char *err;

	/* We get called twice, once in each direction: only create once. */
	if (!layer_find_local_channel(info->local_layer, scidd->scid))
		layer_add_local_channel(info->local_layer,
					self, peer, scidd->scid, capacity_msat);
	layer_add_update_channel(info->local_layer, scidd,
				 &enabled,
				 &htlcmin, &htlcmax,
				 &fee_base, &fee_proportional, &cltv_delta);

	/* We also need to know the feerate and opener, so we can calculate per-HTLC cost */
	feerate = 0; /* Can be unset on unconfirmed channels */
	err = json_scan(tmpctx, buf, chantok,
			"{feerate?:{perkw:%},opener:%}",
			JSON_SCAN(json_to_u32, &feerate),
			JSON_SCAN_TAL(tmpctx, json_strdup, &opener));
	if (err) {
		plugin_log(info->cmd->plugin, LOG_BROKEN,
			   "Cannot scan channel for feerate and owner (%s): %.*s",
			   err, json_tok_full_len(chantok), json_tok_full(buf, chantok));
		return;
	}

	if (feerate != 0 && streq(opener, "local")) {
		/* BOLT #3:
		 * The base fee for a commitment transaction:
		 *   - MUST be calculated to match:
		 *     1. Start with `weight` = 724 (1124 if `option_anchors` applies).
		 *     2. For each committed HTLC, if that output is not trimmed as specified in
		 *     [Trimmed Outputs](#trimmed-outputs), add 172 to `weight`.
		 *     3. Multiply `feerate_per_kw` by `weight`, divide by 1000 (rounding down).
		 */
		struct per_htlc_cost *phc
			= tal(info->additional_costs, struct per_htlc_cost);

		phc->scidd = *scidd;
		if (!amount_sat_to_msat(&phc->per_htlc_cost,
					amount_tx_fee(feerate, 172))) {
			/* Can't happen, since feerate is u32... */
			abort();
		}

		plugin_log(info->cmd->plugin, LOG_DBG, "Per-htlc cost for %s = %s (%u x 172)",
			   fmt_short_channel_id_dir(tmpctx, scidd),
			   fmt_amount_msat(tmpctx, phc->per_htlc_cost),
			   feerate);
		additional_cost_htable_add(info->additional_costs, phc);
	}

	/* can't send more than expendable and no more than max_total_htlc */
	struct amount_msat max_msat = amount_msat_min(spendable, max_total_htlc);
	/* Known capacity on local channels (ts = max) */
	layer_add_constraint(info->local_layer, scidd, UINT64_MAX, &max_msat, &max_msat);
}

static struct command_result *
listpeerchannels_done(struct command *cmd,
		      const char *method UNUSED,
		      const char *buffer,
		      const jsmntok_t *toks,
		      struct getroutes_info *info)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct gossmap_localmods *localmods;

	info->local_layer = new_temp_layer(info, askrene, "auto.localchans");
	localmods = gossmods_from_listpeerchannels(cmd,
						   &askrene->my_id,
						   buffer, toks,
						   false,
						   add_localchan,
						   info);

	return do_getroutes(cmd, localmods, info);
}

/* Mutual recursion */
static struct command_result *begin_request(struct askrene *askrene,
					    struct getroutes_info *info);

/* One is finished.  Maybe wake up a waiter */
static void destroy_live_command(struct command *cmd)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct getroutes_info *info;

	assert(askrene->num_live_requests > 0);
	askrene->num_live_requests--;

	if (askrene->num_live_requests >= askrene->max_children)
		return;

	info = list_pop(&askrene->waiters, struct getroutes_info, list);
	if (info)
		begin_request(askrene, info);
}

static struct command_result *begin_request(struct askrene *askrene,
					    struct getroutes_info *info)
{
	askrene->num_live_requests++;

	/* Wake any waiting ones when we're finished */
	tal_add_destructor(info->cmd, destroy_live_command);

	if (have_layer(info->layers, "auto.localchans")) {
		struct out_req *req;

		req = jsonrpc_request_start(info->cmd,
					    "listpeerchannels",
					    listpeerchannels_done,
					    forward_error, info);
		return send_outreq(req);
	} else
		info->local_layer = NULL;

	return do_getroutes(info->cmd, gossmap_localmods_new(info->cmd), info);
}

static struct command_result *json_getroutes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	/* BOLT #4:
	 * ## `max_htlc_cltv` Selection
	 *
	 * This ... value is defined as 2016 blocks, based on
	 * historical value deployed by Lightning implementations.
	 */
	/* FIXME: Typo in spec for CLTV in descripton! But it breaks our spelling check, so we omit it above */
	const u32 maxdelay_allowed = 2016;
	struct askrene *askrene = get_askrene(cmd->plugin);
	const u32 default_maxparts = 100;
	struct getroutes_info *info = tal(cmd, struct getroutes_info);
	/* param functions require pointers */
	struct node_id *source, *dest;
	struct amount_msat *amount, *maxfee;
	u32 *finalcltv, *maxdelay;
	enum algorithm *dev_algo;
	u32 *maxparts;

	if (!param_check(cmd, buffer, params,
			 p_req("source", param_node_id, &source),
			 p_req("destination", param_node_id, &dest),
			 p_req("amount_msat", param_msat, &amount),
			 p_req("layers", param_layer_names, &info->layers),
			 p_req("maxfee_msat", param_msat, &maxfee),
			 p_req("final_cltv", param_u32, &finalcltv),
			 p_opt_def("maxdelay", param_u32, &maxdelay,
				   maxdelay_allowed),
			 p_opt_def("maxparts", param_u32, &maxparts,
				   default_maxparts),
			 p_opt_dev("dev_algorithm", param_algorithm,
				   &dev_algo, ALGO_DEFAULT),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (amount_msat_is_zero(*amount)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "amount must be non-zero");
	}

	if (maxparts == 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "maxparts must be non-zero");
	}

	if (*maxdelay > maxdelay_allowed) {
		return command_fail(cmd, PAY_USER_ERROR,
				    "maximum delay allowed is %d",
				    maxdelay_allowed);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	info->cmd = cmd;
	info->source = *source;
	info->dest = *dest;
	info->amount = *amount;
	info->maxfee = *maxfee;
	info->finalcltv = *finalcltv;
	info->maxdelay = *maxdelay;
	info->dev_algo = *dev_algo;
	info->additional_costs = new_htable(info, additional_cost_htable);
	info->maxparts = *maxparts;

	if (askrene->num_live_requests >= askrene->max_children) {
		cmd_log(tmpctx, cmd, LOG_INFORM,
			"Too many running at once (%zu vs %u): waiting",
			askrene->num_live_requests, askrene->max_children);
		list_add_tail(&askrene->waiters, &info->list);
		return command_still_pending(cmd);
	}

	return begin_request(askrene, info);
}

static struct command_result *json_askrene_reserve(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct reserve_hop *path;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	for (size_t i = 0; i < tal_count(path); i++)
		reserve_add(askrene->reserved, &path[i], cmd->id);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_unreserve(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *params)
{
	struct reserve_hop *path;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);
	bool *remove_all;

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   p_opt_dev("dev_remove_all", param_bool, &remove_all, false),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (*remove_all) {
		reserve_remove_all(askrene->reserved);
	} else {
		for (size_t i = 0; i < tal_count(path); i++) {
			if (!reserve_remove(askrene->reserved, &path[i])) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Unknown reservation for %s%s%s",
						    fmt_short_channel_id_dir(tmpctx,
									     &path[i].scidd),
						    path[i].layer ? " on layer " : "",
						    path[i].layer ? layer_name(path[i].layer) : "");
			}
		}
	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listreservations(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct json_stream *response;

	/* FIXME: We could allow layer names here? */
	if (!param(cmd, buffer, params,
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	response = jsonrpc_stream_success(cmd);
	json_add_reservations(response, askrene->reserved, "reservations", NULL);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_create_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	struct layer *layer;
	struct node_id *src, *dst;
	struct short_channel_id *scid;
	struct amount_msat *capacity;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_known_layer, &layer),
			 p_req("source", param_node_id, &src),
			 p_req("destination", param_node_id, &dst),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("capacity_msat", param_msat, &capacity),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (layer_find_local_channel(layer, *scid)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "channel already exists");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	layer_add_local_channel(layer, src, dst, *scid, *capacity);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_update_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	bool *enabled;
	struct amount_msat *htlc_min, *htlc_max, *base_fee;
	u32 *proportional_fee;
	u16 *delay;
	struct json_stream *response;

 	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
		   p_opt("enabled", param_bool, &enabled),
		   p_opt("htlc_minimum_msat", param_msat, &htlc_min),
		   p_opt("htlc_maximum_msat", param_msat, &htlc_max),
		   p_opt("fee_base_msat", param_msat, &base_fee),
		   p_opt("fee_proportional_millionths", param_u32, &proportional_fee),
		   p_opt("cltv_expiry_delta", param_u16, &delay),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	layer_add_update_channel(layer, scidd,
				 enabled,
				 htlc_min, htlc_max,
				 base_fee, proportional_fee, delay);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

enum inform {
	INFORM_CONSTRAINED,
	INFORM_UNCONSTRAINED,
	INFORM_SUCCEEDED,
};

static struct command_result *param_inform(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum inform **inform)
{
	*inform = tal(cmd, enum inform);
	if (json_tok_streq(buffer, tok, "constrained"))
		**inform = INFORM_CONSTRAINED;
	else if (json_tok_streq(buffer, tok, "unconstrained"))
		**inform = INFORM_UNCONSTRAINED;
	else if (json_tok_streq(buffer, tok, "succeeded"))
		**inform = INFORM_SUCCEEDED;
	else
		command_fail_badparam(cmd, name, buffer, tok,
				      "must be constrained/unconstrained/succeeded");
	return NULL;
}

static struct command_result *json_askrene_inform_channel(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	struct json_stream *response;
	struct amount_msat *amount;
	enum inform *inform;
	const struct constraint *c;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_known_layer, &layer),
			 p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
			 p_req("amount_msat", param_msat, &amount),
			 p_req("inform", param_inform, &inform),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	switch (*inform) {
	case INFORM_CONSTRAINED:
		/* It didn't pass, so minimal assumption is that reserve was all used
		 * then there we were one msat short. */
		if (!reserve_accumulate(askrene->reserved, scidd, layer, amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Amount overflow with reserves");
		if (!amount_msat_deduct(amount, AMOUNT_MSAT(1)))
			*amount = AMOUNT_MSAT(0);
		if (command_check_only(cmd))
			return command_check_done(cmd);
		c = layer_add_constraint(layer, scidd, clock_time().ts.tv_sec,
					 NULL, amount);
		goto output;
	case INFORM_UNCONSTRAINED:
		/* It passed, so the capacity is at least this much (minimal assumption is
		 * that no reserves were used) */
		if (command_check_only(cmd))
			return command_check_done(cmd);
		c = layer_add_constraint(layer, scidd, clock_time().ts.tv_sec,
					 amount, NULL);
		goto output;
	case INFORM_SUCCEEDED:
		/* FIXME: We could do something useful here! */
		c = NULL;
		goto output;
	}
	abort();

output:
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "constraints");
	if (c)
		json_add_constraint(response, NULL, c, layer);
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *param_s8_hundred(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       s8 **v)
{
	s64 s64val;

	if (!json_to_s64(buffer, tok, &s64val)
	    || s64val < -100
	    || s64val > 100)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be a number between -100 and 100");
	*v = tal(cmd, s8);
	**v = s64val;
	return NULL;
}

static struct command_result *json_askrene_bias_channel(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	struct json_stream *response;
	const char *description;
	s8 *bias;
	const struct bias *b;
	bool *relative;
	u64 timestamp;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
		   p_req("bias", param_s8_hundred, &bias),
		   p_opt("description", param_string, &description),
		   p_opt_def("relative", param_bool, &relative, false),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	timestamp = clock_time().ts.tv_sec;
	b = layer_set_bias(layer, scidd, description, *bias, *relative,
			   timestamp);
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "biases");
	if (b)
		json_add_bias(response, NULL, b, layer);
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_bias_node(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *params)
{
	struct layer *layer;
	struct node_id *node;
        struct json_stream *response;
	const char *description;
	s8 *bias;
	const struct node_bias *b;
	bool *relative;
	bool *out_dir;
	u64 timestamp;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("node", param_node_id, &node),
		   p_req("direction", param_direction, &out_dir),
		   p_req("bias", param_s8_hundred, &bias),
		   p_opt("description", param_string, &description),
		   p_opt_def("relative", param_bool, &relative, false),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	timestamp = clock_time().ts.tv_sec;
	b = layer_set_node_bias(layer, node, description, *bias, *relative,
				*out_dir, timestamp);
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "node_biases");
	if (b)
		json_add_node_bias(response, NULL, b, layer);
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_disable_node(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct node_id *node;
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("node", param_node_id, &node),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	/* We save this in the layer, because they want us to disable all the channels
	 * to the node at *use* time (a new channel might be gossiped!). */
	layer_add_disabled_node(layer, node);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_create_layer(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	const char *layername;
	struct json_stream *response;
	bool *persistent;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_string, &layername),
			 p_opt_def("persistent", param_bool, &persistent, false),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (strstarts(layername, "auto."))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot create auto layer");

	/* If it's persistent, creation is a noop if it already exists */
	layer = find_layer(askrene, layername);
	if (layer && !*persistent) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Layer already exists");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!layer)
		layer = new_layer(askrene, layername, *persistent);

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_remove_layer(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	remove_layer(layer);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listlayers(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("layer", param_known_layer, &layer),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_age(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	struct layer *layer;
	struct json_stream *response;
	u64 *cutoff;
	size_t num_removed;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("cutoff", param_u64, &cutoff),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	num_removed = layer_trim_constraints(layer, *cutoff);

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "layer", layer_name(layer));
	json_add_u64(response, "num_removed", num_removed);
	return command_finished(cmd, response);
}

static const struct plugin_command commands[] = {
	{
		"getroutes",
		json_getroutes,
	},
	{
		"askrene-listreservations",
		json_askrene_listreservations,
	},
	{
		"askrene-reserve",
		json_askrene_reserve,
	},
	{
		"askrene-unreserve",
		json_askrene_unreserve,
	},
	{
		"askrene-disable-node",
		json_askrene_disable_node,
	},
	{
		"askrene-create-channel",
		json_askrene_create_channel,
	},
	{
		"askrene-update-channel",
		json_askrene_update_channel,
	},
	{
		"askrene-inform-channel",
		json_askrene_inform_channel,
	},
	{
		"askrene-bias-channel",
		json_askrene_bias_channel,
	},
	{
		"askrene-bias-node",
		json_askrene_bias_node,
	},
	{
		"askrene-create-layer",
		json_askrene_create_layer,
	},
	{
		"askrene-remove-layer",
		json_askrene_remove_layer,
	},
	{
		"askrene-listlayers",
		json_askrene_listlayers,
	},
	{
		"askrene-age",
		json_askrene_age,
	},
};

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct plugin *plugin = init_cmd->plugin;
	struct askrene *askrene = get_askrene(plugin);

	askrene->plugin = plugin;
	askrene->layers = new_layer_name_hash(askrene);
	list_head_init(&askrene->children);
	list_head_init(&askrene->waiters);
	askrene->num_live_requests = 0;
	askrene->reserved = new_reserve_htable(askrene);
	askrene->gossmap = gossmap_load(askrene, GOSSIP_STORE_FILENAME,
					plugin_gossmap_logcb, plugin);

	if (!askrene->gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	askrene->capacities = get_capacities(askrene, askrene->plugin, askrene->gossmap);
	rpc_scan(init_cmd, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &askrene->my_id));

	plugin_set_data(plugin, askrene);

	load_layers(askrene, init_cmd);

	/* Layer needs its own command to write to the datastore */
	askrene->layer_cmd = aux_command(init_cmd);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct askrene *askrene;
	setup_locale();

	askrene = tal(NULL, struct askrene);
	askrene->route_seconds = 10;
	askrene->max_children = 4;
	plugin_main(argv, init, take(askrene), PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option_dynamic("askrene-timeout",
					  "int",
					  "How many seconds to try before giving up on calculating a route."
					  " Defaults to 10 seconds",
					  u32_option, u32_jsonfmt,
					  &askrene->route_seconds),
		    plugin_option_dynamic("askrene-max-threads",
					  "int",
					  "How many routes to calculate at once."
					  " Defaults to 4",
					  u32_option, u32_jsonfmt,
					  &askrene->max_children),
		    NULL);
}
