#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/json_out/json_out.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/features.h>
#include <common/hsm_encryption.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/scb_wiregen.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <plugins/libplugin.h>
#include <sodium.h>
#include <unistd.h>

#define HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

#define FILENAME "emergency.recover"

/* VERSION is the current version of the data encrypted in the file */
#define VERSION ((u64)1)

/* How many peers do we send a backup to? */
#define NUM_BACKUP_PEERS 2

struct peer_backup {
	struct node_id peer;
	/* Empty if it's a placeholder */
	const u8 *data;
};

static const struct node_id *peer_backup_keyof(const struct peer_backup *pb)
{
	return &pb->peer;
}

static bool peer_backup_eq_node_id(const struct peer_backup *pb,
				   const struct node_id *id)
{
	return node_id_eq(&pb->peer, id);
}

HTABLE_DEFINE_NODUPS_TYPE(struct peer_backup,
			  peer_backup_keyof,
			  node_id_hash,
			  peer_backup_eq_node_id,
			  backup_map);

HTABLE_DEFINE_NODUPS_TYPE(struct node_id,
			  node_id_keyof,
			  node_id_hash,
			  node_id_eq,
			  peer_map);

struct chanbackup {
	/* Do we send/acccept peer backups? */
	bool send_our_peer_backup;
	bool handle_their_peer_backup;

	/* Global secret object to keep the derived encryption key for the SCB */
	struct secret secret;

	/* Cache of backups for each peer we know about */
	struct backup_map *backups;

	/* Cache of known peers which support backups (for sending) */
	struct peer_map *peers;
};

static struct chanbackup *chanbackup(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct chanbackup);
}

/* Must not already exist in map! */
static struct peer_backup *add_to_backup_map(struct chanbackup *cb,
					     const struct node_id *peer,
					     const u8 *data TAKES)
{
	struct peer_backup *pb = tal(cb->backups, struct peer_backup);
	pb->peer = *peer;
	pb->data = tal_dup_talarr(pb, u8, data);
	backup_map_add(cb->backups, pb);
	return pb;
}

static void remove_peer(struct plugin *plugin, const struct node_id *node_id)
{
	struct chanbackup *cb = chanbackup(plugin);
	struct node_id *peer;

	/* Eliminate it (probably it's disconnected) */
	peer = peer_map_get(cb->peers, node_id);
	if (peer) {
		peer_map_del(cb->peers, peer);
		tal_free(peer);
	}
}

/* Helper to fetch out SCB from the RPC call */
static bool json_to_scb_chan(const char *buffer,
			     const jsmntok_t *tok,
			     struct modern_scb_chan ***channels)
{
	size_t i;
	const jsmntok_t *t;
	*channels = tok->size ? tal_arr(tmpctx,
					struct modern_scb_chan *,
					tok->size) : NULL;

	json_for_each_arr(i, t, tok) {
		const u8 *scb_tmp = tal_hexdata(tmpctx,
						json_strdup(tmpctx,
							    buffer,
							    t),
						strlen(json_strdup(tmpctx,
								   buffer,
								   t)));
		size_t scblen_tmp = tal_count(scb_tmp);

		(*channels)[i] = fromwire_modern_scb_chan(tmpctx,
							  &scb_tmp,
							  &scblen_tmp);
	}

	return true;
}

/* This writes encrypted static backup in the recovery file */
static void write_scb(struct plugin *p,
                      int fd,
		      struct modern_scb_chan **scb_chan_arr)
{
	const struct chanbackup *cb = chanbackup(p);
	u32 timestamp = time_now().ts.tv_sec;

	u8 *decrypted_scb = towire_static_chan_backup_with_tlvs(tmpctx,
						      		VERSION,
						      		timestamp,
						      		cast_const2(const struct modern_scb_chan **,
						      		  	    scb_chan_arr));

	u8 *encrypted_scb = tal_arr(tmpctx,
				    u8,
				    tal_bytelen(decrypted_scb) +
				    ABYTES +
				    HEADER_LEN);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state,
							    encrypted_scb,
							    cb->secret.data) != 0)
	{
		plugin_err(p, "Can't encrypt the data!");
		return;
	}

	if (crypto_secretstream_xchacha20poly1305_push(&crypto_state,
						       encrypted_scb +
						       HEADER_LEN,
						       NULL, decrypted_scb,
						       tal_bytelen(decrypted_scb),
						       /* Additional data and tag */
						       NULL, 0, 0)) {
		plugin_err(p, "Can't encrypt the data!");
		return;
	}

	if (!write_all(fd, encrypted_scb, tal_bytelen(encrypted_scb))) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "Writing encrypted SCB: %s",
			   strerror(errno));
	}

}

/* checks if the SCB file exists, creates a new one in case it doesn't. */
static void maybe_create_new_scb(struct plugin *p,
				 struct modern_scb_chan **channels)
{

	/* Note that this is opened for write-only, even though the permissions
	 * are set to read-only.  That's perfectly valid! */
	int fd = open(FILENAME, O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* Don't do anything if the file already exists. */
		if (errno == EEXIST)
			return;
		plugin_err(p, "creating: %s", strerror(errno));
	}

	/* Comes here only if the file haven't existed before */
	unlink_noerr(FILENAME);

	/* This couldn't give EEXIST because we call unlink_noerr("scb.tmp")
	 * in INIT */
	fd = open("scb.tmp", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0)
		plugin_err(p, "Opening: %s", strerror(errno));

	plugin_log(p, LOG_INFORM, "Creating Emergency Recovery");

	write_scb(p, fd, channels);

	/* fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "fsync : %s", strerror(errno));
	}

	/* This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "closing: %s", strerror(errno));
	}

	/* We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0)
		plugin_err(p, "Opening: %s", strerror(errno));

	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
		plugin_err(p, "closing: %s", strerror(errno));
	}

	/* This will never fail, if fsync worked! */
	close(fd);

	/* This will update the scb file */
	rename("scb.tmp", FILENAME);
}

static u8 *get_file_data(const tal_t *ctx, struct plugin *p)
{
	u8 *scb = grab_file(ctx, FILENAME);
	if (!scb) {
		plugin_err(p, "Cannot read emergency.recover: %s", strerror(errno));
	} else {
		/* grab_file adds nul term */
		tal_resize(&scb, tal_bytelen(scb) - 1);
	}
	return scb;
}

/* Returns decrypted SCB in form of a u8 array */
static u8 *decrypt_scb(struct plugin *p)
{
	const struct chanbackup *cb = chanbackup(p);
	u8 *filedata = get_file_data(tmpctx, p);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (tal_bytelen(filedata) < ABYTES +
	    HEADER_LEN)
		plugin_err(p, "SCB file is corrupted!");

	u8 *decrypt_scb = tal_arr(tmpctx, u8, tal_bytelen(filedata) -
				  ABYTES -
				  HEADER_LEN);

	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
							    filedata,
							    cb->secret.data) != 0)
	{
		plugin_err(p, "SCB file is corrupted!");
	}

	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, decrypt_scb,
						       NULL, 0,
						       filedata +
						       HEADER_LEN,
						       tal_bytelen(filedata)-
						       HEADER_LEN,
						       NULL, 0) != 0) {
		plugin_err(p, "SCB file is corrupted!");
	}
	return decrypt_scb;
}

static struct command_result *after_recover_rpc(struct command *cmd,
						const char *method,
					        const char *buf,
					        const jsmntok_t *params,
					        void *cb_arg UNUSED)
{

	size_t i;
	const jsmntok_t *t;
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);

	json_for_each_obj(i, t, params)
		json_add_tok(response, json_strdup(tmpctx, buf, t), t+1, buf);

	return command_finished(cmd, response);
}

static struct modern_scb_chan *convert_from_legacy(const tal_t *ctx, struct legacy_scb_chan *legacy_scb_chan) {
	struct modern_scb_chan *modern_scb_tlv = tal(ctx, struct modern_scb_chan);
	modern_scb_tlv->id = legacy_scb_chan->id;
	modern_scb_tlv->addr = legacy_scb_chan->addr;
	modern_scb_tlv->node_id = legacy_scb_chan->node_id;
	modern_scb_tlv->cid = legacy_scb_chan->cid;
	modern_scb_tlv->funding = legacy_scb_chan->funding;
	modern_scb_tlv->funding_sats = legacy_scb_chan->funding_sats;
	modern_scb_tlv->type = legacy_scb_chan->type;
	modern_scb_tlv->tlvs = tlv_scb_tlvs_new(ctx);
	return modern_scb_tlv;
}

/* Recovers the channels by making RPC to `recoverchannel` */
static struct command_result *json_emergencyrecover(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	struct out_req *req;
	u64 version;
	u32 timestamp;
	struct legacy_scb_chan **scb;
	struct modern_scb_chan **scb_tlvs;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	u8 *res = decrypt_scb(cmd->plugin);
	bool is_tlvs = false;
	if (!fromwire_static_chan_backup(cmd,
                                         res,
                                         &version,
                                         &timestamp,
                                         &scb)) {
		if(!fromwire_static_chan_backup_with_tlvs(cmd,
							  res,
							  &version,
							  &timestamp,
							  &scb_tlvs)) {
			plugin_err(cmd->plugin, "Corrupted SCB!");
		}
		is_tlvs = true;
	}

	if ((version & 0x5555555555555555ULL) != (VERSION & 0x5555555555555555ULL)) {
		plugin_err(cmd->plugin,
                           "Incompatible emergencyrecover version: loaded version %"PRIu64", expected version %"PRIu64". Contact the admin!", version, VERSION);
	}

	req = jsonrpc_request_start(cmd, "recoverchannel",
				    after_recover_rpc,
				    forward_error, NULL);

	json_array_start(req->js, "scb");
	if (is_tlvs) {
		for (size_t i=0; i<tal_count(scb_tlvs); i++) {
			u8 *scb_hex = tal_arr(cmd, u8, 0);
			towire_modern_scb_chan(&scb_hex,scb_tlvs[i]);
			json_add_hex_talarr(req->js, NULL, scb_hex);
		}
	} else {
		plugin_notify_message(cmd, LOG_DBG, "Processing legacy emergency.recover file format. "
				      "Please migrate to the latest file format for improved "
				      "compatibility and fund recovery.");

		for (size_t i=0; i<tal_count(scb); i++) {
			u8 *scb_hex = tal_arr(cmd, u8, 0);
			struct modern_scb_chan *tmp_scb = convert_from_legacy(cmd, scb[i]);
			towire_modern_scb_chan(&scb_hex, tmp_scb);
			json_add_hex_talarr(req->js, NULL, scb_hex);
		}
	}

	json_array_end(req->js);

	return send_outreq(req);
}

static void update_scb(struct plugin *p, struct modern_scb_chan **channels)
{

	/* If the temp file existed before, remove it */
	unlink_noerr("scb.tmp");

	int fd = open("scb.tmp", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd<0)
		plugin_err(p, "Opening: %s", strerror(errno));

	plugin_log(p, LOG_DBG, "Updating the SCB file...");

	write_scb(p, fd, channels);

	/* fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
	}

	/* This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("scb.tmp");
	}
	/* We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		plugin_log(p, LOG_DBG, "Opening: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("scb.tmp");
	}
	close(fd);

	/* This will atomically replace the main file */
	rename("scb.tmp", FILENAME);
}


static struct command_result
*peer_after_send_their_peer_strg(struct command *cmd,
				 const char *method,
				 const char *buf,
				 const jsmntok_t *params,
				 struct node_id *node_id)
{
        plugin_log(cmd->plugin, LOG_DBG, "Sent their peer storage!");
	return command_hook_success(cmd);
}

static struct command_result
*peer_after_send_their_peer_strg_err(struct command *cmd,
				     const char *method,
				     const char *buf,
				     const jsmntok_t *params,
				     struct node_id *node_id)
{
        plugin_log(cmd->plugin, LOG_DBG, "Unable to send Peer storage!");
	remove_peer(cmd->plugin, node_id);
	return command_hook_success(cmd);
}

static struct command_result *send_peers_scb(struct command *cmd,
					     struct node_id *nodeid)
{
	const struct chanbackup *cb = chanbackup(cmd->plugin);
	struct peer_backup *pb;
        struct out_req *req;
	const u8 *msg;

	if (!cb->handle_their_peer_backup)
		return command_hook_success(cmd);

	/* Now send their backup, if any. */
	pb = backup_map_get(cb->backups, nodeid);
	if (!pb || tal_bytelen(pb->data) == 0)
		return command_hook_success(cmd);

        msg = towire_peer_storage_retrieval(cmd, pb->data);

        plugin_log(cmd->plugin, LOG_DBG,
                   "sending their backup from our datastore");

        req = jsonrpc_request_start(cmd,
                                    "sendcustommsg",
                                    peer_after_send_their_peer_strg,
                                    peer_after_send_their_peer_strg_err,
                                    nodeid);

        json_add_node_id(req->js, "node_id", nodeid);
	json_add_hex_talarr(req->js, "msg", msg);

        return send_outreq(req);
}

static struct command_result *peer_after_send_scb(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *params,
						  struct node_id *nodeid)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage sent!");

	return send_peers_scb(cmd, nodeid);
}

static struct command_result *peer_after_send_scb_failed(struct command *cmd,
							 const char *method,
							 const char *buf,
							 const jsmntok_t *params,
							 struct node_id *nodeid)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage send failed %.*s!",
		   json_tok_full_len(params), json_tok_full(buf, params));
	remove_peer(cmd->plugin, nodeid);
	return command_hook_success(cmd);
}

struct info {
	size_t *idx;
	struct node_id node_id;
};

/* We refresh scb from both channel_state_changed notification and
   on_commitment_revocation hook.  Both have to be terminated
   differently. */
static struct command_result *notification_or_hook_done(struct command *cmd)
{
	if (cmd->type == COMMAND_TYPE_NOTIFICATION)
		return notification_handled(cmd);
	assert(cmd->type == COMMAND_TYPE_HOOK);
	return command_hook_success(cmd);
}

static struct command_result *after_send_scb_single(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *params,
						    struct info *info)
{
        plugin_log(cmd->plugin, LOG_TRACE, "Peer storage sent!");
	if (--(*info->idx) != 0)
		return command_still_pending(cmd);

	return notification_or_hook_done(cmd);
}

static struct command_result *after_send_scb_single_fail(struct command *cmd,
							 const char *method,
							 const char *buf,
							 const jsmntok_t *params,
							 struct info *info)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage send failed!");
	remove_peer(cmd->plugin, &info->node_id);
	if (--(*info->idx) != 0)
		return command_still_pending(cmd);

	return notification_or_hook_done(cmd);
}

static bool already_have_node_id(const struct node_id *ids,
				 const struct node_id *id)
{
	for (size_t i = 0; i < tal_count(ids); i++)
		if (node_id_eq(&ids[i], id))
			return true;

	return false;
}

static const struct node_id *random_peers(const tal_t *ctx,
					  const struct chanbackup *cb)
{
	struct peer_map_iter it;
	const struct node_id *peer;
	struct node_id *ids = tal_arr(ctx, struct node_id, 0);

	/* Simple case: pick all of them */
	if (peer_map_count(cb->peers) <= NUM_BACKUP_PEERS) {
		for (peer = peer_map_first(cb->peers, &it);
		     peer;
		     peer = peer_map_next(cb->peers, &it)) {
			tal_arr_expand(&ids, *peer);
		}
	} else {
		while (peer_map_count(cb->peers) < NUM_BACKUP_PEERS) {
			peer = peer_map_pick(cb->peers, pseudorand_u64(), &it);
			if (already_have_node_id(ids, peer))
				continue;
			tal_arr_expand(&ids, *peer);
		}
	}
	return ids;
}

static struct command_result *send_to_peers(struct command *cmd)
{
        struct out_req *req;
	size_t *idx = tal(cmd, size_t);
        u8 *serialise_scb, *data;
	const struct node_id *peers;
	struct chanbackup *cb = chanbackup(cmd->plugin);

	if (!cb->send_our_peer_backup)
		return notification_or_hook_done(cmd);

	/* BOLT #1:
	 * The sender of `peer_storage`:
	 *   - MAY send `peer_storage` whenever necessary.
	 *   - MUST limit its `blob` to 65531 bytes.
	 *   - MUST encrypt the data in a manner that ensures its integrity
	 *     upon receipt.
	 *   - SHOULD pad the `blob` to ensure its length is always exactly 65531 bytes.
	 */
	/* FIXME: We do not pad!  But this is because LDK doesn't store > 1k anyway */
	data = get_file_data(tmpctx, cmd->plugin);
	if (tal_bytelen(data) > 65531) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Peer backup would be %zu bytes.  That is too large: disabling peer backups!",
			   tal_bytelen(data));
		cb->send_our_peer_backup = false;
		return notification_or_hook_done(cmd);
	}
	serialise_scb = towire_peer_storage(cmd, data);

	peers = random_peers(tmpctx, cb);
	*idx = tal_count(peers);
	for (size_t i = 0; i < tal_count(peers); i++) {
		struct info *info = tal(cmd, struct info);

		info->idx = idx;
		info->node_id = peers[i];

		req = jsonrpc_request_start(cmd,
					    "sendcustommsg",
					    after_send_scb_single,
					    after_send_scb_single_fail,
					    info);

		json_add_node_id(req->js, "node_id", &info->node_id);
		json_add_hex_talarr(req->js, "msg", serialise_scb);
		send_outreq(req);
	}

	if (*idx == 0)
		return notification_or_hook_done(cmd);
	return command_still_pending(cmd);
}

static struct command_result *after_staticbackup(struct command *cmd,
						 const char *method,
					         const char *buf,
					         const jsmntok_t *params,
					         void *cb_arg UNUSED)
{
	struct modern_scb_chan **scb_chan;
	const jsmntok_t *scbs = json_get_member(buf, params, "scb");

	json_to_scb_chan(buf, scbs, &scb_chan);
	plugin_log(cmd->plugin, LOG_DBG, "Updating the SCB");

	update_scb(cmd->plugin, scb_chan);
	return send_to_peers(cmd);
}

/* Write to the datastore */
static struct command_result *commit_peer_backup(struct command *cmd,
						 const struct peer_backup *pb)
{
	return jsonrpc_set_datastore_binary(cmd,
					    tal_fmt(cmd,
						    "chanbackup/peers/%s",
						    fmt_node_id(tmpctx,
								&pb->peer)),
					    pb->data, tal_bytelen(pb->data),
					    "create-or-replace",
					    NULL, NULL, NULL);
}

static struct command_result *json_state_changed(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params)
{
	struct chanbackup *cb = chanbackup(cmd->plugin);
	const jsmntok_t *notiftok = json_get_member(buf,
                                                    params,
                                                    "channel_state_changed"),
		*statetok = json_get_member(buf, notiftok, "new_state");

	if (json_tok_streq(buf, statetok, "CLOSED") ||
	    json_tok_streq(buf, statetok, "CHANNELD_AWAITING_LOCKIN") ||
	    json_tok_streq(buf, statetok, "DUALOPEND_AWAITING_LOCKIN")) {
		struct out_req *req;
		req = jsonrpc_request_start(cmd,
                                            "staticbackup",
                                            after_staticbackup,
					    log_broken_and_complete,
                                            NULL);

		return send_outreq(req);
	}

	/* Once it has a normal channel, we will start storing its
	 * backups: put an empty record in place. */
	if (json_tok_streq(buf, statetok, "CHANNELD_NORMAL")) {
		const jsmntok_t *nodeid_tok;
		struct node_id node_id;

		nodeid_tok = json_get_member(buf, notiftok, "peer_id");
		if (!json_to_node_id(buf, nodeid_tok, &node_id))
			plugin_err(cmd->plugin, "Invalid peer_id in %.*s",
				   json_tok_full_len(notiftok),
				   json_tok_full(buf, notiftok));

		/* Create a placeholder if necessary */
		if (!backup_map_get(cb->backups, &node_id)) {
			struct peer_backup *pb
				= add_to_backup_map(cb, &node_id,
						    take(tal_arr(NULL, u8, 0)));
			return commit_peer_backup(cmd, pb);
		}
	}

	return notification_or_hook_done(cmd);
}


/* We use the hook here, since we want to send data to peer before any
 * reconnect messages (which might make it hang up!) */
static struct command_result *peer_connected(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	struct node_id *node_id;
	struct out_req *req;
        u8 *serialise_scb;
	const char *err;
	u8 *features;
	struct chanbackup *cb = chanbackup(cmd->plugin);

	serialise_scb = towire_peer_storage(cmd,
					    get_file_data(tmpctx, cmd->plugin));
	node_id = tal(cmd, struct node_id);
	err = json_scan(cmd, buf, params,
			"{peer:{id:%,features:%}}",
			JSON_SCAN(json_to_node_id, node_id),
			JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &features));
	if (err) {
		plugin_err(cmd->plugin,
			   "peer_connected hook did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));
	}

	/* We shouldn't have to check, but LND hangs up? */
	if (!feature_offered(features, OPT_PROVIDE_STORAGE)) {
		return command_hook_success(cmd);
	}

	/* Remember this peer for future sends */
	if (!peer_map_get(cb->peers, node_id))
		peer_map_add(cb->peers, tal_dup(cb->peers, struct node_id, node_id));

	if (!cb->send_our_peer_backup)
		return send_peers_scb(cmd, node_id);

        req = jsonrpc_request_start(cmd,
                                    "sendcustommsg",
                                    peer_after_send_scb,
                                    peer_after_send_scb_failed,
                                    node_id);

        json_add_node_id(req->js, "node_id", node_id);
	json_add_hex_talarr(req->js, "msg", serialise_scb);

        return send_outreq(req);
}

static struct command_result *failed_peer_restore(struct command *cmd,
						  struct node_id *node_id,
						  char *reason)
{
	/* BOLT #1:
	 *
	 * The receiver of `peer_storage_retrieval`:
	 *   - when it receives `peer_storage_retrieval` with an outdated or irrelevant data:
	 *     - MAY send a warning.
	 */
	/* We don't, we just complain in the logs a little! */
	plugin_log(cmd->plugin, LOG_DBG, "PeerStorageFailed!: %s: %s",
		   fmt_node_id(tmpctx, node_id),
		   reason);
	return command_hook_success(cmd);
}

static struct command_result *datastore_success(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						char *what)
{
	plugin_log(cmd->plugin, LOG_DBG, "datastore succeeded for %s", what);
	return command_hook_success(cmd);
}

static struct command_result *datastore_failed(struct command *cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       char *what)
{
	plugin_log(cmd->plugin, LOG_DBG, "datastore failed for %s: %.*s",
		   what, json_tok_full_len(result), json_tok_full(buf, result));
	return command_hook_success(cmd);
}

static struct command_result *handle_your_peer_storage(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
        struct node_id node_id;
        u8 *payload, *payload_deserialise;
	const char *err;
	const struct chanbackup *cb = chanbackup(cmd->plugin);

	err = json_scan(cmd, buf, params,
			"{payload:%,peer_id:%}",
			JSON_SCAN_TAL(cmd, json_tok_bin_from_hex, &payload),
			JSON_SCAN(json_to_node_id, &node_id));
	if (err) {
		plugin_err(cmd->plugin,
			   "`your_peer_storage` response did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));
	}

	if (fromwire_peer_storage(cmd, payload, &payload_deserialise)) {
		struct peer_backup *pb;

		if (!cb->handle_their_peer_backup)
			return command_hook_success(cmd);

		/* BOLT #1:
		 * The receiver of `peer_storage`:
		 *   - If it offered `option_provide_storage`:
		 *    - if it has an open channel with the sender:
		 *      - MUST store the message.
		 *    - MAY store the message anyway.
		 */
		/* We store if we have a datastore slot for it
		 * (otherwise, this fails).  We create those once it
		 * has a channel, though the user could also create an
		 * empty one if they wanted to */

		/* BOLT #1:
		 * - If it does store the message:
		 *   - MAY delay storage to ratelimit peer to no more than one
		 *     update per minute.
		 *   - MUST replace the old `blob` with the latest received.
		 */
		pb = backup_map_get(cb->backups, &node_id);
		if (!pb)
			return command_hook_success(cmd);

		tal_free(pb->data);
		pb->data = tal_steal(pb, payload_deserialise);
		return commit_peer_backup(cmd, pb);
	} else if (fromwire_peer_storage_retrieval(cmd, payload, &payload_deserialise)) {
		crypto_secretstream_xchacha20poly1305_state crypto_state;

		plugin_log(cmd->plugin, LOG_DBG,
                           "Received peer_storage from peer.");

		if (!cb->send_our_peer_backup)
			return command_hook_success(cmd);

                if (tal_bytelen(payload_deserialise) < ABYTES +
		    HEADER_LEN)
		        return failed_peer_restore(cmd, &node_id,
						   "Too short!");

                u8 *decoded_bkp = tal_arr(tmpctx, u8,
					  tal_bytelen(payload_deserialise) -
					  ABYTES -
					  HEADER_LEN);

                /* The header part */
                if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
                                                                    payload_deserialise,
                                                                    cb->secret.data) != 0)
                        return failed_peer_restore(cmd, &node_id,
						   "Peer altered our data");

                if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state,
                                                               decoded_bkp,
                                                               NULL, 0,
                                                               payload_deserialise +
                                                               HEADER_LEN,
                                                               tal_bytelen(payload_deserialise) -
                                                               HEADER_LEN,
                                                               NULL, 0) != 0)
                        return failed_peer_restore(cmd, &node_id,
					           "Peer altered our data");


		return jsonrpc_set_datastore_binary(cmd,
					     	    "chanbackup/latestscb",
					     	    decoded_bkp,
						    tal_bytelen(decoded_bkp),
					     	    "create-or-replace",
					     	    datastore_success,
					     	    datastore_failed,
						    "Saving latestscb");
	} else {
		/* Any other message we ignore */
		return command_hook_success(cmd);
        }
}

static struct command_result *after_latestscb(struct command *cmd,
					      const u8 *res,
					      void *cb_arg UNUSED)
{
        u64 version;
	u32 timestamp;
	struct modern_scb_chan **scb_tlvs;
	struct legacy_scb_chan **scb;
        struct json_stream *response;
        struct out_req *req;

        if (tal_bytelen(res) == 0) {
        	response = jsonrpc_stream_success(cmd);

		json_add_string(response, "result",
				"No backup received from peers");
		return command_finished(cmd, response);
        }

	bool is_tlvs = false;
	if (!fromwire_static_chan_backup(cmd,
                                         res,
                                         &version,
                                         &timestamp,
                                         &scb)) {
		if(!fromwire_static_chan_backup_with_tlvs(cmd,
							  res,
							  &version,
							  &timestamp,
							  &scb_tlvs)) {
			plugin_err(cmd->plugin, "Corrupted SCB!");
		}
		is_tlvs = true;
	}

	if ((version & 0x5555555555555555ULL) != (VERSION & 0x5555555555555555ULL)) {
		plugin_err(cmd->plugin,
                           "Incompatible emergencyrecover version: loaded version %"PRIu64", expected version %"PRIu64". Contact the admin!", version, VERSION);
	}

	req = jsonrpc_request_start(cmd, "recoverchannel",
				    after_recover_rpc,
				    &forward_error, NULL);

	json_array_start(req->js, "scb");
	if (is_tlvs) {
		for (size_t i=0; i<tal_count(scb_tlvs); i++) {
			u8 *scb_hex = tal_arr(cmd, u8, 0);
			towire_modern_scb_chan(&scb_hex,scb_tlvs[i]);
			json_add_hex_talarr(req->js, NULL, scb_hex);
		}
	} else {
		for (size_t i=0; i<tal_count(scb); i++) {
			u8 *scb_hex = tal_arr(cmd, u8, 0);
			struct modern_scb_chan *tmp_scb_tlv = tal(cmd, struct modern_scb_chan);
			tmp_scb_tlv->id = scb[i]->id;
			tmp_scb_tlv->addr = scb[i]->addr;
			tmp_scb_tlv->cid = scb[i]->cid;
			tmp_scb_tlv->funding = scb[i]->funding;
			tmp_scb_tlv->funding_sats = scb[i]->funding_sats;
			tmp_scb_tlv->type = scb[i]->type;
			tmp_scb_tlv->tlvs = tlv_scb_tlvs_new(cmd);
			towire_modern_scb_chan(&scb_hex, tmp_scb_tlv);
			json_add_hex_talarr(req->js, NULL, scb_hex);
		}
	}

	json_array_end(req->js);

	return send_outreq(req);

}

static struct command_result *json_restorefrompeer(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	return jsonrpc_get_datastore_binary(cmd,
				     	    "chanbackup/latestscb",
				     	    after_latestscb,
				     	    NULL);
}

static struct command_result *json_getemergencyrecoverdata(struct command *cmd,
						    	const char *buf,
						    	const jsmntok_t *params)
{
	u8 *filedata;
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *response;

	filedata = get_file_data(tmpctx, cmd->plugin);
	response = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(response, "filedata", filedata);


	return command_finished(cmd, response);
}

static struct command_result *on_commitment_revocation(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG, "Updated `emergency.recover` state after receiving new commitment secret.");

	req = jsonrpc_request_start(cmd,
				    "staticbackup",
				    after_staticbackup,
				    log_broken_and_complete,
				    NULL);

	return send_outreq(req);
}

static void setup_backup_map(struct command *init_cmd,
			     struct chanbackup *cb)
{
	struct json_out *params = json_out_new(init_cmd);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i, total = 0;

	cb->backups = tal(cb, struct backup_map);
	backup_map_init(cb->backups);
	cb->peers = tal(cb, struct peer_map);
	peer_map_init(cb->peers);

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "chanbackup");
	json_out_addstr(params, NULL, "peers");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      take(params), &buf);

	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const jsmntok_t *keytok, *hextok;
		struct node_id peer;
		u8 *data;

		/* Key is an array, first two elements are chanbackup, peers */
		keytok = json_get_member(buf, t, "key") + 3;
		hextok = json_get_member(buf, t, "hex");
		/* In case someone creates a subdir? */
		if (!hextok)
			continue;
		if (!json_to_node_id(buf, keytok, &peer))
			plugin_err(init_cmd->plugin,
				   "Could not parse datastore id '%.*s'",
				   json_tok_full_len(keytok),
				   json_tok_full(buf, keytok));
		data = json_tok_bin_from_hex(NULL, buf, hextok);
		/* Only count non-empty ones. */
		if (tal_bytelen(data) != 0)
			total++;
		add_to_backup_map(cb, &peer, take(data));
	}
	if (total)
		plugin_log(init_cmd->plugin, LOG_INFORM,
			   "Loaded %zu stored backups for peers", total);
}

static void chanbackup_mark_mem(struct plugin *plugin,
				struct htable *memtable)
{
	const struct chanbackup *cb = chanbackup(plugin);
	memleak_scan_htable(memtable, &cb->backups->raw);
	memleak_scan_htable(memtable, &cb->peers->raw);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct chanbackup *cb = tal(init_cmd->plugin, struct chanbackup);
	struct modern_scb_chan **scb_chan;
	const char *info = "scb secret";
	u8 *info_hex = tal_dup_arr(tmpctx, u8, (u8*)info, strlen(info), 0);
	u8 *features;

	/* Figure out if they specified --experimental-peer-storage */
	rpc_scan(init_cmd, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{our_features:{init:%}}",
		 JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &features));

	/* If we unset this feature, we don't even *send* peer backups */
	cb->handle_their_peer_backup
		= cb->send_our_peer_backup
		= feature_offered(features, OPT_PROVIDE_STORAGE);

	rpc_scan(init_cmd, "staticbackup",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{scb:%}", JSON_SCAN(json_to_scb_chan, &scb_chan));

	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "hex",
		 		   tal_hexstr(tmpctx,
				   	      info_hex,
					      tal_bytelen(info_hex)))),
		 "{secret:%}", JSON_SCAN(json_to_secret, &cb->secret));

	setup_backup_map(init_cmd, cb);
	plugin_set_data(init_cmd->plugin, cb);
	plugin_log(init_cmd->plugin, LOG_DBG, "Chanbackup Initialised!");

	/* flush the tmp file, if exists */
	unlink_noerr("scb.tmp");

	maybe_create_new_scb(init_cmd->plugin, scb_chan);

	plugin_set_memleak_handler(init_cmd->plugin,
				   chanbackup_mark_mem);
	return NULL;
}

static const struct plugin_notification notifs[] = {
	{
		"channel_state_changed",
		json_state_changed,
	},
};

static const struct plugin_hook hooks[] = {
        {
                "custommsg",
                handle_your_peer_storage,
        },
	{
		"peer_connected",
		peer_connected,
	},
	{
		"commitment_revocation",
		on_commitment_revocation,
	}
};

static const struct plugin_command commands[] = {
	{
		"emergencyrecover",
		json_emergencyrecover,
	},
	{
		"getemergencyrecoverdata",
		json_getemergencyrecoverdata,
	},
	{
		"restorefrompeer",
		json_restorefrompeer,
	},
};

int main(int argc, char *argv[])
{
        setup_locale();

	plugin_main(argv, init, NULL, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs), hooks, ARRAY_SIZE(hooks),
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}
