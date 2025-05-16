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
#include <common/scb_wiregen.h>
#include <errno.h>
#include <fcntl.h>
#include <plugins/libplugin.h>
#include <sodium.h>
#include <unistd.h>

#define HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

#define FILENAME "emergency.recover"

/* VERSION is the current version of the data encrypted in the file */
#define VERSION ((u64)1)

struct chanbackup {
	bool peer_backup;
	/* Global secret object to keep the derived encryption key for the SCB */
	struct secret secret;
};

static struct chanbackup *chanbackup(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct chanbackup);
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
				 void *cb_arg UNUSED)
{
        plugin_log(cmd->plugin, LOG_DBG, "Sent their peer storage!");
	return command_hook_success(cmd);
}

static struct command_result
*peer_after_send_their_peer_strg_err(struct command *cmd,
				     const char *method,
				     const char *buf,
				     const jsmntok_t *params,
				     void *cb_arg UNUSED)
{
        plugin_log(cmd->plugin, LOG_DBG, "Unable to send Peer storage!");
	return command_hook_success(cmd);
}

static struct command_result *peer_after_listdatastore(struct command *cmd,
						       const u8 *hexdata,
						       struct node_id *nodeid)
{
        struct out_req *req;

	/* We use an empty record to indicate we *would* store data
	 * for this peer, until we actually get data from them */
        if (tal_bytelen(hexdata) == 0)
        	return command_hook_success(cmd);

	if (!chanbackup(cmd->plugin)->peer_backup)
		return command_hook_success(cmd);

	/* BOLT #1:
	 * - If it does store the message:
	 *...
	 *   - MUST send `peer_storage_retrieval` again after
	 *     reconnection, after exchanging `init` messages.
	 */
	/* BOLT #1:
	 * The sender of `peer_storage_retrieval`:
	 *   - MUST include the last `blob` it stored for that peer.
	 */
        u8 *payload = towire_peer_storage_retrieval(cmd, hexdata);

        plugin_log(cmd->plugin, LOG_DBG,
                   "sending their backup from our datastore");

        req = jsonrpc_request_start(cmd,
                                    "sendcustommsg",
                                    peer_after_send_their_peer_strg,
                                    peer_after_send_their_peer_strg_err,
                                    NULL);

        json_add_node_id(req->js, "node_id", nodeid);
	json_add_hex_talarr(req->js, "msg", payload);

        return send_outreq(req);
}

static struct command_result *peer_after_send_scb(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *params,
						  struct node_id *nodeid)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage sent!");

	return jsonrpc_get_datastore_binary(cmd,
				     	    tal_fmt(cmd,
				     		    "chanbackup/peers/%s",
						    fmt_node_id(tmpctx,
								nodeid)),
				     	    peer_after_listdatastore,
				     	    nodeid);
}

static struct command_result *peer_after_send_scb_failed(struct command *cmd,
							 const char *method,
							 const char *buf,
							 const jsmntok_t *params,
							 struct node_id *nodeid)
{
        plugin_log(cmd->plugin, LOG_DBG, "Peer storage send failed %.*s!",
		   json_tok_full_len(params), json_tok_full(buf, params));
	return command_hook_success(cmd);
}

struct info {
	size_t idx;
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
	if (--info->idx != 0)
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
	if (--info->idx != 0)
		return command_still_pending(cmd);

	return notification_or_hook_done(cmd);
}

static struct command_result *after_listpeers(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *params,
					      void *cb_arg UNUSED)
{
	const jsmntok_t *peers, *peer;
        struct out_req *req;
	size_t i;
	struct info *info = tal(cmd, struct info);
	bool is_connected;
        u8 *serialise_scb;

	if (!chanbackup(cmd->plugin)->peer_backup)
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
	serialise_scb = towire_peer_storage(cmd,
					    get_file_data(tmpctx, cmd->plugin));

	peers = json_get_member(buf, params, "peers");

	info->idx = 0;
	json_for_each_arr(i, peer, peers) {
		const char *err;
		u8 *features;

		/* If connected is false, features is missing, so this fails */
		err = json_scan(cmd, buf, peer,
				"{connected:%,features:%}",
				JSON_SCAN(json_to_bool, &is_connected),
				JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex,
					      &features));
		if (err || !is_connected)
			continue;

		/* We shouldn't have to check, but LND hangs up? */
		if (feature_offered(features, OPT_PROVIDE_STORAGE)) {
			const jsmntok_t *nodeid;
			struct node_id node_id;

			nodeid = json_get_member(buf, peer, "id");
			json_to_node_id(buf, nodeid, &node_id);

			req = jsonrpc_request_start(cmd,
						    "sendcustommsg",
						    after_send_scb_single,
						    after_send_scb_single_fail,
						    info);

			json_add_node_id(req->js, "node_id", &node_id);
			json_add_hex_talarr(req->js, "msg", serialise_scb);
			info->idx++;
			send_outreq(req);
		}
	}

	if (info->idx == 0)
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
	struct out_req *req;
	json_to_scb_chan(buf, scbs, &scb_chan);
	plugin_log(cmd->plugin, LOG_DBG, "Updating the SCB");

	update_scb(cmd->plugin, scb_chan);
	req = jsonrpc_request_start(cmd,
                                    "listpeers",
                                    after_listpeers,
                                    plugin_broken_cb,
                                    NULL);
	return send_outreq(req);
}

static struct command_result *datastore_create_done(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    void *unused)
{
	return notification_or_hook_done(cmd);
}

static struct command_result *json_state_changed(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params)
{
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

		/* Might already exist, that's OK, just don't overwrite! */
		return jsonrpc_set_datastore_binary(cmd,
					     	    tal_fmt(cmd,
						    	    "chanbackup/peers/%s",
					     	     	    fmt_node_id(tmpctx,
									&node_id)),
						    /* Empty record */
						    tal_arr(tmpctx, u8, 0),
						    "must-create",
					     	    datastore_create_done,
					     	    datastore_create_done,
						    NULL);
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

	if (!chanbackup(cmd->plugin)->peer_backup)
		return command_hook_success(cmd);

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

	if (!cb->peer_backup)
		return command_hook_success(cmd);

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
		return jsonrpc_set_datastore_binary(cmd,
					     	    tal_fmt(cmd,
						    	    "chanbackup/peers/%s",
					     	     	    fmt_node_id(tmpctx,
									&node_id)),
						    payload_deserialise,
						    "must-replace",
					     	    datastore_success,
					     	    datastore_failed,
						    "Saving chanbackup/peers/");
	} else if (fromwire_peer_storage_retrieval(cmd, payload, &payload_deserialise)) {
		plugin_log(cmd->plugin, LOG_DBG,
                           "Received peer_storage from peer.");

        	crypto_secretstream_xchacha20poly1305_state crypto_state;

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
	cb->peer_backup = feature_offered(features, OPT_PROVIDE_STORAGE);

	rpc_scan(init_cmd, "staticbackup",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{scb:%}", JSON_SCAN(json_to_scb_chan, &scb_chan));

	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "hex",
		 		   tal_hexstr(tmpctx,
				   	      info_hex,
					      tal_bytelen(info_hex)))),
		 "{secret:%}", JSON_SCAN(json_to_secret, &cb->secret));

	plugin_set_data(init_cmd->plugin, cb);
	plugin_log(init_cmd->plugin, LOG_DBG, "Chanbackup Initialised!");

	/* flush the tmp file, if exists */
	unlink_noerr("scb.tmp");

	maybe_create_new_scb(init_cmd->plugin, scb_chan);

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
