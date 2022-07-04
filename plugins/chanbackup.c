#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/json_out/json_out.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
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

/* VERSION is the current version of the data encrypted in the file */
#define VERSION ((u64)1)

/* Global secret object to keep the derived encryption key for the SCB */
static struct secret secret;

/* Helper to fetch out SCB from the RPC call */
static bool json_to_scb_chan(const char *buffer,
                        const jsmntok_t *tok,
		        struct scb_chan ***channels)
{
	size_t i;
	const jsmntok_t *t;
	*channels = tok->size ? tal_arr(tmpctx,
					struct scb_chan *,
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

		(*channels)[i] = fromwire_scb_chan(tmpctx,
						   &scb_tmp,
						   &scblen_tmp);
	}

	return true;
}

/* This writes encrypted static backup in the recovery file */
static void write_scb(struct plugin *p,
                      int fd,
		      struct scb_chan **scb_chan_arr)
{
	u32 timestamp = time_now().ts.tv_sec;

	u8 *decrypted_scb = towire_static_chan_backup(tmpctx,
						      VERSION,
						      timestamp,
						      cast_const2(const struct scb_chan **,
						      		  scb_chan_arr));

	u8 *encrypted_scb = tal_arr(tmpctx,
                            u8,
                            tal_bytelen(decrypted_scb) +
                            ABYTES +
                            HEADER_LEN);

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (crypto_secretstream_xchacha20poly1305_init_push(&crypto_state,
							    encrypted_scb,
							    (&secret)->data) != 0)
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
				 struct scb_chan **channels)
{

	/* Note that this is opened for write-only, even though the permissions
	 * are set to read-only.  That's perfectly valid! */
	int fd = open("emergency.recover", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* Don't do anything if the file already exists. */
		if (errno == EEXIST)
			return;
		plugin_err(p, "creating: %s", strerror(errno));
	}

	/* Comes here only if the file haven't existed before */
	unlink_noerr("emergency.recover");

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
	rename("scb.tmp", "emergency.recover");
}


/* Returns decrypted SCB in form of a u8 array */
static u8 *decrypt_scb(struct plugin *p)
{
	struct stat st;
	int fd = open("emergency.recover", O_RDONLY);

	if (stat("emergency.recover", &st) != 0)
		plugin_err(p, "SCB file is corrupted!: %s",
                          strerror(errno));

	u8 final[st.st_size];

	if (!read_all(fd, &final, st.st_size)) {
		plugin_log(p, LOG_DBG, "SCB file is corrupted!: %s",
                           strerror(errno));
		return NULL;
	}

	crypto_secretstream_xchacha20poly1305_state crypto_state;

	if (st.st_size < ABYTES +
			 HEADER_LEN)
		plugin_err(p, "SCB file is corrupted!");

	u8 *ans = tal_arr(tmpctx, u8, st.st_size -
                          ABYTES -
                          HEADER_LEN);

	/* The header part */
	if (crypto_secretstream_xchacha20poly1305_init_pull(&crypto_state,
							    final,
							    (&secret)->data) != 0)
	{
		plugin_err(p, "SCB file is corrupted!");
	}

	if (crypto_secretstream_xchacha20poly1305_pull(&crypto_state, ans,
						       NULL, 0,
						       final +
						       HEADER_LEN,
						       st.st_size -
						       HEADER_LEN,
						       NULL, 0) != 0) {
		plugin_err(p, "SCB file is corrupted!");
	}

	if (close(fd) != 0)
		plugin_err(p, "Closing: %s", strerror(errno));

	return ans;
}

static struct command_result *after_recover_rpc(struct command *cmd,
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

/* Recovers the channels by making RPC to `recoverchannel` */
static struct command_result *json_emergencyrecover(struct command *cmd,
				      const char *buf,
                                      const jsmntok_t *params)
{
	struct out_req *req;
	u64 version;
	u32 timestamp;
	struct scb_chan **scb;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	u8 *res = decrypt_scb(cmd->plugin);

	if (!fromwire_static_chan_backup(cmd,
                                         res,
                                         &version,
                                         &timestamp,
                                         &scb)) {
		plugin_err(cmd->plugin, "Corrupted SCB!");
	}

	if (version != VERSION) {
		plugin_err(cmd->plugin,
                           "Incompatible version, Contact the admin!");
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "recoverchannel",
				after_recover_rpc,
				&forward_error, NULL);

	json_array_start(req->js, "scb");
	for (size_t i=0; i<tal_count(scb); i++) {
		u8 *scb_hex = tal_arr(cmd, u8, 0);
		towire_scb_chan(&scb_hex,scb[i]);
		json_add_hex(req->js, NULL, scb_hex, tal_bytelen(scb_hex));
	}
	json_array_end(req->js);

	return send_outreq(cmd->plugin, req);
}

static void update_scb(struct plugin *p, struct scb_chan **channels)
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
	rename("scb.tmp", "emergency.recover");
}

static struct command_result *after_staticbackup(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params,
					         void *cb_arg UNUSED)
{
	struct scb_chan **scb_chan;
	const jsmntok_t *scbs = json_get_member(buf, params, "scb");
	json_to_scb_chan(buf, scbs, &scb_chan);
	plugin_log(cmd->plugin, LOG_INFORM, "Updating the SCB");

	update_scb(cmd->plugin, scb_chan);
	return notification_handled(cmd);
}

static struct command_result *json_state_changed(struct command *cmd,
					         const char *buf,
					         const jsmntok_t *params)
{
	const jsmntok_t *notiftok = json_get_member(buf,
                                                    params,
                                                    "channel_state_changed"),
	*statetok = json_get_member(buf, notiftok, "new_state");

	/* FIXME: I wanted to update the file on CHANNELD_AWAITING_LOCKIN,
	 * But I don't get update for it, maybe because there is
	 * no previous_state, also apparently `channel_opened` gets published
	 * when *peer* funded a channel with us?
	 * So, is their no way to get a notif on CHANNELD_AWAITING_LOCKIN? */
	if (json_tok_streq(buf, statetok, "CLOSED") ||
		json_tok_streq(buf, statetok, "CHANNELD_NORMAL")) {

		struct out_req *req;
		req = jsonrpc_request_start(cmd->plugin,
                                            cmd,
                                            "staticbackup",
                                            after_staticbackup,
                                            &forward_error,
                                            NULL);

		return send_outreq(cmd->plugin, req);
	}

	return notification_handled(cmd);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct scb_chan **scb_chan;
	const char *info = "scb secret";
	u8 *info_hex = tal_dup_arr(tmpctx, u8, (u8*)info, strlen(info), 0);

	rpc_scan(p, "staticbackup",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{scb:%}", JSON_SCAN(json_to_scb_chan, &scb_chan));

	rpc_scan(p, "makesecret",
		 take(json_out_obj(NULL, "hex",
		 		   tal_hexstr(tmpctx,
				   	      info_hex,
					      tal_bytelen(info_hex)))),
		 "{secret:%}", JSON_SCAN(json_to_secret, &secret));

	plugin_log(p, LOG_DBG, "Chanbackup Initialised!");

	/* flush the tmp file, if exists */
	unlink_noerr("scb.tmp");

	maybe_create_new_scb(p, scb_chan);

	return NULL;
}

static const struct plugin_notification notifs[] = {
	{
		"channel_state_changed",
		json_state_changed,
	}
};

static const struct plugin_command commands[] = { {
		"emergencyrecover",
		"recovery",
		"Populates the DB with stub channels",
		"returns stub channel-id's on completion",
		json_emergencyrecover,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
	        notifs, ARRAY_SIZE(notifs), NULL, 0,
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}
