#include <lightningd/json.h>
#include <lightningd/notification_in.h>
#include <wallet/db.h>

static struct notification_in *notification_in_by_name(const char *buffer,
						       const jsmntok_t *methtok)
{
	static struct notification_in **notifications_in = NULL;
	static size_t num_notifications;
	if (!notifications_in)
		notifications_in = autodata_get(notifications_in,
						&num_notifications);

	for (size_t i=0; i<num_notifications; i++)
		if (json_tok_streq(buffer, methtok, notifications_in[i]->name))
			return notifications_in[i];
	return NULL;
}


/**
 * Callback to be passed to the jsonrpc_request.
 *
 * Unbundles the arguments, deserializes the response and dispatches
 * it to the notification_in callback.
 */
bool notification_in_callback(struct plugin *plugin,
			      const jsmntok_t *methtok,
			      const jsmntok_t *paramstok)
{
	struct notification_in *notification;
	const char *buffer = plugin->buffer;

	notification = notification_in_by_name(buffer, methtok);
	if (!notification) {
		/* No such notification_in name registered */
		return false;
	}

	/* `log` is special. It doesn't make change on DB and it may occur
	 * before `ld->wallet` initials. So here we `log` directly.*/
	if (streq(notification->name, "log")) {
		notification->response_cb(plugin, paramstok);
		return true;
	}

	/* Except `log`, notification_in should send to lightningd after plugin
	 * initials(complete `init` method).
	 * Ignore notifications except `log` before we create `ld->wallet`. */
	if (plugin->plugins->ld->wallet) {
		db_begin_transaction(plugin->plugins->ld->wallet->db);
		notification->response_cb(plugin, paramstok);
		db_commit_transaction(plugin->plugins->ld->wallet->db);
	}

	return true;
}

