#ifndef LIGHTNING_LIGHTNINGD_NOTIFICATION_IN_H
#define LIGHTNING_LIGHTNINGD_NOTIFICATION_IN_H

#include "config.h"
#include <ccan/autodata/autodata.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <lightningd/lightningd.h>
#include <lightningd/plugin.h>

struct notification_in {
	const char *name;
	void (*response_cb)(struct plugin *plugin, const jsmntok_t *toks);

	/* Plugin needn't register this notification,
	 * just send with correct format! */
};
AUTODATA_TYPE(notifications_in, struct notification_in);

/* Typechecked registration of a plugin hook. We check that the
 * serialize_payload function converts an object of type payload_type
 * to a json_stream (.params object in the JSON-RPC request), that the
 * deserialize_response function converts from the JSON-RPC response
 * json_stream to an object of type response_type and that the
 * response_cb function accepts the deserialized response format and
 * an arbitrary extra argument used to maintain context.
 */
#define REGISTER_NOTIFICATION_IN(name, response_cb)                  \
	struct notification_in name##_notification_in_gen = {                                 \
	    stringify(name),                                                   \
	    response_cb,                                                       \
	};                                                                     \
	AUTODATA(notifications_in, &name##_notification_in_gen);                                     \

bool notification_in_callback(struct plugin *plugin,
			      const jsmntok_t *methtok,
			      const jsmntok_t *paramstok);

#endif /* LIGHTNING_LIGHTNINGD_NOTIFICATION_IN_H */
