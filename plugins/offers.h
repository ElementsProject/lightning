#ifndef LIGHTNING_PLUGINS_OFFERS_H
#define LIGHTNING_PLUGINS_OFFERS_H
#include "config.h"

struct command_result;
struct command;

/* Helper to send a reply */
struct command_result *WARN_UNUSED_RESULT
send_onion_reply(struct command *cmd,
		 struct tlv_onionmsg_payload_reply_path *reply_path,
		 struct tlv_onionmsg_payload *payload);
#endif /* LIGHTNING_PLUGINS_OFFERS_H */
