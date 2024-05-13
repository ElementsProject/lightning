#ifndef LIGHTNING_PLUGINS_OFFERS_H
#define LIGHTNING_PLUGINS_OFFERS_H
#include "config.h"

struct command_result;
struct command;

/* If they give us an scid, do a lookup */
bool convert_to_scidd(struct command *cmd,
		      struct sciddir_or_pubkey *sciddpk);

/* Helper to send a reply */
struct command_result *WARN_UNUSED_RESULT
send_onion_reply(struct command *cmd,
		 struct blinded_path *reply_path,
		 struct tlv_onionmsg_tlv *payload);
#endif /* LIGHTNING_PLUGINS_OFFERS_H */
