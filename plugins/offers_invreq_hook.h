#ifndef LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H
#define LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H
#include "config.h"
#include <plugins/libplugin.h>

extern u32 cltv_final;

/* We got an onionmessage with an invreq! */
struct command_result *handle_invoice_request(struct command *cmd,
					      const u8 *invreqbin,
					      struct tlv_onionmsg_payload_reply_path *reply_path STEALS,
					      struct tlv_obs2_onionmsg_payload_reply_path *obs2_reply_path STEALS);
#endif /* LIGHTNING_PLUGINS_OFFERS_INVREQ_HOOK_H */
