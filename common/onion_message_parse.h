#ifndef LIGHTNING_COMMON_ONION_MESSAGE_PARSE_H
#define LIGHTNING_COMMON_ONION_MESSAGE_PARSE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <common/amount.h>

struct tlv_onionmsg_tlv;
struct node_id;
struct pubkey;

/**
 * onion_message_parse: core routine to check onion_message
 * @ctx: context to allocate @next_onion_msg or @final_om/@path_id off
 * @onion_message_packet: Sphinx-encrypted onion
 * @blinding: Blinding we were given for @onion_message_packet
 * @me: my pubkey
 * @next_onion_msg (out): set if we should forward, otherwise NULL.
 * @next_node_id (out): set to node id to fwd to, iff *@next_onion_msg.
 * @final_om (out): set if we're the final hop, otherwise NULL.
 * @final_alias (out): our alias (if *@final_om), or our own ID
 * @final_path_id (out): secret enclosed, if any (iff *@final_om).
 *
 * Returns NULL if it was valid, otherwise an error string.
 */
const char *onion_message_parse(const tal_t *ctx,
				const u8 *onion_message_packet,
				const struct pubkey *blinding,
				const struct pubkey *me,
				u8 **next_onion_msg,
				struct pubkey *next_node_id,
				struct tlv_onionmsg_tlv **final_om,
				struct pubkey *final_alias,
				struct secret **final_path_id);

#endif /* LIGHTNING_COMMON_ONION_MESSAGE_PARSE_H */
