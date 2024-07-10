#ifndef LIGHTNING_PLUGINS_OFFERS_H
#define LIGHTNING_PLUGINS_OFFERS_H
#include "config.h"

struct command_result;
struct command;
struct plugin;

/* This is me. */
extern struct pubkey id;
/* Are offers enabled? */
extern bool offers_enabled;
/* --fetchinvoice-noconnect */
extern bool disable_connect;
/* --cltv-final */
extern u16 cltv_final;
/* Current header_count */
extern u32 blockheight;
/* Basis for invoice secrets */
extern struct secret invoicesecret_base;

/* If they give us an scid, do a lookup */
bool convert_to_scidd(struct command *cmd,
		      struct sciddir_or_pubkey *sciddpk);

/* Helper to send a reply */
struct command_result *WARN_UNUSED_RESULT
send_onion_reply(struct command *cmd,
		 struct blinded_path *reply_path,
		 struct tlv_onionmsg_tlv *payload);

/* Get the (latest) gossmap */
struct gossmap *get_gossmap(struct plugin *plugin);
#endif /* LIGHTNING_PLUGINS_OFFERS_H */
