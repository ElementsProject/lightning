#ifndef LIGHTNING_PLUGINS_OFFERS_H
#define LIGHTNING_PLUGINS_OFFERS_H
#include "config.h"

struct command_result;
struct command;
struct onion_message;
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
/* Basis for invoice path_secrets */
extern struct secret invoicesecret_base;
/* Base for offers path_secrets */
extern struct secret offerblinding_base;
/* Base for node aliases for invoice requests */
extern struct secret nodealias_base;
/* --dev-invoice-bpath-scid */
extern bool dev_invoice_bpath_scid;
/* --dev-invoice-internal-scid */
extern struct short_channel_id *dev_invoice_internal_scid;
/* This is me. */
extern struct pubkey id;

/* Helper to send a reply (connecting if required), and discard result */
struct command_result *WARN_UNUSED_RESULT
send_onion_reply(struct command *cmd,
		 struct blinded_path *reply_path,
		 struct tlv_onionmsg_tlv *payload);

/* Helper to send an onion message */
#define inject_onionmessage(cmd, omsg, success, fail, arg)		\
	inject_onionmessage_((cmd), (omsg),				\
			     typesafe_cb_preargs(struct command_result *, void *, \
						 (success), (arg),	\
						 struct command *,	\
						 const char *,		\
						 const jsmntok_t *),	\
			     typesafe_cb_preargs(struct command_result *, void *, \
						 (fail), (arg),		\
						 struct command *,	\
						 const char *,		\
						 const jsmntok_t *),	\
			     (arg))

struct command_result *
inject_onionmessage_(struct command *cmd,
		     const struct onion_message *omsg,
		     struct command_result *(*cb)(struct command *command,
						  const char *buf,
						  const jsmntok_t *result,
						  void *arg),
		     struct command_result *(*errcb)(struct command *command,
						     const char *buf,
						     const jsmntok_t *result,
						     void *arg),
		     void *arg);

/* Get the (latest) gossmap */
struct gossmap *get_gossmap(struct plugin *plugin);

/* Get the best (private) channel */
struct chaninfo {
	struct pubkey id;
	struct amount_msat capacity, htlc_min, htlc_max;
	u32 feebase, feeppm, cltv;
};

/* Calls listpeerchannels, then cb with best peer (if any!) which has needed_feature */
struct command_result *find_best_peer_(struct command *cmd,
				       int needed_feature,
				       struct command_result *(*cb)(struct command *,
								    const struct chaninfo *,
								    void *),
				       void *arg);

#define find_best_peer(cmd, needed_feature, cb, arg)			\
	find_best_peer_((cmd), (needed_feature),			\
			typesafe_cb_preargs(struct command_result *, void *, \
					    (cb), (arg),		\
					    struct command *,		\
					    const struct chaninfo *),	\
			(arg))

#endif /* LIGHTNING_PLUGINS_OFFERS_H */
