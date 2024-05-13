#ifndef LIGHTNING_PLUGINS_ESTABLISH_ONION_PATH_H
#define LIGHTNING_PLUGINS_ESTABLISH_ONION_PATH_H
#include "config.h"
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <plugins/libplugin.h>

/**
 * establish_onion_path: derive (or connect) a path to this peer.
 * @cmd: the command context
 * @gossmap: a gossip map to do lookup in
 * @local_id: our own id
 * @dst: the destination node
 * @connect_disable: if non-null, the arg name which is disabling direct connection
 * @success: the success callback
 * @fail: the failure callback
 * @arg: callback argument
 *
 * If it cannot find an onion-message-carrying path, will connect directly,
 * unless connect_disable is non-NULL.
 */
struct command_result *establish_onion_path_(struct command *cmd,
					     struct gossmap *gossmap,
					     const struct pubkey *local_id,
					     const struct pubkey *dst,
					     const char *connect_disable,
					     struct command_result *(*success)(struct command *,
									   const struct pubkey *,
									   void *arg),
					     struct command_result *(*fail)(struct command *,
									const char *why,
									void *arg),
					     void *arg);

#define establish_onion_path(cmd, gossmap, local_id, id, disable, success, fail, arg) \
	establish_onion_path_((cmd), (gossmap), (local_id), (id), (disable), \
			      typesafe_cb_preargs(struct command_result *, void *, \
						  (success), (arg),	\
						  struct command *,	\
						  const struct pubkey *), \
			      typesafe_cb_preargs(struct command_result *, void *, \
						  (fail), (arg),	\
						  struct command *,	\
						  const char *),	\
			      (arg))

#endif /* LIGHTNING_PLUGINS_ESTABLISH_ONION_PATH_H */
