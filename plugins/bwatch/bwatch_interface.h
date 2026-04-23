#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H

#include "config.h"
#include <plugins/bwatch/bwatch.h>

/* Outward-facing interface from bwatch to lightningd.
 *
 * Subsequent commits add the watch_found / watch_revert notifications
 * and the addwatch / delwatch / listwatch RPC commands. */

/* Send a block_processed RPC to watchman after a new block has been
 * persisted.  The next poll is started from the ack callback so we don't
 * race ahead of watchman's view of the chain.  Chains on the same poll
 * command so timer_complete fires once watchman has acknowledged. */
struct command_result *bwatch_send_block_processed(struct command *cmd);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H */
