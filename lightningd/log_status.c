#include "config.h"
#include <common/status_wiregen.h>
#include <lightningd/log_status.h>

bool log_status_msg(struct log *log,
		    const struct node_id *node_id,
		    const u8 *msg)
{
	char *entry, *who;
	u8 *data;
	struct node_id *suggested_node_id;
 	enum log_level level;
	bool call_notifier;

	if (fromwire_status_log(msg, msg, &level, &suggested_node_id, &entry)) {
		/* If there's not already a node_id (global subdirs), they can
		 * set it */
		if (!node_id)
			node_id = suggested_node_id;
		/* No per-peer daemon should claim a different peer! */
		else if (suggested_node_id
			 && !node_id_eq(node_id, suggested_node_id))
			return false;

		if (level != LOG_IO_IN && level != LOG_IO_OUT) {
			call_notifier = (level == LOG_BROKEN ||
			         level == LOG_UNUSUAL)? true : false;
			log_(log, level, node_id, call_notifier, "%s", entry);
			return true;
		}
		/* FIXME: This would be far more efficient to copy to log in place, rather than doing the additional allocation in fromwire. */
	} else if (fromwire_status_io(msg, msg, &level, &suggested_node_id,
				      &who, &data)) {
		if (level == LOG_IO_IN || level == LOG_IO_OUT) {
			if (!node_id)
				node_id = suggested_node_id;
			log_io(log, level, node_id, who, data, tal_count(data));
			return true;
		}
	}
	return false;
}
