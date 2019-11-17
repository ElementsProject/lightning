#include <common/gen_status_wire.h>
#include <lightningd/log_status.h>

bool log_status_msg(struct log *log,
		    const struct node_id *node_id,
		    const u8 *msg)
{
	char *entry, *who;
	u8 *data;
 	enum log_level level;
	bool call_notifier;

	if (fromwire_status_log(msg, msg, &level, &entry)) {
		if (level != LOG_IO_IN && level != LOG_IO_OUT) {
			call_notifier = (level == LOG_BROKEN ||
			         level == LOG_UNUSUAL)? true : false;
			log_(log, level, node_id, call_notifier, "%s", entry);
			return true;
		}
	} else if (fromwire_status_io(msg, msg, &level, &who, &data)) {
		if (level == LOG_IO_IN || level == LOG_IO_OUT) {
			log_io(log, level, node_id, who, data, tal_count(data));
			return true;
		}
	}
	return false;
}
