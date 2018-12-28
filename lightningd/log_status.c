#include <common/gen_status_wire.h>
#include <lightningd/log_status.h>

bool log_status_msg(struct log *log, const u8 *msg)
{
	char *entry, *who;
	u8 *data;
 	enum log_level level;

	if (fromwire_status_log(msg, msg, &level, &entry)) {
		if (level != LOG_IO_IN && level != LOG_IO_OUT) {
			log_(log, level, "%s", entry);
			return true;
		}
	} else if (fromwire_status_io(msg, msg, &level, &who, &data)) {
		if (level == LOG_IO_IN || level == LOG_IO_OUT) {
			log_io(log, level, who, data, tal_count(data));
			return true;
		}
	}
	return false;
}
