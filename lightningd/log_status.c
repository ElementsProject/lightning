#include <common/gen_status_wire.h>
#include <lightningd/log_status.h>

bool log_status_msg(struct log *log, const u8 *msg)
{
	char *entry;
	u8 *data;
	bool in;
	enum log_level level;

	if (fromwire_status_log(msg, msg, NULL, &level, &entry)) {
		log_(log, level, "%s", entry);
		return true;
	} else if (fromwire_status_io(msg, msg, NULL, &in, &data)) {
		log_io(log, in, data, tal_len(data));
		return true;
	}
	return false;
}
