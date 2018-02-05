#include <lightningd/log_status.h>
#include <wire/wire.h>

bool log_status_msg(struct log *log, const u8 *msg)
{
	size_t max = tal_len(msg);
	int type = fromwire_u16(&msg, &max);
	enum log_level level;

	if (type < STATUS_LOG_MIN || type > STATUS_LOG_MAX)
		return false;

	level = type - STATUS_LOG_MIN;
	if (level == LOG_IO) {
		/* First byte is direction */
		bool dir = fromwire_bool(&msg, &max);
		log_io(log, dir, msg, max);
	} else {
		int i;
		/* Truncate if unprintable */
		for (i = 0; i < max; i++) {
			if (!cisprint((char)msg[i]))
				break;
		}
		log_(log, level, "%.*s%s", i, msg, i == max ? "" : "...");
	}
	return true;
}
