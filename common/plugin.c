#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/plugin.h>

bool is_asterix_notification(const char *notification_name, const char *subscription)
{
	bool is_special;
        /* Asterisk is magic "all", and log notification
	 * is a special notification that must be turn on
	 * only if requested. */
	is_special = streq(subscription, "*") && !streq(notification_name, "log");
	if (is_special)
		return true;
	return false;
}
