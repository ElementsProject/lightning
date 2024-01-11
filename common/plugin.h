#ifndef LIGHTNING_COMMON_PLUGIN_H
#define LIGHTNING_COMMON_PLUGIN_H

#include "config.h"
#include <stdbool.h>

/* is_magic_notification - check if the notification name
 * is a special notification and need to be handled in a
 * special way. */
bool is_asterix_notification(const char *notification_name,
			     const char *subscriptions);

#endif /* LIGHTNING_COMMON_PLUGIN_H */
