#include "lightningd/notification.h"
#include <ccan/array_size/array_size.h>

const char *notification_topics[] = {
};

bool notifications_have_topic(const char *topic)
{
	for (size_t i=0; ARRAY_SIZE(notification_topics); i++)
		if (streq(topic, notification_topics[i]))
			return true;
	return false;
}
