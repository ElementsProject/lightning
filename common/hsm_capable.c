#include "config.h"
#include <common/hsm_capable.h>

/* Is this capability supported by the HSM? (So far, always a message
 * number) */
bool hsm_is_capable(const u32 *capabilities, u32 msgtype)
{
	for (size_t i = 0; i < tal_count(capabilities); i++) {
		if (capabilities[i] == msgtype)
			return true;
	}
	return false;
}
