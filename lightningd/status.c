
#include <assert.h>
#include <lightningd/status.h>


const char *lightningd_status_to_str(enum lightningd_status status)
{
	switch (status) {
	case LIGHTNINGD_STATUS_INITIALIZING:
		return "initializing";
	case LIGHTNINGD_STATUS_SYNCING:
		return "syncing";
	case LIGHTNINGD_STATUS_READY:
		return "ready";
	}

	assert(!"lightningd_status_to_str called with an unknown status");
	return "unknown";
}
