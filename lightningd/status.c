
#include <assert.h>
#include <lightningd/status.h>


const char *lightningd_status_to_str(enum lightningd_status status) {
	switch (status) {
	case LIGHTNINGD_STATUS_READY:
		return "ready";
	case LIGHTNINGD_STATUS_SYNCING:
		return "syncing";
	}

	assert(!"lightningd_status_to_str called with an unknown status");
	return "unknown";
}
