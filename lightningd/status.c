
#include <lightningd/status.h>


const char *lightningd_status_to_str(int status) {
	/* TODO: update to support rendering multiple flags */
	if (status & LIGHTNINGD_STATUS_SYNCING)
		return "syncing";

	return "ready";
}
