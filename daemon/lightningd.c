#include "lightningd.h"
#include "log.h"
#include <ccan/tal/tal.h>
#include <sys/types.h>
#include <unistd.h>

static struct lightningd_state *lightningd_state(void)
{
	struct lightningd_state *state = tal(NULL, struct lightningd_state);

	state->log_record = new_log_record(state, 20 * 1024 * 1024, LOG_INFORM);
	state->base_log = new_log(state, state->log_record,
				  "lightningd(%u):", (int)getpid());

	return state;
}

int main(int argc, char *argv[])
{
	struct lightningd_state *state = lightningd_state();

	log_info(state->base_log, "Hello world!");
	tal_free(state);
	return 0;
}
