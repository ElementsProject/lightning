#ifndef LIGHTNING_DAEMON_LIGHTNING_H
#define LIGHTNING_DAEMON_LIGHTNING_H
#include "config.h"
#include <ccan/list/list.h>
#include <ccan/timer/timer.h>
#include <stdio.h>

/* Here's where the global variables hide! */
struct lightningd_state {
	/* Where all our logging goes. */ 
	struct log_record *log_record;
	struct log *base_log;
	FILE *logf;

	/* Our config dir, and rpc file */
	char *config_dir;
	char *rpc_filename;

	/* Any pending timers. */
	struct timers timers;

	/* Our peers. */
	struct list_head peers;
};
#endif /* LIGHTNING_DAEMON_LIGHTNING_H */
