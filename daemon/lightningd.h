#ifndef LIGHTNING_DAEMON_LIGHTNING_H
#define LIGHTNING_DAEMON_LIGHTNING_H
#include "config.h"

/* Here's where the global variables hide! */
struct lightningd_state {
	/* Where all our logging goes. */ 
	struct log_record *log_record;
	struct log *base_log;
};
#endif /* LIGHTNING_DAEMON_LIGHTNING_H */
