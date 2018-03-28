#ifndef LIGHTNING_COMMON_SUBDAEMON_H
#define LIGHTNING_COMMON_SUBDAEMON_H
#include "config.h"

void subdaemon_setup(int argc, char *argv[]);

/* Shutdown for a valgrind-clean exit (frees everything) */
void subdaemon_shutdown(void);

#endif /* LIGHTNING_COMMON_SUBDAEMON_H */
