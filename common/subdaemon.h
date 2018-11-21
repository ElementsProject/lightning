#ifndef LIGHTNING_COMMON_SUBDAEMON_H
#define LIGHTNING_COMMON_SUBDAEMON_H
#include "config.h"
#include <common/daemon.h>

/* daemon_setup, but for subdaemons */
void subdaemon_setup(int argc, char *argv[]);

#if DEVELOPER
struct htable;

bool dump_memleak(struct htable *memtable);
#endif

#endif /* LIGHTNING_COMMON_SUBDAEMON_H */
