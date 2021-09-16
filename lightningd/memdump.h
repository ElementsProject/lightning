#ifndef LIGHTNING_LIGHTNINGD_MEMDUMP_H
#define LIGHTNING_LIGHTNINGD_MEMDUMP_H
#include "config.h"

struct command;
struct htable;
struct strmap;
struct subd;

void opening_memleak_done(struct command *cmd, struct subd *leaker);
void peer_memleak_done(struct command *cmd, struct subd *leaker);

#endif /* LIGHTNING_LIGHTNINGD_MEMDUMP_H */
