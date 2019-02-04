#ifndef LIGHTNING_LIGHTNINGD_MEMDUMP_H
#define LIGHTNING_LIGHTNINGD_MEMDUMP_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct command;
struct htable;
struct strmap;
struct subd;

void opening_memleak_done(struct command *cmd, struct subd *leaker);
void peer_memleak_done(struct command *cmd, struct subd *leaker);

/* Remove any pointers inside this strmap (which is opaque to memleak). */
#define memleak_remove_strmap(memtable, strmap) \
	memleak_remove_strmap_((memtable), tcon_unwrap(strmap))
void memleak_remove_strmap_(struct htable *memtable, const struct strmap *m);

#endif /* LIGHTNING_LIGHTNINGD_MEMDUMP_H */
