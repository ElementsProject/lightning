#ifndef LIGHTNING_DEVTOOLS_CLEAN_TOPO_H
#define LIGHTNING_DEVTOOLS_CLEAN_TOPO_H
#include "config.h"

struct gossmap;

/* Cleans topology:
 * 1. Removes channels not enabled in both dirs.
 * 2. (if remove_singles) remove nodes with only one connection.
 * 3. Remove isolated nodes (we assume first node is well-connected!).
 */
void clean_topo(struct gossmap *map, bool remove_singles);
#endif /* LIGHTNING_DEVTOOLS_CLEAN_TOPO_H */
