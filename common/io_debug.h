#ifndef LIGHTNING_COMMON_IO_DEBUG_H
#define LIGHTNING_COMMON_IO_DEBUG_H
#include "config.h"
#include <poll.h>

/* Replacement poll which checks for memory leaks in middle of ccan/io loop. */
int debug_poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif /* LIGHTNING_COMMON_IO_DEBUG_H */
