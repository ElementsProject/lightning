/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_FDPASS_H
#define CCAN_FDPASS_H

#include <stdbool.h>

/**
 * fdpass_send - send a file descriptor across a socket
 * @sockout: socket to write to
 * @fd: file descriptor to pass
 *
 * On failure, sets errno and returns false.
 */
bool fdpass_send(int sockout, int fd);

/**
 * fdpass_recv - receive a file descriptor from a socket
 * @sockin: socket to read from
 *
 * On failure, returns -1 and sets errno.  Otherwise returns fd.
 */
int fdpass_recv(int sockin);
#endif /* CCAN_FDPASS_H */
