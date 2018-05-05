/* common/socket_close - Properly close a socket,
 * ensuring that any data we write just before
 * the close has been transmitted to the other
 * side, and ignoring any data the other side
 * has sent at the time the close was started.
 *
 * Reference:
 *
 * http://ia800504.us.archive.org/3/items/TheUltimateSo_lingerPageOrWhyIsMyTcpNotReliable/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable.html
 */
#ifndef LIGHTNING_COMMON_SOCKET_CLOSE_H
#define LIGHTNING_COMMON_SOCKET_CLOSE_H
#include "config.h"
#include <stdbool.h>

/* Return false if something failed, true if
 * nothing failed.
 * If something failed, error is stored in
 * `errno.
 */
bool socket_close(int fd);

#endif /* LIGHTNING_COMMON_SOCKET_CLOSE_H */
