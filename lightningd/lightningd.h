#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <daemon/lightningd.h>

/* BOLT #1:
 *
 * The default TCP port is 9735. This corresponds to hexadecimal
 * `0x2607`, the unicode code point for LIGHTNING.
 */
#define DEFAULT_PORT 0x2607

/* FIXME: This is two structures, during the migration from old setup to new */
struct lightningd {
	/* Must be first, since things assume we can tal() off it */
	struct lightningd_state dstate;

	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Log for general stuff. */
	struct log *log;

	/* Bearer of all my secrets. */
	struct subdaemon *hsm;

	/* All peers we're tracking. */
	struct list_head peers;
};
#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */
