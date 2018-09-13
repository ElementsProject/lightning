/* Macro definitions for constants used in BOLT #4 */
#ifndef LIGHTNING_WIRE_ONION_DEFS_H
#define LIGHTNING_WIRE_ONION_DEFS_H
#include "config.h"

/* BOLT #4:
 *
 * The top byte of `failure_code` can be read as a set of flags:
 * * 0x8000 (BADONION): unparsable onion encrypted by sending peer
 * * 0x4000 (PERM): permanent failure (otherwise transient)
 * * 0x2000 (NODE): node failure (otherwise channel)
 * * 0x1000 (UPDATE): new channel update enclosed
 */
#define BADONION	0x8000
#define PERM		0x4000
#define NODE		0x2000
#define UPDATE		0x1000

#endif /* LIGHTNING_WIRE_ONION_DEFS_H */
