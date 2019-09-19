#ifndef LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H
#define LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H
#include <config.h>

#define REMOTE_CONTRIB_LIMIT 4

/* Designator for flagging what role a peer
 * is playing in channel establishment (v2)
 */
enum role {
	OPENER,
	ACCEPTER,
	NUM_ROLES
};

#endif /* LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H */
