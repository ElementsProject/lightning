#ifndef LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H
#define LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H
#include <config.h>

/**
 *  BOLT-343afe6a339617807ced92ab10480188f8e6970e #2
 *  - if is the `opener`:
 *    ...
 *    - MUST NOT send a total count of more than 64 inputs,
 *      across all `funding_add_input` messages.
 */
#define REMOTE_OPENER_INPUT_LIMIT 64

/* BOLT-343afe6a339617807ced92ab10480188f8e6970e #2
 *
 * - if is the `accepter`:
 *   ...
 *   - MUST NOT send a total count of more than 16 inputs,
 *     across all `funding_add_input` messages.
 */
#define REMOTE_ACCEPTER_INPUT_LIMIT 16

/* BOLT-343afe6a339617807ced92ab10480188f8e6970e #2
 * - if is the `accepter`:
 *   - MUST NOT send a total count of more than 8 outputs,
 *     across all `funding_add_output` messages.
 */
#define REMOTE_OUTPUT_LIMIT 8

/* Designator for flagging what role a peer
 * is playing in channel establishment (v2)
 */
enum role {
	OPENER,
	ACCEPTER,
	NUM_ROLES
};

#endif /* LIGHTNING_OPENINGD_CHANNEL_ESTABLISHMENT_H */
