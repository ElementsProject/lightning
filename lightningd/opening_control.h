#ifndef LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <lightningd/peer_control.h>

struct channel_id;
struct crypto_state;
struct json_stream;
struct lightningd;
struct peer_fd;
struct uncommitted_channel;

void json_add_uncommitted_channel(struct json_stream *response,
				  const struct uncommitted_channel *uc);

void peer_start_openingd(struct peer *peer,
			 struct peer_fd *peer_fd);

struct subd *peer_get_owning_subd(struct peer *peer);

#endif /* LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H */
