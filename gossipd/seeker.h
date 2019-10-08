#ifndef LIGHTNING_GOSSIPD_SEEKER_H
#define LIGHTNING_GOSSIPD_SEEKER_H
#include "config.h"

struct daemon;
struct peer;
struct short_channel_id;

struct seeker *new_seeker(struct daemon *daemon);

void gossip_missing(struct daemon *daemon, struct seeker *seeker);

void query_unknown_channel(struct daemon *daemon,
			   struct peer *peer,
			   const struct short_channel_id *id);

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid);
bool add_unknown_scid(struct seeker *seeker,
		      const struct short_channel_id *scid);

bool seeker_gossip(const struct seeker *seeker);

#endif /* LIGHTNING_GOSSIPD_SEEKER_H */
