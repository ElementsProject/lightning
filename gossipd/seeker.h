#ifndef LIGHTNING_GOSSIPD_SEEKER_H
#define LIGHTNING_GOSSIPD_SEEKER_H
#include "config.h"

struct daemon;
struct peer;
struct short_channel_id;

struct seeker *new_seeker(struct daemon *daemon);

void query_unknown_channel(struct daemon *daemon,
			   struct peer *peer,
			   const struct short_channel_id *id);

void query_unknown_node(struct seeker *seeker, struct peer *peer);

void seeker_setup_peer_gossip(struct seeker *seeker, struct peer *peer);

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid,
			 bool found);
bool add_unknown_scid(struct seeker *seeker,
		      const struct short_channel_id *scid,
		      struct peer *peer);

#endif /* LIGHTNING_GOSSIPD_SEEKER_H */
