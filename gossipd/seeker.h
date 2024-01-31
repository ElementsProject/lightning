#ifndef LIGHTNING_GOSSIPD_SEEKER_H
#define LIGHTNING_GOSSIPD_SEEKER_H
#include "config.h"

struct daemon;
struct node_id;
struct short_channel_id;

struct seeker *new_seeker(struct daemon *daemon);

/* source_peer can be NULL! */
void query_unknown_channel(struct daemon *daemon,
			   const struct node_id *source_peer,
			   const struct short_channel_id unknown_scid);

/* source_peer can be NULL! */
void query_unknown_node(struct daemon *daemon,
			const struct node_id *source_peer,
			const struct node_id *unknown_node);

void seeker_setup_peer_gossip(struct seeker *seeker, struct peer *peer);

bool remove_unknown_scid(struct seeker *seeker,
			 const struct short_channel_id *scid,
			 bool found);

void seeker_peer_gone(struct seeker *seeker,
		      const struct peer *peer);

void dev_seeker_memleak(struct htable *memtable, struct seeker *seeker);
#endif /* LIGHTNING_GOSSIPD_SEEKER_H */
