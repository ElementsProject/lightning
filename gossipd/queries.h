#ifndef LIGHTNING_GOSSIPD_QUERIES_H
#define LIGHTNING_GOSSIPD_QUERIES_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_update_timestamps;
struct daemon;
struct io_conn;
struct peer;
struct range_query_reply;
struct short_channel_id;

/* Various handlers when peer fwds a gossip query reply msg: return is NULL or
 * error packet. */
const u8 *handle_reply_short_channel_ids_end(struct peer *peer, const u8 *msg);
const u8 *handle_reply_channel_range(struct peer *peer, const u8 *msg);

/* Ask this peer for a range of scids.  Must support it, and not already
 * have a query pending. */
bool query_channel_range(struct daemon *daemon,
			 struct peer *peer,
			 u32 first_blocknum, u32 number_of_blocks,
			 enum query_option_flags qflags,
			 void (*cb)(struct peer *peer_,
				    u32 first_blocknum_,
				    u32 number_of_blocks_,
				    const struct range_query_reply *replies_));

/* Ask this peer for info about an array of scids, with optional query_flags */
bool query_short_channel_ids(struct daemon *daemon,
			     struct peer *peer,
			     const struct short_channel_id *scids,
			     const u8 *query_flags,
			     void (*cb)(struct peer *peer_, bool complete));

#endif /* LIGHTNING_GOSSIPD_QUERIES_H */
