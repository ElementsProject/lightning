#ifndef LIGHTNING_GOSSIPD_QUERIES_H
#define LIGHTNING_GOSSIPD_QUERIES_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct daemon;
struct io_conn;
struct peer;
struct short_channel_id;

/* Various handlers when peer fwds a gossip query msg: return is NULL or
 * error packet. */
const u8 *handle_query_short_channel_ids(struct peer *peer, const u8 *msg);
const u8 *handle_reply_short_channel_ids_end(struct peer *peer, const u8 *msg);
const u8 *handle_query_channel_range(struct peer *peer, const u8 *msg);
const u8 *handle_reply_channel_range(struct peer *peer, const u8 *msg);

void query_unknown_channel(struct daemon *daemon,
			   struct peer *peer,
			   const struct short_channel_id *id);

/* This called when the peer is idle. */
void maybe_send_query_responses(struct peer *peer);

/* Ask this peer for a range of scids.  Must support it, and not already
 * have a query pending. */
bool query_channel_range(struct daemon *daemon,
			 struct peer *peer,
			 u32 first_blocknum, u32 number_of_blocks,
			 void (*cb)(struct peer *peer,
				    u32 first_blocknum, u32 number_of_blocks,
				    const struct short_channel_id *scids,
				    bool complete));

#if DEVELOPER
struct io_plan *query_scids_req(struct io_conn *conn,
				struct daemon *daemon,
				const u8 *msg);

struct io_plan *dev_query_channel_range(struct io_conn *conn,
					struct daemon *daemon,
					const u8 *msg);

/* This is a testing hack to allow us to artificially lower the maximum bytes
 * of short_channel_ids we'll encode, using dev_set_max_scids_encode_size. */
struct io_plan *dev_set_max_scids_encode_size(struct io_conn *conn,
					      struct daemon *daemon,
					      const u8 *msg);
#endif /* DEVELOPER */

#endif /* LIGHTNING_GOSSIPD_QUERIES_H */
