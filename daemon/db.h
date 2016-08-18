#ifndef LIGHTNING_DAEMON_DB_H
#define LIGHTNING_DAEMON_DB_H
#include "config.h"
#include "peer.h"
#include <stdbool.h>

void db_init(struct lightningd_state *dstate);

bool db_create_peer(struct peer *peer);
bool db_set_anchor(struct peer *peer);
bool db_set_visible_state(struct peer *peer);

bool db_start_transaction(struct peer *peer);
void db_abort_transaction(struct peer *peer);
bool db_commit_transaction(struct peer *peer);

void db_add_wallet_privkey(struct lightningd_state *dstate,
			   const struct privkey *privkey);

bool db_add_peer_address(struct lightningd_state *dstate,
			 const struct peer_address *addr);

/* Must NOT be inside transaction. */
bool db_htlc_fulfilled(struct peer *peer, const struct htlc *htlc);
bool db_set_our_closing_script(struct peer *peer);
bool db_set_their_closing_script(struct peer *peer);
bool db_update_our_closing(struct peer *peer);
bool db_update_their_closing(struct peer *peer);

/* FIXME: save error handling until db_commit_transaction for calls
 * which have to be inside transaction anyway. */

/* Must be inside transaction. */
bool db_new_htlc(struct peer *peer, const struct htlc *htlc);
bool db_update_htlc_state(struct peer *peer, const struct htlc *htlc,
				 enum htlc_state oldstate);
bool db_new_commit_info(struct peer *peer, enum channel_side side,
			const struct sha256 *prev_rhash);
bool db_remove_their_prev_revocation_hash(struct peer *peer);
bool db_update_next_revocation_hash(struct peer *peer);
bool db_save_shachain(struct peer *peer);
bool db_update_state(struct peer *peer);
bool db_begin_shutdown(struct peer *peer);

bool db_add_commit_map(struct peer *peer,
		       const struct sha256_double *txid, u64 commit_num);

void db_forget_peer(struct peer *peer);
#endif /* LIGHTNING_DAEMON_DB_H */
