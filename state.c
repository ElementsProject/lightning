#include <ccan/build_assert/build_assert.h>
#include <daemon/db.h>
#include <daemon/lightningd.h>
#include <daemon/log.h>
#include <daemon/packets.h>
#include <daemon/peer.h>
#include <daemon/secrets.h>
#include <names.h>
#include <state.h>

static enum state next_state(struct peer *peer, const enum state state)
{
	assert(peer->state != state);
	return state;
}

static void queue_tx_broadcast(const struct bitcoin_tx **broadcast,
			       const struct bitcoin_tx *tx)
{
	assert(!*broadcast);
	assert(tx);
	*broadcast = tx;
}

static void send_open_pkt(struct peer *peer,
			  OpenChannel__AnchorOffer anchor)
{
	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->local.commit = new_commit_info(peer, 0);
	peer->local.commit->revocation_hash = peer->local.next_revocation_hash;
	peer_get_revocation_hash(peer, 1, &peer->local.next_revocation_hash);

	queue_pkt_open(peer, anchor);
}

static Pkt *init_from_pkt_open(struct peer *peer, const Pkt *pkt)
{
	struct commit_info *ci = new_commit_info(peer, 0);
	Pkt *err;

	err = accept_pkt_open(peer, pkt, &ci->revocation_hash,
			      &peer->remote.next_revocation_hash);
	if (err)
		return err;

	if (!db_set_visible_state(peer))
		return pkt_err(peer, "Database error");

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	peer->remote.commit = ci;

	/* Witness script for anchor. */
	peer->anchor.witnessscript
		= bitcoin_redeem_2of2(peer, peer->dstate->secpctx,
				      &peer->local.commitkey,
				      &peer->remote.commitkey);
	return NULL;
}

enum state state(struct peer *peer,
		 const enum state_input input,
		 const Pkt *pkt,
		 const struct bitcoin_tx **broadcast)
{
	Pkt *err;

	*broadcast = NULL;

	switch (peer->state) {
	/*
	 * Initial channel opening states.
	 */
	case STATE_INIT:
		if (input_is(input, CMD_OPEN_WITH_ANCHOR)) {
			send_open_pkt(peer,
				      OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR);
			return next_state(peer,
					  STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR);
		} else if (input_is(input, CMD_OPEN_WITHOUT_ANCHOR)) {
			send_open_pkt(peer,
				      OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
			return next_state(peer,
					  STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR);
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = init_from_pkt_open(peer, pkt);
			if (err) {
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			return next_state(peer, STATE_OPEN_WAIT_FOR_ANCHOR);
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = init_from_pkt_open(peer, pkt);
			if (err) {
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			bitcoin_create_anchor(peer);
			peer->anchor.ours = true;

			/* This shouldn't happen! */
			if (!setup_first_commit(peer)) {
				err = pkt_err(peer,
					      "Own anchor has insufficient funds");
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			queue_pkt_anchor(peer);
			return next_state(peer, STATE_OPEN_WAIT_FOR_COMMIT_SIG);
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			const char *db_err;

			err = accept_pkt_anchor(peer, pkt);
			if (err) {
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}

			peer->anchor.ours = false;
			if (!setup_first_commit(peer)) {
				err = pkt_err(peer, "Insufficient funds for fee");
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}

			log_debug_struct(peer->log, "Creating sig for %s",
					 struct bitcoin_tx,
					 peer->remote.commit->tx);
			log_add_struct(peer->log, " using key %s",
				       struct pubkey, &peer->local.commitkey);

			peer->remote.commit->sig = tal(peer->remote.commit,
						       struct bitcoin_signature);
			peer->remote.commit->sig->stype = SIGHASH_ALL;
			peer_sign_theircommit(peer, peer->remote.commit->tx,
					      &peer->remote.commit->sig->sig);

			peer->remote.commit->order = peer->order_counter++;
			db_start_transaction(peer);
			db_set_anchor(peer);
			db_new_commit_info(peer, REMOTE, NULL);
			peer_add_their_commit(peer,
					      &peer->remote.commit->txid,
					      peer->remote.commit->commit_num);
			db_err = db_commit_transaction(peer);
			if (db_err) {
				err = pkt_err(peer, "database error");
				peer_open_complete(peer, db_err);
				goto err_breakdown;
			}

			queue_pkt_open_commit_sig(peer);
			peer_watch_anchor(peer, peer->local.mindepth);

			return next_state(peer, STATE_OPEN_WAITING_THEIRANCHOR);
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			const char *db_err;

			peer->local.commit->sig = tal(peer->local.commit,
						      struct bitcoin_signature);
			err = accept_pkt_open_commit_sig(peer, pkt,
							 peer->local.commit->sig);
			if (!err &&
			    !check_tx_sig(peer->dstate->secpctx,
					  peer->local.commit->tx, 0,
					  NULL, 0,
					  peer->anchor.witnessscript,
					  &peer->remote.commitkey,
					  peer->local.commit->sig))
				err = pkt_err(peer, "Bad signature");

			if (err) {
				peer->local.commit->sig
					= tal_free(peer->local.commit->sig);
				bitcoin_release_anchor(peer, INPUT_NONE);
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			peer->their_commitsigs++;

			db_start_transaction(peer);
			db_set_anchor(peer);
			db_new_commit_info(peer, LOCAL, NULL);
			db_err = db_commit_transaction(peer);

			if (db_err) {
				bitcoin_release_anchor(peer, INPUT_NONE);
				err = pkt_err(peer, "database error");
				peer_open_complete(peer, db_err);
				goto err_breakdown;
			}
			queue_tx_broadcast(broadcast, bitcoin_anchor(peer));
			peer_watch_anchor(peer, peer->local.mindepth);
			return next_state(peer, STATE_OPEN_WAITING_OURANCHOR);
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_OURANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(peer, pkt);
			if (err) {
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			return next_state(peer,
					  STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED:
		if (input_is(input, PKT_CLOSE_SHUTDOWN)) {
			peer_open_complete(peer, "Received PKT_CLOSE_SHUTDOWN");
			goto accept_shutdown;
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(peer, pkt);
			if (err) {
				peer_open_complete(peer, err->error->problem);
				goto err_breakdown;
			}
			return next_state(peer,
					  STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED:
		if (input_is(input, PKT_CLOSE_SHUTDOWN)) {
			peer_open_complete(peer, "Received PKT_CLOSE_SHUTDOWN");
			goto accept_shutdown;
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business! */
			peer_open_complete(peer, NULL);
			return next_state(peer, STATE_NORMAL);
		} else if (input_is(input, PKT_CLOSE_SHUTDOWN)) {
			peer_open_complete(peer, "Received PKT_CLOSE_SHUTDOWN");
			goto accept_shutdown;
		} else if (input_is_pkt(input)) {
			peer_open_complete(peer, "unexpected packet");
			goto unexpected_pkt;
		}
		break;

	/* Should never happen. */
	case STATE_NORMAL:
	case STATE_NORMAL_COMMITTING:
	case STATE_ERR_INTERNAL:
	case STATE_ERR_ANCHOR_TIMEOUT:
	case STATE_ERR_INFORMATION_LEAK:
	case STATE_ERR_BREAKDOWN:
	case STATE_CLOSED:
	case STATE_MAX:
	case STATE_SHUTDOWN:
	case STATE_SHUTDOWN_COMMITTING:
	case STATE_MUTUAL_CLOSING:
	case STATE_CLOSE_ONCHAIN_CHEATED:
	case STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL:
	case STATE_CLOSE_ONCHAIN_OUR_UNILATERAL:
	case STATE_CLOSE_ONCHAIN_MUTUAL:
		return next_state(peer, STATE_ERR_INTERNAL);
	}

	/* State machine should handle all possible states. */
	return next_state(peer, STATE_ERR_INTERNAL);

unexpected_pkt:
	peer_unexpected_pkt(peer, pkt, __func__);

	/* Don't reply to an error with an error. */
	if (!input_is(input, PKT_ERROR)) {
		goto breakdown;
	}
	err = pkt_err_unexpected(peer, pkt);
	goto err_breakdown;

err_breakdown:
	queue_pkt_err(peer, err);
breakdown:
	return next_state(peer, STATE_ERR_BREAKDOWN);

accept_shutdown:
	err = accept_pkt_close_shutdown(peer, pkt);
	if (err)
		goto err_breakdown;

	/* If we've sent commit, we're still waiting for it when shutdown. */
	if (peer->state == STATE_NORMAL_COMMITTING)
		return next_state(peer, STATE_SHUTDOWN_COMMITTING);
	return next_state(peer, STATE_SHUTDOWN);
}
