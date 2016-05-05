#include <ccan/build_assert/build_assert.h>
#include <daemon/log.h>
#ifndef TEST_STATE_COVERAGE
#include <daemon/peer.h>
#endif
#include <names.h>
#include <state.h>

static enum command_status next_state(struct peer *peer,
				      const enum state_input input,
				      enum command_status cstatus,
				      const enum state state)
{
	assert(peer->state != state);
	set_peer_state(peer, state, input_name(input));
	return cstatus;
}

/*
 * Simple marker to note we don't update state.
 *
 * This happens in three cases:
 * - We're ignoring packets while closing.
 * - We stop watching an on-chain HTLC: we indicate that we want
 *   INPUT_NO_MORE_HTLCS when we get the last one.
 * - HTLC add/remove in STATE_NORMAL.
 */
static enum command_status unchanged_state(const struct peer *peer,
					   const enum state_input input,
					   enum command_status cstatus)
{
	log_debug(peer->log, "%s: %s unchanged",
		  input_name(input), state_name(peer->state));
	return cstatus;
}

static void set_peer_cond(struct peer *peer, enum state_peercond cond)
{
	assert(peer->cond != cond);
	peer->cond = cond;
}

static void change_peer_cond(struct peer *peer,
			      enum state_peercond old,
			      enum state_peercond new)
{
	assert(peer->cond == old);
	peer->cond = new;
}

static void complete_cmd(struct peer *peer, enum command_status *statusp,
			 enum command_status status)
{
	change_peer_cond(peer, PEER_BUSY, PEER_CMD_OK);
	*statusp = status;
}

/* FIXME: We do this when a command succeeds instantly, and 
 * state is unchanged. */
static enum command_status instant_cmd_success(struct peer *peer,
					       enum command_status cstatus)
{
	assert(peer->cond == PEER_CMD_OK);
	assert(cstatus == CMD_NONE);
	return CMD_SUCCESS;
}

static void queue_tx_broadcast(const struct bitcoin_tx **broadcast,
			       const struct bitcoin_tx *tx)
{
	assert(!*broadcast);
	assert(tx);
	*broadcast = tx;
}

enum command_status state(struct peer *peer,
			  const enum state_input input,
			  const union input *idata,
			  const struct bitcoin_tx **broadcast)
{
	Pkt *err;
	enum command_status cstatus = CMD_NONE;

	*broadcast = NULL;

	switch (peer->state) {
	/*
	 * Initial channel opening states.
	 */
	case STATE_INIT:
		if (input_is(input, CMD_OPEN_WITH_ANCHOR)) {
			queue_pkt_open(peer,
				       OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR);
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR);
		} else if (input_is(input, CMD_OPEN_WITHOUT_ANCHOR)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			queue_pkt_open(peer,
				       OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR);
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_breakdown;
			}
			return next_state(peer, input, cstatus, STATE_OPEN_WAIT_FOR_ANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto breakdown;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_breakdown;
			}
			bitcoin_create_anchor(peer, BITCOIN_ANCHOR_CREATED);
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_ANCHOR_CREATE);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto breakdown;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR_CREATE:
		if (input_is(input, BITCOIN_ANCHOR_CREATED)) {
			queue_pkt_anchor(peer);
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_COMMIT_SIG);
		} else if (input_is(input, CMD_CLOSE)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto breakdown;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			err = accept_pkt_anchor(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_breakdown;
			}
			queue_pkt_open_commit_sig(peer);
			peer_watch_anchor(peer, 
					  BITCOIN_ANCHOR_DEPTHOK,
					  BITCOIN_ANCHOR_TIMEOUT);

			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto breakdown;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			err = accept_pkt_open_commit_sig(peer, idata->pkt);
			if (err) {
				bitcoin_release_anchor(peer, INPUT_NONE);
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_breakdown;
			}
			queue_tx_broadcast(broadcast, bitcoin_anchor(peer));
			peer_watch_anchor(peer,
					  BITCOIN_ANCHOR_DEPTHOK,
					  INPUT_NONE);
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto breakdown;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_OURANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				/* We no longer care about anchor depth. */
				peer_unwatch_anchor_depth(peer, 
							  BITCOIN_ANCHOR_DEPTHOK,
							  INPUT_NONE);
				goto err_breakdown;
			}
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt_open_complete(peer);
			if (peer->state == STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, input, cstatus, STATE_NORMAL);
			}
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, PKT_CLOSE_CLEARING)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_clearing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				/* We no longer care about anchor depth. */
				peer_unwatch_anchor_depth(peer, 
							  BITCOIN_ANCHOR_DEPTHOK,
							  BITCOIN_ANCHOR_TIMEOUT);
				goto err_breakdown;
			}
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_TIMEOUT)) {
			/* Anchor didn't reach blockchain in reasonable time. */
			queue_pkt_err(peer, pkt_err(peer, "Anchor timed out"));
			return next_state(peer, input, cstatus, STATE_ERR_ANCHOR_TIMEOUT);
		} else if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt_open_complete(peer);
			if (peer->state == STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, input, cstatus, STATE_NORMAL);
			}
			return next_state(peer, input, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, PKT_CLOSE_CLEARING)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_clearing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business!  Anchorer goes first. */
			if (peer->state == STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, input, cstatus, STATE_NORMAL);
			} else {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, input, cstatus, STATE_NORMAL);
			}
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, PKT_CLOSE_CLEARING)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_clearing;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;

	/*
	 * Channel normal operating states.
	 */
	case STATE_NORMAL:
		/*
		 * FIXME: For simplicity, we disallow new staging requests
		 * while a commit is outstanding.
		 */

		/* You can only issue this command one at a time. */
		if (input_is(input, CMD_SEND_COMMIT)) {
			queue_pkt_commit(peer);
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, input, cstatus, STATE_NORMAL_COMMITTING);
		} else if (input_is(input, CMD_SEND_HTLC_ADD)) {
			/* We are to send an HTLC add. */
			queue_pkt_htlc_add(peer, idata->htlc_prog);
			return instant_cmd_success(peer, cstatus);
		} else if (input_is(input, CMD_SEND_HTLC_FULFILL)) {
			/* We are to send an HTLC fulfill. */
			queue_pkt_htlc_fulfill(peer, idata->htlc_prog);
			return instant_cmd_success(peer, cstatus);
		} else if (input_is(input, CMD_SEND_HTLC_FAIL)) {
			/* We are to send an HTLC fail. */
			queue_pkt_htlc_fail(peer, idata->htlc_prog);
			return instant_cmd_success(peer, cstatus);
		}
		/* Fall through... */
	case STATE_NORMAL_COMMITTING:
		/* Only expect revocation in STATE_NORMAL_COMMITTING */
		if (peer->state == STATE_NORMAL_COMMITTING
		    && input_is(input, PKT_UPDATE_REVOCATION)) {
			err = accept_pkt_revocation(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_breakdown;
			}
			complete_cmd(peer, &cstatus, CMD_SUCCESS);
			return next_state(peer, input, cstatus, STATE_NORMAL);
		}

		if (input_is(input, CMD_CLOSE)) {
			goto start_clearing;
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			err = accept_pkt_htlc_add(peer, idata->pkt);
			if (err)
				goto err_breakdown;
			return unchanged_state(peer, input, cstatus);
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			err = accept_pkt_htlc_fulfill(peer, idata->pkt);
			if (err)
				goto err_breakdown;
			return unchanged_state(peer, input, cstatus);
		} else if (input_is(input, PKT_UPDATE_FAIL_HTLC)) {
			err = accept_pkt_htlc_fail(peer, idata->pkt);
			if (err)
				goto err_breakdown;
			return unchanged_state(peer, input, cstatus);
		} else if (input_is(input, PKT_UPDATE_COMMIT)) {
			err = accept_pkt_commit(peer, idata->pkt);
			if (err)
				goto err_breakdown;
			queue_pkt_revocation(peer);
			return unchanged_state(peer, input, cstatus);
		} else if (input_is(input, PKT_CLOSE_CLEARING)) {
			goto accept_clearing;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;
	case STATE_US_CLEARING:
		/* This is their reply once they're clearing too. */
		if (input_is(input, PKT_CLOSE_CLEARING)) {
			err = accept_pkt_close_clearing(peer, idata->pkt);
			if (err)
				goto err_breakdown;

			/* Notify us when there are no more htlcs in
			 * either commit tx */
			peer_watch_htlcs_cleared(peer, INPUT_HTLCS_CLEARED);

			return next_state(peer, input, cstatus, STATE_BOTH_CLEARING);
		/* FIXME: We must continue to allow fulfill & fail! */
		} else if (input_is(input, CMD_SEND_HTLC_FAIL)
			   || input_is(input, CMD_SEND_HTLC_FULFILL)) {
			err = pkt_err(peer, "FIXME: cmd during clearing.");
			goto err_breakdown;
		} else if (input_is_pkt(input)) {
			/* FIXME: We must continue to allow add, fulfill & fail packets */
			goto unexpected_pkt;
		}
		break;
	case STATE_BOTH_CLEARING:
		if (input_is(input, INPUT_HTLCS_CLEARED)) {
			goto start_closing_cleared;
		} else if (input_is(input, CMD_SEND_HTLC_FAIL)
			   || input_is(input, CMD_SEND_HTLC_FULFILL)) {
			err = pkt_err(peer, "FIXME: cmd during clearing.");
			goto err_breakdown;
		} else if (input_is_pkt(input)) {
			/* FIXME: We must continue to allow fulfill & fail packets */
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_CLOSE_SIG:
		if (input_is(input, PKT_CLOSE_SIGNATURE)) {
			bool acked, we_agree;
			err = accept_pkt_close_sig(peer, idata->pkt,
						   &acked, &we_agree);
			if (err)
				goto err_breakdown;

			/* Are we about to offer the same fee they did? */
			if (we_agree) {
				/* Offer the new fee. */
				queue_pkt_close_signature(peer);
				acked = true;
			}

			/* Do fees now match? */
			if (acked) {
				/* Send close TX. */
				queue_tx_broadcast(broadcast,
						   bitcoin_close(peer));
				change_peer_cond(peer,
						 PEER_CLOSING, PEER_CLOSED);
				return next_state(peer, input, cstatus,
						  STATE_CLOSE_WAIT_CLOSE);
			}

			/* Offer the new fee. */
			queue_pkt_close_signature(peer);
			return unchanged_state(peer, input, cstatus);
		} else if (input_is(input, INPUT_CLOSE_COMPLETE_TIMEOUT)) {
			err = pkt_err(peer, "Close timed out");
			goto err_breakdown;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;

	/* Should never happen. */
	case STATE_ERR_INTERNAL:
	case STATE_ERR_ANCHOR_TIMEOUT:
	case STATE_ERR_BREAKDOWN:
	case STATE_CLOSE_WAIT_CLOSE:
	case STATE_CLOSED:
	case STATE_MAX:
	case STATE_CLOSE_ONCHAIN_CHEATED:
	case STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL:
	case STATE_CLOSE_ONCHAIN_OUR_UNILATERAL:
	case STATE_CLOSE_ONCHAIN_MUTUAL:
		return next_state(peer, input, cstatus, STATE_ERR_INTERNAL);
	}

	/* State machine should handle all possible states. */
	return next_state(peer, input, cstatus, STATE_ERR_INTERNAL);

unexpected_pkt:
	peer_unexpected_pkt(peer, idata->pkt);

	/* Don't reply to an error with an error. */
	if (!input_is(input, PKT_ERROR)) {
		goto breakdown;
	}
	err = pkt_err_unexpected(peer, idata->pkt);
	
err_breakdown:
	queue_pkt_err(peer, err);
breakdown:
	return next_state(peer, input, cstatus, STATE_ERR_BREAKDOWN);

start_clearing:
	/*
	 * Start a mutual close: tell them we want to clear.
	 */
	queue_pkt_close_clearing(peer);

	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);

	return next_state(peer, input, cstatus, STATE_US_CLEARING);

start_closing_cleared:
	/* As soon as we send packet, they could close. */
	peer_calculate_close_fee(peer);
	queue_pkt_close_signature(peer);
	return next_state(peer, input, cstatus, STATE_WAIT_FOR_CLOSE_SIG);

accept_clearing:
	err = accept_pkt_close_clearing(peer, idata->pkt);
	if (err)
		goto err_breakdown;

	/* Notify us when there are no more htlcs in either commit tx */
	peer_watch_htlcs_cleared(peer, INPUT_HTLCS_CLEARED);

	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);

	/* Tell them we're clearing too. */
	queue_pkt_close_clearing(peer);

	return next_state(peer, input, cstatus, STATE_BOTH_CLEARING);
}
