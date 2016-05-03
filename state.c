#include <ccan/build_assert/build_assert.h>
#ifndef TEST_STATE_COVERAGE
#include <daemon/peer.h>
#endif
#include <state.h>

/* STATE_CLOSE* can be treated as a bitset offset from STATE_CLOSED */
#define BITS_TO_STATE(bits) (STATE_CLOSED + (bits))
#define STATE_TO_BITS(state) ((state) - STATE_CLOSED)

/* For the rare cases where state may not change */
static enum command_status next_state_nocheck(struct peer *peer,
					      enum command_status cstatus,
					      const enum state state)
{
	peer->state = state;
	return cstatus;
}

static enum command_status next_state(struct peer *peer,
				      enum command_status cstatus,
				      const enum state state)
{
	assert(peer->state != state);
	return next_state_nocheck(peer, cstatus, state);
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
static enum command_status unchanged_state(enum command_status cstatus)
{
	return cstatus;
}

/* This may not actually change the state. */
static enum command_status next_state_bits(struct peer *peer,
					   enum command_status cstatus,
					   unsigned int bits)
{
	return next_state_nocheck(peer, cstatus, BITS_TO_STATE(bits));
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
	const struct bitcoin_tx *tx;
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
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR);
		} else if (input_is(input, CMD_OPEN_WITHOUT_ANCHOR)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			queue_pkt_open(peer,
				       OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR);
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			return next_state(peer, cstatus, STATE_OPEN_WAIT_FOR_ANCHOR);
		} else if (input_is(input, CMD_CLOSE)
			   || input_is(input, INPUT_CONNECTION_LOST)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			bitcoin_create_anchor(peer, BITCOIN_ANCHOR_CREATED);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_ANCHOR_CREATE);
		} else if (input_is(input, CMD_CLOSE)
			   || input_is(input, INPUT_CONNECTION_LOST)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR_CREATE:
		if (input_is(input, BITCOIN_ANCHOR_CREATED)) {
			queue_pkt_anchor(peer);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMMIT_SIG);
		} else if (input_is(input, CMD_CLOSE)
			   || input_is(input, INPUT_CONNECTION_LOST)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			err = accept_pkt_anchor(peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			queue_pkt_open_commit_sig(peer);
			peer_watch_anchor(peer, 
					  BITCOIN_ANCHOR_DEPTHOK,
					  BITCOIN_ANCHOR_TIMEOUT,
					  BITCOIN_ANCHOR_UNSPENT,
					  BITCOIN_ANCHOR_THEIRSPEND,
					  BITCOIN_ANCHOR_OTHERSPEND);

			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR);
		} else if (input_is(input, CMD_CLOSE)
			   || input_is(input, INPUT_CONNECTION_LOST)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			err = accept_pkt_open_commit_sig(peer, idata->pkt);
			if (err) {
				bitcoin_release_anchor(peer, INPUT_NONE);
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_start_unilateral_close;
			}
			queue_tx_broadcast(broadcast, bitcoin_anchor(peer));
			peer_watch_anchor(peer,
					  BITCOIN_ANCHOR_DEPTHOK,
					  INPUT_NONE,
					  BITCOIN_ANCHOR_UNSPENT,
					  BITCOIN_ANCHOR_THEIRSPEND,
					  BITCOIN_ANCHOR_OTHERSPEND);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR);
		} else if (input_is(input, CMD_CLOSE)
			   || input_is(input, INPUT_CONNECTION_LOST)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
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
				goto err_start_unilateral_close;
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt_open_complete(peer);
			if (peer->state == STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus, STATE_NORMAL);
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer, 
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(peer, cstatus, STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_unilateral_close;
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
				goto err_start_unilateral_close;
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_TIMEOUT)) {
			/* Anchor didn't reach blockchain in reasonable time. */
			queue_pkt_err(peer, pkt_err(peer, "Anchor timed out"));
			return next_state(peer, cstatus, STATE_ERR_ANCHOR_TIMEOUT);
		} else if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt_open_complete(peer);
			if (peer->state == STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus, STATE_NORMAL);
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(peer, cstatus,
					  STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_unilateral_close;
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
				return next_state(peer, cstatus, STATE_NORMAL);
			} else {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus, STATE_NORMAL);
			}
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		/* Nobody should be able to spend anchor, except via the
		 * commit txs. */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			return next_state(peer, cstatus,
					  STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_clearing;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_unilateral_close;
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
			return next_state(peer, cstatus, STATE_NORMAL_COMMITTING);
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
				goto err_start_unilateral_close;
			}
			complete_cmd(peer, &cstatus, CMD_SUCCESS);
			return next_state(peer, cstatus, STATE_NORMAL);
		}

		if (input_is(input, CMD_CLOSE)) {
			goto start_clearing;
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			err = accept_pkt_htlc_add(peer, idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			return unchanged_state(cstatus);
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			err = accept_pkt_htlc_fulfill(peer, idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			return unchanged_state(cstatus);
		} else if (input_is(input, PKT_UPDATE_FAIL_HTLC)) {
			err = accept_pkt_htlc_fail(peer, idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			return unchanged_state(cstatus);
		} else if (input_is(input, PKT_UPDATE_COMMIT)) {
			err = accept_pkt_commit(peer, idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			queue_pkt_revocation(peer);
			return unchanged_state(cstatus);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			goto old_commit_spotted;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			goto start_unilateral_close;
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
				goto err_start_unilateral_close;

			/* Notify us when there are no more htlcs in
			 * either commit tx */
			peer_watch_htlcs_cleared(peer, INPUT_HTLCS_CLEARED);

			return next_state(peer, cstatus, STATE_BOTH_CLEARING);
		/* FIXME: We must continue to allow fulfill & fail! */
		} else if (input_is(input, CMD_SEND_HTLC_FAIL)
			   || input_is(input, CMD_SEND_HTLC_FULFILL)) {
			err = pkt_err(peer, "FIXME: cmd during clearing.");
			goto err_start_unilateral_close;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			goto start_unilateral_close;
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
			goto err_start_unilateral_close;
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			goto start_unilateral_close;
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
				goto err_start_unilateral_close;

			/* Are we about to offer the same fee they did? */
			if (we_agree) {
				/* Offer the new fee. */
				queue_pkt_close_signature(peer);
				acked = true;
			}

			/* Do fees now match? */
			if (acked) {
				peer_unwatch_close_timeout(peer,
						   INPUT_CLOSE_COMPLETE_TIMEOUT);

				/* Send close TX. */
				queue_tx_broadcast(broadcast,
						   bitcoin_close(peer));
				change_peer_cond(peer,
						 PEER_CLOSING, PEER_CLOSED);
				return next_state(peer, cstatus,
						  STATE_CLOSE_WAIT_CLOSE);
			}

			/* Offer the new fee. */
			queue_pkt_close_signature(peer);
			return unchanged_state(cstatus);
		} else if (input_is(input, INPUT_CONNECTION_LOST)) {
			goto start_unilateral_close;
		} else if (input_is(input, INPUT_CLOSE_COMPLETE_TIMEOUT)) {
			err = pkt_err(peer, "Close timed out");
			goto err_start_unilateral_close;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;

	/* Close states are regular: handle as a group. */
	case STATE_CLOSE_WAIT_HTLCS:
	case STATE_CLOSE_WAIT_STEAL:
	case STATE_CLOSE_WAIT_SPENDTHEM:
	case STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_CLOSE:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_OURCOMMIT:
	case STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDOURS_WITH_HTLCS: {
		unsigned int bits;
		enum state_input closed;

		bits = STATE_TO_BITS(peer->state);

		/* Once we see a steal or spend completely buried, we
		 * close unless we're still waiting for htlcs*/
		if (bits & STATE_CLOSE_HTLCS_BIT)
			closed = STATE_CLOSE_WAIT_HTLCS;
		else
			closed = STATE_CLOSED;

		if ((bits & STATE_CLOSE_STEAL_BIT)
		    && input_is(input, BITCOIN_STEAL_DONE)) {
			/* One a steal is complete, we don't care about htlcs
			 * (we stole them all) */
			if (bits & STATE_CLOSE_HTLCS_BIT)
				peer_unwatch_all_htlc_outputs(peer);
			return next_state(peer, cstatus, STATE_CLOSED);
		}

		if ((bits & STATE_CLOSE_SPENDTHEM_BIT)
		    && input_is(input, BITCOIN_SPEND_THEIRS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDTHEM_BIT));
			return next_state(peer, cstatus, closed);
		}

		if ((bits & STATE_CLOSE_CLOSE_BIT)
		    && input_is(input, BITCOIN_CLOSE_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_CLOSE_BIT));
			return next_state(peer, cstatus, closed);
		}

		if ((bits & STATE_CLOSE_OURCOMMIT_BIT)
		    && input_is(input, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_OURCOMMIT_BIT));
			tx = bitcoin_spend_ours(peer);
			/* Now we need to wait for our commit to be done. */
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_SPEND_OURS_DONE);
			bits &= ~STATE_CLOSE_OURCOMMIT_BIT;
			bits |= STATE_CLOSE_SPENDOURS_BIT;
			return next_state(peer, cstatus, BITS_TO_STATE(bits));
		}

		if ((bits & STATE_CLOSE_SPENDOURS_BIT)
		    && input_is(input, BITCOIN_SPEND_OURS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDOURS_BIT));
			return next_state(peer, cstatus, closed);
		}

		/* If we have htlcs, we can get other inputs... */
		if (bits & STATE_CLOSE_HTLCS_BIT) {
			if (input_is(input, INPUT_NO_MORE_HTLCS)) {
				/* Clear bit, might lead to STATE_CLOSED. */
				BUILD_ASSERT((BITS_TO_STATE(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS) & ~STATE_CLOSE_HTLCS_BIT)) == STATE_CLOSED);
				bits &= ~STATE_CLOSE_HTLCS_BIT;
				return next_state(peer, cstatus,
						  BITS_TO_STATE(bits));
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_SPENT)) {
				/* They revealed R value. */
				peer_tx_revealed_r_value(peer,
							 idata->htlc_onchain);
				/* We don't care any more. */
				peer_unwatch_htlc_output(peer,
							 idata->htlc_onchain,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_TIMEOUT)){
				tx = bitcoin_htlc_timeout(peer,
							  idata->htlc_onchain);
				/* HTLC timed out, spend it back to us. */
				queue_tx_broadcast(broadcast, tx);
				/* Don't unwatch yet; they could yet
				 * try to spend, revealing rvalue. */

				/* We're done when that gets buried. */
				peer_watch_htlc_spend(peer, tx,
						      idata->htlc_onchain,
						      BITCOIN_HTLC_RETURN_SPEND_DONE);
				return unchanged_state(cstatus);
			} else if (input_is(input, INPUT_RVALUE)) {
				tx = bitcoin_htlc_spend(peer,
							idata->htlc_onchain);

				/* Spend it... */
				queue_tx_broadcast(broadcast, tx);
				/* We're done when it gets buried. */
				peer_watch_htlc_spend(peer, tx,
						      idata->htlc_onchain,
						 BITCOIN_HTLC_FULFILL_SPEND_DONE);
				/* Don't care about this one any more. */
				peer_unwatch_htlc_output(peer,
							 idata->htlc_onchain,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_FULFILL_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				peer_unwatch_htlc_spend(peer,
							idata->htlc_onchain,
							INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_RETURN_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				peer_unwatch_htlc_spend(peer,
							idata->htlc_onchain,
							INPUT_NO_MORE_HTLCS);

				/* Don't need to watch the HTLC output any more,
				 * either. */
				peer_unwatch_htlc_output(peer,
							 idata->htlc_onchain,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_TOUS_TIMEOUT)) {
				/* They can spend, we no longer care
				 * about this HTLC. */
				peer_unwatch_htlc_output(peer,
							 idata->htlc_onchain,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			}
		}

		/* If we're just waiting for HTLCs, anything else is an error */
		if (peer->state == STATE_CLOSE_WAIT_HTLCS)
			break;

		/*
		 * Now, other side can always spring a commit transaction on us
		 * (even if they already have, due to tx malleability).
		 */
		if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			tx = bitcoin_spend_theirs(peer, idata->btc);
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_SPEND_THEIRS_DONE);
			/* HTLC watches: if any, set HTLCs bit. */
			if (peer_watch_their_htlc_outputs(peer, idata->btc,
						BITCOIN_HTLC_TOUS_TIMEOUT,
						BITCOIN_HTLC_TOTHEM_SPENT,
						BITCOIN_HTLC_TOTHEM_TIMEOUT))
				bits |= STATE_CLOSE_HTLCS_BIT;

			bits |= STATE_CLOSE_SPENDTHEM_BIT;
			return next_state_bits(peer, cstatus, bits);
			/* This can happen multiple times: need to steal ALL */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			tx = bitcoin_steal(peer, idata->btc);
			if (!tx)
				return next_state(peer, cstatus,
						  STATE_ERR_INFORMATION_LEAK);
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_STEAL_DONE);
			bits |= STATE_CLOSE_STEAL_BIT;
			return next_state_bits(peer, cstatus, bits);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT))
			goto anchor_unspent;

		break;
	}

	/* Should never happen. */
	case STATE_ERR_INTERNAL:
	case STATE_ERR_INFORMATION_LEAK:
	case STATE_ERR_ANCHOR_TIMEOUT:
	case STATE_ERR_ANCHOR_LOST:
	case STATE_CLOSED:
	case STATE_MAX:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS_WITH_HTLCS:
		return next_state(peer, cstatus, STATE_ERR_INTERNAL);
	}

	/* State machine should handle all possible states. */
	return next_state(peer, cstatus, STATE_ERR_INTERNAL);

unexpected_pkt:
	/*
	 * We got a weird packet, so we need to close unilaterally.
	 */
	peer_unexpected_pkt(peer, idata->pkt);

	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		goto start_unilateral_close;
	}
	err = pkt_err_unexpected(peer, idata->pkt);
	goto err_start_unilateral_close;

unexpected_pkt_nocleanup:
	/*
	 * Unexpected packet, but nothing sent to chain yet, so no cleanup.
	 */
	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		goto close_nocleanup;
	}
	err = pkt_err_unexpected(peer, idata->pkt);
	goto err_close_nocleanup;

anchor_unspent:
	/*
	 * Bitcoind tells us anchor got double-spent.  If we double-spent it
	 * then we're malfunctioning.  If they double-spent it, then they
	 * managed to cheat us: post_to_reddit();
	 */
	return next_state(peer, cstatus, STATE_ERR_ANCHOR_LOST);

err_close_nocleanup:
	/*
	 * Something went wrong, but we haven't sent anything to the blockchain
	 * so there's nothing to clean up.
	 */
	queue_pkt_err(peer, err);

close_nocleanup:
	change_peer_cond(peer, PEER_CMD_OK, PEER_CLOSED);
	return next_state(peer, cstatus, STATE_CLOSED);

err_start_unilateral_close:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	queue_pkt_err(peer, err);

start_unilateral_close:
	/*
	 * Close unilaterally.
	 */

	/* No more inputs, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);

	/*
	 * If they sent us a close tx, that's always cheaper than
	 * broadcasting our last commit tx, and our funds are not
	 * timelocked.
	 */
	if (peer_has_close_sig(peer)) {
		queue_tx_broadcast(broadcast, bitcoin_close(peer));
		return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE);
	}

	tx = bitcoin_commit(peer);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_delayed(peer, tx, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED);

	/* HTLC watches. */
	if (peer_watch_our_htlc_outputs(peer, tx,
					BITCOIN_HTLC_TOUS_TIMEOUT,
					BITCOIN_HTLC_TOTHEM_SPENT,
					BITCOIN_HTLC_TOTHEM_TIMEOUT))
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS);

	return next_state(peer, cstatus, STATE_CLOSE_WAIT_OURCOMMIT);

them_unilateral:
	assert(input == BITCOIN_ANCHOR_THEIRSPEND);

	/*
	 * Bitcoind tells us they did unilateral close.
	 */
	queue_pkt_err(peer, pkt_err(peer, "Commit tx noticed"));

	/* No more inputs, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);
	tx = bitcoin_spend_theirs(peer, idata->btc);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_tx(peer, tx, BITCOIN_SPEND_THEIRS_DONE);

	/* HTLC watches (based on what they broadcast, which *may* be out
	 * of step with our current state by +/- 1 htlc. */
	if (peer_watch_their_htlc_outputs(peer, idata->btc,
					  BITCOIN_HTLC_TOUS_TIMEOUT,
					  BITCOIN_HTLC_TOTHEM_SPENT,
					  BITCOIN_HTLC_TOTHEM_TIMEOUT))
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS);

	return next_state(peer, cstatus, STATE_CLOSE_WAIT_SPENDTHEM);

start_clearing:
	/*
	 * Start a mutual close: tell them we want to clear.
	 */
	queue_pkt_close_clearing(peer);

	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);

	return next_state(peer, cstatus, STATE_US_CLEARING);

start_closing_cleared:
	/* As soon as we send packet, they could close. */
	peer_calculate_close_fee(peer);
	peer_watch_close(peer, BITCOIN_CLOSE_DONE, INPUT_CLOSE_COMPLETE_TIMEOUT);
	queue_pkt_close_signature(peer);
	return next_state(peer, cstatus, STATE_WAIT_FOR_CLOSE_SIG);

accept_clearing:
	err = accept_pkt_close_clearing(peer, idata->pkt);
	if (err)
		goto err_start_unilateral_close;

	/* Notify us when there are no more htlcs in either commit tx */
	peer_watch_htlcs_cleared(peer, INPUT_HTLCS_CLEARED);

	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);

	/* Tell them we're clearing too. */
	queue_pkt_close_clearing(peer);

	return next_state(peer, cstatus, STATE_BOTH_CLEARING);

instant_close:
	/*
	 * Closing, but we haven't sent anything to the blockchain so
	 * there's nothing to clean up.
	 */
	/* FIXME: Should we tell other side we're going? */
	set_peer_cond(peer, PEER_CLOSED);

	/* We can't have any HTLCs, since we haven't started. */
	if (committed_to_htlcs(peer))
		return next_state(peer, cstatus, STATE_ERR_INTERNAL);

	return next_state(peer, cstatus, STATE_CLOSED);

old_commit_spotted:
	/*
	 * bitcoind reported a broadcast of the not-latest commit tx.
	 */
	queue_pkt_err(peer, pkt_err(peer, "Otherspend noticed"));

	/* No more packets, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);

	/* If we can't find it, we're lost. */
	tx = bitcoin_steal(peer, idata->btc);
	if (!tx)
		return next_state(peer, cstatus,
				  STATE_ERR_INFORMATION_LEAK);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_tx(peer, tx, BITCOIN_STEAL_DONE);
	return next_state(peer, cstatus, STATE_CLOSE_WAIT_STEAL);
}
