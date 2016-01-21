#include <ccan/build_assert/build_assert.h>
#include <state.h>

static inline bool high_priority(enum state state)
{
	return (state & 1) == (STATE_NORMAL_HIGHPRIO & 1);
}
	
#define prio(state, name) \
	(high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

#define toggle_prio(state, name) \
	(!high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

#define add_effect(e, field, val)				\
	do {							\
		struct state_effect *_e = tal(ctx, struct state_effect); \
		_e->etype = STATE_EFFECT_##field;		\
		_e->u.field = (val);				\
		_e->next = (*e);				\
		(*e) = _e;					\
	} while(0)

/* STATE_CLOSE* can be treated as a bitset offset from STATE_CLOSED */
#define BITS_TO_STATE(bits) (STATE_CLOSED + (bits))
#define STATE_TO_BITS(state) ((state) - STATE_CLOSED)

static struct state_effect *next_state(const tal_t *ctx,
				       struct state_effect *effect,
				       const enum state state)
{
	add_effect(&effect, new_state, state);
	return effect;
}

struct state_effect *state(const tal_t *ctx,
			   const enum state state,
			   const struct peer *peer,
			   const enum state_input input,
			   const union input *idata)
{
	struct state_effect *effect = NULL;
	Pkt *decline;
	struct bitcoin_tx *tx;
	Pkt *err;
	struct htlc_watch *htlcs;
	struct htlc_progress *htlcprog;

	switch (state) {
	/*
	 * Initial channel opening states.
	 */
	case STATE_INIT:
		if (input_is(input, CMD_OPEN_WITH_ANCHOR)) {
			add_effect(&effect, send_pkt,
				   pkt_open(ctx, peer,
					    OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR));
			return next_state(ctx, effect,
					  STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR);
		} else if (input_is(input, CMD_OPEN_WITHOUT_ANCHOR)) {
			add_effect(&effect, send_pkt,
				   pkt_open(ctx, peer,
					    OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR));
			return next_state(ctx, effect,
					  STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR);
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(ctx, peer, idata->pkt, &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				goto err_close_nocleanup;
			}
			return next_state(ctx, effect, STATE_OPEN_WAIT_FOR_ANCHOR);
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(ctx, peer, idata->pkt, &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				goto err_close_nocleanup;
			}
			add_effect(&effect, send_pkt, pkt_anchor(ctx, peer));
			return next_state(ctx, effect,
					  STATE_OPEN_WAIT_FOR_COMMIT_SIG);
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			err = accept_pkt_anchor(ctx, peer, idata->pkt, &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				goto err_close_nocleanup;
			}
			add_effect(&effect, send_pkt,
				   pkt_open_commit_sig(ctx, peer));
			add_effect(&effect, watch,
				   bitcoin_watch_anchor(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							BITCOIN_ANCHOR_TIMEOUT,
							BITCOIN_ANCHOR_UNSPENT,
							BITCOIN_ANCHOR_THEIRSPEND,
							BITCOIN_ANCHOR_OTHERSPEND));

			return next_state(ctx, effect,
					  STATE_OPEN_WAITING_THEIRANCHOR);
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			err = accept_pkt_open_commit_sig(ctx, peer, idata->pkt,
							 &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				goto err_start_unilateral_close;
			}
			add_effect(&effect, broadcast_tx,
				   bitcoin_anchor(ctx, peer));
			add_effect(&effect, watch,
				   bitcoin_watch_anchor(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE,
							BITCOIN_ANCHOR_UNSPENT,
							BITCOIN_ANCHOR_THEIRSPEND,
							BITCOIN_ANCHOR_OTHERSPEND));
			return next_state(ctx, effect, STATE_OPEN_WAITING_OURANCHOR);
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAITING_OURANCHOR:
		if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			add_effect(&effect, send_pkt,
				   pkt_open_complete(ctx, peer));
			return next_state(ctx, effect,
					  STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, cmd_fail, NULL);
			goto anchor_unspent;
		} else if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ignore until we've hit depth ourselves. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			add_effect(&effect, cmd_fail, NULL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(ctx, effect, STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			add_effect(&effect, cmd_fail, NULL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			add_effect(&effect, cmd_fail, NULL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAITING_THEIRANCHOR:
		if (input_is(input, BITCOIN_ANCHOR_TIMEOUT)) {
			/* Anchor didn't reach blockchain in reasonable time. */
			add_effect(&effect, send_pkt,
				   pkt_err(ctx, "Anchor timed out"));
			return next_state(ctx, effect, STATE_ERR_ANCHOR_TIMEOUT);
		} else if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			add_effect(&effect, send_pkt,
				   pkt_open_complete(ctx, peer));
			return next_state(ctx, effect, STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, cmd_fail, NULL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(ctx, effect, STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			add_effect(&effect, cmd_fail, NULL);
			goto them_unilateral;
		} else if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ignore until we've hit depth ourselves. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			add_effect(&effect, cmd_fail, NULL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			add_effect(&effect, cmd_fail, NULL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			add_effect(&effect, unwatch,
				   bitcoin_unwatch_anchor_depth(ctx, peer,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business!  Anchorer goes first. */
			if (state == STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR) {
				add_effect(&effect, cmd_success, CMD_OPEN_WITH_ANCHOR);
				return next_state(ctx, effect, STATE_NORMAL_HIGHPRIO);
			} else {
				add_effect(&effect, cmd_success, CMD_OPEN_WITHOUT_ANCHOR);
				return next_state(ctx, effect, STATE_NORMAL_LOWPRIO);
			}
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, cmd_fail, NULL);
			goto anchor_unspent;
		/* Nobody should be able to spend anchor, except via the
		 * commit txs. */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			return next_state(ctx, effect, STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			add_effect(&effect, cmd_fail, NULL);
			goto them_unilateral;
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
			add_effect(&effect, cmd_defer, input);
			/* No state change. */
			return effect;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt;
		}
		break;

	/*
	 * Channel normal operating states.
	 */
	case STATE_NORMAL_LOWPRIO:
	case STATE_NORMAL_HIGHPRIO:
		if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* We are to send an HTLC update. */
			add_effect(&effect, send_pkt,
				   pkt_htlc_update(ctx, peer,
						   idata->htlc_prog));
			add_effect(&effect, htlc_in_progress, idata->htlc_prog);
			return next_state(ctx, effect,
					  prio(state, STATE_WAIT_FOR_HTLC_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_FULFILL)) {
			/* We are to send an HTLC fulfill. */
			/* This gives us the r value (FIXME: type!) */
			add_effect(&effect, r_value,
				   r_value_from_cmd(ctx, peer, idata->htlc));
			add_effect(&effect, send_pkt,
				   pkt_htlc_fulfill(ctx, peer,
						    idata->htlc_prog));
			add_effect(&effect, htlc_in_progress, idata->htlc_prog);
			return next_state(ctx, effect,
					  prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_TIMEDOUT)) {
			/* We are to send an HTLC timedout. */
			add_effect(&effect, send_pkt,
				   pkt_htlc_timedout(ctx, peer,
						     idata->htlc_prog));
			add_effect(&effect, htlc_in_progress, idata->htlc_prog);
			return next_state(ctx, effect,
					  prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_ROUTEFAIL)) {
			/* We are to send an HTLC routefail. */
			add_effect(&effect, send_pkt,
				   pkt_htlc_routefail(ctx, peer,
						      idata->htlc_prog));
			add_effect(&effect, htlc_in_progress, idata->htlc_prog);
			return next_state(ctx, effect,
					  prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_CLOSE)) {
			goto start_closing;
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			goto accept_htlc_update;
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			goto accept_htlc_fulfill;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_ROUTEFAIL_HTLC)) {
			goto accept_htlc_routefail;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			goto old_commit_spotted;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, PKT_CLOSE)) {
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_HTLC_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_HTLC_ACCEPT_HIGHPRIO:
		/* HTLCs can also evoke a refusal. */
		if (input_is(input, PKT_UPDATE_DECLINE_HTLC)) {
			add_effect(&effect, cmd_fail, idata->pkt);
			add_effect(&effect, htlc_abandon, true);
			/* No update means no priority change. */
			return next_state(ctx, effect,
					  prio(state, STATE_NORMAL));
		/* They can't close with an HTLC, so only possible here */	
		} else if (input_is(input, PKT_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto accept_closing;
		}
		/* Fall thru */
	case STATE_WAIT_FOR_UPDATE_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_ACCEPT_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return effect;

			/* Otherwise, process their request first: defer ours */
			add_effect(&effect, cmd_requeue, CMD_SEND_UPDATE_ANY);
			add_effect(&effect, htlc_abandon, true);
			goto accept_htlc_update;
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return effect;

			/* Otherwise, process their request first: defer ours */
			add_effect(&effect, cmd_requeue, CMD_SEND_UPDATE_ANY);
			add_effect(&effect, htlc_abandon, true);
			goto accept_htlc_fulfill;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return effect;

			/* Otherwise, process their request first: defer ours */
			add_effect(&effect, cmd_requeue, CMD_SEND_UPDATE_ANY);
			add_effect(&effect, htlc_abandon, true);
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_ROUTEFAIL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return effect;

			/* Otherwise, process their request first: defer ours */
			add_effect(&effect, cmd_requeue, CMD_SEND_UPDATE_ANY);
			add_effect(&effect, htlc_abandon, true);
			goto accept_htlc_routefail;
		} else if (input_is(input, PKT_UPDATE_ACCEPT)) {
			struct signature *sig;
			err = accept_pkt_update_accept(ctx, peer, idata->pkt,
						       &sig, &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				add_effect(&effect, htlc_abandon, true);
				goto err_start_unilateral_close;
			}
			add_effect(&effect, update_theirsig, sig);
			add_effect(&effect, send_pkt,
				   pkt_update_signature(ctx, peer));
			/* HTLC is signed (though old tx not revoked yet!) */
			add_effect(&effect, htlc_fulfill, true);
			return next_state(ctx, effect,
					  prio(state, STATE_WAIT_FOR_UPDATE_COMPLETE));
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto start_closing;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			add_effect(&effect, htlc_abandon, true);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_COMPLETE_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_COMPLETE_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_COMPLETE)) {
			err = accept_pkt_update_complete(ctx, peer, idata->pkt,
							 &effect);
			if (err) {
				add_effect(&effect, cmd_fail, NULL);
				goto err_start_unilateral_close;
			}
			add_effect(&effect, cmd_success, CMD_SEND_UPDATE_ANY);
			return next_state(ctx, effect,
					  toggle_prio(state, STATE_NORMAL));
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, cmd_fail, NULL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			add_effect(&effect, cmd_fail, NULL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			add_effect(&effect, cmd_fail, NULL);
			goto old_commit_spotted;
		} else if (input_is(input, PKT_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto accept_closing;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, cmd_fail, NULL);
			goto start_closing;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, cmd_fail, NULL);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_SIG_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_SIG_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_SIGNATURE)) {
			struct signature *sig;
			err = accept_pkt_update_signature(ctx, peer, idata->pkt,
							  &sig, &effect);
			if (err) {
				add_effect(&effect, htlc_abandon, true);
				goto err_start_unilateral_close;
			}
			add_effect(&effect, update_theirsig, sig);
			add_effect(&effect, send_pkt,
				   pkt_update_complete(ctx, peer));
			add_effect(&effect, htlc_fulfill, true);
			/* Toggle between high and low priority states. */
			return next_state(ctx, effect,
					  toggle_prio(state, STATE_NORMAL));
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			add_effect(&effect, cmd_defer, input);
			return effect;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			add_effect(&effect, htlc_abandon, true);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			add_effect(&effect, htlc_abandon, true);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			add_effect(&effect, htlc_abandon, true);
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			add_effect(&effect, htlc_abandon, true);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			add_effect(&effect, htlc_abandon, true);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			add_effect(&effect, htlc_abandon, true);
			goto unexpected_pkt;
		}
		break;

	case STATE_WAIT_FOR_CLOSE_COMPLETE:
		if (input_is(input, PKT_CLOSE_COMPLETE)) {
			err = accept_pkt_close_complete(ctx, peer, idata->pkt,
							&effect);
			if (err)
				goto err_start_unilateral_close_already_closing;
			add_effect(&effect, cmd_close_done, true);
			add_effect(&effect, send_pkt,
				   pkt_close_ack(ctx, peer));
			add_effect(&effect, broadcast_tx,
				   bitcoin_close(ctx, peer));
			add_effect(&effect, stop_commands, true);
			add_effect(&effect, stop_packets, true);
			return next_state(ctx, effect, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, PKT_CLOSE)) {
			/* We can use the sig just like CLOSE_COMPLETE */
			err = accept_pkt_simultaneous_close(ctx, peer,
							    idata->pkt,
							    &effect);
			if (err)
				goto err_start_unilateral_close_already_closing;
			add_effect(&effect, cmd_close_done, true);
			add_effect(&effect, send_pkt,
				   pkt_close_ack(ctx, peer));
			add_effect(&effect, broadcast_tx,
				   bitcoin_close(ctx, peer));
			add_effect(&effect, stop_commands, true);
			add_effect(&effect, stop_packets, true);
			return next_state(ctx, effect, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, PKT_ERROR)) {
			add_effect(&effect, in_error,
				   tal_steal(ctx, idata->pkt));
			goto start_unilateral_close_already_closing;
		} else if (input_is_pkt(input)) {
			/* We ignore all other packets while closing. */
			return next_state(ctx, effect, STATE_WAIT_FOR_CLOSE_COMPLETE);
		} else if (input_is(input, INPUT_CLOSE_COMPLETE_TIMEOUT)) {
			/* They didn't respond in time.  Unilateral close. */
			err = pkt_err(ctx, "Close timed out");
			goto err_start_unilateral_close_already_closing;
		}
		add_effect(&effect, cmd_close_done, false);
		add_effect(&effect, stop_commands, true);
		goto fail_during_close;

	case STATE_WAIT_FOR_CLOSE_ACK:
		if (input_is(input, PKT_CLOSE_ACK)) {
			err = accept_pkt_close_ack(ctx, peer, idata->pkt,
						   &effect);
			if (err)
				add_effect(&effect, send_pkt, err);
			add_effect(&effect, stop_packets, true);
			/* Just wait for close to happen now. */
			return next_state(ctx, effect, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is_pkt(input)) {
			if (input_is(input, PKT_ERROR)) {
				add_effect(&effect, in_error,
					   tal_steal(ctx, idata->pkt));
			} else {
				add_effect(&effect, send_pkt,
					   unexpected_pkt(ctx, input));
			}
			add_effect(&effect, stop_packets, true);
			/* Just wait for close to happen now. */
			return next_state(ctx, effect, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, BITCOIN_CLOSE_DONE)) {
			/* They didn't ack, but we're closed, so stop. */
			add_effect(&effect, stop_packets, true);
			return next_state(ctx, effect, STATE_CLOSED);
		}
		goto fail_during_close;

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

		bits = STATE_TO_BITS(state);

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
				add_effect(&effect, unwatch_htlc,
					   htlc_unwatch_all(ctx, peer));
			return next_state(ctx, effect, STATE_CLOSED);
		}

		if ((bits & STATE_CLOSE_SPENDTHEM_BIT)
		    && input_is(input, BITCOIN_SPEND_THEIRS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDTHEM_BIT));
			return next_state(ctx, effect, closed);
		}

		if ((bits & STATE_CLOSE_CLOSE_BIT)
		    && input_is(input, BITCOIN_CLOSE_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_CLOSE_BIT));
			return next_state(ctx, effect, closed);
		}

		if ((bits & STATE_CLOSE_OURCOMMIT_BIT)
		    && input_is(input, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_OURCOMMIT_BIT));
			tx = bitcoin_spend_ours(ctx, peer);
			/* Now we need to wait for our commit to be done. */
			add_effect(&effect, broadcast_tx, tx);
			add_effect(&effect, watch,
				   bitcoin_watch(ctx, tx,
						 BITCOIN_SPEND_OURS_DONE));
			bits &= ~STATE_CLOSE_OURCOMMIT_BIT;
			bits |= STATE_CLOSE_SPENDOURS_BIT;
			return next_state(ctx, effect, BITS_TO_STATE(bits));
		}

		if ((bits & STATE_CLOSE_SPENDOURS_BIT)
		    && input_is(input, BITCOIN_SPEND_OURS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDOURS_BIT));
			return next_state(ctx, effect, closed);
		}

		/* If we have htlcs, we can get other inputs... */
		if (bits & STATE_CLOSE_HTLCS_BIT) {
			if (input_is(input, INPUT_NO_MORE_HTLCS)) {
				/* Clear bit, might lead to STATE_CLOSED. */
				BUILD_ASSERT((BITS_TO_STATE(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS) & ~STATE_CLOSE_HTLCS_BIT)) == STATE_CLOSED);
				bits &= ~STATE_CLOSE_HTLCS_BIT;
				return next_state(ctx, effect, BITS_TO_STATE(bits));
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_SPENT)) {
				/* They revealed R value. */
				add_effect(&effect, r_value,
					   bitcoin_r_value(ctx, idata->htlc));
				/* We don't care any more. */
				add_effect(&effect, unwatch_htlc,
					   htlc_unwatch(ctx, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return effect;
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_TIMEOUT)){
				tx = bitcoin_htlc_timeout(ctx,
							  peer,
							  idata->htlc);
				/* HTLC timed out, spend it back to us. */
				add_effect(&effect, broadcast_tx, tx);
				/* Don't unwatch yet; they could yet
				 * try to spend, revealing rvalue. */

				/* We're done when that gets buried. */
				add_effect(&effect, watch_htlc_spend,
					   htlc_spend_watch(ctx,
						 tx,
						 idata->cmd,
						 BITCOIN_HTLC_RETURN_SPEND_DONE));
				return effect;
			} else if (input_is(input, INPUT_RVALUE)) {
				tx = bitcoin_htlc_spend(ctx, peer,
							idata->htlc);

				/* This gives us the r value. */
				add_effect(&effect, r_value,
					   r_value_from_cmd(ctx, peer,
							    idata->htlc));
				/* Spend it... */
				add_effect(&effect, broadcast_tx, tx);
				/* We're done when it gets buried. */
				add_effect(&effect, watch_htlc_spend,
					   htlc_spend_watch(ctx,
						 tx,
						 idata->cmd,
						 BITCOIN_HTLC_FULFILL_SPEND_DONE));
				/* Don't care about this one any more. */
				add_effect(&effect, unwatch_htlc,
					   htlc_unwatch(ctx, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return effect;
			} else if (input_is(input, BITCOIN_HTLC_FULFILL_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				add_effect(&effect, unwatch_htlc_spend,
					   htlc_spend_unwatch(ctx,
							      idata->htlc,
							      INPUT_NO_MORE_HTLCS));
				return effect;
			} else if (input_is(input, BITCOIN_HTLC_RETURN_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				add_effect(&effect, unwatch_htlc_spend,
					   htlc_spend_unwatch(ctx,
							      idata->htlc,
							      INPUT_NO_MORE_HTLCS));

				/* Don't need to watch the HTLC output any more,
				 * either. */
				add_effect(&effect, unwatch_htlc,
					   htlc_unwatch(ctx, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return effect;
			} else if (input_is(input, BITCOIN_HTLC_TOUS_TIMEOUT)) {
				/* They can spend, we no longer care
				 * about this HTLC. */
				add_effect(&effect, unwatch_htlc,
					   htlc_unwatch(ctx, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return effect;
			}
		}

		/* If we're just waiting for HTLCs, anything else is an error */
		if (state == STATE_CLOSE_WAIT_HTLCS)
			break;

		/*
		 * Now, other side can always spring a commit transaction on us
		 * (even if they already have, due to tx malleability).
		 */
		if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
			add_effect(&effect, broadcast_tx, tx);
			add_effect(&effect, watch,
				   bitcoin_watch(ctx, tx,
						 BITCOIN_SPEND_THEIRS_DONE));
			/* HTLC watches. */
			htlcs = htlc_outputs_their_commit(ctx, peer,
						idata->btc,
						BITCOIN_HTLC_TOUS_TIMEOUT,
						BITCOIN_HTLC_TOTHEM_SPENT,
						BITCOIN_HTLC_TOTHEM_TIMEOUT);
			if (htlcs) {
				add_effect(&effect, watch_htlcs, htlcs);
				bits |= STATE_CLOSE_HTLCS_BIT;
			}
			bits |= STATE_CLOSE_SPENDTHEM_BIT;
			return next_state(ctx, effect, BITS_TO_STATE(bits));
			/* This can happen multiple times: need to steal ALL */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			tx = bitcoin_steal(ctx, peer, idata->btc);
			if (!tx)
				return next_state(ctx, effect,
						  STATE_ERR_INFORMATION_LEAK);
			add_effect(&effect, broadcast_tx, tx);
			add_effect(&effect, watch,
				   bitcoin_watch(ctx, tx,
						 BITCOIN_STEAL_DONE));
			bits |= STATE_CLOSE_STEAL_BIT;
			return next_state(ctx, effect, BITS_TO_STATE(bits));
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
		return next_state(ctx, effect, STATE_ERR_INTERNAL);
	}

	/* State machine should handle all possible states. */
	return next_state(ctx, effect, STATE_ERR_INTERNAL);

unexpected_pkt:
	/*
	 * We got a weird packet, so we need to close unilaterally.
	 */
	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		add_effect(&effect, in_error, tal_steal(ctx, idata->pkt));
		goto start_unilateral_close;
	}
	err = unexpected_pkt(ctx, input);
	goto err_start_unilateral_close;

unexpected_pkt_nocleanup:
	/*
	 * Unexpected packet, but nothing sent to chain yet, so no cleanup.
	 */
	err = unexpected_pkt(ctx, input);
	goto err_close_nocleanup;

anchor_unspent:
	/*
	 * Bitcoind tells us anchor got double-spent.  If we double-spent it
	 * then we're malfunctioning.  If they double-spent it, then they
	 * managed to cheat us: post_to_reddit();
	 */
	return next_state(ctx, effect, STATE_ERR_ANCHOR_LOST);

err_close_nocleanup:
	/*
	 * Something went wrong, but we haven't sent anything to the blockchain
	 * so there's nothing to clean up.
	 */
	add_effect(&effect, send_pkt, err);
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);
	return next_state(ctx, effect, STATE_CLOSED);

err_start_unilateral_close:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	add_effect(&effect, send_pkt, err);

start_unilateral_close:
	/*
	 * Close unilaterally.
	 */
	/* No more inputs, no more commands. */
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);
	tx = bitcoin_commit(ctx, peer);
	add_effect(&effect, broadcast_tx, tx);
	add_effect(&effect, watch,
		   bitcoin_watch_delayed(ctx, tx,
					 BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED));

	/* HTLC watches. */
	htlcs = htlc_outputs_our_commit(ctx, peer, tx,
					BITCOIN_HTLC_TOUS_TIMEOUT,
					BITCOIN_HTLC_TOTHEM_SPENT,
					BITCOIN_HTLC_TOTHEM_TIMEOUT);
	if (htlcs) {
		add_effect(&effect, watch_htlcs, htlcs);
		return next_state(ctx, effect,
				  STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS);
	}
	return next_state(ctx, effect, STATE_CLOSE_WAIT_OURCOMMIT);

err_start_unilateral_close_already_closing:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	add_effect(&effect, send_pkt, err);

start_unilateral_close_already_closing:
	add_effect(&effect, cmd_close_done, false);

	/*
	 * Close unilaterally.
	 */
	/* No more inputs, no more commands. */
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);
	tx = bitcoin_commit(ctx, peer);
	add_effect(&effect, broadcast_tx, tx);
	add_effect(&effect, watch,
		   bitcoin_watch_delayed(ctx, tx,
					 BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED));

	/* We agreed to close: shouldn't have any HTLCs */
	if (committed_to_htlcs(peer))
		return next_state(ctx, effect, STATE_ERR_INTERNAL);

	return next_state(ctx, effect, STATE_CLOSE_WAIT_CLOSE_OURCOMMIT);
	
them_unilateral:
	assert(input == BITCOIN_ANCHOR_THEIRSPEND);

	/*
	 * Bitcoind tells us they did unilateral close.
	 */
	add_effect(&effect, send_pkt, pkt_err(ctx, "Commit tx noticed"));

	/* No more inputs, no more commands. */
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);
	tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
	add_effect(&effect, broadcast_tx, tx);
	add_effect(&effect, watch,
		   bitcoin_watch(ctx, tx,
				 BITCOIN_SPEND_THEIRS_DONE));

	/* HTLC watches (based on what they broadcast, which *may* be out
	 * of step with our current state by +/- 1 htlc. */
	htlcs = htlc_outputs_their_commit(ctx, peer, idata->btc,
					  BITCOIN_HTLC_TOUS_TIMEOUT,
					  BITCOIN_HTLC_TOTHEM_SPENT,
					  BITCOIN_HTLC_TOTHEM_TIMEOUT);
	if (htlcs) {
		add_effect(&effect, watch_htlcs, htlcs);
		return next_state(ctx, effect, STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS);
	}
	return next_state(ctx, effect, STATE_CLOSE_WAIT_SPENDTHEM);

accept_htlc_update:
	err = accept_pkt_htlc_update(ctx, peer, idata->pkt, &decline, &htlcprog,
				     &effect);
	if (err)
		goto err_start_unilateral_close;
	if (decline) {
		add_effect(&effect, send_pkt, decline);
		/* No update means no priority change. */
		return next_state(ctx, effect, prio(state, STATE_NORMAL));
	}
	add_effect(&effect, htlc_in_progress, htlcprog);
	add_effect(&effect, send_pkt, pkt_update_accept(ctx, peer));
	return next_state(ctx, effect, prio(state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_routefail:
	err = accept_pkt_htlc_routefail(ctx, peer, idata->pkt, &htlcprog,
					&effect);
	if (err)
		goto err_start_unilateral_close;
	add_effect(&effect, htlc_in_progress, htlcprog);
	add_effect(&effect, send_pkt, pkt_update_accept(ctx, peer));
	return next_state(ctx, effect, prio(state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_timedout:
	err = accept_pkt_htlc_timedout(ctx, peer, idata->pkt, &htlcprog,
				       &effect);
	if (err)
		goto err_start_unilateral_close;
	add_effect(&effect, htlc_in_progress, htlcprog);
	add_effect(&effect, send_pkt, pkt_update_accept(ctx, peer));
	return next_state(ctx, effect, prio(state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_fulfill:
	err = accept_pkt_htlc_fulfill(ctx, peer, idata->pkt, &htlcprog,
				      &effect);
	if (err)
		goto err_start_unilateral_close;
	add_effect(&effect, htlc_in_progress, htlcprog);
	add_effect(&effect, send_pkt, pkt_update_accept(ctx, peer));
	add_effect(&effect, r_value, r_value_from_pkt(ctx, idata->pkt));
	return next_state(ctx, effect, prio(state, STATE_WAIT_FOR_UPDATE_SIG));

start_closing:
	/*
	 * Start a mutual close.
	 */
	/* Protocol doesn't (currently?) allow closing with HTLCs. */
	if (committed_to_htlcs(peer)) {
		add_effect(&effect, cmd_close_done, false);
		err = pkt_err(ctx, "Close forced due to HTLCs");
		goto err_start_unilateral_close;
	}
	add_effect(&effect, close_timeout, INPUT_CLOSE_COMPLETE_TIMEOUT);

	add_effect(&effect, watch,
		   bitcoin_watch_close(ctx, peer, BITCOIN_CLOSE_DONE));

	/* As soon as we send packet, they could close. */
	add_effect(&effect, send_pkt, pkt_close(ctx, peer));
	return next_state(ctx, effect, STATE_WAIT_FOR_CLOSE_COMPLETE);

accept_closing:
	err = accept_pkt_close(ctx, peer, idata->pkt, &effect);
	if (err)
		goto err_start_unilateral_close;
	/* As soon as we send packet, they could close. */
	add_effect(&effect, watch,
		   bitcoin_watch_close(ctx, peer, BITCOIN_CLOSE_DONE));
	add_effect(&effect, send_pkt, pkt_close_complete(ctx, peer));
	/* No more commands, we're already closing. */
	add_effect(&effect, stop_commands, true);
	return next_state(ctx, effect, STATE_WAIT_FOR_CLOSE_ACK);
	
instant_close:
	/*
	 * Closing, but we haven't sent anything to the blockchain so
	 * there's nothing to clean up.
	 */
	add_effect(&effect, cmd_close_done, true);
	/* FIXME: Should we tell other side we're going? */
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);

	/* We can't have any HTLCs, since we haven't started. */
	if (committed_to_htlcs(peer))
		return next_state(ctx, effect, STATE_ERR_INTERNAL);
	return next_state(ctx, effect, STATE_CLOSED);

fail_during_close:
	/*
	 * We've broadcast close tx; if anything goes wrong, we just close
	 * connection and wait.
	 */
	add_effect(&effect, stop_packets, true);

	/* Once close tx is deep enough, we consider it done. */
	if (input_is(input, BITCOIN_CLOSE_DONE)) {
		return next_state(ctx, effect, STATE_CLOSED);
	} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
		/* A reorganization could make this happen. */
		tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
		add_effect(&effect, broadcast_tx, tx);
		add_effect(&effect, watch,
			   bitcoin_watch(ctx, tx,
					 BITCOIN_SPEND_THEIRS_DONE));
		htlcs = htlc_outputs_their_commit(ctx, peer, idata->btc,
						  BITCOIN_HTLC_TOUS_TIMEOUT,
						  BITCOIN_HTLC_TOTHEM_SPENT,
						  BITCOIN_HTLC_TOTHEM_TIMEOUT);
		/* Expect either close or spendthem to complete */
		if (htlcs) {
			/* FIXME: Make sure caller uses INPUT_RVAL
			 * if they were in the middle of FULFILL! */
			add_effect(&effect, watch_htlcs, htlcs);
			return next_state(ctx, effect, STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS);
		}
		return next_state(ctx, effect, STATE_CLOSE_WAIT_SPENDTHEM_CLOSE);
	} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
		tx = bitcoin_steal(ctx, peer, idata->btc);
		if (!tx)
			return next_state(ctx, effect,
					  STATE_ERR_INFORMATION_LEAK);
		add_effect(&effect, broadcast_tx, tx);
		add_effect(&effect, watch,
			   bitcoin_watch(ctx, tx, BITCOIN_STEAL_DONE));
		/* Expect either close or steal to complete */
		return next_state(ctx, effect, STATE_CLOSE_WAIT_STEAL_CLOSE);
	} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
		return next_state(ctx, effect, STATE_ERR_ANCHOR_LOST);
	}
	return next_state(ctx, effect, STATE_ERR_INTERNAL);
	
old_commit_spotted:
	/*
	 * bitcoind reported a broadcast of the not-latest commit tx.
	 */
	add_effect(&effect, send_pkt, pkt_err(ctx, "Otherspend noticed"));

	/* No more packets, no more commands. */
	add_effect(&effect, stop_packets, true);
	add_effect(&effect, stop_commands, true);

	/* If we can't find it, we're lost. */
	tx = bitcoin_steal(ctx, peer, idata->btc);
	if (!tx)
		return next_state(ctx, effect, STATE_ERR_INFORMATION_LEAK);
	add_effect(&effect, broadcast_tx, tx);
	add_effect(&effect, watch,
		   bitcoin_watch(ctx, tx, BITCOIN_STEAL_DONE));
	return next_state(ctx, effect, STATE_CLOSE_WAIT_STEAL);
}
