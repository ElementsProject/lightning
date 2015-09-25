#include <state.h>

char cmd_requeue;

static inline bool high_priority(enum state state)
{
	return (state & 1) == (STATE_NORMAL_HIGHPRIO & 1);
}
	
#define prio(state, name) \
	(high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

#define toggle_prio(state, name) \
	(!high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

#define INIT_EFFECT_broadcast NULL
#define INIT_EFFECT_send NULL
#define INIT_EFFECT_watch NULL
#define INIT_EFFECT_unwatch NULL
#define INIT_EFFECT_defer INPUT_NONE
#define INIT_EFFECT_complete INPUT_NONE
#define INIT_EFFECT_complete_data NULL
#define INIT_EFFECT_stop_packets false
#define INIT_EFFECT_stop_commands false
#define INIT_EFFECT_close_timeout INPUT_NONE
#define INIT_EFFECT_in_error NULL

void state_effect_init(struct state_effect *effect)
{
	effect->broadcast = INIT_EFFECT_broadcast;
	effect->send = INIT_EFFECT_send;
	effect->watch = INIT_EFFECT_watch;
	effect->unwatch = INIT_EFFECT_unwatch;
	effect->defer = INIT_EFFECT_defer;
	effect->complete = INIT_EFFECT_complete;
	effect->complete_data = INIT_EFFECT_complete_data;
	effect->stop_packets = INIT_EFFECT_stop_packets;
	effect->stop_commands = INIT_EFFECT_stop_commands;
	effect->close_timeout = INIT_EFFECT_close_timeout;
	effect->in_error = INIT_EFFECT_in_error;
}

#define set_effect(effect, field, val)				\
	do {							\
		struct state_effect *_e = (effect);		\
		assert(_e->field == INIT_EFFECT_##field);	\
		_e->field = (val);				\
		assert(_e->field != INIT_EFFECT_##field);	\
	} while(0)

static void fail_cmd(struct state_effect *effect, 
		     const enum state_input input,
		     void *faildata)
{
	set_effect(effect, complete, input);
	/* Use dummy value if they don't want one. */
	set_effect(effect, complete_data, faildata ? faildata : effect);
}

static void requeue_cmd(struct state_effect *effect, 
			const enum state_input input)
{
	set_effect(effect, complete, input);
	set_effect(effect, complete_data, &cmd_requeue);
}

enum state state(const enum state state, const struct state_data *sdata,
		 const enum state_input input, const union input *idata,
		 struct state_effect *effect)
{
	Pkt *decline;
	struct bitcoin_tx *steal;
	Pkt *err;

	switch (state) {
	/*
	 * Initial channel opening states.
	 */
	case STATE_INIT_NOANCHOR:
		assert(input == INPUT_NONE);
		set_effect(effect, send, pkt_open(effect, sdata));
		return STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR;
	case STATE_INIT_WITHANCHOR:
		assert(input == INPUT_NONE);
		set_effect(effect, send, pkt_open(effect, sdata));
		return STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(effect, sdata, idata->pkt);
			if (err)
				goto err_close_nocleanup;
			return STATE_OPEN_WAIT_FOR_ANCHOR;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			goto instant_close;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(effect, sdata, idata->pkt);
			if (err)
				goto err_close_nocleanup;
			set_effect(effect, send, pkt_anchor(effect, sdata));
			return STATE_OPEN_WAIT_FOR_COMMIT_SIG;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			goto instant_close;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			err = accept_pkt_anchor(effect, sdata, idata->pkt);
			if (err)
				goto err_close_nocleanup;
			set_effect(effect, send,
				   pkt_open_commit_sig(effect, sdata));
			set_effect(effect, watch,
				   bitcoin_watch_anchor(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							BITCOIN_ANCHOR_TIMEOUT,
							BITCOIN_ANCHOR_UNSPENT,
							BITCOIN_ANCHOR_THEIRSPEND,
							BITCOIN_ANCHOR_OTHERSPEND));

			return STATE_OPEN_WAITING_THEIRANCHOR;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			goto instant_close;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			err = accept_pkt_open_commit_sig(effect, sdata,
							 idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, broadcast,
				   bitcoin_anchor(effect, sdata));
			set_effect(effect, watch,
				   bitcoin_watch_anchor(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE,
							BITCOIN_ANCHOR_UNSPENT,
							BITCOIN_ANCHOR_THEIRSPEND,
							BITCOIN_ANCHOR_OTHERSPEND));
			return STATE_OPEN_WAITING_OURANCHOR;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			goto instant_close;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAITING_OURANCHOR:
		if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			set_effect(effect, send,
				   pkt_open_complete(effect, sdata));
			return STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ignore until we've hit depth ourselves. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return STATE_ERR_INFORMATION_LEAK;
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
							BITCOIN_ANCHOR_DEPTHOK,
							INPUT_NONE));
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_THEIRANCHOR:
		if (input_is(input, BITCOIN_ANCHOR_TIMEOUT)) {
			/* Anchor didn't reach blockchain in reasonable time. */
			set_effect(effect, send,
				   pkt_err(effect, "Anchor timed out"));
			return STATE_ERR_ANCHOR_TIMEOUT;
		} else if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			set_effect(effect, send,
				   pkt_open_complete(effect, sdata));
			return STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return STATE_ERR_INFORMATION_LEAK;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			goto them_unilateral;
		} else if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ignore until we've hit depth ourselves. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			set_effect(effect, unwatch,
				   bitcoin_unwatch_anchor_depth(effect, sdata,
						     BITCOIN_ANCHOR_DEPTHOK,
						     BITCOIN_ANCHOR_TIMEOUT));
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business!  Anchorer goes first. */
			if (state == STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR)
				return STATE_NORMAL_HIGHPRIO;
			else
				return STATE_NORMAL_LOWPRIO;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		/* Nobody should be able to spend anchor, except via the
		 * commit txs. */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			return STATE_ERR_INFORMATION_LEAK;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			goto them_unilateral;
		} else if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business! */
			return STATE_NORMAL_HIGHPRIO;
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			/* Can't do these until we're open. */
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, CMD_CLOSE)) {
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			goto accept_closing;
		} else if (input_is_pkt(input)) {
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
			set_effect(effect, send,
				   pkt_htlc_update(effect, sdata, idata->cmd));
			return prio(state, STATE_WAIT_FOR_HTLC_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_COMPLETE)) {
			/* We are to send an HTLC complete. */
			set_effect(effect, send,
				   pkt_htlc_complete(effect, sdata, idata->cmd));
			return prio(state, STATE_WAIT_FOR_HTLC_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_TIMEDOUT)) {
			/* We are to send an HTLC timedout. */
			set_effect(effect, send,
				   pkt_htlc_timedout(effect, sdata, idata->cmd));
			return prio(state, STATE_WAIT_FOR_HTLC_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_ROUTEFAIL)) {
			/* We are to send an HTLC routefail. */
			set_effect(effect, send,
				   pkt_htlc_routefail(effect, sdata,
						      idata->cmd));
			return prio(state, STATE_WAIT_FOR_HTLC_ACCEPT);
		} else if (input_is(input, CMD_CLOSE)) {
			goto start_closing;
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			goto accept_htlc_update;
		} else if (input_is(input, PKT_UPDATE_COMPLETE_HTLC)) {
			goto accept_htlc_complete;
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
			fail_cmd(effect, CMD_SEND_HTLC_UPDATE, idata->pkt);
			/* Toggle between high and low priority states. */
			return toggle_prio(state, STATE_NORMAL);
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			goto accept_htlc_update;
		} else if (input_is(input, PKT_UPDATE_COMPLETE_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			goto accept_htlc_complete;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_ROUTEFAIL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			goto accept_htlc_routefail;
		} else if (input_is(input, PKT_UPDATE_ACCEPT)) {
			err = accept_pkt_update_accept(effect, sdata,
						       idata->pkt);
			if (err) {
				fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
				goto err_start_unilateral_close;
			}
			set_effect(effect, send,
				   pkt_update_signature(effect, sdata));
			return prio(state, STATE_WAIT_FOR_UPDATE_COMPLETE);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto old_commit_spotted;
		} else if (input_is(input, PKT_CLOSE)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_COMPLETE_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_COMPLETE_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_COMPLETE)) {
			err = accept_pkt_update_complete(effect, sdata,
							 idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, complete, CMD_SEND_UPDATE_ANY);
			return toggle_prio(state, STATE_NORMAL);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto old_commit_spotted;
		} else if (input_is(input, PKT_CLOSE)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_SIG_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_SIG_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_SIGNATURE)) {
			err = accept_pkt_update_signature(effect, sdata,
							  idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, send,
				   pkt_update_complete(effect, sdata));
			/* Toggle between high and low priority states. */
			return toggle_prio(state, STATE_NORMAL);
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			goto start_closing;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;

	case STATE_WAIT_FOR_CLOSE_COMPLETE:
		if (input_is(input, PKT_CLOSE_COMPLETE)) {
			err = accept_pkt_close_complete(effect, sdata,
							idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, complete, CMD_CLOSE);
			set_effect(effect, send, pkt_close_ack(effect, sdata));
			set_effect(effect, broadcast,
				   bitcoin_close(effect, sdata));
			set_effect(effect, stop_commands, true);
			set_effect(effect, stop_packets, true);
			return STATE_CLOSE_WAIT_CLOSE;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We can use the sig just like CLOSE_COMPLETE */
			err = accept_pkt_simultaneous_close(effect, sdata,
							    idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, complete, CMD_CLOSE);
			set_effect(effect, send, pkt_close_ack(effect, sdata));
			set_effect(effect, broadcast,
				   bitcoin_close(effect, sdata));
			set_effect(effect, stop_commands, true);
			set_effect(effect, stop_packets, true);
			return STATE_CLOSE_WAIT_CLOSE;
		} else if (input_is_pkt(input)) {
			/* We ignore all other packets while closing. */
			return STATE_WAIT_FOR_CLOSE_COMPLETE;
		} else if (input_is(input, INPUT_CLOSE_COMPLETE_TIMEOUT)) {
			/* They didn't respond in time.  Unilateral close. */
			set_effect(effect, send,
				   pkt_err(effect, "Close timed out"));
			fail_cmd(effect, CMD_CLOSE, effect->send);
			set_effect(effect, stop_commands, true);
			set_effect(effect, stop_packets, true);
			set_effect(effect, broadcast,
				   bitcoin_commit(effect, sdata));
			set_effect(effect, watch,
				   bitcoin_watch_delayed(effect,
					 effect->broadcast,
					 BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED));
			/* They could still close. */
			return STATE_CLOSE_WAIT_CLOSE_OURCOMMIT;
		}
		fail_cmd(effect, CMD_CLOSE, NULL);
		set_effect(effect, stop_commands, true);
		goto fail_during_close;

	case STATE_WAIT_FOR_CLOSE_ACK:
		if (input_is(input, PKT_CLOSE_ACK)) {
			err = accept_pkt_close_ack(effect, sdata, idata->pkt);
			if (err)
				set_effect(effect, send, err);
			set_effect(effect, stop_packets, true);
			/* Just wait for close to happen now. */
			return STATE_CLOSE_WAIT_CLOSE;
		} else if (input_is_pkt(input)) {
			if (input_is(input, PKT_ERROR)) {
				set_effect(effect, in_error,
					   tal_steal(effect, idata->pkt));
			} else {
				set_effect(effect, send,
					   unexpected_pkt(effect, input));
			}
			set_effect(effect, stop_packets, true);
			/* Just wait for close to happen now. */
			return STATE_CLOSE_WAIT_CLOSE;
		} else if (input_is(input, BITCOIN_CLOSE_DONE)) {
			/* They didn't ack, but we're closed, so stop. */
			set_effect(effect, stop_packets, true);
			return STATE_CLOSED;
		}
		goto fail_during_close;

	/* Close states are regular: handle as a group. */
	case STATE_CLOSE_WAIT_STEAL:
	case STATE_CLOSE_WAIT_SPENDTHEM:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM:
	case STATE_CLOSE_WAIT_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_CLOSE:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDOURS: {
		unsigned int bits, base;

		base = (unsigned)STATE_CLOSE_WAIT_STEAL - 1;
		bits = (unsigned)state - base;

		if ((bits & STATE_CLOSE_STEAL_BIT)
		    && input_is(input, BITCOIN_STEAL_DONE)) {
			return STATE_CLOSED;
		}

		if ((bits & STATE_CLOSE_SPENDTHEM_BIT)
		    && input_is(input, BITCOIN_SPEND_THEIRS_DONE)) {
			return STATE_CLOSED;
		}

		if ((bits & STATE_CLOSE_CLOSE_BIT)
		    && input_is(input, BITCOIN_CLOSE_DONE)) {
			return STATE_CLOSED;
		}

		if ((bits & STATE_CLOSE_OURCOMMIT_BIT)
		    && input_is(input, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED)) {
			/* Now we need to wait for our commit to be done. */
			set_effect(effect, broadcast,
				   bitcoin_spend_ours(effect, sdata));
			set_effect(effect, watch,
				   bitcoin_watch(effect, effect->broadcast,
						 BITCOIN_SPEND_OURS_DONE));
			bits &= ~STATE_CLOSE_OURCOMMIT_BIT;
			bits |= STATE_CLOSE_SPENDOURS_BIT;
			return base + bits;
		}

		if ((bits & STATE_CLOSE_SPENDOURS_BIT)
		    && input_is(input, BITCOIN_SPEND_OURS_DONE)) {
			return STATE_CLOSED;
		}

		/* Now, other side can always spring a commit transaction on us
		 * (even if they already have, due to tx malleability) */
		if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			set_effect(effect, broadcast,
				   bitcoin_spend_theirs(effect, sdata));
			set_effect(effect, watch,
				   bitcoin_watch(effect, effect->broadcast,
						 BITCOIN_SPEND_THEIRS_DONE));
			bits |= STATE_CLOSE_SPENDTHEM_BIT;
			return base + bits;
			/* This can happen multiple times: need to steal ALL */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			struct bitcoin_tx *steal;
			steal = bitcoin_steal(effect, sdata, idata->btc);
			if (!steal)
				return STATE_ERR_INFORMATION_LEAK;
			set_effect(effect, broadcast, steal);
			set_effect(effect, watch,
				   bitcoin_watch(effect, effect->broadcast,
						 BITCOIN_STEAL_DONE));
			bits |= STATE_CLOSE_STEAL_BIT;
			return base + bits;
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
		return STATE_ERR_INTERNAL;
	}

	/* State machine should handle all possible states. */
	return STATE_ERR_INTERNAL;

unexpected_pkt:
	/*
	 * We got a weird packet, so we need to close unilaterally.
	 */
	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		set_effect(effect, in_error, tal_steal(effect, idata->pkt));
		goto start_unilateral_close;
	}
	err = unexpected_pkt(effect, input);
	goto err_start_unilateral_close;

unexpected_pkt_nocleanup:
	/*
	 * Unexpected packet, but nothing sent to chain yet, so no cleanup.
	 */
	err = unexpected_pkt(effect, input);
	goto err_close_nocleanup;

anchor_unspent:
	/*
	 * Bitcoind tells us anchor got double-spent.  If we double-spent it
	 * then we're malfunctioning.  If they double-spent it, then they
	 * managed to cheat us: post_to_reddit();
	 */
	return STATE_ERR_ANCHOR_LOST;

err_close_nocleanup:
	/*
	 * Something went wrong, but we haven't sent anything to the blockchain
	 * so there's nothing to clean up.
	 */
	set_effect(effect, send, err);
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);
	return STATE_CLOSED;	

err_start_unilateral_close:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	set_effect(effect, send, err);

start_unilateral_close:
	/*
	 * Close unilaterally.
	 */
	/* No more inputs, no more commands. */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);
	set_effect(effect, broadcast, bitcoin_commit(effect, sdata));
	set_effect(effect, watch,
		   bitcoin_watch_delayed(effect, effect->broadcast,
					 BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED));
	return STATE_CLOSE_WAIT_OURCOMMIT;

them_unilateral:
	/*
	 * Bitcoind tells us they did unilateral close.
	 */
	set_effect(effect, send, pkt_err(effect, "Commit tx noticed"));

	/* No more inputs, no more commands. */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);
	set_effect(effect, broadcast, bitcoin_spend_theirs(effect, sdata));
	set_effect(effect, watch,
		   bitcoin_watch(effect, effect->broadcast,
				 BITCOIN_SPEND_THEIRS_DONE));
	return STATE_CLOSE_WAIT_SPENDTHEM;

accept_htlc_update:
	err = accept_pkt_htlc_update(effect, sdata, idata->pkt, &decline);
	if (err)
		goto err_start_unilateral_close;
	if (decline) {
		set_effect(effect, send, decline);
		/* Toggle between high/low priority states. */
		return toggle_prio(state, STATE_NORMAL);
	}
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_routefail:
	err = accept_pkt_htlc_routefail(effect, sdata, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_timedout:
	err = accept_pkt_htlc_timedout(effect, sdata, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_complete:
	err = accept_pkt_htlc_complete(effect, sdata, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

start_closing:
	/*
	 * Start a mutual close.
	 */
	set_effect(effect, close_timeout, INPUT_CLOSE_COMPLETE_TIMEOUT);

	set_effect(effect, watch,
		   bitcoin_watch_close(effect, sdata, BITCOIN_CLOSE_DONE));

	/* As soon as we send packet, they could close. */
	set_effect(effect, send, pkt_close(effect, sdata));
	return STATE_WAIT_FOR_CLOSE_COMPLETE;

accept_closing:
	err = accept_pkt_close(effect, sdata, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	/* As soon as we send packet, they could close. */
	set_effect(effect, watch,
		   bitcoin_watch_close(effect, sdata, BITCOIN_CLOSE_DONE));
	set_effect(effect, send, pkt_close_complete(effect, sdata));
	/* No more commands, we're already closing. */
	set_effect(effect, stop_commands, true);
	return STATE_WAIT_FOR_CLOSE_ACK;
	
instant_close:
	/*
	 * Closing, but we haven't sent anything to the blockchain so
	 * there's nothing to clean up.
	 */
	set_effect(effect, complete, CMD_CLOSE);
	/* FIXME: Should we tell other side we're going? */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);
	return STATE_CLOSED;

fail_during_close:
	/*
	 * We've broadcast close tx; if anything goes wrong, we just close
	 * connection and wait.
	 */
	set_effect(effect, stop_packets, true);

	/* Once close tx is deep enough, we consider it done. */
	if (input_is(input, BITCOIN_CLOSE_DONE)) {
		return STATE_CLOSED;
	} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
		/* A reorganization could make this happen. */
		set_effect(effect, broadcast,
			   bitcoin_spend_theirs(effect, sdata));
		set_effect(effect, watch,
			   bitcoin_watch(effect, effect->broadcast,
					 BITCOIN_SPEND_THEIRS_DONE));
		/* Expect either close or spendthem to complete */
		return STATE_CLOSE_WAIT_SPENDTHEM_CLOSE;
	} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
		steal = bitcoin_steal(effect, sdata, idata->btc);
		if (!steal)
			return STATE_ERR_INFORMATION_LEAK;
		set_effect(effect, broadcast, steal);
		set_effect(effect, watch,
			   bitcoin_watch(effect, effect->broadcast,
					 BITCOIN_STEAL_DONE));
		/* Expect either close or steal to complete */
		return STATE_CLOSE_WAIT_STEAL_CLOSE;
	} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
		return STATE_ERR_ANCHOR_LOST;
	}
	return STATE_ERR_INTERNAL;
	
old_commit_spotted:
	/*
	 * bitcoind reported a broadcast of the not-latest commit tx.
	 */
	set_effect(effect, send, pkt_err(effect, "Otherspend noticed"));

	/* No more packets, no more commands. */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);

	/* If we can't find it, we're lost. */
	steal = bitcoin_steal(effect, sdata, idata->btc);
	if (!steal)
		return STATE_ERR_INFORMATION_LEAK;
	set_effect(effect, broadcast, steal);
	set_effect(effect, watch,
		   bitcoin_watch(effect, effect->broadcast, BITCOIN_STEAL_DONE));
	return STATE_CLOSE_WAIT_STEAL;
}
