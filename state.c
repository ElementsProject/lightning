#include <state.h>
#include <ccan/build_assert/build_assert.h>

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
#define INIT_EFFECT_status CMD_STATUS_ONGOING
#define INIT_EFFECT_faildata NULL
#define INIT_EFFECT_stop_packets false
#define INIT_EFFECT_stop_commands false
#define INIT_EFFECT_close_timeout INPUT_NONE
#define INIT_EFFECT_in_error NULL
#define INIT_EFFECT_r_value NULL
#define INIT_EFFECT_watch_htlcs NULL
#define INIT_EFFECT_unwatch_htlc NULL
#define INIT_EFFECT_htlc_in_progress NULL
#define INIT_EFFECT_htlc_abandon false
#define INIT_EFFECT_htlc_fulfill false
#define INIT_EFFECT_update_theirsig NULL
#define INIT_EFFECT_watch_htlc_spend NULL
#define INIT_EFFECT_unwatch_htlc_spend NULL

void state_effect_init(struct state_effect *effect)
{
	effect->broadcast = INIT_EFFECT_broadcast;
	effect->send = INIT_EFFECT_send;
	effect->watch = INIT_EFFECT_watch;
	effect->unwatch = INIT_EFFECT_unwatch;
	effect->defer = INIT_EFFECT_defer;
	effect->complete = INIT_EFFECT_complete;
	effect->status = INIT_EFFECT_status;
	effect->faildata = INIT_EFFECT_faildata;
	effect->stop_packets = INIT_EFFECT_stop_packets;
	effect->stop_commands = INIT_EFFECT_stop_commands;
	effect->close_timeout = INIT_EFFECT_close_timeout;
	effect->in_error = INIT_EFFECT_in_error;
	effect->r_value = INIT_EFFECT_r_value;
	effect->watch_htlcs = INIT_EFFECT_watch_htlcs;
	effect->unwatch_htlc = INIT_EFFECT_unwatch_htlc;
	effect->htlc_in_progress = INIT_EFFECT_htlc_in_progress;
	effect->htlc_abandon = INIT_EFFECT_htlc_abandon;
	effect->htlc_fulfill = INIT_EFFECT_htlc_fulfill;
	effect->update_theirsig = INIT_EFFECT_update_theirsig;
	effect->watch_htlc_spend = INIT_EFFECT_watch_htlc_spend;
	effect->unwatch_htlc_spend = INIT_EFFECT_unwatch_htlc_spend;
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
	set_effect(effect, status, CMD_STATUS_FAILED);
	if (faildata)
		set_effect(effect, faildata, faildata);
}

static void requeue_cmd(struct state_effect *effect, 
			const enum state_input input)
{
	set_effect(effect, complete, input);
	set_effect(effect, status, CMD_STATUS_REQUEUE);
}

static void complete_cmd(struct state_effect *effect, 
			 const enum state_input input)
{
	set_effect(effect, complete, input);
	set_effect(effect, status, CMD_STATUS_SUCCESS);
}

enum state state(const enum state state, const struct state_data *sdata,
		 const enum state_input input, const union input *idata,
		 struct state_effect *effect)
{
	Pkt *decline;
	struct bitcoin_tx *steal;
	Pkt *err;
	struct htlc_watch *htlcs;
	struct htlc_progress *htlcprog;

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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
		} else if (input_is(input, CMD_SEND_HTLC_UPDATE)) {
			/* Can't do this until we're open. */
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
				   pkt_htlc_update(effect, sdata,
						   idata->htlc_prog));
			set_effect(effect, htlc_in_progress, idata->htlc_prog);
			return prio(state, STATE_WAIT_FOR_HTLC_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_FULFILL)) {
			/* We are to send an HTLC fulfill. */
			/* This gives us the r value (FIXME: type!) */
			set_effect(effect, r_value,
				   r_value_from_cmd(effect, sdata, idata->htlc));
			set_effect(effect, send,
				   pkt_htlc_fulfill(effect, sdata,
						    idata->htlc_prog));
			set_effect(effect, htlc_in_progress, idata->htlc_prog);
			return prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_TIMEDOUT)) {
			/* We are to send an HTLC timedout. */
			set_effect(effect, send,
				   pkt_htlc_timedout(effect, sdata,
						     idata->htlc_prog));
			set_effect(effect, htlc_in_progress, idata->htlc_prog);
			return prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT);
		} else if (input_is(input, CMD_SEND_HTLC_ROUTEFAIL)) {
			/* We are to send an HTLC routefail. */
			set_effect(effect, send,
				   pkt_htlc_routefail(effect, sdata,
						      idata->htlc_prog));
			set_effect(effect, htlc_in_progress, idata->htlc_prog);
			return prio(state, STATE_WAIT_FOR_UPDATE_ACCEPT);
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
			fail_cmd(effect, CMD_SEND_HTLC_UPDATE, idata->pkt);
			set_effect(effect, htlc_abandon, true);
			/* Toggle between high and low priority states. */
			return toggle_prio(state, STATE_NORMAL);
		/* They can't close with an HTLC, so only possible here */	
		} else if (input_is(input, PKT_CLOSE)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			set_effect(effect, htlc_abandon, true);
			goto accept_closing;
		}
		/* Fall thru */
	case STATE_WAIT_FOR_UPDATE_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_ACCEPT_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			set_effect(effect, htlc_abandon, true);
			goto accept_htlc_update;
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			set_effect(effect, htlc_abandon, true);
			goto accept_htlc_fulfill;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			set_effect(effect, htlc_abandon, true);
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_ROUTEFAIL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(state))
				return state;

			/* Otherwise, process their request first: defer ours */
			requeue_cmd(effect, CMD_SEND_UPDATE_ANY);
			set_effect(effect, htlc_abandon, true);
			goto accept_htlc_routefail;
		} else if (input_is(input, PKT_UPDATE_ACCEPT)) {
			struct signature *sig;
			err = accept_pkt_update_accept(effect, sdata,
						       idata->pkt, &sig);
			if (err) {
				fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
				goto err_start_unilateral_close;
			}
			set_effect(effect, update_theirsig, sig);
			set_effect(effect, send,
				   pkt_update_signature(effect, sdata));
			/* HTLC is signed (though old tx not revoked yet!) */
			set_effect(effect, htlc_fulfill, true);
			return prio(state, STATE_WAIT_FOR_UPDATE_COMPLETE);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			set_effect(effect, htlc_abandon, true);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			set_effect(effect, htlc_abandon, true);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			set_effect(effect, htlc_abandon, true);
			goto old_commit_spotted;
		} else if (input_is_pkt(input)) {
			fail_cmd(effect, CMD_SEND_UPDATE_ANY, NULL);
			set_effect(effect, htlc_abandon, true);
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
			complete_cmd(effect, CMD_SEND_UPDATE_ANY);
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
			struct signature *sig;
			err = accept_pkt_update_signature(effect, sdata,
							  idata->pkt, &sig);
			if (err)
				goto err_start_unilateral_close;
			set_effect(effect, update_theirsig, sig);
			set_effect(effect, send,
				   pkt_update_complete(effect, sdata));
			set_effect(effect, htlc_fulfill, true);
			/* Toggle between high and low priority states. */
			return toggle_prio(state, STATE_NORMAL);
		} else if (input_is(input, CMD_SEND_UPDATE_ANY)) {
			set_effect(effect, defer, input);
			return state;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			set_effect(effect, htlc_abandon, true);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			set_effect(effect, htlc_abandon, true);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			set_effect(effect, htlc_abandon, true);
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			set_effect(effect, htlc_abandon, true);
			goto start_closing;
		} else if (input_is_pkt(input)) {
			set_effect(effect, htlc_abandon, true);
			goto unexpected_pkt;
		}
		break;

	case STATE_WAIT_FOR_CLOSE_COMPLETE:
		if (input_is(input, PKT_CLOSE_COMPLETE)) {
			err = accept_pkt_close_complete(effect, sdata,
							idata->pkt);
			if (err)
				goto err_start_unilateral_close;
			complete_cmd(effect, CMD_CLOSE);
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
			complete_cmd(effect, CMD_CLOSE);
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

			/* We agreed to close: shouldn't have any HTLCs */
			if (committed_to_htlcs(sdata))
				return STATE_ERR_INTERNAL;

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
		unsigned int bits, base;
		enum state_input closed;

		base = (unsigned)STATE_CLOSED;
		bits = (unsigned)state - base;

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
				set_effect(effect, unwatch_htlc,
					   htlc_unwatch_all(effect, sdata));
			return STATE_CLOSED;
		}

		if ((bits & STATE_CLOSE_SPENDTHEM_BIT)
		    && input_is(input, BITCOIN_SPEND_THEIRS_DONE)) {
			BUILD_ASSERT(!((STATE_CLOSE_WAIT_HTLCS - base)
				       & STATE_CLOSE_SPENDTHEM_BIT));
			return closed;
		}

		if ((bits & STATE_CLOSE_CLOSE_BIT)
		    && input_is(input, BITCOIN_CLOSE_DONE)) {
			BUILD_ASSERT(!((STATE_CLOSE_WAIT_HTLCS - base)
				       & STATE_CLOSE_CLOSE_BIT));
			return closed;
		}

		if ((bits & STATE_CLOSE_OURCOMMIT_BIT)
		    && input_is(input, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED)) {
			BUILD_ASSERT(!((STATE_CLOSE_WAIT_HTLCS - base)
				       & STATE_CLOSE_OURCOMMIT_BIT));
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
			BUILD_ASSERT(!((STATE_CLOSE_WAIT_HTLCS - base)
				       & STATE_CLOSE_SPENDOURS_BIT));
			return closed;
		}

		/* If we have htlcs, we can get other inputs... */
		if (bits & STATE_CLOSE_HTLCS_BIT) {
			if (input_is(input, INPUT_NO_MORE_HTLCS)) {
				/* Clear bit, might lead to STATE_CLOSED. */
				BUILD_ASSERT(((STATE_CLOSE_WAIT_HTLCS - base)
					      & ~STATE_CLOSE_HTLCS_BIT)
					     == STATE_CLOSED);
				bits &= ~STATE_CLOSE_HTLCS_BIT;
				return base + bits;
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_SPENT)) {
				/* They revealed R value. */
				set_effect(effect, r_value,
					   bitcoin_r_value(effect, idata->htlc));
				/* We don't care any more. */
				set_effect(effect, unwatch_htlc,
					   htlc_unwatch(effect, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return state;
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_TIMEOUT)){
				/* HTLC timed out, spend it back to us. */
				set_effect(effect, broadcast,
					   bitcoin_htlc_timeout(effect,
								sdata,
								idata->htlc));
				/* Don't unwatch yet; they could yet
				 * try to spend, revealing rvalue. */

				/* We're done when that gets buried. */
				set_effect(effect, watch_htlc_spend,
					   htlc_spend_watch(effect,
						 effect->broadcast,
						 idata->cmd,
						 BITCOIN_HTLC_RETURN_SPEND_DONE));
				return state;
			} else if (input_is(input, INPUT_RVALUE)) {
				/* This gives us the r value. */
				set_effect(effect, r_value,
					   r_value_from_cmd(effect, sdata,
							    idata->htlc));
				/* Spend it... */
				set_effect(effect, broadcast,
					   bitcoin_htlc_spend(effect, sdata,
							      idata->htlc));
				/* We're done when it gets buried. */
				set_effect(effect, watch_htlc_spend,
					   htlc_spend_watch(effect,
						 effect->broadcast,
						 idata->cmd,
						 BITCOIN_HTLC_FULFILL_SPEND_DONE));
				/* Don't care about this one any more. */
				set_effect(effect, unwatch_htlc,
					   htlc_unwatch(effect, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return state;
			} else if (input_is(input, BITCOIN_HTLC_FULFILL_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				set_effect(effect, unwatch_htlc_spend,
					   htlc_spend_unwatch(effect,
							      idata->htlc,
							      INPUT_NO_MORE_HTLCS));
				return state;
			} else if (input_is(input, BITCOIN_HTLC_RETURN_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				set_effect(effect, unwatch_htlc_spend,
					   htlc_spend_unwatch(effect,
							      idata->htlc,
							      INPUT_NO_MORE_HTLCS));

				/* Don't need to watch the HTLC output any more,
				 * either. */
				set_effect(effect, unwatch_htlc,
					   htlc_unwatch(effect, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return state;
			} else if (input_is(input, BITCOIN_HTLC_TOUS_TIMEOUT)) {
				/* They can spend, we no longer care
				 * about this HTLC. */
				set_effect(effect, unwatch_htlc,
					   htlc_unwatch(effect, idata->htlc,
							INPUT_NO_MORE_HTLCS));
				return state;
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
			set_effect(effect, broadcast,
				   bitcoin_spend_theirs(effect, sdata,
							idata->btc));
			set_effect(effect, watch,
				   bitcoin_watch(effect, effect->broadcast,
						 BITCOIN_SPEND_THEIRS_DONE));
			/* HTLC watches. */
			htlcs = htlc_outputs_their_commit(effect, sdata,
						idata->btc,
						BITCOIN_HTLC_TOUS_TIMEOUT,
						BITCOIN_HTLC_TOTHEM_SPENT,
						BITCOIN_HTLC_TOTHEM_TIMEOUT);
			if (htlcs) {
				set_effect(effect, watch_htlcs, htlcs);
				bits |= STATE_CLOSE_HTLCS_BIT;
			}
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
	case STATE_UNUSED_CLOSE_WAIT_STEAL_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS_WITH_HTLCS:
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
		set_effect(effect, in_error, set_errpkt(effect, idata->pkt));
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

	/* HTLC watches. */
	htlcs = htlc_outputs_our_commit(effect, sdata, effect->broadcast,
					BITCOIN_HTLC_TOUS_TIMEOUT,
					BITCOIN_HTLC_TOTHEM_SPENT,
					BITCOIN_HTLC_TOTHEM_TIMEOUT);
	if (htlcs) {
		set_effect(effect, watch_htlcs, htlcs);
		return STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS;
	}
	return STATE_CLOSE_WAIT_OURCOMMIT;

them_unilateral:
	assert(input == BITCOIN_ANCHOR_THEIRSPEND);

	/*
	 * Bitcoind tells us they did unilateral close.
	 */
	set_effect(effect, send, pkt_err(effect, "Commit tx noticed"));

	/* No more inputs, no more commands. */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);
	set_effect(effect, broadcast,
		   bitcoin_spend_theirs(effect, sdata, idata->btc));
	set_effect(effect, watch,
		   bitcoin_watch(effect, effect->broadcast,
				 BITCOIN_SPEND_THEIRS_DONE));

	/* HTLC watches (based on what they broadcast, which *may* be out
	 * of step with our current state by +/- 1 htlc. */
	htlcs = htlc_outputs_their_commit(effect, sdata, idata->btc,
					  BITCOIN_HTLC_TOUS_TIMEOUT,
					  BITCOIN_HTLC_TOTHEM_SPENT,
					  BITCOIN_HTLC_TOTHEM_TIMEOUT);
	if (htlcs) {
		set_effect(effect, watch_htlcs, htlcs);
		return STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS;
	}
	return STATE_CLOSE_WAIT_SPENDTHEM;

accept_htlc_update:
	err = accept_pkt_htlc_update(effect, sdata, idata->pkt, &decline,
				     &htlcprog);
	if (err)
		goto err_start_unilateral_close;
	if (decline) {
		set_effect(effect, send, decline);
		/* Toggle between high/low priority states. */
		return toggle_prio(state, STATE_NORMAL);
	}
	set_effect(effect, htlc_in_progress, htlcprog);
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_routefail:
	err = accept_pkt_htlc_routefail(effect, sdata, idata->pkt, &htlcprog);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, htlc_in_progress, htlcprog);
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_timedout:
	err = accept_pkt_htlc_timedout(effect, sdata, idata->pkt, &htlcprog);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, htlc_in_progress, htlcprog);
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

accept_htlc_fulfill:
	err = accept_pkt_htlc_fulfill(effect, sdata, idata->pkt, &htlcprog);
	if (err)
		goto err_start_unilateral_close;
	set_effect(effect, htlc_in_progress, htlcprog);
	set_effect(effect, send, pkt_update_accept(effect, sdata));
	set_effect(effect, r_value, r_value_from_pkt(effect, idata->pkt));
	return prio(state, STATE_WAIT_FOR_UPDATE_SIG);

start_closing:
	/*
	 * Start a mutual close.
	 */
	/* Protocol doesn't (currently?) allow closing with HTLCs. */
	if (committed_to_htlcs(sdata)) {
		fail_cmd(effect, CMD_CLOSE, NULL);
		err = pkt_err(effect, "Close forced due to HTLCs");
		goto err_start_unilateral_close;
	}
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
	complete_cmd(effect, CMD_CLOSE);
	/* FIXME: Should we tell other side we're going? */
	set_effect(effect, stop_packets, true);
	set_effect(effect, stop_commands, true);

	/* We can't have any HTLCs, since we haven't started. */
	if (committed_to_htlcs(sdata))
		return STATE_ERR_INTERNAL;
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
			   bitcoin_spend_theirs(effect, sdata, idata->btc));
		set_effect(effect, watch,
			   bitcoin_watch(effect, effect->broadcast,
					 BITCOIN_SPEND_THEIRS_DONE));
		htlcs = htlc_outputs_their_commit(effect, sdata, idata->btc,
						  BITCOIN_HTLC_TOUS_TIMEOUT,
						  BITCOIN_HTLC_TOTHEM_SPENT,
						  BITCOIN_HTLC_TOTHEM_TIMEOUT);
		/* Expect either close or spendthem to complete */
		if (htlcs) {
			/* FIXME: Make sure caller uses INPUT_RVAL
			 * if they were in the middle of FULFILL! */
			set_effect(effect, watch_htlcs, htlcs);
			return STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS;
		}
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
