//! Lsps2 Service FSM

use crate::proto::{
    lsps0::{Msat, ShortChannelId},
    lsps2::{
        compute_opening_fee,
        failure_codes::{TEMPORARY_CHANNEL_FAILURE, UNKNOWN_NEXT_PEER},
        OpeningFeeParams, SessionOutcome,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid state transition")]
    InvalidTransition {
        state: SessionState,
        input: SessionInput,
    },
    #[error(
        "opening fee {opening_fee_msat} exceeds deductible capacity {deductible_capacity_msat}"
    )]
    InsufficientDeductibleCapacity {
        opening_fee_msat: u64,
        deductible_capacity_msat: u128,
    },
}

type Result<T> = std::result::Result<T, Error>;

/// Number of blocks before the earliest held HTLC's cltv_expiry at which we
/// give up on the session and fail its HTLCs off-chain. Failing only at (or
/// after) expiry is too late: the upstream peer is then entitled to
/// force-close to claim the timeout on-chain.
pub const CLTV_SAFETY_BUFFER: u32 = 6;

/// Identifies an incoming HTLC. The protocol numbers HTLCs per channel, so
/// MPP parts arriving over different incoming channels can carry the same
/// `id`; the incoming channel's scid is needed to disambiguate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HtlcId {
    pub scid: ShortChannelId,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPart {
    pub htlc_id: HtlcId,
    pub amount_msat: Msat,
    pub cltv_expiry: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPart {
    pub htlc_id: HtlcId,
    pub fee_msat: u64,
    pub forward_msat: u64,
}

impl From<PaymentPart> for ForwardPart {
    fn from(part: PaymentPart) -> Self {
        Self {
            htlc_id: part.htlc_id,
            fee_msat: 0,
            forward_msat: part.amount_msat.msat(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInput {
    /// Htlc intercepted
    AddPart { part: PaymentPart },
    /// Timeout waiting for parts to arrive from blip052: defaults to 90s.
    CollectTimeout,
    /// Channel funding failed.
    FundingFailed,
    /// Zero-conf channel funded, withheld, and ready.
    ChannelReady {
        channel_id: String,
        funding_psbt: String,
    },
    /// The initial payment was successfull
    PaymentSettled,
    /// A forwarded part failed downstream. `htlc_id` identifies the failed
    /// part when known; `None` means the whole payment failed.
    PaymentFailed { htlc_id: Option<HtlcId> },
    /// Funding tx was broadcasted
    FundingBroadcasted,
    /// A new block has been mined.
    NewBlock { height: u32 },
    /// The JIT channel has been closed or is no longer in CHANNELD_NORMAL.
    ChannelClosed { channel_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    FailHtlcs {
        failure_code: &'static str,
    },
    ForwardHtlcs {
        parts: Vec<ForwardPart>,
        channel_id: String,
    },
    FundChannel {
        peer_id: String,
        channel_capacity_msat: Msat,
        opening_fee_params: OpeningFeeParams,
    },
    FailSession,
    AbandonSession {
        channel_id: String,
        funding_psbt: String,
    },
    BroadcastFundingTx {
        channel_id: String,
        funding_psbt: String,
    },
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    PaymentPartAdded {
        part: PaymentPart,
        n_parts: usize,
        parts_sum: Msat,
    },
    TooManyParts {
        n_parts: usize,
    },
    PaymentInsufficientForOpeningFee {
        opening_fee_msat: u64,
        n_parts: usize,
        parts_sum: Msat,
    },
    CollectTimeout {
        n_parts: usize,
        parts_sum: Msat,
    },
    FundingChannel,
    ForwardHtlcs {
        channel_id: String,
        n_parts: usize,
        parts_sum: Msat,
        opening_fee_msat: u64,
    },
    PaymentSettled {
        parts: Vec<ForwardPart>,
    },
    PaymentFailed,
    ChannelReady {
        channel_id: String,
        funding_psbt: String,
    },
    FundingBroadcasted {
        funding_psbt: String,
    },
    SessionFailed,
    SessionAbandoned,
    SessionSucceeded,
    UnsafeHtlcTimeout {
        height: u32,
        cltv_min: u32,
    },
    UnusualInput {
        state: String,
        input: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Collecting {
        parts: Vec<PaymentPart>,
    },

    /// Channel opened in progress, waiting for `channel_ready`.
    AwaitingChannelReady {
        parts: Vec<PaymentPart>,
        opening_fee_msat: u64,
    },

    /// HTLCs forwarded, waiting for the client to settle or reject.
    AwaitingSettlement {
        forwarded_parts: Vec<ForwardPart>,
        forwarded_amount_msat: u64,
        deducted_fee_msat: u64,
        channel_id: String,
        funding_psbt: String,
    },

    /// HTLCs got resolved, broadcasting funding tx.
    Broadcasting {
        channel_id: String,
        funding_psbt: String,
    },

    /// Terminal: session failed before a channel was opened.
    Failed,

    /// Terminal: session failed after a channel was opened.
    Abandoned,

    /// Terminal: session successfully finished
    Succeeded,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub actions: Vec<SessionAction>,
    pub events: Vec<SessionEvent>,
}

impl ApplyResult {
    fn unusual_input(state: &SessionState, input: &SessionInput) -> Self {
        Self {
            events: vec![SessionEvent::UnusualInput {
                state: format!("{:?}", state),
                input: format!("{:?}", input),
            }],
            ..Default::default()
        }
    }
}

fn cltv_min(parts: &[PaymentPart]) -> Option<u32> {
    parts.iter().map(|p| p.cltv_expiry).min()
}

#[derive(Debug)]
pub struct Session {
    state: SessionState,
    // from BOLT2
    max_parts: usize,
    // From the offer/fee_policy
    opening_fee_params: OpeningFeeParams,
    payment_size_msat: Option<Msat>,
    channel_capacity_msat: Msat,
    peer_id: String,
}

impl Session {
    pub fn new(
        max_parts: usize,
        opening_fee_params: OpeningFeeParams,
        payment_size_msat: Option<Msat>,
        channel_capacity_msat: Msat,
        peer_id: String,
    ) -> Self {
        Self {
            state: SessionState::Collecting { parts: vec![] },
            max_parts,
            opening_fee_params,
            payment_size_msat,
            channel_capacity_msat,
            peer_id,
        }
    }

    /// Reconstruct a session from persisted state for crash recovery.
    ///
    /// Initializes the FSM in the appropriate state based on whether a
    /// preimage was already captured:
    /// - `preimage: None` → `AwaitingSettlement` (waiting for payment outcome)
    /// - `preimage: Some` → `Broadcasting` (payment settled, need to broadcast)
    ///
    /// Forwarded HTLC parts are not reconstructed — CLN manages those
    /// independently. The FSM only needs channel identity to drive
    /// remaining actions.
    pub fn recover(
        channel_id: String,
        funding_psbt: String,
        preimage: Option<String>,
        opening_fee_params: OpeningFeeParams,
    ) -> (Self, Vec<SessionAction>) {
        let (state, actions) = if preimage.is_some() {
            (
                SessionState::Broadcasting {
                    channel_id: channel_id.clone(),
                    funding_psbt: funding_psbt.clone(),
                },
                vec![SessionAction::BroadcastFundingTx {
                    channel_id,
                    funding_psbt,
                }],
            )
        } else {
            (
                SessionState::AwaitingSettlement {
                    forwarded_parts: vec![],
                    forwarded_amount_msat: 0,
                    deducted_fee_msat: 0,
                    channel_id,
                    funding_psbt,
                },
                vec![],
            )
        };

        let session = Self {
            state,
            max_parts: 0,
            opening_fee_params,
            payment_size_msat: None,
            channel_capacity_msat: Msat::from_msat(0),
            peer_id: String::new(),
        };

        (session, actions)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            SessionState::Failed | SessionState::Abandoned | SessionState::Succeeded
        )
    }

    pub fn outcome(&self) -> Option<SessionOutcome> {
        match &self.state {
            SessionState::Succeeded => Some(SessionOutcome::Succeeded),
            SessionState::Abandoned => Some(SessionOutcome::Abandoned),
            SessionState::Failed => Some(SessionOutcome::Failed),
            _ => None,
        }
    }

    fn check_cltv_timeout(
        &mut self,
        parts: &[PaymentPart],
        height: u32,
    ) -> Option<ApplyResult> {
        let min = cltv_min(parts)?;
        if height.saturating_add(CLTV_SAFETY_BUFFER) >= min {
            self.state = SessionState::Failed;
            Some(ApplyResult {
                actions: vec![
                    SessionAction::FailHtlcs {
                        failure_code: TEMPORARY_CHANNEL_FAILURE,
                    },
                    SessionAction::Disconnect,
                    SessionAction::FailSession,
                ],
                events: vec![
                    SessionEvent::UnsafeHtlcTimeout {
                        height,
                        cltv_min: min,
                    },
                    SessionEvent::SessionFailed,
                ],
            })
        } else {
            None
        }
    }

    pub fn apply(&mut self, input: SessionInput) -> Result<ApplyResult> {
        match (&mut self.state, input) {
            //
            // Collecting transitions.
            //
            (SessionState::Collecting { parts }, SessionInput::AddPart { part }) => {
                parts.push(part.clone());
                let n_parts = parts.len();
                let parts_sum = parts.iter().map(|p| p.amount_msat).sum();

                let mut events = vec![SessionEvent::PaymentPartAdded {
                    part: part.clone(),
                    n_parts,
                    parts_sum,
                }];

                // Variable-amount (None): first HTLC triggers immediately, second fails.
                // Fixed-amount (Some): accumulate until threshold, fail if too many parts.
                let threshold_reached = match self.payment_size_msat {
                    None => {
                        if n_parts > 1 {
                            // Retryable: the payer can retry as a single
                            // part, so use a temporary failure instead of
                            // the permanent unknown_next_peer (LSPS2 only
                            // says we MAY use the latter).
                            self.state = SessionState::Failed;
                            events.push(SessionEvent::TooManyParts { n_parts });
                            events.push(SessionEvent::SessionFailed);
                            return Ok(ApplyResult {
                                actions: vec![
                                    SessionAction::FailHtlcs {
                                        failure_code: TEMPORARY_CHANNEL_FAILURE,
                                    },
                                    SessionAction::FailSession,
                                ],
                                events,
                            });
                        }
                        true
                    }
                    Some(_) => {
                        if n_parts > self.max_parts {
                            // Retryable: the payer can retry with fewer
                            // parts, see above.
                            self.state = SessionState::Failed;
                            events.push(SessionEvent::TooManyParts { n_parts });
                            events.push(SessionEvent::SessionFailed);
                            return Ok(ApplyResult {
                                actions: vec![
                                    SessionAction::FailHtlcs {
                                        failure_code: TEMPORARY_CHANNEL_FAILURE,
                                    },
                                    SessionAction::FailSession,
                                ],
                                events,
                            });
                        }
                        parts_sum >= self.payment_size_msat.unwrap()
                    }
                };

                if threshold_reached {
                    // The fee was promised against payment_size_msat and the
                    // client verifies the deducted extra_fees against that,
                    // so compute it from the negotiated size when we have
                    // one; the payer may overpay (parts_sum > payment_size).
                    // In var-invoice mode the fee is based on the value of
                    // the first (only) incoming HTLC.
                    let fee_base_msat = match self.payment_size_msat {
                        Some(size) => size.msat(),
                        None => parts_sum.msat(),
                    };
                    // LSPS2: an overflowing opening fee computation MUST
                    // fail with unknown_next_peer. Fail the session right
                    // away instead of leaving the HTLCs hanging.
                    let Some(opening_fee_msat) = compute_opening_fee(
                        fee_base_msat,
                        self.opening_fee_params.min_fee_msat.msat(),
                        self.opening_fee_params.proportional.ppm() as u64,
                    ) else {
                        self.state = SessionState::Failed;
                        events.push(SessionEvent::SessionFailed);
                        return Ok(ApplyResult {
                            actions: vec![
                                SessionAction::FailHtlcs {
                                    failure_code: UNKNOWN_NEXT_PEER,
                                },
                                SessionAction::FailSession,
                            ],
                            events,
                        });
                    };

                    // LSPS2 mandates unknown_next_peer when the payment
                    // cannot cover the opening fee.
                    if opening_fee_msat >= parts_sum.msat()
                        || !is_deductible(parts, opening_fee_msat)
                    {
                        self.state = SessionState::Failed;
                        events.push(SessionEvent::PaymentInsufficientForOpeningFee {
                            opening_fee_msat,
                            n_parts,
                            parts_sum,
                        });
                        events.push(SessionEvent::SessionFailed);
                        return Ok(ApplyResult {
                            actions: vec![
                                SessionAction::FailHtlcs {
                                    failure_code: UNKNOWN_NEXT_PEER,
                                },
                                SessionAction::FailSession,
                            ],
                            events,
                        });
                    }

                    // We collected enough parts to fund the channel, transition.
                    self.state = SessionState::AwaitingChannelReady {
                        parts: std::mem::take(parts),
                        opening_fee_msat,
                    };

                    events.push(SessionEvent::FundingChannel);

                    return Ok(ApplyResult {
                        events,
                        actions: vec![SessionAction::FundChannel {
                            peer_id: self.peer_id.clone(),
                            channel_capacity_msat: self.channel_capacity_msat,
                            opening_fee_params: self.opening_fee_params.clone(),
                        }],
                    });
                }

                // Keep collecting
                Ok(ApplyResult {
                    events,
                    ..Default::default()
                })
            }
            (SessionState::Collecting { parts }, SessionInput::CollectTimeout) => {
                // Session collection timed out: we fail the session but keep
                // the offer active. Next payment can create a new session.
                let n_parts = parts.len();
                let parts_sum = parts.iter().map(|p| p.amount_msat).sum();

                self.state = SessionState::Failed;
                Ok(ApplyResult {
                    actions: vec![
                        SessionAction::FailHtlcs {
                            failure_code: TEMPORARY_CHANNEL_FAILURE,
                        },
                        SessionAction::FailSession,
                    ],
                    events: vec![
                        SessionEvent::CollectTimeout { n_parts, parts_sum },
                        SessionEvent::SessionFailed,
                    ],
                })
            }
            (SessionState::Collecting { parts }, SessionInput::NewBlock { height }) => {
                let parts = parts.clone();
                Ok(self.check_cltv_timeout(&parts, height).unwrap_or_default())
            }
            (
                SessionState::Collecting { .. },
                ref input @ (SessionInput::ChannelReady { .. }
                | SessionInput::PaymentSettled
                | SessionInput::PaymentFailed { .. }
                | SessionInput::FundingBroadcasted
                | SessionInput::FundingFailed
                | SessionInput::ChannelClosed { .. }),
            ) => Ok(ApplyResult::unusual_input(&self.state, input)),

            //
            // AwaitChannelReady transitions.
            //
            (SessionState::AwaitingChannelReady { parts, .. }, SessionInput::AddPart { part }) => {
                parts.push(part.clone());
                let n_parts = parts.len();
                let parts_sum = parts.iter().map(|p| p.amount_msat).sum();

                // We don't check for max parts here as we are in the middle of
                // the channel funding. We'll check once we transitioned.

                Ok(ApplyResult {
                    events: vec![SessionEvent::PaymentPartAdded {
                        part,
                        n_parts,
                        parts_sum,
                    }],
                    ..Default::default()
                })
            }
            (
                SessionState::AwaitingChannelReady {
                    parts,
                    opening_fee_msat,
                },
                SessionInput::ChannelReady {
                    channel_id,
                    funding_psbt,
                },
            ) => {
                // We are transitioning in any case.
                let parts = std::mem::take(parts);
                let opening_fee_msat = std::mem::take(opening_fee_msat);

                let n_parts = parts.len();

                let mut events = vec![SessionEvent::ChannelReady {
                    channel_id: channel_id.clone(),
                    funding_psbt: funding_psbt.clone(),
                }];

                // Fail if we have too many parts. Retryable with fewer
                // parts, so temporary failure.
                if n_parts > self.max_parts {
                    self.state = SessionState::Abandoned;
                    events.push(SessionEvent::TooManyParts { n_parts });
                    events.push(SessionEvent::SessionAbandoned);
                    return Ok(ApplyResult {
                        actions: vec![
                            SessionAction::FailHtlcs {
                                failure_code: TEMPORARY_CHANNEL_FAILURE,
                            },
                            SessionAction::Disconnect,
                            SessionAction::AbandonSession {
                                channel_id,
                                funding_psbt,
                            },
                        ],
                        events,
                    });
                }

                // Deduct opening_fee_msat.
                let forwards = if let Ok(forwards) = allocate_forwards(&parts, opening_fee_msat) {
                    forwards
                } else {
                    self.state = SessionState::Abandoned;
                    events.push(SessionEvent::SessionAbandoned);
                    return Ok(ApplyResult {
                        actions: vec![
                            SessionAction::FailHtlcs {
                                failure_code: TEMPORARY_CHANNEL_FAILURE,
                            },
                            SessionAction::Disconnect,
                            SessionAction::AbandonSession {
                                channel_id,
                                funding_psbt,
                            },
                        ],
                        events,
                    });
                };

                let parts_sum =
                    Msat::from_msat(forwards.iter().map(|p| p.forward_msat + p.fee_msat).sum());

                events.push(SessionEvent::ForwardHtlcs {
                    channel_id: channel_id.clone(),
                    n_parts,
                    parts_sum,
                    opening_fee_msat,
                });

                // Forward HTLCs and await settlement.
                self.state = SessionState::AwaitingSettlement {
                    forwarded_parts: forwards.clone(),
                    forwarded_amount_msat: forwards.iter().map(|p| p.forward_msat).sum(),
                    deducted_fee_msat: forwards.iter().map(|p| p.fee_msat).sum(),
                    channel_id: channel_id.clone(),
                    funding_psbt: funding_psbt.clone(),
                };

                return Ok(ApplyResult {
                    actions: vec![SessionAction::ForwardHtlcs {
                        parts: forwards,
                        channel_id,
                    }],
                    events,
                });
            }
            (
                SessionState::AwaitingChannelReady { .. },
                ref input @ SessionInput::CollectTimeout,
            ) => {
                // Collection timeout is only relevant as long as we are still
                // collecting parts to cover the fee. Once we opened the channel
                // we don't care anymore.
                Ok(ApplyResult::unusual_input(&self.state, input))
            }
            (SessionState::AwaitingChannelReady { .. }, SessionInput::FundingFailed) => {
                // LSPS2: a client disconnect before funding_signed MUST be
                // failed with temporary_channel_failure so the payer knows
                // it can retry. We can't currently distinguish an explicit
                // client reject (which LSPS2 fails with unknown_next_peer)
                // from other funding errors, so prefer the retryable code.
                self.state = SessionState::Failed;
                Ok(ApplyResult {
                    actions: vec![
                        SessionAction::FailHtlcs {
                            failure_code: TEMPORARY_CHANNEL_FAILURE,
                        },
                        SessionAction::Disconnect,
                        SessionAction::FailSession,
                    ],
                    events: vec![SessionEvent::SessionFailed],
                })
            }
            (
                SessionState::AwaitingChannelReady { parts, .. },
                SessionInput::NewBlock { height },
            ) => {
                let parts = parts.clone();
                Ok(self.check_cltv_timeout(&parts, height).unwrap_or_default())
            }
            (
                SessionState::AwaitingChannelReady { .. },
                ref input @ (SessionInput::PaymentSettled
                | SessionInput::PaymentFailed { .. }
                | SessionInput::FundingBroadcasted
                | SessionInput::ChannelClosed { .. }),
            ) => Ok(ApplyResult::unusual_input(&self.state, input)),

            //
            // AwaitingSettlement transitions.
            //
            (
                SessionState::AwaitingSettlement {
                    forwarded_parts,
                    forwarded_amount_msat,
                    deducted_fee_msat,
                    channel_id,
                    ..
                },
                SessionInput::AddPart { part },
            ) => {
                // We forward late-arriving parts immediately in this state.
                let fp = ForwardPart {
                    htlc_id: part.htlc_id,
                    fee_msat: 0,
                    forward_msat: part.amount_msat.msat(),
                };
                *forwarded_amount_msat += fp.forward_msat;
                *deducted_fee_msat += fp.fee_msat;
                forwarded_parts.push(fp.clone());

                let n_parts = forwarded_parts.len();
                let parts_sum = Msat::from_msat(*forwarded_amount_msat + *deducted_fee_msat);

                // We don't check max_parts here as there is not much we can
                // do about this at this stage, we definitely need a:
                // TODO: Add integration test for #Htlcs > max_accepted_htlcs

                Ok(ApplyResult {
                    events: vec![
                        SessionEvent::PaymentPartAdded {
                            part: part.clone(),
                            n_parts,
                            parts_sum,
                        },
                        SessionEvent::ForwardHtlcs {
                            channel_id: channel_id.clone(),
                            n_parts: 1,
                            parts_sum: part.amount_msat,
                            opening_fee_msat: 0,
                        },
                    ],
                    actions: vec![SessionAction::ForwardHtlcs {
                        parts: vec![fp],
                        channel_id: channel_id.clone(),
                    }],
                })
            }
            (
                SessionState::AwaitingSettlement {
                    forwarded_parts,
                    channel_id,
                    funding_psbt,
                    ..
                },
                SessionInput::PaymentSettled,
            ) => {
                let channel_id = std::mem::take(channel_id);
                let funding_psbt = std::mem::take(funding_psbt);
                let parts = std::mem::take(forwarded_parts);

                self.state = SessionState::Broadcasting {
                    channel_id: channel_id.clone(),
                    funding_psbt: funding_psbt.clone(),
                };

                Ok(ApplyResult {
                    actions: vec![SessionAction::BroadcastFundingTx {
                        channel_id,
                        funding_psbt,
                    }],
                    events: vec![SessionEvent::PaymentSettled { parts }],
                })
            }
            (
                SessionState::AwaitingSettlement {
                    forwarded_parts,
                    forwarded_amount_msat,
                    deducted_fee_msat,
                    channel_id,
                    funding_psbt,
                },
                SessionInput::PaymentFailed { htlc_id },
            ) => {
                // A single failed part (e.g. one exceeding the channel's
                // max_accepted_htlcs) must not tear down the session while
                // other forwarded parts are still offered and settleable.
                // Only abandon once no forwarded parts remain, or when the
                // failed part is unknown (recovered sessions don't
                // reconstruct their parts).
                if let Some(id) = htlc_id {
                    if let Some(pos) = forwarded_parts.iter().position(|p| p.htlc_id == id) {
                        let p = forwarded_parts.remove(pos);
                        *forwarded_amount_msat = forwarded_amount_msat.saturating_sub(p.forward_msat);
                        *deducted_fee_msat = deducted_fee_msat.saturating_sub(p.fee_msat);
                    }
                    if !forwarded_parts.is_empty() {
                        return Ok(ApplyResult::default());
                    }
                }

                let channel_id = std::mem::take(channel_id);
                let funding_psbt = std::mem::take(funding_psbt);

                // No forwarded parts left that could still settle.
                // Abandon session.

                self.state = SessionState::Abandoned;

                Ok(ApplyResult {
                    actions: vec![
                        SessionAction::AbandonSession {
                            channel_id,
                            funding_psbt,
                        },
                        SessionAction::Disconnect,
                    ],
                    events: vec![
                        SessionEvent::PaymentFailed,
                        SessionEvent::SessionAbandoned,
                    ],
                })
            }
            (
                SessionState::AwaitingSettlement {
                    channel_id,
                    funding_psbt,
                    ..
                },
                SessionInput::ChannelClosed {
                    channel_id: closed_id,
                },
            ) if closed_id == *channel_id => {
                let channel_id = std::mem::take(channel_id);
                let funding_psbt = std::mem::take(funding_psbt);

                self.state = SessionState::Abandoned;

                Ok(ApplyResult {
                    actions: vec![
                        SessionAction::AbandonSession {
                            channel_id,
                            funding_psbt,
                        },
                        SessionAction::Disconnect,
                    ],
                    events: vec![
                        SessionEvent::PaymentFailed,
                        SessionEvent::SessionAbandoned,
                    ],
                })
            }
            (
                SessionState::AwaitingSettlement { .. },
                ref input @ (SessionInput::CollectTimeout
                | SessionInput::ChannelReady { .. }
                | SessionInput::FundingFailed
                | SessionInput::FundingBroadcasted
                | SessionInput::ChannelClosed { .. }
                | SessionInput::NewBlock { .. }),
            ) => Ok(ApplyResult::unusual_input(&self.state, input)),

            //
            // Broadcasting transitions.
            //
            (SessionState::Broadcasting { channel_id, .. }, SessionInput::AddPart { part }) => {
                // We already successfully settled htlcs for this payment
                // hash, we don't care about max_parts anymore (for whatever
                // reason we are collecting more of the same payment hash)
                let n_parts = 1;
                let parts_sum = part.amount_msat;

                Ok(ApplyResult {
                    actions: vec![SessionAction::ForwardHtlcs {
                        parts: vec![ForwardPart {
                            htlc_id: part.htlc_id,
                            fee_msat: 0,
                            forward_msat: part.amount_msat.msat(),
                        }],
                        channel_id: channel_id.clone(),
                    }],
                    events: vec![
                        SessionEvent::PaymentPartAdded {
                            part: part.clone(),
                            n_parts,
                            parts_sum,
                        },
                        SessionEvent::ForwardHtlcs {
                            channel_id: channel_id.clone(),
                            n_parts,
                            parts_sum,
                            opening_fee_msat: 0,
                        },
                    ],
                })
            }
            (SessionState::Broadcasting { funding_psbt, .. }, SessionInput::FundingBroadcasted) => {
                let funding_psbt = std::mem::take(funding_psbt);

                self.state = SessionState::Succeeded;
                Ok(ApplyResult {
                    actions: vec![],
                    events: vec![
                        SessionEvent::FundingBroadcasted { funding_psbt },
                        SessionEvent::SessionSucceeded,
                    ],
                })
            }
            (
                SessionState::Broadcasting { .. },
                ref input @ (SessionInput::CollectTimeout
                | SessionInput::ChannelReady { .. }
                | SessionInput::PaymentSettled
                | SessionInput::FundingFailed
                | SessionInput::PaymentFailed { .. }
                | SessionInput::ChannelClosed { .. }
                | SessionInput::NewBlock { .. }),
            ) => Ok(ApplyResult::unusual_input(&self.state, input)),

            //
            // Terminal states.
            //
            (SessionState::Failed | SessionState::Abandoned | SessionState::Succeeded, input) => {
                return Err(Error::InvalidTransition {
                    state: self.state.clone(),
                    input,
                })
            }
        }
    }
}

fn max_deductible(parts: &[PaymentPart]) -> u128 {
    parts
        .iter()
        .map(|p| u128::from(p.amount_msat.msat().saturating_sub(1)))
        .sum()
}

fn is_deductible(parts: &[PaymentPart], opening_fee_msat: u64) -> bool {
    max_deductible(parts) >= u128::from(opening_fee_msat)
}

fn allocate_forwards(parts: &[PaymentPart], opening_fee_msat: u64) -> Result<Vec<ForwardPart>> {
    if !is_deductible(parts, opening_fee_msat) {
        return Err(Error::InsufficientDeductibleCapacity {
            opening_fee_msat,
            deductible_capacity_msat: max_deductible(parts),
        });
    }

    let mut remaining = opening_fee_msat;
    let forwards: Vec<ForwardPart> = parts
        .iter()
        .map(|p| {
            let amt = p.amount_msat.msat();
            let deduct = remaining.min(amt.saturating_sub(1));
            remaining -= deduct;
            ForwardPart {
                htlc_id: p.htlc_id,
                fee_msat: deduct,
                forward_msat: amt - deduct,
            }
        })
        .collect();

    debug_assert_eq!(remaining, 0);
    Ok(forwards)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::lsps0::Ppm;
    use crate::proto::lsps2::Promise;
    use chrono::{Duration, Utc};

    fn htlc_id(id: u64) -> HtlcId {
        HtlcId {
            scid: ShortChannelId::from(100u64 << 40 | 1u64 << 16),
            id,
        }
    }

    fn part(id: u64, amount_msat: u64) -> PaymentPart {
        PaymentPart {
            htlc_id: htlc_id(id),
            amount_msat: Msat::from_msat(amount_msat),
            cltv_expiry: 100,
        }
    }

    fn part_with_cltv(id: u64, amount_msat: u64, cltv_expiry: u32) -> PaymentPart {
        PaymentPart {
            htlc_id: htlc_id(id),
            amount_msat: Msat::from_msat(amount_msat),
            cltv_expiry,
        }
    }

    fn opening_fee_params(min_fee_msat: u64, proportional_ppm: u32) -> OpeningFeeParams {
        OpeningFeeParams {
            min_fee_msat: Msat::from_msat(min_fee_msat),
            proportional: Ppm::from_ppm(proportional_ppm),
            valid_until: Utc::now() + Duration::hours(1),
            min_lifetime: 144,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: Msat::from_msat(1),
            max_payment_size_msat: Msat::from_msat(u64::MAX),
            promise: Promise("test-promise".to_owned()),
        }
    }

    fn session(max_parts: usize, payment_size_msat: Option<u64>, min_fee_msat: u64) -> Session {
        Session {
            state: SessionState::Collecting { parts: vec![] },
            max_parts,
            opening_fee_params: opening_fee_params(min_fee_msat, 1_000),
            payment_size_msat: payment_size_msat.map(Msat::from_msat),
            channel_capacity_msat: Msat::from_msat(100_000_000),
            peer_id: "peer-1".to_owned(),
        }
    }

    #[test]
    fn collecting_add_part_emits_payment_part_added() {
        let mut s = session(3, Some(2_000), 1);
        let p = part(1, 1_000);

        let res = s.apply(SessionInput::AddPart { part: p.clone() }).unwrap();

        assert!(res.actions.is_empty());
        assert_eq!(
            res.events,
            vec![SessionEvent::PaymentPartAdded {
                part: p,
                n_parts: 1,
                parts_sum: Msat::from_msat(1_000),
            }]
        );
    }

    #[test]
    fn collecting_below_expected_stays_collecting_no_actions() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
    }

    #[test]
    fn collecting_reaches_expected_transitions_and_funds_channel() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let res = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::AwaitingChannelReady { .. }));
        assert_eq!(res.actions.len(), 1);
        match &res.actions[0] {
            SessionAction::FundChannel {
                peer_id,
                channel_capacity_msat,
                opening_fee_params,
            } => {
                assert_eq!(peer_id, "peer-1");
                assert_eq!(*channel_capacity_msat, Msat::from_msat(100_000_000));
                assert_eq!(opening_fee_params.min_fee_msat, Msat::from_msat(1));
                assert_eq!(opening_fee_params.proportional, Ppm::from_ppm(1_000));
                assert_eq!(opening_fee_params.min_payment_size_msat, Msat::from_msat(1));
                assert_eq!(
                    opening_fee_params.max_payment_size_msat,
                    Msat::from_msat(u64::MAX)
                );
                assert_eq!(
                    opening_fee_params.promise,
                    Promise("test-promise".to_owned())
                );
            }
            _ => panic!("expected FundChannel action"),
        }
        assert!(res.events.contains(&SessionEvent::FundingChannel));
    }

    #[test]
    fn collecting_too_many_parts_emits_fail_action() {
        let mut s = session(0, Some(1_000), 1);

        let res = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();

        assert_eq!(
            res.events,
            vec![
                SessionEvent::PaymentPartAdded {
                    part: part(1, 1_000),
                    n_parts: 1,
                    parts_sum: Msat::from_msat(1_000),
                },
                SessionEvent::TooManyParts { n_parts: 1 },
                SessionEvent::SessionFailed,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE
                },
                SessionAction::FailSession
            ]
        );
    }

    #[test]
    fn collecting_insufficient_for_opening_fee_emits_fail_action() {
        let mut s = session(3, Some(1_000), 1_000);

        let res = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();

        assert_eq!(
            res.events,
            vec![
                SessionEvent::PaymentPartAdded {
                    part: part(1, 1_000),
                    n_parts: 1,
                    parts_sum: Msat::from_msat(1_000),
                },
                SessionEvent::PaymentInsufficientForOpeningFee {
                    opening_fee_msat: 1_000,
                    n_parts: 1,
                    parts_sum: Msat::from_msat(1_000),
                },
                SessionEvent::SessionFailed,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: UNKNOWN_NEXT_PEER
                },
                SessionAction::FailSession,
            ]
        );
    }

    #[test]
    fn collecting_collect_timeout_with_no_parts_fails_and_transitions_failed() {
        let mut s = session(3, Some(2_000), 1);

        let res = s.apply(SessionInput::CollectTimeout).unwrap();

        assert!(matches!(s.state, SessionState::Failed));
        assert_eq!(
            res.events,
            vec![
                SessionEvent::CollectTimeout {
                    n_parts: 0,
                    parts_sum: Msat::from_msat(0),
                },
                SessionEvent::SessionFailed,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::FailSession,
            ]
        );
    }

    #[test]
    fn collecting_collect_timeout_with_parts_reports_count_and_sum() {
        let mut s = session(3, Some(5_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 2_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();

        let res = s.apply(SessionInput::CollectTimeout).unwrap();

        assert!(matches!(s.state, SessionState::Failed));
        assert_eq!(
            res.events,
            vec![
                SessionEvent::CollectTimeout {
                    n_parts: 2,
                    parts_sum: Msat::from_msat(3_000),
                },
                SessionEvent::SessionFailed,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::FailSession,
            ]
        );
    }

    #[test]
    fn failed_rejects_add_part_with_invalid_transition() {
        let mut s = session(3, Some(2_000), 1);
        s.state = SessionState::Failed;

        let err = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap_err();

        assert_eq!(
            err,
            Error::InvalidTransition {
                state: SessionState::Failed,
                input: SessionInput::AddPart {
                    part: part(1, 1_000),
                },
            }
        );
    }

    #[test]
    fn failed_rejects_collect_timeout_with_invalid_transition() {
        let mut s = session(3, Some(2_000), 1);
        s.state = SessionState::Failed;

        let err = s.apply(SessionInput::CollectTimeout).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidTransition {
                state: SessionState::Failed,
                input: SessionInput::CollectTimeout,
            }
        );
    }

    #[test]
    fn collecting_var_amount_single_htlc_triggers_funding() {
        let mut s = session(3, None, 1);
        let res = s
            .apply(SessionInput::AddPart {
                part: part(1, 10_000_000),
            })
            .unwrap();

        assert!(matches!(
            s.state,
            SessionState::AwaitingChannelReady { .. }
        ));
        assert!(res
            .actions
            .iter()
            .any(|a| matches!(a, SessionAction::FundChannel { .. })));
        assert!(res
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::FundingChannel)));
    }

    #[test]
    fn collecting_var_amount_second_htlc_fails() {
        // Set up a session with one part already in Collecting
        let mut s = session(3, None, 1);
        s.state = SessionState::Collecting {
            parts: vec![part(1, 5_000_000)],
        };
        let res = s
            .apply(SessionInput::AddPart {
                part: part(2, 5_000_000),
            })
            .unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert!(res
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::TooManyParts { n_parts: 2 })));
        assert!(res
            .actions
            .iter()
            .any(|a| matches!(a, SessionAction::FailHtlcs { .. })));
    }

    #[test]
    fn collecting_var_amount_fee_computed_on_htlc_amount() {
        let mut s = session(3, None, 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 10_000_000),
            })
            .unwrap();

        // fee = max(min_fee=1000, 10_000_000 * 1000 / 1_000_000) = max(1000, 10_000) = 10_000
        if let SessionState::AwaitingChannelReady {
            opening_fee_msat, ..
        } = s.state
        {
            assert_eq!(opening_fee_msat, 10_000);
        } else {
            panic!("expected AwaitingChannelReady, got {:?}", s.state);
        }
    }

    #[test]
    fn overpaying_parts_charge_fee_on_payment_size() {
        // Payers may overpay (parts_sum > payment_size, permitted by BOLT4).
        // The opening fee is promised against payment_size_msat and the
        // client verifies the deducted extra_fees against that promise, so
        // the fee must be computed from the negotiated payment size, not
        // from the amount actually delivered.
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_500),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_500),
            })
            .unwrap();

        // proportional = 1_000 ppm: fee(2_000) = 2, while fee(3_000) = 3.
        match &s.state {
            SessionState::AwaitingChannelReady {
                opening_fee_msat, ..
            } => assert_eq!(*opening_fee_msat, 2),
            other => panic!("expected AwaitingChannelReady, got {other:?}"),
        }
    }

    #[test]
    fn collecting_fee_overflow_fails_session_with_unknown_next_peer() {
        // LSPS2: if the opening fee computation overflows, the LSP MUST
        // fail with unknown_next_peer. The HTLCs must be failed promptly,
        // not left hanging until the collect timeout.
        let mut s = session(3, Some(u64::MAX), 1);
        s.opening_fee_params.proportional = Ppm::from_ppm(u32::MAX);

        let res = s
            .apply(SessionInput::AddPart {
                part: part(1, u64::MAX),
            })
            .unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: UNKNOWN_NEXT_PEER,
                },
                SessionAction::FailSession,
            ]
        );
    }

    #[test]
    fn collecting_unexpected_inputs_emit_unusual_input() {
        let mut s = session(3, Some(2_000), 1);

        let res = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
        assert!(res.actions.is_empty());
        assert_eq!(res.events.len(), 1);
        assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
    }

    #[test]
    fn channel_ready_forwards_all_parts_and_transitions_to_awaiting_settlement() {
        let mut s = session(4, Some(2_000), 1);

        let p1 = part(1, 1_000);
        let p2 = part(2, 1_000);
        let p3 = part(3, 500);

        let _ = s.apply(SessionInput::AddPart { part: p1.clone() }).unwrap();
        let _ = s.apply(SessionInput::AddPart { part: p2.clone() }).unwrap();
        let _ = s.apply(SessionInput::AddPart { part: p3.clone() }).unwrap();

        let res = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        assert_eq!(
            s.state,
            SessionState::AwaitingSettlement {
                forwarded_parts: vec![
                    ForwardPart {
                        htlc_id: p1.htlc_id,
                        fee_msat: 2,
                        forward_msat: 998,
                    },
                    ForwardPart {
                        htlc_id: p2.htlc_id,
                        fee_msat: 0,
                        forward_msat: 1_000,
                    },
                    ForwardPart {
                        htlc_id: p3.htlc_id,
                        fee_msat: 0,
                        forward_msat: 500,
                    },
                ],
                forwarded_amount_msat: 2_498,
                deducted_fee_msat: 2,
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            }
        );

        assert_eq!(
            res.actions,
            vec![SessionAction::ForwardHtlcs {
                parts: vec![
                    ForwardPart {
                        htlc_id: p1.htlc_id,
                        fee_msat: 2,
                        forward_msat: 998,
                    },
                    ForwardPart {
                        htlc_id: p2.htlc_id,
                        fee_msat: 0,
                        forward_msat: 1_000,
                    },
                    ForwardPart {
                        htlc_id: p3.htlc_id,
                        fee_msat: 0,
                        forward_msat: 500,
                    },
                ],
                channel_id: "chan-1".to_owned(),
            }]
        );
        assert_eq!(
            res.events,
            vec![
                SessionEvent::ChannelReady {
                    channel_id: "chan-1".to_owned(),
                    funding_psbt: "psbt-1".to_owned(),
                },
                SessionEvent::ForwardHtlcs {
                    channel_id: "chan-1".to_owned(),
                    n_parts: 3,
                    parts_sum: Msat::from_msat(2_500),
                    opening_fee_msat: 2,
                },
            ]
        );
    }

    #[test]
    fn awaiting_settlement_add_part_forwards_single_part() {
        let mut s = session(5, Some(2_000), 1);

        let p1 = part(1, 1_000);
        let p2 = part(2, 1_000);
        let p3 = part(3, 500);

        let _ = s.apply(SessionInput::AddPart { part: p1.clone() }).unwrap();
        let _ = s.apply(SessionInput::AddPart { part: p2.clone() }).unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        let res = s.apply(SessionInput::AddPart { part: p3.clone() }).unwrap();

        assert_eq!(
            s.state,
            SessionState::AwaitingSettlement {
                forwarded_parts: vec![
                    ForwardPart {
                        htlc_id: p1.htlc_id,
                        fee_msat: 2,
                        forward_msat: 998,
                    },
                    ForwardPart {
                        htlc_id: p2.htlc_id,
                        fee_msat: 0,
                        forward_msat: 1_000,
                    },
                    ForwardPart {
                        htlc_id: p3.htlc_id,
                        fee_msat: 0,
                        forward_msat: 500,
                    },
                ],
                forwarded_amount_msat: 2_498,
                deducted_fee_msat: 2,
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            }
        );

        assert_eq!(
            res.actions,
            vec![SessionAction::ForwardHtlcs {
                parts: vec![p3.clone().into()],
                channel_id: "chan-1".to_owned(),
            }]
        );
        assert_eq!(
            res.events,
            vec![
                SessionEvent::PaymentPartAdded {
                    part: p3.clone(),
                    n_parts: 3,
                    parts_sum: Msat::from_msat(2_500),
                },
                SessionEvent::ForwardHtlcs {
                    channel_id: "chan-1".to_owned(),
                    n_parts: 1,
                    parts_sum: Msat::from_msat(500),
                    opening_fee_msat: 0,
                },
            ]
        );
    }

    #[test]
    fn allocate_forwards_allows_exact_deductible_capacity() {
        let parts = vec![part(1, 1_000), part(2, 1_000)];

        let forwards = allocate_forwards(&parts, 1_998).unwrap();

        assert_eq!(
            forwards,
            vec![
                ForwardPart {
                    htlc_id: htlc_id(1),
                    fee_msat: 999,
                    forward_msat: 1,
                },
                ForwardPart {
                    htlc_id: htlc_id(2),
                    fee_msat: 999,
                    forward_msat: 1,
                },
            ]
        );
    }

    #[test]
    fn payment_settled_transitions_to_broadcasting_and_emits_broadcast_action() {
        let mut s = session(4, Some(2_000), 1);

        let p1 = part(1, 1_000);
        let p2 = part(2, 1_000);
        let _ = s.apply(SessionInput::AddPart { part: p1.clone() }).unwrap();
        let _ = s.apply(SessionInput::AddPart { part: p2.clone() }).unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        let res = s.apply(SessionInput::PaymentSettled).unwrap();

        assert_eq!(
            s.state,
            SessionState::Broadcasting {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            }
        );
        assert_eq!(
            res.actions,
            vec![SessionAction::BroadcastFundingTx {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            }]
        );
        assert_eq!(
            res.events,
            vec![SessionEvent::PaymentSettled {
                parts: vec![
                    ForwardPart {
                        htlc_id: p1.htlc_id,
                        fee_msat: 2,
                        forward_msat: 998,
                    },
                    ForwardPart {
                        htlc_id: p2.htlc_id,
                        fee_msat: 0,
                        forward_msat: 1_000,
                    },
                ]
            }]
        );
    }

    #[test]
    fn channel_ready_with_too_many_parts_abandons_session_and_fails_htlcs() {
        let mut s = session(2, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        // Extra part while awaiting channel ready.
        let _ = s
            .apply(SessionInput::AddPart { part: part(3, 500) })
            .unwrap();

        let res = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-overflow".to_owned(),
                funding_psbt: "psbt-overflow".to_owned(),
            })
            .unwrap();

        assert_eq!(s.state, SessionState::Abandoned);
        assert_eq!(
            res.events,
            vec![
                SessionEvent::ChannelReady {
                    channel_id: "chan-overflow".to_owned(),
                    funding_psbt: "psbt-overflow".to_owned(),
                },
                SessionEvent::TooManyParts { n_parts: 3 },
                SessionEvent::SessionAbandoned,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::Disconnect,
                SessionAction::AbandonSession {
                    channel_id: "chan-overflow".to_owned(),
                    funding_psbt: "psbt-overflow".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn channel_ready_with_unallocatable_fee_abandons_with_temporary_failure() {
        let mut s = session(5, Some(2_000), 1);
        // Force a state where the opening fee can no longer be deducted from
        // the collected parts (fee exceeds the parts sum).
        s.state = SessionState::AwaitingChannelReady {
            parts: vec![part(1, 1)],
            opening_fee_msat: 5_000,
        };

        let res = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        assert_eq!(s.state, SessionState::Abandoned);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::Disconnect,
                SessionAction::AbandonSession {
                    channel_id: "chan-1".to_owned(),
                    funding_psbt: "psbt-1".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn abandoned_rejects_further_inputs_with_invalid_transition() {
        let mut s = session(2, Some(2_000), 1);
        s.state = SessionState::Abandoned;

        let err = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap_err();

        assert_eq!(
            err,
            Error::InvalidTransition {
                state: SessionState::Abandoned,
                input: SessionInput::ChannelReady {
                    channel_id: "chan-1".to_owned(),
                    funding_psbt: "psbt-1".to_owned(),
                },
            }
        );
    }

    #[test]
    fn broadcasting_add_part_forwards_single_htlc() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();
        let _ = s.apply(SessionInput::PaymentSettled).unwrap();

        let p3 = part(3, 500);
        let res = s.apply(SessionInput::AddPart { part: p3.clone() }).unwrap();

        assert_eq!(
            res.actions,
            vec![SessionAction::ForwardHtlcs {
                parts: vec![p3.clone().into()],
                channel_id: "chan-1".to_owned(),
            }]
        );
        assert_eq!(
            res.events,
            vec![
                SessionEvent::PaymentPartAdded {
                    part: p3.clone(),
                    n_parts: 1,
                    parts_sum: Msat::from_msat(500),
                },
                SessionEvent::ForwardHtlcs {
                    channel_id: "chan-1".to_owned(),
                    n_parts: 1,
                    parts_sum: Msat::from_msat(500),
                    opening_fee_msat: 0,
                },
            ]
        );
    }

    #[test]
    fn funding_broadcasted_transitions_to_succeeded() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();
        let _ = s.apply(SessionInput::PaymentSettled).unwrap();

        let res = s.apply(SessionInput::FundingBroadcasted).unwrap();

        assert_eq!(s.state, SessionState::Succeeded);
        assert_eq!(res.actions, vec![]);
        assert_eq!(
            res.events,
            vec![
                SessionEvent::FundingBroadcasted {
                    funding_psbt: "psbt-1".to_owned(),
                },
                SessionEvent::SessionSucceeded,
            ]
        );
    }

    #[test]
    fn succeeded_rejects_new_inputs_with_invalid_transition() {
        let mut s = session(4, Some(2_000), 1);
        s.state = SessionState::Succeeded;

        let err = s
            .apply(SessionInput::AddPart {
                part: part(99, 1_000),
            })
            .unwrap_err();

        assert_eq!(
            err,
            Error::InvalidTransition {
                state: SessionState::Succeeded,
                input: SessionInput::AddPart {
                    part: part(99, 1_000),
                },
            }
        );
    }

    #[test]
    fn funding_failed_in_awaiting_channel_ready_fails_htlcs_and_transitions_to_failed() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::AwaitingChannelReady { .. }));

        let res = s.apply(SessionInput::FundingFailed).unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::Disconnect,
                SessionAction::FailSession,
            ]
        );
        assert_eq!(res.events, vec![SessionEvent::SessionFailed]);
    }

    #[test]
    fn funding_failed_in_awaiting_channel_ready_with_extra_parts_reports_all() {
        let mut s = session(5, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        // Extra part arrived while awaiting channel ready.
        let _ = s
            .apply(SessionInput::AddPart { part: part(3, 500) })
            .unwrap();

        let res = s.apply(SessionInput::FundingFailed).unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(res.events, vec![SessionEvent::SessionFailed]);
    }

    #[test]
    fn collecting_unexpected_funding_failed_emits_unusual_input() {
        let mut s = session(3, Some(2_000), 1);

        let res = s.apply(SessionInput::FundingFailed).unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
        assert!(res.actions.is_empty());
        assert_eq!(res.events.len(), 1);
        assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
    }

    #[test]
    fn funding_failed_is_terminal() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s.apply(SessionInput::FundingFailed).unwrap();

        assert!(s.is_terminal());

        let err = s
            .apply(SessionInput::AddPart { part: part(3, 500) })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition { .. }));
    }

    #[test]
    fn new_block_collecting_timeout_fails_session() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part_with_cltv(1, 1_000, 50),
            })
            .unwrap();

        let res = s.apply(SessionInput::NewBlock { height: 51 }).unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(
            res.events,
            vec![
                SessionEvent::UnsafeHtlcTimeout {
                    height: 51,
                    cltv_min: 50,
                },
                SessionEvent::SessionFailed,
            ]
        );
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::Disconnect,
                SessionAction::FailSession,
            ]
        );
    }

    #[test]
    fn new_block_collecting_safe_height_is_noop() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part_with_cltv(1, 1_000, 50),
            })
            .unwrap();

        // More than CLTV_SAFETY_BUFFER blocks left until expiry: safe.
        let res = s
            .apply(SessionInput::NewBlock {
                height: 50 - CLTV_SAFETY_BUFFER - 1,
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
        assert!(res.actions.is_empty());
        assert!(res.events.is_empty());
    }

    #[test]
    fn new_block_collecting_fails_within_safety_buffer() {
        // HTLCs must be failed off-chain BEFORE their expiry: at expiry the
        // upstream peer is entitled to force-close to claim the timeout.
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part_with_cltv(1, 1_000, 50),
            })
            .unwrap();

        let height = 50 - CLTV_SAFETY_BUFFER;
        let res = s.apply(SessionInput::NewBlock { height }).unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(
            res.events,
            vec![
                SessionEvent::UnsafeHtlcTimeout {
                    height,
                    cltv_min: 50,
                },
                SessionEvent::SessionFailed,
            ]
        );
    }

    #[test]
    fn new_block_collecting_no_parts_is_noop() {
        let mut s = session(3, Some(2_000), 1);

        let res = s.apply(SessionInput::NewBlock { height: 100 }).unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
        assert!(res.actions.is_empty());
        assert!(res.events.is_empty());
    }

    #[test]
    fn new_block_awaiting_channel_ready_timeout_fails_with_disconnect() {
        let mut s = session(3, Some(2_000), 1);

        let _ = s
            .apply(SessionInput::AddPart {
                part: part_with_cltv(1, 1_000, 50),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part_with_cltv(2, 1_000, 60),
            })
            .unwrap();

        assert!(matches!(s.state, SessionState::AwaitingChannelReady { .. }));

        let res = s.apply(SessionInput::NewBlock { height: 51 }).unwrap();

        assert_eq!(s.state, SessionState::Failed);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::FailHtlcs {
                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                },
                SessionAction::Disconnect,
                SessionAction::FailSession,
            ]
        );
        assert_eq!(
            res.events,
            vec![
                SessionEvent::UnsafeHtlcTimeout {
                    height: 51,
                    cltv_min: 50,
                },
                SessionEvent::SessionFailed,
            ]
        );
    }

    #[test]
    fn new_block_awaiting_settlement_emits_unusual_input() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        let res = s.apply(SessionInput::NewBlock { height: 200 }).unwrap();

        assert!(matches!(s.state, SessionState::AwaitingSettlement { .. }));
        assert!(res.actions.is_empty());
        assert_eq!(res.events.len(), 1);
        assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
    }

    #[test]
    fn awaiting_settlement_payment_failed_disconnects() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        let res = s.apply(SessionInput::PaymentFailed { htlc_id: None }).unwrap();

        assert_eq!(s.state, SessionState::Abandoned);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::AbandonSession {
                    channel_id: "chan-1".to_owned(),
                    funding_psbt: "psbt-1".to_owned(),
                },
                SessionAction::Disconnect,
            ]
        );
        assert_eq!(
            res.events,
            vec![SessionEvent::PaymentFailed, SessionEvent::SessionAbandoned]
        );
    }

    #[test]
    fn awaiting_settlement_single_part_failure_keeps_session_alive() {
        // With multiple forwarded parts, one part failing (e.g. exceeding
        // max_accepted_htlcs) must not abandon the session: the client can
        // still settle the remaining offered parts. Only when no forwarded
        // parts remain is the session abandoned.
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        // Part 1 fails; part 2 is still offered.
        let res = s
            .apply(SessionInput::PaymentFailed {
                htlc_id: Some(htlc_id(1)),
            })
            .unwrap();
        assert!(matches!(s.state, SessionState::AwaitingSettlement { .. }));
        assert!(res.actions.is_empty());

        // Last remaining part fails: now abandon.
        let res = s
            .apply(SessionInput::PaymentFailed {
                htlc_id: Some(htlc_id(2)),
            })
            .unwrap();
        assert_eq!(s.state, SessionState::Abandoned);
        assert_eq!(
            res.actions,
            vec![
                SessionAction::AbandonSession {
                    channel_id: "chan-1".to_owned(),
                    funding_psbt: "psbt-1".to_owned(),
                },
                SessionAction::Disconnect,
            ]
        );
    }

    #[test]
    fn awaiting_settlement_unusual_inputs_emit_unusual_input() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();

        for input in [
            SessionInput::CollectTimeout,
            SessionInput::FundingFailed,
            SessionInput::FundingBroadcasted,
            SessionInput::NewBlock { height: 100 },
        ] {
            let res = s.apply(input).unwrap();
            assert!(res.actions.is_empty());
            assert_eq!(res.events.len(), 1);
            assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
        }
    }

    #[test]
    fn broadcasting_unusual_inputs_emit_unusual_input() {
        let mut s = session(4, Some(2_000), 1);
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::AddPart {
                part: part(2, 1_000),
            })
            .unwrap();
        let _ = s
            .apply(SessionInput::ChannelReady {
                channel_id: "chan-1".to_owned(),
                funding_psbt: "psbt-1".to_owned(),
            })
            .unwrap();
        let _ = s.apply(SessionInput::PaymentSettled).unwrap();

        for input in [
            SessionInput::CollectTimeout,
            SessionInput::FundingFailed,
            SessionInput::PaymentFailed { htlc_id: None },
            SessionInput::NewBlock { height: 100 },
        ] {
            let res = s.apply(input).unwrap();
            assert!(res.actions.is_empty());
            assert_eq!(res.events.len(), 1);
            assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
        }
    }

    #[test]
    fn recover_without_preimage_enters_awaiting_settlement() {
        let (session, actions) = Session::recover(
            "channel-id-1".to_string(),
            "psbt-1".to_string(),
            None,
            opening_fee_params(1_000, 0),
        );
        assert!(actions.is_empty());
        assert!(!session.is_terminal());
    }

    #[test]
    fn recover_with_preimage_enters_broadcasting() {
        let (session, actions) = Session::recover(
            "channel-id-1".to_string(),
            "psbt-1".to_string(),
            Some("preimage-1".to_string()),
            opening_fee_params(1_000, 0),
        );
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SessionAction::BroadcastFundingTx { channel_id, funding_psbt }
            if channel_id == "channel-id-1" && funding_psbt == "psbt-1"
        ));
        assert!(!session.is_terminal());
    }

    #[test]
    fn recovered_awaiting_settlement_transitions_on_payment_settled() {
        let (mut session, _) = Session::recover(
            "channel-id-1".to_string(),
            "psbt-1".to_string(),
            None,
            opening_fee_params(1_000, 0),
        );
        let result = session.apply(SessionInput::PaymentSettled).unwrap();
        assert!(matches!(
            result.actions.as_slice(),
            [SessionAction::BroadcastFundingTx { .. }]
        ));
    }

    #[test]
    fn recovered_awaiting_settlement_transitions_on_payment_failed() {
        let (mut session, _) = Session::recover(
            "channel-id-1".to_string(),
            "psbt-1".to_string(),
            None,
            opening_fee_params(1_000, 0),
        );
        let result = session.apply(SessionInput::PaymentFailed { htlc_id: None }).unwrap();
        assert!(matches!(
            result.actions.as_slice(),
            [SessionAction::AbandonSession { .. }, SessionAction::Disconnect]
        ));
        assert!(session.is_terminal());
    }

    #[test]
    fn recovered_broadcasting_transitions_on_funding_broadcasted() {
        let (mut session, _) = Session::recover(
            "channel-id-1".to_string(),
            "psbt-1".to_string(),
            Some("preimage-1".to_string()),
            opening_fee_params(1_000, 0),
        );
        let result = session.apply(SessionInput::FundingBroadcasted).unwrap();
        let _ = result;
        assert!(session.is_terminal());
        assert_eq!(session.outcome(), Some(SessionOutcome::Succeeded));
    }
}
