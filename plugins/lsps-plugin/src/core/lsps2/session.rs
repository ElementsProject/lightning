//! Lsps2 Service FSM

use crate::proto::{
    lsps0::Msat,
    lsps2::{
        compute_opening_fee,
        failure_codes::{TEMPORARY_CHANNEL_FAILURE, UNKNOWN_NEXT_PEER},
        OpeningFeeParams, SessionOutcome,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("variable amount payments are not supported")]
    UnimplementedVarAmount,
    #[error("opening fee computation overflow")]
    FeeOverflow,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPart {
    pub htlc_id: u64,
    pub amount_msat: Msat,
    pub cltv_expiry: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPart {
    pub htlc_id: u64,
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
    /// The inital payment failed
    PaymentFailed,
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

    pub fn apply(&mut self, input: SessionInput) -> Result<ApplyResult> {
        match (&mut self.state, input) {
            //
            // Collecting transitions.
            //
            (SessionState::Collecting { parts }, SessionInput::AddPart { part }) => {
                if self.payment_size_msat.is_none() {
                    return Err(Error::UnimplementedVarAmount);
                }

                parts.push(part.clone());
                let n_parts = parts.len();
                let parts_sum = parts.iter().map(|p| p.amount_msat).sum();

                let mut events = vec![SessionEvent::PaymentPartAdded {
                    part: part.clone(),
                    n_parts,
                    parts_sum,
                }];

                // Fail early if we have too many parts.
                if n_parts > self.max_parts {
                    self.state = SessionState::Failed;
                    events.push(SessionEvent::TooManyParts { n_parts });
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

                let expected_msat = self.payment_size_msat.unwrap_or_else(|| Msat(0)); // We checked that it isn't None
                if parts_sum >= expected_msat {
                    let opening_fee_msat = compute_opening_fee(
                        parts_sum.msat(),
                        self.opening_fee_params.min_fee_msat.msat(),
                        self.opening_fee_params.proportional.ppm() as u64,
                    )
                    .ok_or(Error::FeeOverflow)?;

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
                if let Some(min) = cltv_min(parts) {
                    if height > min {
                        self.state = SessionState::Failed;
                        return Ok(ApplyResult {
                            actions: vec![
                                SessionAction::FailHtlcs {
                                    failure_code: TEMPORARY_CHANNEL_FAILURE,
                                },
                                SessionAction::FailSession,
                            ],
                            events: vec![
                                SessionEvent::UnsafeHtlcTimeout {
                                    height,
                                    cltv_min: min,
                                },
                                SessionEvent::SessionFailed,
                            ],
                        });
                    }
                }
                // No parts or height <= cltv_min: stay collecting.
                Ok(ApplyResult::default())
            }
            (
                SessionState::Collecting { .. },
                ref input @ (SessionInput::ChannelReady { .. }
                | SessionInput::PaymentSettled
                | SessionInput::PaymentFailed
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

                // Fail if we have too many parts.
                if n_parts > self.max_parts {
                    self.state = SessionState::Abandoned;
                    events.push(SessionEvent::TooManyParts { n_parts });
                    events.push(SessionEvent::SessionAbandoned);
                    return Ok(ApplyResult {
                        actions: vec![
                            SessionAction::FailHtlcs {
                                failure_code: UNKNOWN_NEXT_PEER,
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
                                failure_code: UNKNOWN_NEXT_PEER,
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
                self.state = SessionState::Failed;
                Ok(ApplyResult {
                    actions: vec![
                        SessionAction::FailHtlcs {
                            failure_code: UNKNOWN_NEXT_PEER,
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
                if let Some(min) = cltv_min(parts) {
                    if height > min {
                        self.state = SessionState::Failed;
                        return Ok(ApplyResult {
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
                        });
                    }
                }
                Ok(ApplyResult::default())
            }
            (
                SessionState::AwaitingChannelReady { .. },
                ref input @ (SessionInput::PaymentSettled
                | SessionInput::PaymentFailed
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
                    channel_id,
                    funding_psbt,
                    ..
                },
                SessionInput::PaymentFailed,
            ) => {
                let channel_id = std::mem::take(channel_id);
                let funding_psbt = std::mem::take(funding_psbt);

                // Parts are already forwarded so we can't do anything here.
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
                | SessionInput::PaymentFailed
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

    fn part(htlc_id: u64, amount_msat: u64) -> PaymentPart {
        PaymentPart {
            htlc_id,
            amount_msat: Msat::from_msat(amount_msat),
            cltv_expiry: 100,
        }
    }

    fn part_with_cltv(htlc_id: u64, amount_msat: u64, cltv_expiry: u32) -> PaymentPart {
        PaymentPart {
            htlc_id,
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
                    failure_code: UNKNOWN_NEXT_PEER
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
    fn collecting_payment_size_none_errors_without_mutating_state() {
        let mut s = session(3, None, 1);
        let err = s
            .apply(SessionInput::AddPart {
                part: part(1, 1_000),
            })
            .unwrap_err();

        assert_eq!(err, Error::UnimplementedVarAmount);
        assert_eq!(s.state, SessionState::Collecting { parts: vec![] });
    }

    #[test]
    fn collecting_fee_overflow_returns_fee_overflow() {
        let mut s = session(3, Some(u64::MAX), 1);
        s.opening_fee_params.proportional = Ppm::from_ppm(u32::MAX);

        let err = s
            .apply(SessionInput::AddPart {
                part: part(1, u64::MAX),
            })
            .unwrap_err();
        assert_eq!(err, Error::FeeOverflow);
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
                    htlc_id: 1,
                    fee_msat: 999,
                    forward_msat: 1,
                },
                ForwardPart {
                    htlc_id: 2,
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
                    failure_code: UNKNOWN_NEXT_PEER,
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
                    failure_code: UNKNOWN_NEXT_PEER,
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

        let res = s.apply(SessionInput::NewBlock { height: 49 }).unwrap();

        assert!(matches!(s.state, SessionState::Collecting { .. }));
        assert!(res.actions.is_empty());
        assert!(res.events.is_empty());
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

        let res = s.apply(SessionInput::PaymentFailed).unwrap();

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
            SessionInput::PaymentFailed,
            SessionInput::NewBlock { height: 100 },
        ] {
            let res = s.apply(input).unwrap();
            assert!(res.actions.is_empty());
            assert_eq!(res.events.len(), 1);
            assert!(matches!(&res.events[0], SessionEvent::UnusualInput { .. }));
        }
    }
}
