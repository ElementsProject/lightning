use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum ChannelState {
    OPENINGD,
    CHANNELD_AWAITING_LOCKIN,
    CHANNELD_NORMAL,
    CHANNELD_SHUTTING_DOWN,
    CLOSINGD_SIGEXCHANGE,
    CLOSINGD_COMPLETE,
    AWAITING_UNILATERAL,
    FUNDING_SPEND_SEEN,
    ONCHAIN,
    DUALOPEND_OPEN_INIT,
    DUALOPEND_AWAITING_LOCKIN,
}

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)]
pub enum ChannelStateChangeCause {
    UNKNOWN,
    LOCAL,
    USER,
    REMOTE,
    PROTOCOL,
    ONCHAIN,
}

#[derive(Deserialize, Debug)]
pub enum Amount {
    Millisatoshi(u64),
    Satoshi(u64),
    Millibitcoin(u64),
    Bitcoin(u64),
}
