"""stash provides functions which resolve at action time.

During a run, Events often put state in the runner object for later
events to access at action time.  This is called the "stash".

These accessors actually return functions, which most Events know
means they're to be called at action time.  For the sake of (perhaps
non-Pythony) test authors, they are always called as (), even if they
simply return another function.

"""
from .stash import (
    commitsig_to_send,
    commitsig_to_recv,
    channel_id,
    channel_announcement,
    channel_update,
    get_member,
    rcvd,
    sent,
    funding_amount,
    funding_pubkey,
    funding_tx,
    funding_txid,
    funding,
    funding_close_tx,
    htlc_sigs_to_send,
    htlc_sigs_to_recv,
    locking_script,
    witnesses,
)


__all__ = [
    "commitsig_to_send",
    "commitsig_to_recv",
    "htlc_sigs_to_send",
    "htlc_sigs_to_recv",
    "channel_id",
    "channel_announcement",
    "channel_update",
    "get_member",
    "rcvd",
    "sent",
    "funding_amount",
    "funding_pubkey",
    "funding_tx",
    "funding_txid",
    "funding",
    "funding_close_tx",
    "locking_script",
    "witnesses",
]
