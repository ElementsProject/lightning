#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


UTXO_DEPOSIT_TAG = "utxo_deposit"
UTXO_SPEND_TAG = "utxo_spend"


@plugin.method("sendspend")
def emit_spend(plugin, acct, outpoint, txid, amount, **kwargs):
    """Emit a 'utxo_spend' movement
    """
    utxo_spend = {
        "account": acct,
        "outpoint": outpoint,
        "spending_txid": txid,
        "amount_msat": amount,
        "coin_type": "bcrt",
        "timestamp": 1679955976,
        "blockheight": 111,
    }
    plugin.notify(UTXO_SPEND_TAG, {UTXO_SPEND_TAG: utxo_spend})


@plugin.method("senddeposit")
def emit_deposit(plugin, acct, is_withdraw, outpoint, amount, **kwargs):
    """Emit a 'utxo_deposit' movement
    """
    transfer_from = None

    if is_withdraw:
        acct = "external"
        transfer_from = acct

    utxo_deposit = {
        "account": acct,
        "transfer_from": transfer_from,
        "outpoint": outpoint,
        "amount_msat": amount,
        "coin_type": "bcrt",
        "timestamp": 1679955976,
        "blockheight": 111,
    }
    plugin.notify(UTXO_DEPOSIT_TAG, {UTXO_DEPOSIT_TAG: utxo_deposit})


plugin.add_notification_topic(UTXO_DEPOSIT_TAG)
plugin.add_notification_topic(UTXO_SPEND_TAG)
plugin.run()
