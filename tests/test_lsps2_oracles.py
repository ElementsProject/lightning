"""Unit tests for the LSPS2 oracles, on observations written by hand."""

from copy import deepcopy
from lsps2_oracles import Observation, violations


CLIENT = "02" + "11" * 32
LSP = "03" + "22" * 32
SCID = "1000000x1x0"
PAYMENT_HASH = "aa" * 32
CHANNEL_ID = "cc" * 32

PARAMS = {
    "min_fee_msat": "1000",
    "proportional": 10_000,
    "min_lifetime": 1008,
    "max_client_to_self_delay": 2016,
    "min_payment_size_msat": "1000",
    "max_payment_size_msat": "100000000",
    "valid_until": "2100-01-01T00:00:00.000Z",
    "promise": "mock-promise-0001",
}


def honest_run():
    """A no-MPP+var-invoice session paid with 10_000_000 msat, minus the
    1% opening fee, over a confirmed channel."""
    return {
        "client_id": CLIENT,
        "lsp_id": LSP,
        "mock_state": {
            "issued": [PARAMS],
            "sessions": [
                {
                    "jit_channel_scid": SCID,
                    "peer_id": CLIENT,
                    "opening_fee_params": PARAMS,
                    "payment_size_msat": None,
                    "opening_fee_msat": 100_000,
                    "state": "forwarded",
                    "payment_hash": PAYMENT_HASH,
                    "channel_id": CHANNEL_ID,
                }
            ],
            "events": [
                forward_event(PAYMENT_HASH, 10_000_000, 100_000),
            ],
        },
        "invoices": [
            {
                "label": "jit",
                "status": "paid",
                "payment_hash": PAYMENT_HASH,
                "amount_received_msat": 9_900_000,
                "decoded": {
                    "routes": [
                        [
                            {
                                "pubkey": LSP,
                                "short_channel_id": SCID,
                                "fee_base_msat": 0,
                                "fee_proportional_millionths": 0,
                                "cltv_expiry_delta": 144,
                            }
                        ]
                    ],
                },
            }
        ],
        "channels": [
            {
                "peer_id": LSP,
                "channel_id": CHANNEL_ID,
                "state": "CHANNELD_NORMAL",
                "opener": "remote",
                "confirmations": 1,
                "to_us_msat": 9_900_000,
                "alias": {"local": "5x5x5", "remote": "6x6x6"},
                "htlcs": [],
            }
        ],
    }


def forward_event(payment_hash, onion_msat, deduction_msat, status="settled"):
    return {
        "type": "htlc",
        "time": "2026-01-01T00:00:00.000Z",
        "jit_channel_scid": SCID,
        "payment_hash": payment_hash,
        "in_channel": "7x7x7",
        "in_htlc_id": 0,
        "amount_msat": onion_msat,
        "onion_forward_msat": onion_msat,
        "forward_msat": onion_msat - deduction_msat,
        "extra_fee_msat": deduction_msat or None,
        "decision": "forward",
        "status": status,
    }


def check_ids(run):
    return [cid for cid, _ in violations(Observation(**run))]


def test_lsps2_oracles_honest_run():
    assert check_ids(honest_run()) == []


def test_lsps2_oracles_amount():
    run = honest_run()
    run["invoices"][0]["amount_received_msat"] -= 1
    run["channels"][0]["to_us_msat"] -= 1
    assert check_ids(run) == ["amount.received"]

    # A part the client failed is not part of the payment.
    run = honest_run()
    failed = forward_event(PAYMENT_HASH, 10_000_000, 100_000, status="failed")
    run["mock_state"]["events"].insert(2, failed)
    assert check_ids(run) == []

    # A fixed invoice owes the fee for the payment size bought.
    run = honest_run()
    run["mock_state"]["sessions"][0]["payment_size_msat"] = 10_000_000
    run["invoices"][0]["amount_msat"] = 9_900_000
    assert check_ids(run) == []
    run["mock_state"]["sessions"][0]["payment_size_msat"] = 11_000_000
    assert check_ids(run) == ["amount.received"]

    # Later payments owe no fee.
    run = honest_run()
    later = deepcopy(run["invoices"][0])
    later.update(label="later", payment_hash="bb" * 32)
    run["invoices"].append(later)
    run["mock_state"]["events"].append(forward_event("bb" * 32, 10_000_000, 100_000))
    run["channels"][0]["to_us_msat"] *= 2
    assert check_ids(run) == ["amount.received"]


def test_lsps2_oracles_balance():
    run = honest_run()
    run["channels"][0]["to_us_msat"] += 1
    assert check_ids(run) == ["amount.balance"]

    # Funds in a channel the client opened are its own.
    run = honest_run()
    run["channels"].append(
        {**run["channels"][0], "channel_id": "dd" * 32, "opener": "local", "alias": {}}
    )
    assert check_ids(run) == []


def test_lsps2_oracles_route_hint():
    run = honest_run()
    run["invoices"][0]["decoded"]["routes"][0][0]["short_channel_id"] = "1x2x3"
    assert check_ids(run) == ["identity.route_hint"]

    run = honest_run()
    run["invoices"][0]["decoded"]["routes"][0][0]["pubkey"] = "02" + "33" * 32
    assert check_ids(run) == ["identity.route_hint"]

    run = honest_run()
    routes = run["invoices"][0]["decoded"]["routes"]
    routes.append(deepcopy(routes[0]))
    assert check_ids(run) == ["identity.route_hint"]

    # A hint to a channel the client has is fine.
    run = honest_run()
    run["invoices"][0]["decoded"]["routes"][0][0]["short_channel_id"] = "6x6x6"
    assert check_ids(run) == []


def test_lsps2_oracles_zero_conf_channel():
    run = honest_run()
    run["channels"][0]["confirmations"] = 0
    assert "identity.zero_conf_channel" not in check_ids(run)

    run["channels"].append(
        {
            **run["channels"][0],
            "channel_id": "dd" * 32,
            "to_us_msat": 0,
            "alias": {},
        }
    )
    assert "identity.zero_conf_channel" in check_ids(run)
