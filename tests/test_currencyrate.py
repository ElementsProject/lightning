import logging
import pytest
import threading
import time
from utils import wait_for, only_one
from pyln.client import RpcError
from fixtures import *  # noqa: F401,F403
from flask import Flask, jsonify
from werkzeug.serving import make_server


LOGGER = logging.getLogger(__name__)


def median(rateslist):
    rates = [entry["amount"] for entry in rateslist]
    rates.sort()

    if len(rates) % 2 == 1:
        return rates[len(rates) // 2]
    else:
        return (rates[len(rates) - 1] + rates[len(rates) - 1]) / 2


def median_conversion(amount, rateslist):
    msats = amount * 100_000_000_000 / median(rateslist)

    # Give it +/- 1%
    return range(int(msats * 0.99), int(msats * 1.01))


def median_rate(rateslist):
    rate = median(rateslist)

    return range(int(rate * 0.99), int(rate * 1.01))


def test_apis_batch1(node_factory):
    opts = {
        "currencyrate-disable-source": ["bitstamp", "coinbase"],
    }
    l1 = node_factory.get_node(options=opts)

    rateslist = l1.rpc.call("listcurrencyrates", ["USD"])['currencyrates']
    LOGGER.info(rateslist)
    rates = {entry["source"]: entry["amount"] for entry in rateslist}

    assert "bitstamp" not in rates
    assert "coinbase" not in rates

    assert "coingecko" in rates
    assert "kraken" in rates
    assert "blockchain.info" in rates
    assert "coindesk" in rates
    assert "binance" in rates

    # Death to the 58k gang!
    assert rates["coingecko"] > 58000
    assert rates["kraken"] > 58000
    assert rates["blockchain.info"] > 58000
    assert rates["coindesk"] > 58000
    assert rates["binance"] > 58000

    rates = [
        rates["coingecko"],
        rates["kraken"],
        rates["blockchain.info"],
        rates["coindesk"],
        rates["binance"],
    ]

    rates.sort()

    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    assert "msat" in convert
    assert convert["msat"] > 0
    assert convert["msat"] in median_conversion(100, rateslist)

    assert int(l1.rpc.currencyrate("usd")['rate']) in median_rate(rateslist)


def test_apis_batch2(node_factory):
    opts = {
        "currencyrate-disable-source": [
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
    }
    l1 = node_factory.get_node(options=opts)

    rateslist = l1.rpc.call("listcurrencyrates", ["USD"])['currencyrates']
    LOGGER.info(rateslist)
    rates = {entry["source"]: entry["amount"] for entry in rateslist}

    assert "bitstamp" in rates
    assert "coinbase" in rates

    assert "coingecko" not in rates
    assert "kraken" not in rates
    assert "blockchain.info" not in rates
    assert "coindesk" not in rates
    assert "binance" not in rates

    assert rates["bitstamp"] > 0
    assert rates["coinbase"] > 0

    rates = [
        rates["bitstamp"],
        rates["coinbase"],
    ]
    rates.sort()

    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    assert "msat" in convert
    assert convert["msat"] > 0
    assert convert["msat"] in median_conversion(100, rateslist)

    assert int(l1.rpc.currencyrate("USD")['rate']) in median_rate(rateslist)


def test_custom_source(node_factory):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            r"my-coingecko,https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={currency_lc},bitcoin,{currency_lc}",
            r"my-kraken,https://api.kraken.com/0/public/Ticker?pair=XXBTZ{currency},result,XXBTZ{currency},c,0",
        ],
    }
    l1 = node_factory.get_node(options=opts)

    rateslist = l1.rpc.call("listcurrencyrates", ["USD"])['currencyrates']
    LOGGER.info(rateslist)
    rates = {entry["source"]: entry["amount"] for entry in rateslist}

    assert "bitstamp" not in rates
    assert "coinbase" not in rates
    assert "coingecko" not in rates
    assert "kraken" not in rates
    assert "blockchain.info" not in rates
    assert "coindesk" not in rates
    assert "binance" not in rates

    assert "my-coingecko" in rates
    assert "my-kraken" in rates

    assert rates["my-coingecko"] > 0
    assert rates["my-kraken"] > 0

    rates = [
        rates["my-coingecko"],
        rates["my-kraken"],
    ]
    rates.sort()

    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    assert "msat" in convert
    assert convert["msat"] > 0
    assert convert["msat"] in median_conversion(100, rateslist)

    assert int(l1.rpc.currencyrate("USD")['rate']) in median_rate(rateslist)


def test_no_sources(node_factory):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
    }
    l1 = node_factory.get_node(options=opts)

    with pytest.raises(
        RpcError,
        match="Unknown command 'listcurrencyrates'",
    ):
        rates = l1.rpc.call("listcurrencyrates", ["USD"])
        LOGGER.info(rates)


def test_invalid_currency(node_factory):
    opts = {}
    l1 = node_factory.get_node(options=opts)

    with pytest.raises(
        RpcError,
        match=r"no results for `XXX`, is the currency supported\? Check the logs!",
    ):
        rates = l1.rpc.call("listcurrencyrates", ["XXX"])
        LOGGER.info(rates)

    l1.daemon.wait_for_logs(["failed to get `XXX` rate from bitstamp",
                             "failed to get `XXX` rate from coinbase",
                             "failed to get `XXX` rate from coingecko",
                             "failed to get `XXX` rate from kraken",
                             "failed to get `XXX` rate from blockchain.info",
                             "failed to get `XXX` rate from coindesk",
                             "failed to get `XXX` rate from binance"])


class _ServerThread(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self._server = make_server("127.0.0.1", 0, app)
        self.port = self._server.server_port

    def run(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()


@pytest.fixture
def fake_rateserver():
    app = Flask(__name__)
    state = {
        "fast": 100_000_000,
        "slow": 50_000_000,
        "slow_delay": 1,
    }

    @app.get("/fast")
    def fast():
        return jsonify({"price": state["fast"]})

    @app.get("/slow")
    def slow():
        time.sleep(state["slow_delay"])
        return jsonify({"price": state["slow"]})

    srv = _ServerThread(app)
    srv.start()
    try:
        yield {
            "url": f"http://127.0.0.1:{srv.port}",
            "state": state,
        }
    finally:
        srv.shutdown()
        srv.join()


def test_cached_median(node_factory, fake_rateserver):
    """This should use the median of available sources"""
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
    }
    l1 = node_factory.get_node(options=opts)

    rateslist = l1.rpc.call("listcurrencyrates", ["USD"])['currencyrates']
    LOGGER.info(rateslist)
    rates = {entry["source"]: entry["amount"] for entry in rateslist}

    assert "fast" in rates
    assert "slow" in rates

    assert rates["fast"] == fake_rateserver["state"]["fast"]
    assert rates["slow"] == fake_rateserver["state"]["slow"]

    # Cached result should be median of two rates.
    median_rate = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2
    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    # Median of raw rates is used.
    assert convert["msat"] == 100 * 100_000_000_000 // median_rate


def test_bkpr_listaccountevents_currencyrate(node_factory, fake_rateserver):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
        "bkpr-currency": "USD",
    }
    l1, l2 = node_factory.line_graph(2, opts=opts)

    inv = l2.rpc.invoice(100000, "test-bkpr-currency", "desc")
    l1.rpc.xpay(inv["bolt11"])
    # We want this event in the list, so wait until it's totally closed.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    events = l1.rpc.bkpr_listaccountevents()["events"]
    median_rate = (100_000_000 + 50_000_000) / 2
    for e in events:
        assert e["currencyrate"] == median_rate


def test_bkpr_listaccountevents_realtime(node_factory, fake_rateserver):
    """Make sure we don't wait for bkpr command to look up rates!"""
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
        "bkpr-currency": "USD",
    }
    l1, l2 = node_factory.line_graph(2, opts=opts)

    old_median = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    inv = l2.rpc.invoice(100000, "test_bkpr_listaccountevents_realtime", "desc")
    l1.rpc.xpay(inv["bolt11"])
    # We want this event in the list, so wait until it's totally closed.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # We could put a log msg inside bookkeeper, but that's spammy.
    time.sleep(10)

    # Change rates.  But old ones should be used!
    fake_rateserver["state"]["fast"] = 200_000_000
    fake_rateserver["state"]["slow"] = 150_000_000

    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert events
    for e in events:
        assert e["currencyrate"] == old_median


def test_bkpr_currency_dynamic(node_factory, fake_rateserver):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
    }
    l1, l2 = node_factory.line_graph(2, opts=opts)

    median_rate = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    inv1 = l2.rpc.invoice(100000, "test_bkpr_currency_dynamic_1", "desc")
    l1.rpc.xpay(inv1["bolt11"])
    # We want this event in the list, so wait until it's totally closed.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # No bookkeeker-currency, no currencyrate
    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert events
    assert all("currencyrate" not in e for e in events)
    num_events_1 = len(events)

    time.sleep(1)

    l1.rpc.setconfig("bkpr-currency", "USD")

    inv2 = l2.rpc.invoice(100000, "test_bkpr_currency_dynamic_2", "desc")
    l1.rpc.xpay(inv2["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert len(events) > num_events_1

    old_events = events[:num_events_1]
    new_events = events[num_events_1:]

    assert all("currencyrate" not in e for e in old_events)
    assert all(e["currencyrate"] == median_rate for e in new_events)

    # Disables all currency conversions.
    l1.rpc.setconfig("bkpr-currency", "")

    inv3 = l2.rpc.invoice(100000, "test_bkpr_currency_dynamic_3", "desc")
    l1.rpc.xpay(inv3["bolt11"])
    # If we don't wait here, we can get a spurious error from
    # cln-currencyrate as fixture gets torn down!
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert events
    assert all("currencyrate" not in e for e in events)


def test_bkpr_currencyrate_persisted(node_factory, fake_rateserver):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
        "bkpr-currency": "USD",
        'may_reconnect': True,
    }
    l1, l2 = node_factory.line_graph(2, opts=opts)

    old_median = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    inv = l2.rpc.invoice(100000, "test_bkpr_currencyrate_persisted", "desc")
    l1.rpc.xpay(inv["bolt11"])
    # Make sure it's fully resolved so we get all events now.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])

    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert events
    for e in events:
        assert e["currencyrate"] == old_median

    l1.restart()
    l1.connect(l2)

    fake_rateserver["state"]["fast"] = 200_000_000
    fake_rateserver["state"]["slow"] = 150_000_000
    new_median = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    new_events = l1.rpc.bkpr_listaccountevents()["events"]
    assert new_events == events

    # And we can add more.
    inv2 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_persisted2", "desc")
    l1.rpc.xpay(inv2["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])

    new_events = l1.rpc.bkpr_listaccountevents()["events"]
    assert new_events[:len(events)] == events
    assert new_events[len(events):]

    for e in new_events[len(events):]:
        assert e["currencyrate"] == new_median

    # Underlying datastore check: they should all be human readable timestamp->rate.
    stored_rates = {}
    for r in l1.rpc.listdatastore(['bookkeeper', 'currencyrate', 'USD'])['datastore']:
        start = int(r['key'][3])
        raw_rate, duration = r['string'].split(':')
        raw_rate = int(raw_rate)
        duration = int(duration)

        for t in range(start, start + duration):
            assert t not in stored_rates
            stored_rates[t] = raw_rate

    for e in new_events:
        assert e["currencyrate"] == stored_rates[e["timestamp"]] / 100


def test_bkpr_currencyrate_warns_for_old_events(node_factory, fake_rateserver):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
        'may_reconnect': True,
        'broken_log': "too old for current USD currencyrate",
    }
    l1, l2 = node_factory.line_graph(2, opts=opts)

    # 1. Create old events before bkpr-currency is enabled.
    inv1 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_warns_old_1", "desc")
    l1.rpc.xpay(inv1["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])
    events = l1.rpc.bkpr_listaccountevents()["events"]
    assert events
    assert all("currencyrate" not in e for e in events)
    time.sleep(61)

    # 2. Enable bkpr-currency. This historical backfill case should not warn (transient)
    l1.rpc.setconfig("bkpr-currency", "USD", True)

    # New events.
    inv2 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_warns_old_2", "desc")
    l1.rpc.xpay(inv2["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])

    # It does NOT complain about records before we set currency at all.
    new_events = l1.rpc.bkpr_listaccountevents()["events"][len(events):]
    assert new_events
    assert all("currencyrate" in e for e in new_events)
    assert not l1.daemon.is_in_log("too old for current USD currencyrate")

    # 3. Stop bookkeeper so new events will not be processed yet (not a dynamic plugin!)
    l1.daemon.opts['disable-plugin'] = "bookkeeper"
    l1.restart()
    l1.connect(l2)

    # 4. Create new events while bookkeeper is stopped, then let them go stale.
    inv3 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_warns_old_3", "desc")
    l1.rpc.xpay(inv3["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])
    time.sleep(61)

    # 5. Restart with bookkeeper (with currency)
    del l1.daemon.opts['disable-plugin']
    l1.daemon.opts['bkpr-currency'] = "USD"
    l1.restart()

    # 6. It should now complain about processing stale events with conversion enabled.
    # (Could be early in startup!)
    wait_for(lambda: l1.daemon.is_in_log("too old for current USD currencyrate"))


def test_bkpr_currencyrate_ranges(node_factory, fake_rateserver):
    opts = {
        "currencyrate-disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "currencyrate-add-source": [
            f"fast,{fake_rateserver['url']}/fast,price",
            f"slow,{fake_rateserver['url']}/slow,price",
        ],
        "bkpr-currency": "USD",
        'may_reconnect': True,
    }
    # This generates onchain events.
    l1, l2 = node_factory.line_graph(2, opts=opts)
    old_median = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    # This generates a channel event: be sure timestamp is different.
    time.sleep(1)

    inv1 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_ranges_1", "desc")
    l1.rpc.xpay(inv1["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])

    # Now we change the rate (and make sure time goes forward so it re-checks!)
    time.sleep(1)

    fake_rateserver["state"]["fast"] = 200_000_000
    fake_rateserver["state"]["slow"] = 150_000_000
    new_median = (fake_rateserver["state"]["fast"] + fake_rateserver["state"]["slow"]) / 2

    l1.restart()
    l1.connect(l2)

    inv2 = l2.rpc.invoice(100000, "test_bkpr_currencyrate_ranges_2", "desc")
    l1.rpc.xpay(inv2["bolt11"])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])

    # Calling this here makes sure it's finished processing currencyrates
    events = l1.rpc.bkpr_listaccountevents()
    rates = l1.rpc.listdatastore(['bookkeeper', 'currencyrate', 'USD'])['datastore']

    # Same-rate timestamps should be coalesced into one stored range.
    assert len(rates) == 2

    assert int(rates[0]['key'][3]) < int(rates[1]['key'][3])
    raw_rate, duration = rates[0]['string'].split(':')
    assert int(raw_rate) == int(old_median * 100)
    assert int(duration) >= 2

    raw_rate, duration = rates[1]['string'].split(':')
    assert int(raw_rate) == int(new_median * 100)
    assert int(duration) >= 1

    # We will load them fine on restart, too.
    l1.restart()
    assert l1.rpc.bkpr_listaccountevents() == events
