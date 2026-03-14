import logging
import pytest
import threading
import time
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

    needle = l1.daemon.logsearch_start

    with pytest.raises(
        RpcError,
        match=r"no results for `XXX`, is the currency supported\? Check the logs!",
    ):
        rates = l1.rpc.call("listcurrencyrates", ["XXX"])
        LOGGER.info(rates)

    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from bitstamp")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from coinbase")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from coingecko")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from kraken")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from blockchain.info")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from coindesk")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("failed to get `XXX` rate from binance")


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

    @app.get("/fast")
    def fast():
        # 1e11 / 100_000_000 = 1000 msat per USD
        return jsonify({"price": 100_000_000})

    @app.get("/slow")
    def slow():
        # Make this complete later, so it becomes latest_fresh_price().
        time.sleep(1)
        # 1e11 / 50_000_000 = 2000 msat per USD
        return jsonify({"price": 50_000_000})

    srv = _ServerThread(app)
    srv.start()
    try:
        yield f"http://127.0.0.1:{srv.port}"
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
            f"fast,{fake_rateserver}/fast,price",
            f"slow,{fake_rateserver}/slow,price",
        ],
    }
    l1 = node_factory.get_node(options=opts)

    rateslist = l1.rpc.call("listcurrencyrates", ["USD"])['currencyrates']
    LOGGER.info(rateslist)
    rates = {entry["source"]: entry["amount"] for entry in rateslist}

    assert "fast" in rates
    assert "slow" in rates

    assert rates["fast"] == 100_000_000
    assert rates["slow"] == 50_000_000

    # Cached result should be median of two rates.
    median_rate = (100_000_000 + 50_000_000) / 2
    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    # Median of raw rates is used.
    assert convert["msat"] == 100 * 100_000_000_000 // median_rate
