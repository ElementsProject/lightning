import logging
import pytest
import threading
import time
from pyln.client import RpcError
from fixtures import *  # noqa: F401,F403
from flask import Flask, jsonify
from werkzeug.serving import make_server


LOGGER = logging.getLogger(__name__)


def test_apis_batch1(node_factory):
    opts = {
        "currencyrate-disable-source": ["bitstamp", "coinbase"],
    }
    l1 = node_factory.get_node(options=opts)

    rates = l1.rpc.call("currencyrates", ["USD"])
    LOGGER.info(rates)

    assert "bitstamp" not in rates
    assert "coinbase" not in rates

    assert "coingecko" in rates
    assert "kraken" in rates
    assert "blockchain.info" in rates
    assert "coindesk" in rates
    assert "binance" in rates

    assert rates["coingecko"] > 0
    assert rates["kraken"] > 0
    assert rates["blockchain.info"] > 0
    assert rates["coindesk"] > 0
    assert rates["binance"] > 0

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

    assert convert["msat"] >= (rates[0] - 1) * 100
    assert convert["msat"] <= (rates[len(rates) - 1] + 1) * 100


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

    rates = l1.rpc.call("currencyrates", ["USD"])
    LOGGER.info(rates)

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

    assert convert["msat"] >= (rates[0] - 1) * 100
    assert convert["msat"] <= (rates[len(rates) - 1] + 1) * 100


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

    rates = l1.rpc.call("currencyrates", ["USD"])
    LOGGER.info(rates)

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

    assert convert["msat"] >= (rates[0] - 1) * 100
    assert convert["msat"] <= (rates[len(rates) - 1] + 1) * 100


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
        match="Unknown command 'currencyrates'",
    ):
        rates = l1.rpc.call("currencyrates", ["USD"])
        LOGGER.info(rates)


def test_invalid_currency(node_factory):
    opts = {}
    l1 = node_factory.get_node(options=opts)

    needle = l1.daemon.logsearch_start

    with pytest.raises(
        RpcError,
        match=r"no results for `XXX`, is the currency supported\? Check the logs!",
    ):
        rates = l1.rpc.call("currencyrates", ["XXX"])
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

    rates = l1.rpc.call("currencyrates", ["USD"])
    LOGGER.info(rates)

    assert "fast" in rates
    assert "slow" in rates

    assert rates["fast"] == 1000
    assert rates["slow"] == 2000

    # With two fresh cached rates, the correct median is midpoint(1000, 2000) = 1500.
    # For 100 USD, that should be 150000 msat.
    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    assert convert["msat"] == 150000
