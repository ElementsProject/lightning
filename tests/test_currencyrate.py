import logging
import pytest
from pyln.client import RpcError
from fixtures import *  # noqa: F401,F403


LOGGER = logging.getLogger(__name__)


def test_apis_batch1(node_factory):
    opts = {
        "disable-source": ["bitstamp", "coinbase"],
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

    l1.daemon.wait_for_log("Using cached rates for USD")

    assert "msat" in convert
    assert convert["msat"] > 0

    assert convert["msat"] == pytest.approx(rates[int(len(rates) / 2)] * 100, abs=100)


def test_apis_batch2(node_factory):
    opts = {
        "disable-source": [
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

    median_rate = int((rates["bitstamp"] + rates["coinbase"]) / 2)

    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    l1.daemon.wait_for_log("Using cached rates for USD")

    assert "msat" in convert
    assert convert["msat"] > 0

    assert convert["msat"] == pytest.approx(median_rate * 100, abs=100)


def test_custom_source(node_factory):
    opts = {
        "disable-source": [
            "bitstamp",
            "coinbase",
            "coingecko",
            "kraken",
            "blockchain.info",
            "coindesk",
            "binance",
        ],
        "add-source": [
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

    median_rate = int((rates["my-coingecko"] + rates["my-kraken"]) / 2)

    convert = l1.rpc.call("currencyconvert", [100, "USD"])
    LOGGER.info(convert)

    l1.daemon.wait_for_log("Using cached rates for USD")

    assert "msat" in convert
    assert convert["msat"] > 0

    assert convert["msat"] == pytest.approx(median_rate * 100, abs=100)


def test_no_sources(node_factory):
    opts = {
        "disable-source": [
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
        RpcError, match="No sources configured or all failed, check the logs."
    ):
        rates = l1.rpc.call("currencyrates", ["USD"])
        LOGGER.info(rates)


def test_invalid_currency(node_factory):
    opts = {}
    l1 = node_factory.get_node(options=opts)

    needle = l1.daemon.logsearch_start

    with pytest.raises(
        RpcError, match="No sources configured or all failed, check the logs."
    ):
        rates = l1.rpc.call("currencyrates", ["XXX"])
        LOGGER.info(rates)

    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from bitstamp")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from coinbase")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from coingecko")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from kraken")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from blockchain.info")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from coindesk")
    l1.daemon.logsearch_start = needle
    l1.daemon.wait_for_log("Error fetching from binance")
