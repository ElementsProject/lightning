from utils import BitcoinD, LightningD, LightningRpc, LightningNode

import logging
import os
import pytest
import sys
import time

if os.getenv("TEST_DEBUG", None) != None:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

@pytest.fixture(scope="module")
def bitcoind():
    bitcoind = BitcoinD(rpcport=28332)
    bitcoind.start()
    yield bitcoind
    bitcoind.stop()

def create_node(bitcoind, node_id):
    lightning_dir = "/tmp/lightning-{}/".format(node_id)
    l = LightningNode(
        LightningD(lightning_dir, bitcoind.bitcoin_dir, port=16330+node_id),
        LightningRpc(os.path.join(lightning_dir, "lightning-rpc").format(node_id))
    )
    l.daemon.start()
    l.rpc.connect_rpc()
    return l


@pytest.fixture(scope="function")
def l1(bitcoind):
    l = create_node(bitcoind, 1)
    yield l
    l.daemon.stop()


@pytest.fixture(scope="function")
def l2(bitcoind):
    l = create_node(bitcoind, 2)
    yield l
    l.daemon.stop()


@pytest.fixture(scope="function")
def l3(bitcoind):
    l = create_node(bitcoind, 3)
    yield l
    l.daemon.stop()

    
def test_connect(bitcoind, l1, l2):
    print(l1.rpc.getinfo())
    #print(l2.rpc.getinfo())
    print(bitcoind.rpc.getinfo())

def test_2(l1, l2, l3):
    print(l1.rpc.getinfo())
    print(l2.rpc.getinfo())
    print(l3.rpc.getinfo())
