#!/usr/bin/python3
# This script exercises the c-lightning implementation

# Released by Rusty Russell under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/

import os
import shutil
import subprocess
import logging
import socket

from contextlib import closing
from typing import Any, Callable
from bitcoin.rpc import RawProxy
from .backend import Backend


class BitcoinProxy:
    """Wrapper for BitcoinProxy to reconnect.

    Long wait times between calls to the Bitcoin RPC could result in
    `bitcoind` closing the connection, so here we just create
    throwaway connections. This is easier than to reach into the RPC
    library to close, reopen and reauth upon failure.
    """

    def __init__(self, btc_conf_file: str, *args: Any, **kwargs: Any):
        self.btc_conf_file = btc_conf_file

    def __getattr__(self, name: str) -> Callable:
        if name.startswith("__") and name.endswith("__"):
            # Python internal stuff
            raise AttributeError

        def f(*args: Any) -> Callable:
            self.__proxy = RawProxy(btc_conf_file=self.btc_conf_file)

            logging.debug(
                "Calling {name} with arguments {args}".format(name=name, args=args)
            )
            res = self.__proxy._call(name, *args)
            logging.debug(
                "Result for {name} call: {res}".format(
                    name=name,
                    res=res,
                )
            )
            return res

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class Bitcoind(Backend):
    """Starts regtest bitcoind on an ephemeral port, and returns the RPC proxy"""

    def __init__(self, basedir: str):
        self.rpc = None
        self.proc = None
        self.base_dir = basedir
        logging.debug(f"Base dir is {basedir}")
        self.bitcoin_dir = os.path.join(basedir, "bitcoind")
        self.bitcoin_conf = os.path.join(self.bitcoin_dir, "bitcoin.conf")
        self.cmd_line = [
            "bitcoind",
            "-datadir={}".format(self.bitcoin_dir),
            "-server",
            "-regtest",
            "-logtimestamps",
            "-nolisten",
        ]
        self.btc_version = None

    def __reserve(self) -> int:
        """
        When python asks for a free port from the os, it is possible that
        with concurrent access, the port that is picked is a port that is not free
        anymore when we go to bind the daemon like bitcoind port.

        Source: https://stackoverflow.com/questions/1365265/on-localhost-how-do-i-pick-a-free-port-number
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def __init_bitcoin_conf(self):
        """Init the bitcoin core directory with all the necessary information
        to startup the node"""
        if not os.path.exists(self.bitcoin_dir):
            os.makedirs(self.bitcoin_dir)
            logging.debug(f"Creating {self.bitcoin_dir} directory")
        self.port = self.__reserve()
        logging.debug("Port is {}, dir is {}".format(self.port, self.bitcoin_dir))
        # For after 0.16.1 (eg. 3f398d7a17f136cd4a67998406ca41a124ae2966), this
        # needs its own [regtest] section.
        logging.debug(f"Writing bitcoin conf file at {self.bitcoin_conf}")
        with open(self.bitcoin_conf, "w") as f:
            f.write("regtest=1\n")
            f.write("rpcuser=rpcuser\n")
            f.write("rpcpassword=rpcpass\n")
            f.write("[regtest]\n")
            f.write("rpcport={}\n".format(self.port))
        self.rpc = BitcoinProxy(btc_conf_file=self.bitcoin_conf)

    def __version_compatibility(self) -> None:
        """
        This method tries to manage the compatibility between
        different versions of Bitcoin Core implementation.

        This method could sometimes be useful when it is necessary to
        run the test with a different version of Bitcoin core.
        """
        if self.rpc is None:
            # Sanity check
            raise ValueError("bitcoind not initialized")

        self.btc_version = self.rpc.getnetworkinfo()["version"]
        assert self.btc_version is not None
        logging.debug("Bitcoin Core version {}".format(self.btc_version))
        if self.btc_version >= 210000:
            # Maintains the compatibility between wallet
            # different ln implementation can use the main wallet (?)
            self.rpc.createwallet("main")  # Automatically loads

    def __is__bitcoind_ready(self) -> bool:
        """Check if bitcoind is ready during the execution"""
        if self.proc is None:
            # Sanity check
            raise ValueError("bitcoind not initialized")

        # Wait for it to startup.
        while b"Done loading" not in self.proc.stdout.readline():
            pass
        return True

    def start(self) -> None:
        if self.rpc is None:
            self.__init_bitcoin_conf()
        # TODO: We can move this to a single call and not use Popen
        self.proc = subprocess.Popen(self.cmd_line, stdout=subprocess.PIPE)
        assert self.proc.stdout

        # Wait for it to startup.
        while not self.__is__bitcoind_ready():
            logging.debug("Bitcoin core is loading")

        self.__version_compatibility()
        # Block #1.
        # Privkey the coinbase spends to:
        #    cUB4V7VCk6mX32981TWviQVLkj3pa2zBcXrjMZ9QwaZB5Kojhp59
        self.rpc.submitblock(
            "0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f84591a56720aabc8023cecf71801c5e0f9d049d0c550ab42412ad12a67d89f3a3dbb6c60ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0200f2052a0100000016001419f5016f07fe815f611df3a2a0802dbd74e634c40000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
        )
        self.rpc.generatetoaddress(100, self.rpc.getnewaddress())

    def stop(self) -> None:
        self.rpc.stop()
        self.proc.kill()
        shutil.rmtree(os.path.join(self.bitcoin_dir, "regtest"))

    def restart(self) -> None:
        # Only restart if we have to.
        if self.rpc.getblockcount() != 101 or self.rpc.getrawmempool() != []:
            self.stop()
            self.start()
