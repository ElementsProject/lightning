#!/usr/bin/python3
# This script exercises the c-lightning implementation

# Released by Rusty Russell under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/

import hashlib
import pyln.client
import pyln.proto.wire
import os
import subprocess
import lnprototest
import bitcoin.core
import struct
import shutil
import logging
import socket

from contextlib import closing
from datetime import date
from concurrent import futures
from lnprototest.backend import Bitcoind
from lnprototest import (
    Event,
    EventError,
    SpecFileError,
    KeySet,
    Conn,
    namespace,
    MustNotMsg,
)
from lnprototest import wait_for
from typing import Dict, Any, Callable, List, Optional, cast

TIMEOUT = int(os.getenv("TIMEOUT", "30"))
LIGHTNING_SRC = os.path.join(os.getcwd(), os.getenv("LIGHTNING_SRC", "../lightning/"))


class CLightningConn(lnprototest.Conn):
    def __init__(self, connprivkey: str, port: int):
        super().__init__(connprivkey)
        # FIXME: pyln.proto.wire should just use coincurve PrivateKey!
        self.connection = pyln.proto.wire.connect(
            pyln.proto.wire.PrivateKey(bytes.fromhex(self.connprivkey.to_hex())),
            # FIXME: Ask node for pubkey
            pyln.proto.wire.PublicKey(
                bytes.fromhex(
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                )
            ),
            "127.0.0.1",
            port,
        )


class Runner(lnprototest.Runner):
    def __init__(self, config: Any):
        super().__init__(config)
        self.running = False
        self.rpc = None
        self.bitcoind = None
        self.proc = None
        self.cleanup_callbacks: List[Callable[[], None]] = []
        self.fundchannel_future: Optional[Any] = None
        self.is_fundchannel_kill = False
        self.executor = futures.ThreadPoolExecutor(max_workers=20)

        self.startup_flags = []
        for flag in config.getoption("runner_args"):
            self.startup_flags.append("--{}".format(flag))

        opts = (
            subprocess.run(
                [
                    "{}/lightningd/lightningd".format(LIGHTNING_SRC),
                    "--list-features-only",
                ],
                stdout=subprocess.PIPE,
                check=True,
            )
            .stdout.decode("utf-8")
            .splitlines()
        )
        self.options: Dict[str, str] = {}
        for o in opts:
            if o.startswith("supports_"):
                self.options[o] = "true"
            else:
                k, v = o.split("/")
                self.options[k] = v

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

    def __init_sandbox_dir(self) -> None:
        """Create the tmp directory for lnprotest and lightningd"""
        self.lightning_dir = os.path.join(self.directory, "lightningd")
        if not os.path.exists(self.lightning_dir):
            os.makedirs(self.lightning_dir)

    def get_keyset(self) -> KeySet:
        return KeySet(
            revocation_base_secret="0000000000000000000000000000000000000000000000000000000000000011",
            payment_base_secret="0000000000000000000000000000000000000000000000000000000000000012",
            delayed_payment_base_secret="0000000000000000000000000000000000000000000000000000000000000013",
            htlc_base_secret="0000000000000000000000000000000000000000000000000000000000000014",
            shachain_seed="FF" * 32,
        )

    def get_node_privkey(self) -> str:
        return "01"

    def get_node_bitcoinkey(self) -> str:
        return "0000000000000000000000000000000000000000000000000000000000000010"

    def is_running(self) -> bool:
        return self.running

    def start(self, also_bitcoind: bool = True) -> None:
        self.logger.debug("[START]")
        self.__init_sandbox_dir()
        self.lightning_port = self.__reserve()
        if also_bitcoind:
            self.bitcoind = Bitcoind(self.directory)
            try:
                self.bitcoind.start()
            except Exception as ex:
                self.logger.debug(f"Exception with message {ex}")
            self.logger.debug("RUN Bitcoind")
        self.proc = subprocess.Popen(
            [
                "{}/lightningd/lightningd".format(LIGHTNING_SRC),
                "--lightning-dir={}".format(self.lightning_dir),
                "--funding-confirms=3",
                "--dev-force-privkey=0000000000000000000000000000000000000000000000000000000000000001",
                "--dev-force-bip32-seed=0000000000000000000000000000000000000000000000000000000000000001",
                "--dev-force-channel-secrets=0000000000000000000000000000000000000000000000000000000000000010/0000000000000000000000000000000000000000000000000000000000000011/0000000000000000000000000000000000000000000000000000000000000012/0000000000000000000000000000000000000000000000000000000000000013/0000000000000000000000000000000000000000000000000000000000000014/FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "--dev-bitcoind-poll=1",
                "--dev-fast-gossip",
                "--dev-no-htlc-timeout",
                "--bind-addr=127.0.0.1:{}".format(self.lightning_port),
                "--network=regtest",
                "--bitcoin-rpcuser=rpcuser",
                "--bitcoin-rpcpassword=rpcpass",
                "--bitcoin-rpcport={}".format(self.bitcoind.port),
                "--log-level=debug",
                "--log-file=log",
            ]
            + self.startup_flags
        )
        self.running = True
        self.rpc = pyln.client.LightningRpc(
            os.path.join(self.lightning_dir, "regtest", "lightning-rpc")
        )
        self.logger.debug("RUN c-lightning")

        def node_ready(rpc: pyln.client.LightningRpc) -> bool:
            try:
                rpc.getinfo()
                return True
            except Exception as ex:
                logging.debug(f"waiting for c-lightning: Exception received {ex}")
                return False

        wait_for(lambda: node_ready(self.rpc))
        logging.debug("Waited fro c-lightning")

        # Make sure that we see any funds that come to our wallet
        for i in range(5):
            self.rpc.newaddr()

    def shutdown(self, also_bitcoind: bool = True) -> None:
        for cb in self.cleanup_callbacks:
            cb()
        self.rpc.stop()
        if also_bitcoind:
            self.bitcoind.stop()

    def stop(self, print_logs: bool = False, also_bitcoind: bool = True) -> None:
        self.logger.debug("[STOP]")
        self.shutdown(also_bitcoind=also_bitcoind)
        self.running = False
        for c in self.conns.values():
            cast(CLightningConn, c).connection.connection.close()
        if print_logs:
            log_path = f"{self.lightning_dir}/regtest/log"
            with open(log_path) as log:
                self.logger.info("---------- c-lightning logging ----------------")
                self.logger.info(log.read())
                # now we make a backup of the log
                shutil.copy(
                    log_path,
                    f'/tmp/c-lightning-log_{date.today().strftime("%b-%d-%Y_%H:%M:%S")}',
                )
        shutil.rmtree(os.path.join(self.lightning_dir, "regtest"))

    def restart(self) -> None:
        self.logger.debug("[RESTART]")
        self.stop(also_bitcoind=False)
        # Make a clean start
        super().restart()
        self.bitcoind.restart()
        self.start(also_bitcoind=False)

    def kill_fundchannel(self) -> None:
        fut = self.fundchannel_future
        self.fundchannel_future = None
        self.is_fundchannel_kill = True
        if fut:
            try:
                fut.result(0)
            except (SpecFileError, futures.TimeoutError):
                pass

    def connect(self, event: Event, connprivkey: str) -> None:
        self.add_conn(CLightningConn(connprivkey, self.lightning_port))

    def getblockheight(self) -> int:
        return self.bitcoind.rpc.getblockcount()

    def trim_blocks(self, newheight: int) -> None:
        h = self.bitcoind.rpc.getblockhash(newheight + 1)
        self.bitcoind.rpc.invalidateblock(h)

    def add_blocks(self, event: Event, txs: List[str], n: int) -> None:
        for tx in txs:
            self.bitcoind.rpc.sendrawtransaction(tx)
        self.bitcoind.rpc.generatetoaddress(n, self.bitcoind.rpc.getnewaddress())

        wait_for(lambda: self.rpc.getinfo()["blockheight"] == self.getblockheight())

    def recv(self, event: Event, conn: Conn, outbuf: bytes) -> None:
        try:
            cast(CLightningConn, conn).connection.send_message(outbuf)
        except BrokenPipeError:
            # This happens when they've sent an error and closed; try
            # reading it to figure out what went wrong.
            fut = self.executor.submit(
                cast(CLightningConn, conn).connection.read_message
            )
            try:
                msg = fut.result(1)
            except futures.TimeoutError:
                msg = None
            if msg:
                raise EventError(
                    event, "Connection closed after sending {}".format(msg.hex())
                )
            else:
                raise EventError(event, "Connection closed")

    def fundchannel(
        self,
        event: Event,
        conn: Conn,
        amount: int,
        feerate: int = 253,
        expect_fail: bool = False,
    ) -> None:
        """
        event       - the event which cause this, for error logging
        conn        - which conn (i.e. peer) to fund.
        amount      - amount to fund the channel with
        feerate     - feerate, in kiloweights
        expect_fail - true if this command is expected to error/fail
        """
        # First, check that another fundchannel isn't already running
        if self.fundchannel_future:
            if not self.fundchannel_future.done():
                raise RuntimeError(
                    "{} called fundchannel while another channel funding (fundchannel/init_rbf) is still in process".format(
                        event
                    )
                )
            self.fundchannel_future = None

        def _fundchannel(
            runner: Runner,
            conn: Conn,
            amount: int,
            feerate: int,
            expect_fail: bool = False,
        ) -> str:
            peer_id = conn.pubkey.format().hex()
            # Need to supply feerate here, since regtest cannot estimate fees
            return runner.rpc.fundchannel(
                peer_id, amount, feerate="{}perkw".format(feerate)
            )

        def _done(fut: Any) -> None:
            exception = fut.exception(0)
            if exception and not self.is_fundchannel_kill and not expect_fail:
                raise exception
            self.fundchannel_future = None
            self.is_fundchannel_kill = False
            self.cleanup_callbacks.remove(self.kill_fundchannel)

        fut = self.executor.submit(
            _fundchannel, self, conn, amount, feerate, expect_fail
        )
        fut.add_done_callback(_done)
        self.fundchannel_future = fut
        self.cleanup_callbacks.append(self.kill_fundchannel)

    def init_rbf(
        self,
        event: Event,
        conn: Conn,
        channel_id: str,
        amount: int,
        utxo_txid: str,
        utxo_outnum: int,
        feerate: int,
    ) -> None:

        if self.fundchannel_future:
            self.kill_fundchannel()

        startweight = 42 + 172  # base weight, funding output
        # Build a utxo using the given utxo
        fmt_feerate = "{}perkw".format(feerate)
        utxos = ["{}:{}".format(utxo_txid, utxo_outnum)]
        initial_psbt = self.rpc.utxopsbt(
            amount,
            fmt_feerate,
            startweight,
            utxos,
            reservedok=True,
            min_witness_weight=110,
            locktime=0,
            excess_as_change=True,
        )["psbt"]

        def _run_rbf(runner: Runner, conn: Conn) -> Dict[str, Any]:
            bump = runner.rpc.openchannel_bump(
                channel_id, amount, initial_psbt, funding_feerate=fmt_feerate
            )
            update = runner.rpc.openchannel_update(channel_id, bump["psbt"])

            # Run until they're done sending us updates
            while not update["commitments_secured"]:
                update = runner.rpc.openchannel_update(channel_id, update["psbt"])
            signed_psbt = runner.rpc.signpsbt(update["psbt"])["signed_psbt"]
            return runner.rpc.openchannel_signed(channel_id, signed_psbt)

        def _done(fut: Any) -> None:
            exception = fut.exception(0)
            if exception:
                raise (exception)

        fut = self.executor.submit(_run_rbf, self, conn)
        fut.add_done_callback(_done)

    def invoice(self, event: Event, amount: int, preimage: str) -> None:
        self.rpc.invoice(
            msatoshi=amount,
            label=str(event),
            description="invoice from {}".format(event),
            preimage=preimage,
        )

    def accept_add_fund(self, event: Event) -> None:
        self.rpc.call(
            "funderupdate",
            {
                "policy": "match",
                "policy_mod": 100,
                "fuzz_percent": 0,
                "leases_only": False,
            },
        )

    def addhtlc(self, event: Event, conn: Conn, amount: int, preimage: str) -> None:
        payhash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        routestep = {
            "msatoshi": amount,
            "id": conn.pubkey.format().hex(),
            # We internally add one.
            "delay": 4,
            # We actually ignore this.
            "channel": "1x1x1",
        }
        self.rpc.sendpay([routestep], payhash)

    def get_output_message(
        self, conn: Conn, event: Event, timeout: int = TIMEOUT
    ) -> Optional[bytes]:
        fut = self.executor.submit(cast(CLightningConn, conn).connection.read_message)
        try:
            return fut.result(timeout)
        except (futures.TimeoutError, ValueError):
            return None

    def check_error(self, event: Event, conn: Conn) -> Optional[str]:
        # We get errors in form of err msgs, always.
        super().check_error(event, conn)
        msg = self.get_output_message(conn, event)
        if msg is None:
            return None
        return msg.hex()

    def check_final_error(
        self,
        event: Event,
        conn: Conn,
        expected: bool,
        must_not_events: List[MustNotMsg],
    ) -> None:
        if not expected:
            # Inject raw packet to ensure it hangs up *after* processing all previous ones.
            cast(CLightningConn, conn).connection.connection.send(bytes(18))

            while True:
                binmsg = self.get_output_message(conn, event)
                if binmsg is None:
                    break
                for e in must_not_events:
                    if e.matches(binmsg):
                        raise EventError(
                            event, "Got msg banned by {}: {}".format(e, binmsg.hex())
                        )

                # Don't assume it's a message type we know!
                msgtype = struct.unpack(">H", binmsg[:2])[0]
                if msgtype == namespace().get_msgtype("error").number:
                    raise EventError(event, "Got error msg: {}".format(binmsg.hex()))

        cast(CLightningConn, conn).connection.connection.close()

    def expect_tx(self, event: Event, txid: str) -> None:
        # Ah bitcoin endianness...
        revtxid = bitcoin.core.lx(txid).hex()

        # This txid should appear in the mempool.
        try:
            wait_for(lambda: revtxid in self.bitcoind.rpc.getrawmempool())
        except ValueError:
            raise EventError(
                event,
                "Did not broadcast the txid {}, just {}".format(
                    revtxid,
                    [
                        (txid, self.bitcoind.rpc.getrawtransaction(txid))
                        for txid in self.bitcoind.rpc.getrawmempool()
                    ],
                ),
            )

    def has_option(self, optname: str) -> Optional[str]:
        """Returns None if it doesn't support, otherwise 'even' or 'odd' (required or supported)"""
        if optname in self.options:
            return self.options[optname]
        return None

    def add_startup_flag(self, flag: str) -> None:
        if self.config.getoption("verbose"):
            print("[ADD STARTUP FLAG '{}']".format(flag))
        self.startup_flags.append("--{}".format(flag))

    def close_channel(self, channel_id: str) -> bool:
        if self.config.getoption("verbose"):
            print("[CLOSE CHANNEL '{}']".format(channel_id))
        try:
            self.rpc.close(peer_id=channel_id)
        except Exception as ex:
            print(ex)
            return False
        return True
