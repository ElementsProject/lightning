"""Tests for reconciling pycoin and wally transaction signature hashes"""
import unittest
from wallycore import *
try:
    from pycoin.tx.Tx import Tx, TxIn, TxOut
    from pycoin.encoding import to_bytes_32
    have_pycoin = True
except ImportError:
    have_pycoin = False

USE_WITNESS = 1

class TxTests(unittest.TestCase):

    def do_test_tx(self, sighash, index_, flags):
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'\x51', b'000000'
        out_script, spend_script, locktime = b'\x00\x00\x51', b'\x00\x51', 999999
        txs_in = [TxIn(txhash, 0, script, seq),
                  TxIn(txhash, 1, script+b'\x51', seq-1),
                  TxIn(txhash, 2, script+b'\x51\x51', seq-2),
                  TxIn(txhash, 3, script+b'\x51\x51\x51', seq-3)]
        txs_out = [TxOut(55, out_script),
                   TxOut(54, out_script+b'\x51'),
                   TxOut(53, out_script+b'\x51\x51')]
        pytx = Tx(2, txs_in, txs_out, lock_time=locktime)
        pytx.unspents = {0: TxOut(5000, spend_script), # FIXME: Make script unique
                         1: TxOut(5001, spend_script),
                         2: TxOut(5002, spend_script),
                         3: TxOut(5003, spend_script)}
        unspent = pytx.unspents[index_]
        pytx_hex = pytx.as_hex()
        if flags & USE_WITNESS:
            pytx_hash = pytx.signature_for_hash_type_segwit(unspent.script, index_, sighash)
        else:
            pytx_hash = pytx.signature_hash(spend_script, index_, sighash)
        pytx_hash = hex_from_bytes(to_bytes_32(pytx_hash))

        tx = tx_init(2, locktime, 3, 3)
        tx_add_input(tx, tx_input_init(txhash, 0, seq, script, None))
        tx_add_raw_input(tx, txhash, 1, seq-1, script+b'\x51', None, 0)
        tx_add_raw_input(tx, txhash, 2, seq-2, script+b'\x51\x51', None, 0)
        tx_add_raw_input(tx, txhash, 3, seq-3, script+b'\x51\x51\x51', None, 0)
        tx_add_raw_output(tx, 55, out_script, 0)
        tx_add_raw_output(tx, 54, out_script+b'\x51', 0)
        tx_add_raw_output(tx, 53, out_script+b'\x51\x51', 0)
        tx_hex = tx_to_hex(tx, 0)
        amount = (index_ + 1) * 5000
        tx_hash = tx_get_btc_signature_hash(tx, index_,
                                            unspent.script, unspent.coin_value,
                                            sighash, flags)
        tx_hash = hex_from_bytes(tx_hash)

        self.assertEqual(pytx_hex, tx_hex)
        self.assertEqual(pytx_hash, tx_hash)

    def test_tx(self):
        for sighash in [WALLY_SIGHASH_ALL, WALLY_SIGHASH_NONE, WALLY_SIGHASH_SINGLE]:
            for index_ in [0, 1, 2, 3]:
                for anyonecanpay in [0, WALLY_SIGHASH_ANYONECANPAY]:
                    for flags in [0, USE_WITNESS]:
                        self.do_test_tx(sighash | anyonecanpay, index_, flags)


if __name__ == '__main__':
    if have_pycoin:
        unittest.main()
