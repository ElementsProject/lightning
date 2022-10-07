import unittest
from util import *

MAX_SATOSHI = 21000000 * 100000000

TX_MAX_LEN = 1000
TX_MAX_VERSION = 2

TX_FAKE_HEX = utf8('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000')
TX_HEX = utf8('0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000')
TX_WITNESS_HEX = utf8('020000000001012f94ddd965758445be2dfac132c5e75c517edf5ea04b745a953d0bc04c32829901000000006aedc98002a8c500000000000022002009246bbe3beb48cf1f6f2954f90d648eb04d68570b797e104fead9e6c3c87fd40544020000000000160014c221cdfc1b867d82f19d761d4e09f3b6216d8a8304004830450221008aaa56e4f0efa1f7b7ed690944ac1b59f046a59306fcd1d09924936bd500046d02202b22e13a2ad7e16a0390d726c56dfc9f07647f7abcfac651e35e5dc9d830fc8a01483045022100e096ad0acdc9e8261d1cdad973f7f234ee84a6ee68e0b89ff0c1370896e63fe102202ec36d7554d1feac8bc297279f89830da98953664b73d38767e81ee0763b9988014752210390134e68561872313ba59e56700732483f4a43c2de24559cb8c7039f25f7faf821039eb59b267a78f1020f27a83dc5e3b1e4157e4a517774040a196e9f43f08ad17d52ae89a3b720')

class TransactionTests(unittest.TestCase):

    def tx_deserialize_hex(self, hex_):
        tx_p = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_from_hex(hex_, 0x0, tx_p))
        return tx_p[0]

    def tx_serialize_hex(self, tx):
        ret, hex_ = wally_tx_to_hex(tx, 0x1)
        self.assertEqual(ret, WALLY_OK)
        return hex_

    def test_serialization(self):
        """Testing serialization and deserialization"""
        tx_out = pointer(wally_tx())
        tx_copy = pointer(wally_tx())

        # Invalid arguments
        for args in [
            (None, 0, tx_out), # Null hex
            (utf8(''), 0, tx_out), # Empty hex
            (utf8('00'*5), 0, tx_out), # Short hex
            (TX_FAKE_HEX, 0, None), # Empty output
            (TX_FAKE_HEX, 16, tx_out), # Unsupported flag
            (TX_WITNESS_HEX[:11]+utf8('0')+TX_WITNESS_HEX[12:], 0, tx_out), # Invalid witness flag
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_from_hex(*args))

        # No-input/no-output transactions
        for tx_hex in [
             TX_FAKE_HEX[:9]+utf8('0')+TX_FAKE_HEX[92:],   # No inputs
             TX_FAKE_HEX[:93]+utf8('0')+TX_FAKE_HEX[112:], # No outputs
            ]:
            self.assertEqual(WALLY_OK, wally_tx_from_hex(tx_hex, 0, tx_out))
            # Partial transactions cannot be dumped by default
            self.assertEqual(WALLY_EINVAL, wally_tx_to_hex(tx_out, 0)[0])
            # Check the partial transaction can be cloned
            self.assertEqual(WALLY_OK, wally_tx_clone_alloc(tx_out, 0, tx_copy))
            if tx_out.contents.num_inputs != 0:
                # Partial txs with inputs can be dumped with ALLOW_PARTIAL:0x4
                ret, hex_ = wally_tx_to_hex(tx_out, 0x1|0x4)
                self.assertEqual(WALLY_OK, ret)
                self.assertEqual(tx_hex, utf8(hex_))

        # Valid transactions
        for tx_hex in [ TX_HEX,
                        utf8('00')+TX_HEX[2:],
                        utf8('ff')+TX_FAKE_HEX[2:],
                        TX_FAKE_HEX,
                        TX_WITNESS_HEX ]:
            self.assertEqual(WALLY_OK, wally_tx_from_hex(tx_hex, 0 ,tx_out))
            hex_ = utf8(self.tx_serialize_hex(tx_out))
            self.assertEqual(tx_hex, hex_)
            # Check the transaction can be cloned and serializes to the same hex
            self.assertEqual(WALLY_OK, wally_tx_clone_alloc(tx_out, 0, tx_copy))
            self.assertEqual(hex_, utf8(self.tx_serialize_hex(tx_copy)))
            # Check that the txid can be computed
            txid, txid_len = make_cbuffer('00' * 32)
            self.assertEqual(WALLY_OK, wally_tx_get_txid(tx_out, txid, txid_len))

    def test_lengths(self):
        """Testing functions measuring different lengths for a tx"""
        for tx_hex, length in [
            (TX_FAKE_HEX, 60),
            (TX_HEX, 224),
            (TX_WITNESS_HEX, 125),
            ]:
            tx = self.tx_deserialize_hex(tx_hex)
            length_with_witness = len(tx_hex) // 2
            witness_len = length_with_witness - length
            weight = witness_len + length * 4
            vsize = (weight + 3) // 4
            self.assertEqual((WALLY_OK, length), wally_tx_get_length(byref(tx), 0))
            self.assertEqual((WALLY_OK, length_with_witness), wally_tx_get_length(byref(tx), 1))
            self.assertEqual((WALLY_EINVAL, 0), wally_tx_get_length(byref(tx), 16)) # Unsupported flag
            self.assertEqual((WALLY_OK, weight), wally_tx_get_weight(byref(tx)))
            self.assertEqual((WALLY_OK, vsize), wally_tx_get_vsize(byref(tx)))
            self.assertEqual((WALLY_OK, vsize), wally_tx_vsize_from_weight(weight))
            if witness_len > 0:
                ret, count = wally_tx_get_witness_count(byref(tx))
                self.assertEqual(WALLY_OK, ret)
                self.assertTrue(count > 0)

    def test_outputs(self):
        """Testing functions manipulating outputs"""
        # Add
        script, script_len = make_cbuffer('00')
        for args in [
            (None, 1, script, script_len, 0), # Invalid tx
            (wally_tx(), -1, script, script_len, 0), # Invalid amount
            (wally_tx(), MAX_SATOSHI+1, script, script_len, 0), # Invalid amount
            (self.tx_deserialize_hex(TX_HEX), MAX_SATOSHI, script, script_len, 0), # Invalid total amount
            (wally_tx(), 1, None, script_len, 0), # Empty script
            (wally_tx(), 1, script, 0, 0), # Invalid script length
            (wally_tx(), 1, script, script_len, 1), # Invalid flag
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_add_raw_output(*args))
            # Testing only wally_tx_add_raw_output, because it calls wally_tx_add_output and
            # wally_tx_get_total_output_satoshi

        # Remove
        for args in [
            (None, 0), # Invalid tx
            (wally_tx(), 0), # Remove from empty tx
            (self.tx_deserialize_hex(TX_FAKE_HEX), 1), # Invalid index
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_remove_output(*args))

        # Add and remove inputs and outputs, test that serialization remains the same
        script2, script2_len = make_cbuffer('77' * 16)
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        self.assertEqual(WALLY_OK, wally_tx_add_raw_output(tx, 55, script2, script2_len, 0))
        before_hex = self.tx_serialize_hex(tx)
        num_outputs = tx.num_outputs

        def remove_and_test(idx):
            self.assertNotEqual(before_hex, self.tx_serialize_hex(tx))
            self.assertEqual(WALLY_OK, wally_tx_remove_output(tx, idx))
            self.assertEqual(before_hex, self.tx_serialize_hex(tx))

        self.assertEqual(WALLY_OK, wally_tx_add_raw_output(tx, 1, script, script_len, 0))
        remove_and_test(num_outputs)
        for idx in range(0, num_outputs + 1):
            ret = wally_tx_add_raw_output_at(tx, idx, 1, script, script_len, 0)
            self.assertEqual(ret, WALLY_OK)
            remove_and_test(idx)

        ret = wally_tx_add_raw_output_at(tx, num_outputs + 1, 1, script, script_len, 0)
        self.assertEqual(ret, WALLY_EINVAL) # Invalid index

    def test_inputs(self):
        """Testing functions manipulating inputs"""
        # Add
        txhash, txhash_len = make_cbuffer('00'*32)
        script, script_len = make_cbuffer('00')
        for args in [
            (None, txhash, txhash_len, 0, 0xffffffff, script, script_len, None, 0), # Empty tx
            (wally_tx(), None, txhash_len, 0, 0xffffffff, script, script_len, None, 0), # Empty hash
            (wally_tx(), txhash, txhash_len-1, 0, 0xffffffff, script, script_len, None, 0), # Invalid hash length
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, None, script_len, None, 0), # Empty script
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, script, 0, None, 0), # Invalid script length
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, script, script_len, None, 1), # Unsupported flags
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_add_raw_input(*args))
            # Testing only wally_tx_add_raw_input, because it calls wally_tx_add_input

        # Remove
        for args in [
            (None, 0), # Invalid tx
            (wally_tx(), 0), # Remove from empty tx
            (self.tx_deserialize_hex(TX_FAKE_HEX), 1), # Invalid index
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_remove_input(*args))

        # Add and then remove, then test that serialization remains the same
        wit = wally_tx_witness_stack()
        for args, expected in [
            ((self.tx_deserialize_hex(TX_FAKE_HEX), txhash, txhash_len, 0, 0xffffffff, script, script_len, wit, 0),
             None),
            ((self.tx_deserialize_hex(TX_WITNESS_HEX), txhash, txhash_len, 0, 0xffffffff, script, script_len, wit, 0),
             TX_WITNESS_HEX[:13]+utf8('2')+TX_WITNESS_HEX[14:96]+utf8('00'*36)+utf8('0100ffffffff')+TX_WITNESS_HEX[96:-8]+utf8('00')+TX_WITNESS_HEX[-8:]),
            ]:
            before = self.tx_serialize_hex(args[0])
            self.assertEqual(WALLY_OK, wally_tx_add_raw_input(*args))
            if expected:
                self.assertEqual(utf8(self.tx_serialize_hex(args[0])), expected)
            self.assertEqual(WALLY_OK, wally_tx_remove_input(byref(args[0]), args[0].num_inputs-1))
            self.assertEqual(before, self.tx_serialize_hex(args[0]))

        script2, script2_len = make_cbuffer('77' * 16)
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        ret = wally_tx_add_raw_input(tx, txhash, txhash_len, 1, 0xfffffffe, script2, script2_len, wit, 0)
        self.assertEqual(ret, WALLY_OK)
        before_hex = self.tx_serialize_hex(tx)
        num_inputs = tx.num_inputs

        def remove_and_test(idx):
            self.assertNotEqual(before_hex, self.tx_serialize_hex(tx))
            self.assertEqual(WALLY_OK, wally_tx_remove_input(tx, idx))
            self.assertEqual(before_hex, self.tx_serialize_hex(tx))

        for idx in range(0, num_inputs + 1):
            ret = wally_tx_add_raw_input_at(tx, idx, txhash, txhash_len,
                                            2, 0xfffffffd, script, script_len, wit, 0)
            self.assertEqual(ret, WALLY_OK)
            remove_and_test(idx)

        ret = wally_tx_add_raw_input_at(tx, num_inputs + 1, txhash, txhash_len,
                                        2, 0xfffffffd, script, script_len, wit, 0)
        self.assertEqual(ret, WALLY_EINVAL) # Invalid index


    def test_witness(self):
        """Testing functions manipulating witness"""
        witness, witness_len = make_cbuffer('00')
        for args in [
            (None, witness, witness_len), # Empty stack
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_witness_stack_add(*args))
            # Testing only wally_tx_witness_stack_add, because it calls wally_tx_witness_stack_set

        for args in [
            (wally_tx_witness_stack(), witness, witness_len),
            ]:
            self.assertEqual(WALLY_OK, wally_tx_witness_stack_add(*args))
            # To test the expected stack, it should be included in serialized transaction

    def test_get_signature_hash(self):
        """Testing function to get the signature hash"""
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        script, script_len = make_cbuffer('00')
        out, out_len = make_cbuffer('00'*32)
        for args in [
            (None, 0, script, script_len, 1, 1, 0, out, out_len), # Empty tx
            (tx, 0, None, script_len, 1, 1, 0, out, out_len), # Empty script
            (tx, 0, script, 0, 1, 1, 0, out, out_len), # Invalid script length
            (tx, 0, script, script_len, MAX_SATOSHI+1, 1, 1, out, out_len), # Invalid amount (only with segwit)
            (tx, 0, script, script_len, 1, 0x100, 0, out, out_len), # Invalid sighash
            (tx, 0, script, script_len, 1, 1, 16, out, out_len), # Invalid flags
            (tx, 0, script, script_len, 1, 1, 0, None, out_len), # Empty bytes
            (tx, 0, script, script_len, 1, 1, 0, out, 31), # Short len
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_get_btc_signature_hash(*args))

        def sha256d(hex_):
            bin_input, bin_input_len = make_cbuffer(hex_)
            buf, buf_len = make_cbuffer('00'*32)
            self.assertEqual(WALLY_OK, wally_sha256d(bin_input, bin_input_len, buf, buf_len))
            return h(buf)

        script, script_len = make_cbuffer('00')
        out, out_len = make_cbuffer('00'*32)
        for args, expected in [
            ((tx, 0, script, script_len, 1, 1, 0, out, out_len),
             utf8('1bcf681d585c3cbbc64b30a69e60b721fc0aacc57132dfbe43af6df8f4797a80')),
           ((tx, 1, script, script_len, 1, 1, 0, out, out_len),
            utf8('01'+'00'*31)),
           ((tx, 0, script, script_len, 1, 0, 0, out, out_len),
            utf8('882630e74173c928fc18236b99e25ffd15643faabc65c010e9ca27b8db29278a')),
           ((tx, 0, script, script_len, 1, 1, 1, out, out_len),
            utf8('5dad88b42332e3559950b325bba69eedb64b9330e55585fc1098964572f9c45d')),
           ((tx, 0, script, script_len, 0, 1, 1, out, out_len),
            utf8('bb30f5feed35b2591eedd8e778d507236a756e8c2eff8cf72ef0afa83abdea31')),
            ]:
            self.assertEqual(WALLY_OK, wally_tx_get_btc_signature_hash(*args))
            self.assertEqual(expected, h(out[:out_len]))


if __name__ == '__main__':
    unittest.main()

