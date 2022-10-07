"""Tests for transaction construction"""
import unittest
from wallycore import *

FLAG_USE_WITNESS = 1

class TxTests(unittest.TestCase):

    def test_tx_witness(self):
        witness_script = b'000000'
        witness = tx_witness_stack_init(5)
        tx_witness_stack_set(witness, 0, witness_script)
        for i in range(8):
            tx_witness_stack_add(witness, witness_script)
        tx_witness_stack_set(witness, 0, None)

        witness = tx_witness_stack_init(0)
        tx_witness_stack_set(witness, 0, witness_script)

        with self.assertRaises(ValueError):
            tx_witness_stack_clone(None)
        cloned = tx_witness_stack_clone(witness)

    def test_tx_input(self):
        # Test invalid inputs
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        with self.assertRaises(ValueError):
            tx_input_init(None, 0, seq, script, witness) # Null txhash
        with self.assertRaises(ValueError):
            tx_input_init(bytes(), 0, seq, script, witness) # Empty txhash

        # Create a valid input
        tx_input = tx_input_init(txhash, 0, seq, script, witness)
        self.assertEqual(tx_input_get_txhash(tx_input), txhash)
        self.assertEqual(tx_input_get_index(tx_input), 0)
        self.assertEqual(tx_input_get_sequence(tx_input), seq)
        self.assertEqual(tx_input_get_script_len(tx_input), len(script))
        self.assertEqual(tx_input_get_script(tx_input), script)
        self.assertEqual(tx_input_get_witness_len(tx_input, 0), len(witness_script))
        self.assertEqual(tx_input_get_witness(tx_input, 0), witness_script)
        # Witness can be null
        tx_input = tx_input_init(txhash, 0, seq, b'0000', None)
        with self.assertRaises(ValueError):
            tx_input_get_witness(tx_input, 0) # Can't get a non-existent witness

    def test_tx_output(self):
        # Test invalid outputs
        satoshi, script = 10000, b'0000'

        # Create a valid output
        tx_output = tx_output_init(satoshi, script)
        self.assertEqual(tx_output_get_satoshi(tx_output), satoshi)
        self.assertEqual(tx_output_get_script_len(tx_output), len(script))
        self.assertEqual(tx_output_get_script(tx_output), script)

    def test_tx_set_output(self):
        satoshi, script = WALLY_SATOSHI_MAX, b'0000'

        # Create tx with single output value = MAX
        tx = tx_init(2, 0, 10, 2)
        tx_add_output(tx, tx_output_init(satoshi, script))
        self.assertEqual(tx_get_output_satoshi(tx, 0), WALLY_SATOSHI_MAX)
        self.assertEqual(tx_get_total_output_satoshi(tx), WALLY_SATOSHI_MAX)

        # Change value of output from MAX -> 1
        tx_set_output_satoshi(tx, 0, 1)
        self.assertEqual(tx_get_output_satoshi(tx, 0), 1)
        self.assertEqual(tx_get_total_output_satoshi(tx), 1)

    def test_tx(self):
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        tx_input = tx_input_init(txhash, 0, seq, script, witness)
        tx_input_no_witness = tx_input_init(txhash, 0, seq, script, None)
        tx_output = tx_output_init(10000, script)

        tx = tx_init(2, 0, 10, 2)
        self.assertEqual(tx_get_num_inputs(tx), 0)
        self.assertEqual(tx_get_witness_count(tx), 0)
        self.assertEqual(tx_get_num_outputs(tx), 0)
        self.assertEqual(tx_get_total_output_satoshi(tx), 0)
        tx_add_input(tx, tx_input_no_witness)
        self.assertEqual(tx_get_num_inputs(tx), 1)
        self.assertEqual(tx_get_witness_count(tx), 0)
        tx_add_input(tx, tx_input)
        self.assertEqual(tx_get_witness_count(tx), 1)
        tx_add_input(tx, tx_input)
        tx_add_raw_input(tx, txhash, 0, seq, script, witness, 0)
        with self.assertRaises(ValueError):
            tx_remove_input(tx, 4)
        tx_remove_input(tx, 2) # Remove last
        tx_remove_input(tx, 1) # Remove middle
        tx_remove_input(tx, 0) # Remove first
        tx_remove_input(tx, 0) # Remove only input

        tx_add_input(tx, tx_input)
        tx_add_output(tx, tx_output)
        self.assertEqual(tx_get_total_output_satoshi(tx), 10000)
        tx_add_raw_output(tx, 20000, script, 0)
        self.assertEqual(tx_get_total_output_satoshi(tx), 30000)
        size = tx_get_length(tx, 0)
        vsize = tx_vsize_from_weight(tx_get_weight(tx))
        tx_hex = tx_to_hex(tx, FLAG_USE_WITNESS)

        with self.assertRaises(ValueError):
            tx_add_raw_output(tx, WALLY_SATOSHI_MAX + 1, script, 0)
        with self.assertRaises(ValueError):
            total_to_overflow = WALLY_SATOSHI_MAX - tx_get_total_output_satoshi(tx) + 1
            tx_add_raw_output(tx, total_to_overflow, script, 0)

if __name__ == '__main__':
    unittest.main()
