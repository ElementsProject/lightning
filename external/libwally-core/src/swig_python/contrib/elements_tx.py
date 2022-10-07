"""Tests for Elements/Liquid transaction construction"""
import unittest
from wallycore import *


class ElementsTxTests(unittest.TestCase):

    def test_tx_input(self):
        # Test invalid inputs
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        nonce, entropy = b'0' * 32, b'0' * 32
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        with self.assertRaises(ValueError):
            tx_elements_input_init(None, 0, seq, script, witness, nonce, entropy) # Null txhash
        with self.assertRaises(ValueError):
            tx_elements_input_init(bytes(), 0, seq, script, witness, nonce, entropy) # Empty txhash

        # Create a valid input
        tx_input = tx_elements_input_init(txhash, 0, seq, script, witness, nonce, entropy)
        self.assertEqual(tx_input_get_txhash(tx_input), txhash)
        self.assertEqual(tx_input_get_index(tx_input), 0)
        self.assertEqual(tx_input_get_sequence(tx_input), seq)
        self.assertEqual(tx_input_get_script_len(tx_input), len(script))
        self.assertEqual(tx_input_get_script(tx_input), script)
        self.assertEqual(tx_input_get_witness_len(tx_input, 0), len(witness_script))
        self.assertEqual(tx_input_get_witness(tx_input, 0), witness_script)
        # Witness can be null
        tx_input = tx_elements_input_init(txhash, 0, seq, b'0000')
        with self.assertRaises(ValueError):
            tx_input_get_witness(tx_input, 0) # Can't get a non-existent witness

    def test_tx_output(self):
        # Test outputs
        satoshi, script, asset, asset2 = 10000, b'0000', b'0' * 33, b'1' * 33

        # Create a valid output
        ct_value = tx_confidential_value_from_satoshi(satoshi)
        tx_output = tx_elements_output_init(script, asset, ct_value)
        self.assertEqual(tx_output_get_script_len(tx_output), len(script))
        self.assertEqual(tx_output_get_script(tx_output), script)
        self.assertEqual(tx_output_get_asset(tx_output), asset)
        self.assertEqual(tx_output_get_asset_len(tx_output), len(asset))
        tx_output_set_asset(tx_output, asset2)
        self.assertEqual(tx_output_get_asset(tx_output), asset2)
        self.assertEqual(tx_output_get_value_len(tx_output), len(ct_value))
        self.assertEqual(tx_output_get_value(tx_output), ct_value)

    def test_tx(self):
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        nonce, entropy = b'0' * 32, b'0' * 32
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        tx_input = tx_elements_input_init(txhash, 0, seq, script, witness, nonce, entropy)
        tx_input_no_witness = tx_elements_input_init(txhash, 0, seq, script, None, nonce, entropy)

        ct_value = tx_confidential_value_from_satoshi(10000)
        tx_output = tx_elements_output_init(script, None, ct_value)

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
        tx_add_elements_raw_input(tx, txhash, 0, seq, script, witness, nonce, entropy, None, None, None, None, None, 0)
        with self.assertRaises(ValueError):
            tx_remove_input(tx, 4)
        tx_remove_input(tx, 2) # Remove last
        tx_remove_input(tx, 1) # Remove middle
        tx_remove_input(tx, 0) # Remove first
        tx_remove_input(tx, 0) # Remove only input

        tx_add_input(tx, tx_input)
        tx_add_output(tx, tx_output)
        ct_value = tx_confidential_value_from_satoshi(20000)
        tx_add_elements_raw_output(tx, script, None, ct_value, None, None, None, 0)
        size = tx_get_length(tx, 0)
        vsize = tx_vsize_from_weight(tx_get_weight(tx))
        for extra_flags in (0, WALLY_TX_FLAG_USE_ELEMENTS, WALLY_TX_FLAG_ALLOW_PARTIAL):
            tx_hex = tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS | extra_flags)
            tx_bytes = tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS | extra_flags)
            self.assertEqual(tx_hex, hex_from_bytes(tx_bytes))

    def test_coinbase(self):
        txhash, seq, script = bytearray(b'\x00'*32), 0xffffffff, b'0000'
        tx_input_no_witness = tx_elements_input_init(txhash, seq, seq, script)

        ct_value = tx_confidential_value_from_satoshi(10000)
        tx_output = tx_elements_output_init(script, None, ct_value)
        tx = tx_init(2, 0, 10, 2)
        tx_add_input(tx, tx_input_no_witness)
        tx_add_output(tx, tx_output)
        self.assertEqual(tx_is_coinbase(tx), 1)

    def test_issuance(self):
        txhash = hex_to_bytes("39453cf897e2f0c2e9563364874f4b2a85be06dd8ec10665085033eeb75016c3")[::-1]
        vout = 68
        contract_hash = bytearray(b'\x00'*32)
        entropy = tx_elements_issuance_generate_entropy(txhash, vout, contract_hash)
        self.assertEqual(hex_from_bytes(entropy), "3db9d8b4a9da087b42f29f34431412aaa24d63750bb31b9a2e263797248135e0")
        asset = tx_elements_issuance_calculate_asset(entropy)
        self.assertEqual(hex_from_bytes(asset[::-1]), "dedf795f74e8b52c6ff8a9ad390850a87b18aeb2be9d1967038308290093a893")

    def test_reissuance_token(self):
        entropy = hex_to_bytes("7746cd11098b1de0cb6f3a8eae8fe3b7c9aef69b96ea91c6feaf480f0135e7c5")
        asset = tx_elements_issuance_calculate_asset(entropy)
        self.assertEqual(hex_from_bytes(asset[::-1]), "eb82f87a64d7b701569a88d9b1578953038b53916ebf7f87b865beab3a3e26d2")
        reissuance_token = tx_elements_issuance_calculate_reissuance_token(entropy, 0)
        self.assertEqual(hex_from_bytes(reissuance_token[::-1]), "42066f5f26d72da30758487822436c61cccea78e8f9b6b9f08230f5d9003848c")

    def test_confidential_address(self):
        addr = "Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6"
        pubkey_hex = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623"
        addr_c = "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK"

        self.assertEqual(confidential_addr_to_addr(addr_c, WALLY_CA_PREFIX_LIQUID), addr)

        pubkey = confidential_addr_to_ec_public_key(addr_c, WALLY_CA_PREFIX_LIQUID)
        self.assertEqual(hex_from_bytes(pubkey), pubkey_hex)

        self.assertEqual(confidential_addr_from_addr(addr, WALLY_CA_PREFIX_LIQUID, pubkey), addr_c)

        addr_segwit = "ex1qhmhvfukrduq38q84v9gxctl97h8dny4u7p8r3v"
        pubkey_hex_segwit = "03c280c377e428069606af6c7d8c152b39b0c9103473a6e0f27b06733dfecf6a6e"
        addr_c_segwit = "lq1qq0pgpsmhus5qd9sx4ak8mrq49vumpjgsx3e6dc8j0vr8x007ea4xa0hwcnevxmcpzwq02c2sdsh7tawwmxftcu9pkfd2q68dp"

        self.assertEqual(confidential_addr_to_addr_segwit(addr_c_segwit, "lq", "ex"), addr_segwit)

        pubkey = confidential_addr_segwit_to_ec_public_key(addr_c_segwit, "lq")
        self.assertEqual(hex_from_bytes(pubkey), pubkey_hex_segwit)

        self.assertEqual(confidential_addr_from_addr_segwit(addr_segwit, "ex", "lq", pubkey), addr_c_segwit)

if __name__ == '__main__':
    unittest.main()
