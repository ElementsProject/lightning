"""A simple demonstration/test of BIP32 derivation using wally"""
import unittest
from wallycore import *

# BIP32 test vector 1
# FIXME: Put this in a data file to share with src/test/test_bip32.py
vec_1 = {
    'seed':                     '000102030405060708090a0b0c0d0e0f',

    'm': {
        BIP32_FLAG_KEY_PUBLIC:  '0488B21E000000000000000000873DFF'
                                '81C02F525623FD1FE5167EAC3A55A049'
                                'DE3D314BB42EE227FFED37D5080339A3'
                                '6013301597DAEF41FBE593A02CC513D0'
                                'B55527EC2DF1050E2E8FF49C85C2AB473B21',

        BIP32_FLAG_KEY_PRIVATE: '0488ADE4000000000000000000873DFF'
                                '81C02F525623FD1FE5167EAC3A55A049'
                                'DE3D314BB42EE227FFED37D50800E8F3'
                                '2E723DECF4051AEFAC8E2C93C9C5B214'
                                '313817CDB01A1494B917C8436B35E77E9D71'
    },
}

class BIP32Tests(unittest.TestCase):

    def compare_keys(self, key, expected, flags):
        for fn in [bip32_key_get_chain_code, bip32_key_get_pub_key,
                   bip32_key_get_parent160, bip32_key_get_depth,
                   bip32_key_get_child_num]:
            self.assertEqual(fn(key), fn(expected))
        self.assertEqual(bip32_key_get_version(key), BIP32_VER_MAIN_PRIVATE)
        if flags == BIP32_FLAG_KEY_PRIVATE:
            self.assertEqual(bip32_key_get_priv_key(key),
                             bip32_key_get_priv_key(expected))

    def test_bip32(self):
        seed_data = hex_to_bytes(vec_1['seed'])
        master = bip32_key_from_seed(seed_data, BIP32_VER_MAIN_PRIVATE, 0)

        for flags in [BIP32_FLAG_KEY_PUBLIC, BIP32_FLAG_KEY_PRIVATE]:
            serialized_data = hex_to_bytes(vec_1['m'][flags])
            serialized_data = serialized_data[:BIP32_SERIALIZED_LEN] # Trim checksum
            expected_key = bip32_key_unserialize(serialized_data)
            self.compare_keys(master, expected_key, flags)

        # Test our SWIG integer conversions for overflow etc in path derivation
        for p, valid in [([2**32-1],  True),   # 0xffffffff is valid
                         ([float(1)], False),  # We don't support float casting
                         ([2**32],    False),  # Overflow
                         ([-1],       False)]: # Underflow
            if valid:
                bip32_key_from_parent_path(master, p, 0)
            else:
                with self.assertRaises(OverflowError):
                    bip32_key_from_parent_path(master, p, 0)



if __name__ == '__main__':
    unittest.main()
