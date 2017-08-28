import unittest
from util import *

VER_MAIN_PUBLIC = 0x0488B21E
VER_MAIN_PRIVATE = 0x0488ADE4
VER_TEST_PUBLIC = 0x043587CF
VER_TEST_PRIVATE = 0x04358394

FLAG_KEY_PRIVATE, FLAG_KEY_PUBLIC, FLAG_SKIP_HASH, = 0x0, 0x1, 0x2
ALL_DEFINED_FLAGS = FLAG_KEY_PRIVATE | FLAG_KEY_PUBLIC | FLAG_SKIP_HASH
BIP32_SERIALIZED_LEN = 78

# These vectors are expressed in binary rather than base 58. The spec base 58
# representation just obfuscates the data we are validating. For example, the
# chain codes in pub/priv results can be seen as equal in the hex data only.
#
# The vector results are the serialized resulting extended key using either the
# contained public or private key. This is not to be confused with private or
# public derivation - these vectors only derive privately.
vec_1 = {
    'seed':               '000102030405060708090a0b0c0d0e0f',

    'm': {
        FLAG_KEY_PUBLIC:  '0488B21E000000000000000000873DFF'
                          '81C02F525623FD1FE5167EAC3A55A049'
                          'DE3D314BB42EE227FFED37D5080339A3'
                          '6013301597DAEF41FBE593A02CC513D0'
                          'B55527EC2DF1050E2E8FF49C85C2AB473B21',

        FLAG_KEY_PRIVATE: '0488ADE4000000000000000000873DFF'
                          '81C02F525623FD1FE5167EAC3A55A049'
                          'DE3D314BB42EE227FFED37D50800E8F3'
                          '2E723DECF4051AEFAC8E2C93C9C5B214'
                          '313817CDB01A1494B917C8436B35E77E9D71'
    },

    'm/0H': {
        FLAG_KEY_PUBLIC:  '0488B21E013442193E8000000047FDAC'
                          'BD0F1097043B78C63C20C34EF4ED9A11'
                          '1D980047AD16282C7AE6236141035A78'
                          '4662A4A20A65BF6AAB9AE98A6C068A81'
                          'C52E4B032C0FB5400C706CFCCC56B8B9C580',

        FLAG_KEY_PRIVATE: '0488ADE4013442193E8000000047FDAC'
                          'BD0F1097043B78C63C20C34EF4ED9A11'
                          '1D980047AD16282C7AE623614100EDB2'
                          'E14F9EE77D26DD93B4ECEDE8D16ED408'
                          'CE149B6CD80B0715A2D911A0AFEA0A794DEC'
    },

    'm/0H/1': {
        FLAG_KEY_PUBLIC:  '0488B21E025C1BD648000000012A7857'
                          '631386BA23DACAC34180DD1983734E44'
                          '4FDBF774041578E9B6ADB37C1903501E'
                          '454BF00751F24B1B489AA925215D66AF'
                          '2234E3891C3B21A52BEDB3CD711C6F6E2AF7',

        FLAG_KEY_PRIVATE: '0488ADE4025C1BD648000000012A7857'
                          '631386BA23DACAC34180DD1983734E44'
                          '4FDBF774041578E9B6ADB37C19003C6C'
                          'B8D0F6A264C91EA8B5030FADAA8E538B'
                          '020F0A387421A12DE9319DC93368B34BC442'
    },

    'm/0H/1/2H': {
        FLAG_KEY_PUBLIC:  '0488B21E03BEF5A2F98000000204466B'
                          '9CC8E161E966409CA52986C584F07E9D'
                          'C81F735DB683C3FF6EC7B1503F0357BF'
                          'E1E341D01C69FE5654309956CBEA5168'
                          '22FBA8A601743A012A7896EE8DC2A5162AFA',

        FLAG_KEY_PRIVATE: '0488ADE403BEF5A2F98000000204466B'
                          '9CC8E161E966409CA52986C584F07E9D'
                          'C81F735DB683C3FF6EC7B1503F00CBCE'
                          '0D719ECF7431D88E6A89FA1483E02E35'
                          '092AF60C042B1DF2FF59FA424DCA25814A3A'
    }
}

class BIP32Tests(unittest.TestCase):

    NULL_HASH160 = '00' * 20
    SERIALIZED_LEN = 4 + 1 + 4 + 4 + 32 + 33

    def unserialize_key(self, buf, buf_len):
        key_out = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key_out))
        return ret, key_out

    def get_test_master_key(self, vec):
        seed, seed_len = make_cbuffer(vec['seed'])
        master = ext_key()
        ret = bip32_key_from_seed(seed, seed_len,
                                  VER_MAIN_PRIVATE, 0, byref(master))
        self.assertEqual(ret, WALLY_OK)
        return master

    def get_test_key(self, vec, path, flags):
        buf, buf_len = make_cbuffer(vec[path][flags])
        ret, key_out = self.unserialize_key(buf, self.SERIALIZED_LEN)
        self.assertEqual(ret, WALLY_OK)
        return key_out

    def derive_key(self, parent, child_num, flags):
        key_out = ext_key()
        ret = bip32_key_from_parent(byref(parent), child_num,
                                    flags, byref(key_out))
        self.assertEqual(ret, WALLY_OK)

        # Verify that path derivation matches also
        p_key_out = self.derive_key_by_path(parent, [child_num], flags)
        self.compare_keys(p_key_out, key_out, flags)
        return key_out

    def path_to_c(self, path):
        c_path = (c_uint * len(path))()
        for i, n in enumerate(path):
            c_path[i] = n
        return c_path

    def derive_key_by_path(self, parent, path, flags, expected=WALLY_OK):
        key_out = ext_key()
        c_path = self.path_to_c(path)
        ret = bip32_key_from_parent_path(byref(parent), c_path, len(path),
                                         flags, byref(key_out))
        self.assertEqual(ret, expected)
        return key_out

    def compare_keys(self, key, expected, flags):
        self.assertEqual(h(key.chain_code), h(expected.chain_code))
        key_name = 'pub_key' if (flags & FLAG_KEY_PUBLIC) else 'priv_key'
        expected_cmp = getattr(expected, key_name)
        key_cmp = getattr(key, key_name)
        self.assertEqual(h(key_cmp), h(expected_cmp))
        self.assertEqual(key.depth, expected.depth)
        self.assertEqual(key.child_num, expected.child_num)
        self.assertEqual(h(key.chain_code), h(expected.chain_code))
        # These would be more useful tests if there were any public
        # derivation test vectors
        # We can only compare the first 4 bytes of the parent fingerprint
        # Since that is all thats serialized.
        # FIXME: Implement bip32_key_set_parent and test it here
        b32 = lambda k: h(k)[0:8]
        if flags & FLAG_SKIP_HASH:
            self.assertEqual(h(key.hash160), utf8(self.NULL_HASH160))
            self.assertEqual(b32(key.parent160), utf8(self.NULL_HASH160[0:8]))
        else:
            self.assertEqual(h(key.hash160), h(expected.hash160))
            self.assertEqual(b32(key.parent160), b32(expected.parent160))


    def test_serialisation(self):

        # Try short, correct, long lengths. Trimming 8 chars is the correct
        # length because the vector value contains 4 check bytes at the end.
        for trim, expected in [(0, WALLY_EINVAL), (8, WALLY_OK), (16, WALLY_EINVAL)]:
            serialized_hex = vec_1['m'][FLAG_KEY_PRIVATE][0:-trim]
            buf, buf_len = make_cbuffer(serialized_hex)
            ret, key_out = self.unserialize_key(buf, buf_len)
            self.assertEqual(ret, expected)
            if ret == 0:
                # Check this key serializes back to the same representation
                # FIXME: Add full test cases for the serialisation code including errors
                buf, buf_len = make_cbuffer('0' * len(serialized_hex))
                ret = bip32_key_serialize(key_out, FLAG_KEY_PRIVATE,
                                          buf, buf_len)
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(h(buf).upper(), utf8(serialized_hex))

        # Check correct and incorrect version numbers as well
        # as mismatched key types and versions
        ver_cases = [(VER_MAIN_PUBLIC,  FLAG_KEY_PUBLIC,  WALLY_OK),
                     (VER_MAIN_PUBLIC,  FLAG_KEY_PRIVATE, WALLY_EINVAL),
                     (VER_MAIN_PRIVATE, FLAG_KEY_PUBLIC,  WALLY_EINVAL),
                     (VER_MAIN_PRIVATE, FLAG_KEY_PRIVATE, WALLY_OK),
                     (VER_TEST_PUBLIC,  FLAG_KEY_PUBLIC,  WALLY_OK),
                     (VER_TEST_PUBLIC , FLAG_KEY_PRIVATE, WALLY_EINVAL),
                     (VER_TEST_PRIVATE, FLAG_KEY_PUBLIC,  WALLY_EINVAL),
                     (VER_TEST_PRIVATE, FLAG_KEY_PRIVATE, WALLY_OK),
                     (0x01111111,            FLAG_KEY_PUBLIC,  WALLY_EINVAL),
                     (0x01111111,            FLAG_KEY_PRIVATE, WALLY_EINVAL)]

        for ver, flags, expected in ver_cases:
            no_ver = vec_1['m'][flags][8:-8]
            v_str = '0' + hex(ver)[2:]
            buf, buf_len = make_cbuffer(v_str + no_ver)
            ret, _ = self.unserialize_key(buf, buf_len)
            self.assertEqual(ret, expected)


    def test_key_from_seed(self):

        seed, seed_len = make_cbuffer(vec_1['seed'])
        key_out = ext_key()

        # Only private key versions can be used
        ver_cases = [(VER_MAIN_PUBLIC,   0,               WALLY_EINVAL),
                     (VER_MAIN_PRIVATE,  0,               WALLY_OK),
                     (VER_TEST_PUBLIC,   0,               WALLY_EINVAL),
                     (VER_TEST_PRIVATE,  0,               WALLY_OK),
                     (VER_TEST_PRIVATE,  FLAG_KEY_PUBLIC, WALLY_EINVAL),
                     (VER_TEST_PRIVATE,  FLAG_SKIP_HASH,  WALLY_OK)]
        for ver, flags, expected in ver_cases:
            ret = bip32_key_from_seed(seed, seed_len, ver, flags, byref(key_out))
            self.assertEqual(ret, expected)


    def test_bip32_vectors(self):

        # BIP32 Test vector 1
        master = self.get_test_master_key(vec_1)

        # Chain m:
        for flags in [FLAG_KEY_PUBLIC, FLAG_KEY_PRIVATE]:
            expected = self.get_test_key(vec_1, 'm', flags)
            self.compare_keys(master, expected, flags)

        derived = master
        for path, i in [('m/0H', 0x80000000),
                        ('m/0H/1', 1),
                        ('m/0H/1/2H', 0x80000002)]:

            # Derive a public and private child. Verify that the private child
            # contains the public and private published vectors. Verify that
            # the public child matches the public vector and has no private
            # key. Finally, check that the child holds the correct parent hash.
            parent160 = derived.hash160
            derived_pub = self.derive_key(derived, i, FLAG_KEY_PUBLIC)
            derived = self.derive_key(derived, i, FLAG_KEY_PRIVATE)
            for flags in [FLAG_KEY_PUBLIC, FLAG_KEY_PRIVATE]:
                expected = self.get_test_key(vec_1, path, flags)
                self.compare_keys(derived, expected, flags)
                if flags & FLAG_KEY_PUBLIC:
                    self.compare_keys(derived_pub, expected, flags)
                    # A neutered private key is indicated by
                    # BIP32_FLAG_KEY_PUBLIC (0x1) as its first byte.
                    self.assertEqual(h(derived_pub.priv_key), utf8('01' + '00' * 32))
                self.assertEqual(h(derived.parent160), h(parent160))

    def create_master_pub_priv(self):

        # Start with BIP32 Test vector 1
        master = self.get_test_master_key(vec_1)
        # Derive the same child public and private keys from master
        priv = self.derive_key(master, 1, FLAG_KEY_PRIVATE)
        pub = self.derive_key(master, 1, FLAG_KEY_PUBLIC)
        return master, pub, priv

    def test_public_derivation_identities(self):

        master, pub, priv = self.create_master_pub_priv()
        # From the private child we can derive public and private keys
        priv_pub = self.derive_key(priv, 1, FLAG_KEY_PUBLIC)
        priv_priv = self.derive_key(priv, 1, FLAG_KEY_PRIVATE)
        # From the public child we can only derive a public key
        pub_pub = self.derive_key(pub, 1, FLAG_KEY_PUBLIC)

        # Verify that trying to derive a private key doesn't work
        key_out = ext_key()
        ret = bip32_key_from_parent(byref(pub), 1,
                                    FLAG_KEY_PRIVATE, byref(key_out))
        self.assertEqual(ret, WALLY_EINVAL)

        # Now our identities:
        # The children share the same public key
        self.assertEqual(h(pub.pub_key), h(priv.pub_key))
        # The grand-children share the same public key
        self.assertEqual(h(priv_pub.pub_key), h(priv_priv.pub_key))
        self.assertEqual(h(priv_pub.pub_key), h(pub_pub.pub_key))
        # The children and grand-children do not share the same public key
        self.assertNotEqual(h(pub.pub_key), h(priv_pub.pub_key))

        # Test path derivation with multiple child elements
        for flags, expected in [(FLAG_KEY_PUBLIC,                   pub_pub),
                                (FLAG_KEY_PRIVATE,                  priv_priv),
                                (FLAG_KEY_PUBLIC  | FLAG_SKIP_HASH, pub_pub),
                                (FLAG_KEY_PRIVATE | FLAG_SKIP_HASH, priv_priv)]:
            path_derived = self.derive_key_by_path(master, [1, 1], flags)
            self.compare_keys(path_derived, expected, flags)


if __name__ == '__main__':
    unittest.main()
