import unittest
import copy
from util import *

VER_MAIN_PUBLIC = 0x0488B21E
VER_MAIN_PRIVATE = 0x0488ADE4
VER_TEST_PUBLIC = 0x043587CF
VER_TEST_PRIVATE = 0x04358394

FLAG_KEY_PRIVATE, FLAG_KEY_PUBLIC, FLAG_SKIP_HASH, = 0x0, 0x1, 0x2
FLAG_KEY_TWEAK_SUM, FLAG_STR_WILDCARD, FLAG_STR_BARE = 0x4, 0x8, 0x10
ALL_DEFINED_FLAGS = FLAG_KEY_PRIVATE | FLAG_KEY_PUBLIC | FLAG_SKIP_HASH
BIP32_SERIALIZED_LEN = 78
BIP32_FLAG_SKIP_HASH = 0x2

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

vec_3 = {
    'seed':               '4B381541583BE4423346C643850DA4B3'
                          '20E46A87AE3D2A4E6DA11EBA819CD4AC'
                          'BA45D239319AC14F863B8D5AB5A0D0C6'
                          '4D2E8A1E7D1457DF2E5A3C51C73235BE',

    'm': {
        FLAG_KEY_PUBLIC:  '0488B21E00000000000000000001D28A'
                          '3E53CFFA419EC122C968B3259E16B650'
                          '76495494D97CAE10BBFEC3C36F03683A'
                          'F1BA5743BDFC798CF814EFEEAB2735EC'
                          '52D95ECED528E692B8E34C4E56696541E136',

        FLAG_KEY_PRIVATE: '0488ADE400000000000000000001D28A'
                          '3E53CFFA419EC122C968B3259E16B650'
                          '76495494D97CAE10BBFEC3C36F0000DD'
                          'B80B067E0D4993197FE10F2657A844A3'
                          '84589847602D56F0C629C81AAE3233C0C6BF'
    },

    'm/0H': {
        FLAG_KEY_PUBLIC:  '0488B21E0141D63B5080000000E5FEA1'
                          '2A97B927FC9DC3D2CB0D1EA1CF50AA5A'
                          '1FDC1F933E8906BB38DF3377BD026557'
                          'FDDA1D5D43D79611F784780471F086D5'
                          '8E8126B8C40ACB82272A7712E7F20158D8FD',

        FLAG_KEY_PRIVATE: '0488ADE40141D63B5080000000E5FEA1'
                          '2A97B927FC9DC3D2CB0D1EA1CF50AA5A'
                          '1FDC1F933E8906BB38DF3377BD00491F'
                          '7A2EEBC7B57028E0D3FAA0ACDA02E75C'
                          '33B03C48FB288C41E2EA44E1DAEF7332BB35'
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
        p_key_out, p_str_key_out = self.derive_key_by_path(parent, [child_num], flags)
        self.compare_keys(p_key_out, key_out, flags)
        self.compare_keys(p_str_key_out, key_out, flags)
        return key_out

    def child_num_to_str(self, child_num):
        indicator, v = '', child_num
        if child_num >= 0x80000000:
            indicator, v = 'h', child_num - 0x80000000
        return '/' + str(v) + indicator

    def path_to_str(self, path):
        return utf8('m' + ''.join(self.child_num_to_str(v) for v in path))

    def path_to_c(self, path):
        c_path = (c_uint * len(path))()
        for i, n in enumerate(path):
            c_path[i] = n
        return c_path

    def str_to_path(self, path_str, wildcard):
        path = path_str.replace('*h', str(2147483648 + wildcard))
        path = path.replace('*', str(wildcard)).replace('m/', '').split('/')
        return [int(v) for v in path]

    def derive_key_by_path(self, parent, path, flags, expected=WALLY_OK):
        key_out, str_key_out = ext_key(), ext_key()
        c_path = self.path_to_c(path)
        ret = bip32_key_from_parent_path(byref(parent), c_path, len(path),
                                         flags, byref(key_out))
        self.assertEqual(ret, expected)
        str_path = self.path_to_str(path)
        ret = bip32_key_from_parent_path_str(byref(parent), str_path, 0,
                                             flags, byref(str_key_out))
        self.assertEqual(ret, expected)
        return key_out, str_key_out

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


    def test_serialization(self):

        # Try short, correct, long lengths. Trimming 8 chars is the correct
        # length because the vector value contains 4 check bytes at the end.
        for trim, expected in [(0, WALLY_EINVAL), (8, WALLY_OK), (16, WALLY_EINVAL)]:
            serialized_hex = vec_1['m'][FLAG_KEY_PRIVATE][0:-trim]
            buf, buf_len = make_cbuffer(serialized_hex)
            ret, key_out = self.unserialize_key(buf, buf_len)
            self.assertEqual(ret, expected)
            if ret == WALLY_OK:
                # Check this key serializes back to the same representation
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
                     (0x01111111,       FLAG_KEY_PUBLIC,  WALLY_EINVAL),
                     (0x01111111,       FLAG_KEY_PRIVATE, WALLY_EINVAL)]

        for ver, flags, expected in ver_cases:
            no_ver = vec_1['m'][flags][8:-8]
            v_str = '0' + hex(ver)[2:]
            buf, buf_len = make_cbuffer(v_str + no_ver)
            ret, _ = self.unserialize_key(buf, buf_len)
            self.assertEqual(ret, expected)

        # Check invalid arguments fail
        master = self.get_test_master_key(vec_1)
        pub = self.derive_key(master, 1, FLAG_KEY_PUBLIC)
        key_out = ext_key()
        cases = [
            [~ALL_DEFINED_FLAGS, BIP32_SERIALIZED_LEN],
            [FLAG_KEY_PRIVATE, BIP32_SERIALIZED_LEN],
            [FLAG_KEY_PUBLIC, BIP32_SERIALIZED_LEN + 1],
        ]
        for (flags, len_out) in cases:
            ret = bip32_key_serialize(byref(pub), flags, byref(key_out), len_out)
            self.assertEqual(WALLY_EINVAL, ret)

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
            ret = bip32_key_from_seed_custom(seed, seed_len, ver, None, 0, flags, byref(key_out))
            self.assertEqual(ret, expected)

        # Other invalid args
        ver, flags = VER_MAIN_PRIVATE, FLAG_SKIP_HASH
        cases = [
            (None, seed_len, ver, None, 0, flags, byref(key_out)), # NULL seed
            (seed, 0,        ver, None, 0, flags, byref(key_out)), # Empty seed
            (seed, seed_len, 0x1, None, 0, flags, byref(key_out)), # Invalid version
            (seed, seed_len, ver, seed, 0, flags, byref(key_out)), # 0-length hmac key
            (seed, seed_len, ver, None, 1, flags, byref(key_out)), # NULL hmac key
            (seed, seed_len, ver, None, 0, 0x1,   byref(key_out)), # Invalid flags
            (seed, seed_len, ver, None, 0, flags, None)]           # NULL output
        for case in cases:
            if not case[3] and not case[4]:
                # Not testing hmac key, test non-custom call
                ret = bip32_key_from_seed(case[0], case[1], case[2], case[5], case[6])
                self.assertEqual(ret, WALLY_EINVAL)
            ret = bip32_key_from_seed_custom(*case)
            self.assertEqual(ret, WALLY_EINVAL)

    def test_key_from_seed_custom(self):
        seed_hex = ('1EBF38D0B1FC10AC12059141276C1B8B'
                    '7A410BA43D04BBE9F3A371D884A30440'
                    '0B6A39FDA34E5B282A3717663FB33795'
                    '4DF3DADF802A4CBA3D008D5E2988F70A')
        seed, seed_len = make_cbuffer(seed_hex)
        key_out = ext_key()

        ver, flags = VER_MAIN_PRIVATE, 0
        cases = [('Bitcoin seed',   '0488ADE40000000000000000002FB77E25CD3E2'
                                    'E034BCBAFA1F81EC7E4CAF927B06C87DB296F11'
                                    '86208315525E00CA18C524148649DFD1126D8D9'
                                    '8B2DDB696181F25F4A6031713783B541AA14D02'),

                 ('Nist256p1 seed', '0488ADE400000000000000000075C34EB4C3F4E'
                                    'BC771C8A431B8F5516D6B5881DE5200898CCABF'
                                    '93ACF877A57C00607D6DF3D1C7FC3371FA0CA34'
                                    'E3D1F52E87885A74A3E21A991CBDB67EFA34803'),

                 ('ed25519 seed',   '0488ADE400000000000000000041A8BB1828138'
                                    '6DC1E958E481A2577C111893D66BB5790F91065'
                                    'E1E56BEFAD7500EF2D5DA0A37454A826131CF57'
                                    'A5B97ECD0DCD18F0D1B74C7678617F873749C77')]

        # cases[0] should match the default, as should passing 'None'
        custom_data = cases[0][0].encode()
        default_key_out = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, ver, flags, byref(default_key_out))
        self.assertEqual(ret, WALLY_OK)

        for data, len_ in [(custom_data, len(custom_data)), (None, 0)]:
            ret = bip32_key_from_seed_custom(seed, seed_len, ver, custom_data, len(custom_data), flags, byref(key_out))
            self.assertEqual(ret, WALLY_OK)
            self.compare_keys(key_out, default_key_out, flags)

        for case in cases:
            custom_data = case[0].encode()
            ret = bip32_key_from_seed_custom(seed, seed_len, ver, custom_data, len(custom_data), flags, byref(key_out))
            self.assertEqual(ret, WALLY_OK)

            expected, expected_len = make_cbuffer(case[1])
            ret, expected_key = self.unserialize_key(expected, expected_len)
            self.assertEqual(ret, WALLY_OK)
            self.compare_keys(key_out, expected_key, flags)

    def test_key_init(self):
        # Note we test bip32_key_init_alloc: it calls bip32_key_init internally
        _, _, priv = self.create_master_pub_priv()

        ver, depth, num = priv.version, priv.depth, priv.child_num
        cc, cc_len = make_cbuffer(h(priv.chain_code))
        pub_key, pub_key_len = make_cbuffer(h(priv.pub_key))
        priv_key, priv_key_len = make_cbuffer(h(priv.priv_key)[2:])
        h160, h160_len = make_cbuffer(h(priv.hash160))
        p160, p160_len = make_cbuffer(h(priv.parent160))
        key_out = POINTER(ext_key)()
        valid_args = [ver, depth, num, cc, cc_len, pub_key, pub_key_len,
                      priv_key, priv_key_len, h160, h160_len, p160, p160_len]

        # Test cases
        arg_diffs = [
            (True,  12, p160_len),  # No change
            (True,  12, 4),         # 4 byte fingerprint only
            (False, 1,  256),       # Depth > 255
            (False, 3,  None),      # Null chaincode, valid length
            (False, 4,  15),        # Invalid chaincode length
            (False, 5,  None),      # Null pub key, valid length
            (False, 6,  15),        # Invalid pub key length
            (False, 7,  None),      # Null priv key, valid length
            (False, 8,  15),        # Invalid priv key length
            (False, 9,  None),      # Null hash160, valid length
            (False, 10, 15),        # Invalid hash160 length
            (False, 11, None),      # Null parent160, valid length
            (False, 12, 15),        # Invalid parent160 length
        ]
        for ok, idx, new_val in arg_diffs:
            call_args = copy.deepcopy(valid_args) + [byref(key_out)]
            call_args[idx] = new_val
            ret = bip32_key_init_alloc(*call_args)
            self.assertEqual(ret, WALLY_OK if ok else WALLY_EINVAL)

    def test_bip32_vectors(self):
        self.do_test_vector(vec_1)
        self.do_test_vector(vec_3)

    def do_test_vector(self, vec):

        # BIP32 Test vector 1
        master = self.get_test_master_key(vec)

        # Chain m:
        for flags in [FLAG_KEY_PUBLIC, FLAG_KEY_PRIVATE]:
            expected = self.get_test_key(vec, 'm', flags)
            self.compare_keys(master, expected, flags)

        derived = master
        for path, i in [('m/0H', 0x80000000),
                        ('m/0H/1', 1),
                        ('m/0H/1/2H', 0x80000002)]:

            if path not in vec:
                continue

            # Derive a public and private child. Verify that the private child
            # contains the public and private published vectors. Verify that
            # the public child matches the public vector and has no private
            # key. Finally, check that the child holds the correct parent hash.
            parent160 = derived.hash160
            derived_pub = self.derive_key(derived, i, FLAG_KEY_PUBLIC)
            derived = self.derive_key(derived, i, FLAG_KEY_PRIVATE)
            for flags in [FLAG_KEY_PUBLIC, FLAG_KEY_PRIVATE]:
                expected = self.get_test_key(vec, path, flags)
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
            path_derived, str_derived = self.derive_key_by_path(master, [1, 1], flags)
            self.compare_keys(path_derived, expected, flags)
            self.compare_keys(str_derived, expected, flags)

    def test_key_from_parent_invalid(self):
        master, pub, priv = self.create_master_pub_priv()
        key_out = byref(ext_key())

        cases = [[None,        FLAG_KEY_PRIVATE,   key_out],  # Null parent
                 [byref(priv), FLAG_KEY_PRIVATE,   None],     # Null output key
                 [byref(pub),  ~ALL_DEFINED_FLAGS, key_out],  # Invalid flags (pub)
                 [byref(priv), ~ALL_DEFINED_FLAGS, key_out]]  # Invalid flags (priv)

        for key, flags, key_out in cases:
            ret = bip32_key_from_parent(key, 1, flags, key_out)
            self.assertEqual(ret, WALLY_EINVAL)

        m, path_, long_ = byref(master), [1, 1], [1] * 256
        def get_paths(path):
            return (self.path_to_c(path), self.path_to_str(path)) if path else (None, None)

        cases = [(None, path_, len(path_), FLAG_KEY_PRIVATE,   key_out), # Null parent
                 (m,    path_, len(path_), FLAG_KEY_PRIVATE,   None),    # Null output key
                 (m,    path_, len(path_), ~ALL_DEFINED_FLAGS, key_out), # Invalid flags
                 (m,    None,  len(path_), FLAG_KEY_PRIVATE,   key_out), # NULL path
                 (m,    path_, 0,          FLAG_KEY_PRIVATE,   key_out), # Bad path length
                 (m,    long_, len(long_), FLAG_KEY_PRIVATE,   key_out)] # Path too long

        for key, path, plen, flags, key_out in cases:
            c_path, str_path = get_paths(path)
            ret = bip32_key_from_parent_path(key, c_path, plen, flags, key_out)
            self.assertEqual(ret, WALLY_EINVAL)
            plen = len(str_path) if str_path and plen else plen
            ret = bip32_key_from_parent_path_str_n(key, str_path, plen, 0, flags, key_out)
            self.assertEqual(ret, WALLY_EINVAL)

        c_path, str_path = get_paths(path_)
        master.depth = 0xff # Cant derive from a parent of depth 255
        ret = bip32_key_from_parent(m, 5, FLAG_KEY_PUBLIC, key_out)
        self.assertEqual(ret, WALLY_EINVAL)
        ret = bip32_key_from_parent_path(m, c_path, len(c_path), FLAG_KEY_PUBLIC, key_out)
        self.assertEqual(ret, WALLY_EINVAL)
        ret = bip32_key_from_parent_path_str_n(m, str_path, len(str_path), 0, FLAG_KEY_PUBLIC, key_out)
        self.assertEqual(ret, WALLY_EINVAL)

        # String paths: Invalid cases
        master.depth = 0
        B, W = FLAG_STR_BARE, FLAG_STR_WILDCARD
        cases = [('m',            0, 0),          # Empty resulting path (1)
                 ('m/',           0, 0),          # Empty resulting path (2)
                 ('/',            0, 0),          # Empty resulting path (3)
                 ('//',           0, 0),          # Trailing slash (1)
                 ('/1/',          0, 0),          # Trailing slash (2)
                 ('m/1',          B, 0),          # Non-bare path (1)
                 ('/1',           B, 0),          # Non-bare path (2)
                 ('/1//1',        0, 0),          # Missing number (1)
                 ('/1/h',         0, 0),          # Missing number (2)
                 ('/h',           0, 0),          # Missing number (3)
                 ('h',            B, 0),          # Missing number (bare)
                 ('/h1',          0, 0),          # Invalid hardened indicator position
                 ('m/2147483648', 0, 0),          # Child num too large
                 ('/*',           0, 0),          # Wildcard without flag
                 ('/*/*',         W, 0),          # More than one wildcard
                 ('/1*',          W, 0),          # Invalid wildcard position (1)
                 ('/*1',          W, 0),          # Invalid wildcard position (2)
                 ('/*',           W, 2147483648)] # Hardened wildcard

        for path, flags, wildcard in cases:
            flags = flags | FLAG_KEY_PRIVATE
            ret = bip32_key_from_parent_path_str_n(m, path, len(path), wildcard, flags, key_out)
            self.assertEqual(ret, WALLY_EINVAL)

        # After stripping the parents' private key, hardened path derivation fails
        self.assertEqual(bip32_key_strip_private_key(m), WALLY_OK)
        ret = bip32_key_from_parent_path_str_n(m, 'm/1h', len('m/1h'), 0, FLAG_KEY_PUBLIC, key_out)
        self.assertEqual(ret, WALLY_EINVAL)

    def test_wildcard(self):
        master, pub, priv = self.create_master_pub_priv()
        m = byref(master)
        flags = FLAG_STR_WILDCARD | FLAG_KEY_PRIVATE
        key_out, int_key_out = ext_key(), ext_key()
        cases = [('m/1/*',    55),
                 ('m/*',      55),
                 ('m/1/*/1',  55),
                 ('m/1/*h',   55),
                 ('m/*h',     55),
                 ('m/1/*h/1', 55)]

        for path, wildcard in cases:
            ret = bip32_key_from_parent_path_str(m, path, wildcard, flags, byref(key_out))
            self.assertEqual(ret, WALLY_OK)

            # Verify the result matches a key derived using the non-string version
            path = self.str_to_path(path, wildcard)
            c_path = self.path_to_c(path)
            ret = bip32_key_from_parent_path(m, c_path, len(path), flags, byref(int_key_out))
            self.assertEqual(ret, WALLY_OK)
            self.compare_keys(key_out, int_key_out, flags)

    def test_free_invalid(self):
        self.assertEqual(WALLY_EINVAL, bip32_key_free(None))

    def test_base58(self):
        key = self.create_master_pub_priv()[2]
        buf, buf_len = make_cbuffer('00' * 78)

        for flag in [FLAG_KEY_PRIVATE, FLAG_KEY_PUBLIC]:
            self.assertEqual(bip32_key_serialize(key, flag, buf, buf_len), WALLY_OK)
            exp_hex = h(buf).upper()

            ret, out = bip32_key_to_base58(key, flag)
            self.assertEqual(ret, WALLY_OK)
            out = utf8(out)

            key_out = POINTER(ext_key)()
            self.assertEqual(bip32_key_from_base58_alloc(out, byref(key_out)), WALLY_OK)
            self.assertEqual(bip32_key_serialize(key_out, flag, buf, buf_len), WALLY_OK)
            self.assertEqual(h(buf).upper(), exp_hex)

            self.assertEqual(bip32_key_from_base58_n_alloc(out, len(out), byref(key_out)), WALLY_OK)

            # Bad args: _n
            bad_args = [
                (None, len(out), byref(key_out)), # NULL input
                (out,  0,        byref(key_out)), # 0 length input
                (out,  0,        None),           # NULL output
            ]
            for base58, base58_len, output in bad_args:
                ret = bip32_key_from_base58_n_alloc(base58, base58_len, output)
                self.assertEqual(ret, WALLY_EINVAL) # 0 length Input

    def test_strip_private_key(self):
        self.assertEqual(bip32_key_strip_private_key(None), WALLY_EINVAL)

        _, pub, priv = self.create_master_pub_priv()

        self.assertEqual(priv.priv_key[0], FLAG_KEY_PRIVATE)
        self.assertEqual(bip32_key_strip_private_key(priv), WALLY_OK)
        self.assertEqual(priv.priv_key[0], FLAG_KEY_PUBLIC)
        self.assertEqual(priv.priv_key[1:], [0] * 32)

        self.assertEqual(bip32_key_strip_private_key(pub), WALLY_OK)
        self.assertEqual(pub.priv_key[0], FLAG_KEY_PUBLIC)
        self.assertEqual(pub.priv_key[1:], [0] * 32)

    def test_get_fingerprint(self):
        key = self.create_master_pub_priv()[2]
        buf, buf_len = make_cbuffer('00' * 4)

        self.assertEqual(bip32_key_get_fingerprint(key, buf, buf_len), WALLY_OK)
        self.assertEqual(h(buf), b'bbe06d6a')

        # As a sanity check, derive a child and ask for its parent fingerprint
        child = self.derive_key(key, 0, FLAG_KEY_PUBLIC)
        b32 = lambda k: h(k)[0:8]
        self.assertEqual(b32(child.parent160), b'bbe06d6a')

        # Check fingerprint when hash calculation was skipped during derivation
        child = self.derive_key(key, 0, FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH)
        self.assertEqual(bip32_key_get_fingerprint(child, buf, buf_len), WALLY_OK)
        self.assertEqual(h(buf), b'f09cb160')


if __name__ == '__main__':
    unittest.main()
