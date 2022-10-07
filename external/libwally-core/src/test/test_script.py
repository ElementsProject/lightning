import unittest
from util import *

SCRIPT_TYPE_UNKNOWN = 0x0
SCRIPT_TYPE_OP_RETURN = 0x1
SCRIPT_TYPE_P2PKH = 0x2
SCRIPT_TYPE_P2SH = 0x4
SCRIPT_TYPE_P2WPKH = 0x8
SCRIPT_TYPE_P2WSH = 0x10
SCRIPT_TYPE_MULTISIG = 0x20
SCRIPT_TYPE_P2TR = 0x40

SCRIPT_MULTISIG_SORTED = 0x8

SCRIPT_HASH160 = 0x1
SCRIPT_SHA256  = 0x2

MAX_OP_RETURN_LEN = 80

SCRIPTPUBKEY_OP_RETURN_MAX_LEN = 83
SCRIPTPUBKEY_P2PKH_LEN = 25
SCRIPTPUBKEY_P2SH_LEN = 23
HASH160_LEN = 20
SCRIPTSIG_P2PKH_MAX_LEN = 140

PK, PK_LEN = make_cbuffer('11' * 33) # Fake compressed pubkey
PKU, PKU_LEN = make_cbuffer('11' * 65) # Fake uncompressed pubkey
SH, SH_LEN = make_cbuffer('11' * 20)  # Fake script hash
MPK_2, MPK_2_LEN = make_cbuffer('11' * 33 * 2) # Fake multiple (2) pubkeys
MPK_3, MPK_3_LEN =  make_cbuffer('11' * 33 * 3) # Fake multiple (3) pubkeys
SPK, SPK_LEN =  make_cbuffer('01'*33 + '10'*33 + '11'*33) # Fake multiple (3) sorted pubkeys
RPK, _ =  make_cbuffer('11'*33 + '10'*33 + '01'*33) # Fake multiple (3) sorted pubkeys, in reverse order
SPK_KEY_PUSH = '21'+'01'*33 + '21'+'10'*33 + '21'+'11'*33
MPK_15, MPK_15_LEN = make_cbuffer('11' * 33 * 15) # Fake multiple (15) pubkeys
MPK_16, MPK_16_LEN = make_cbuffer('11' * 33 * 16) # Fake multiple (16) pubkeys

SIG, SIG_LEN = make_cbuffer('11' * 64) # Fake signature
SIG_LARGE, SIG_LARGE_LEN = make_cbuffer('ff' * 64) # Fake out of range signature
SIG_COUPLE, SIG_COUPLE_LEN = make_cbuffer('11' * 64 * 2) # Fake couple of signatures
SIG_DER, SIG_DER_LEN = make_cbuffer('30450220' + '11'*32 + '0220' + '11'*32 + '01') # Fake DER encoded sig

RS_1of2, RS_1of2_LEN = make_cbuffer('5121' + '11'*33 + '21' + '11'*33 + '52ae') # Fake 1of2 redeem script
RS_2of2, RS_2of2_LEN = make_cbuffer('5221' + '11'*33 + '21' + '11'*33 + '52ae') # Fake 2of2 redeem script

class ScriptTests(unittest.TestCase):

    def test_scriptpubkey_get_type(self):
        """Tests for script analysis"""
        # Test invalid args, we test results with the functions that make scripts
        in_, in_len = make_cbuffer('00' * 16)
        for b, b_len in [(None, in_len), (in_, 0)]:
            ret, typ = wally_scriptpubkey_get_type(b, b_len)
            self.assertEqual(ret, WALLY_EINVAL)
            self.assertEqual(typ, SCRIPT_TYPE_UNKNOWN)

        # Segwit scripts
        segwit_cases = [
            [ '0014' + ('33' * 20), SCRIPT_TYPE_P2WPKH ],
            [ '0020' + ('33' * 32), SCRIPT_TYPE_P2WSH ],
            [ '5120' + ('33' * 32), SCRIPT_TYPE_P2TR ],
        ]
        for script_hex, expected_type in segwit_cases:
            script, script_len = make_cbuffer(script_hex)
            ret, typ = wally_scriptpubkey_get_type(script, script_len)
            self.assertEqual((ret, typ), (WALLY_OK, expected_type))

    def test_scriptpubkey_op_return_from_bytes(self):
        """Tests for creating OP_RETURN scriptPubKeys"""
        # Invalid args
        DATA, DATA_LEN = make_cbuffer('00' * MAX_OP_RETURN_LEN)
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_OP_RETURN_MAX_LEN)
        invalid_args = [
            (None, 20, 0, out, out_len), # Null bytes
            (DATA, DATA_LEN, 0x1, out, out_len), # Unsupported flags
            (DATA, DATA_LEN, 0, None, out_len), # Null output
            (DATA, DATA_LEN, 0, out, 0), # Short output len
            (DATA, DATA_LEN+1, 0, out, 0), # Long output len
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_op_return_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(DATA, DATA_LEN, 0, out, out_len),'6a4c50' + '00' * MAX_OP_RETURN_LEN],
            [(DATA, 0, 0, out, out_len),'6a00'], # Note that empty bytes are allowed
        ]
        for args, exp_script in valid_args:
            ret = wally_scriptpubkey_op_return_from_bytes(*args)
            exp_script, exp_script_len = make_cbuffer(exp_script)
            self.assertEqual(ret, (WALLY_OK, exp_script_len))
            self.assertEqual(args[3][:ret[1]], exp_script)
            ret = wally_scriptpubkey_get_type(out, ret[1])
            self.assertEqual(ret, (WALLY_OK, SCRIPT_TYPE_OP_RETURN))

    def test_scriptpubkey_p2pkh_from_bytes(self):
        """Tests for creating p2pkh scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2PKH_LEN)
        invalid_args = [
            (None, PK_LEN, SCRIPT_HASH160, out, out_len), # Null bytes
            (PK, 0, SCRIPT_HASH160, out, out_len), # Empty bytes
            (PK, PK_LEN, SCRIPT_SHA256, out, out_len), # Unsupported flags
            (PK, PK_LEN, SCRIPT_HASH160, None, out_len), # Null output
            (PK, PK_LEN, SCRIPT_HASH160, out, SCRIPTPUBKEY_P2PKH_LEN-1), # Short output len
            (PK, PK_LEN, 0, out, out_len), # Pubkey w/o SCRIPT_HASH160
            (PKU, PKU_LEN, 0, out, out_len), # Uncompressed pubkey w/o SCRIPT_HASH160
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_p2pkh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(PK, PK_LEN, SCRIPT_HASH160, out, out_len),'76a9148ec4cf3ee160b054e0abb6f5c8177b9ee56fa51e88ac'],
            [(PKU, PKU_LEN, SCRIPT_HASH160, out, out_len),'76a914e723a0f62396b8b03dbd9e48e9b9efe2eb704aab88ac'],
            [(PKU, HASH160_LEN, 0, out, out_len),'76a914111111111111111111111111111111111111111188ac'],
        ]
        for args, exp_script in valid_args:
            ret = wally_scriptpubkey_p2pkh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, SCRIPTPUBKEY_P2PKH_LEN))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(args[3], exp_script)
            ret = wally_scriptpubkey_get_type(out, SCRIPTPUBKEY_P2PKH_LEN)
            self.assertEqual(ret, (WALLY_OK, SCRIPT_TYPE_P2PKH))

    def test_scriptpubkey_p2sh_from_bytes(self):
        """Tests for creating p2sh scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        invalid_args = [
            (None, SH_LEN, SCRIPT_HASH160, out, out_len), # Null bytes
            (SH, 0, SCRIPT_HASH160, out, out_len), # Empty bytes
            (SH, SH_LEN, SCRIPT_SHA256, out, out_len), # Unsupported flags
            (SH, SH_LEN, SCRIPT_HASH160, None, out_len), # Null output
            (SH, SH_LEN, SCRIPT_HASH160, out, SCRIPTPUBKEY_P2SH_LEN-1), # Short output len
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_p2sh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(SH, SH_LEN, SCRIPT_HASH160, out, out_len), 'a914a9592ad6e8b4b5042937a3ee0d425d17c40d04b387'],
            [(SH, SH_LEN, 0, out, out_len), 'a914111111111111111111111111111111111111111187'],
        ]
        for args, exp_script in valid_args:
            ret = wally_scriptpubkey_p2sh_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, SCRIPTPUBKEY_P2SH_LEN))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(args[3], exp_script)
            ret = wally_scriptpubkey_get_type(out, SCRIPTPUBKEY_P2SH_LEN)
            self.assertEqual(ret, (WALLY_OK, SCRIPT_TYPE_P2SH))

    def test_scriptpubkey_multisig_from_bytes(self):
        """Tests for creating multisig scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * 33 * 3)
        invalid_args = [
            (None, MPK_2_LEN, 1, 0, out, out_len), # Null bytes
            (MPK_2, 0, 1, 0, out, out_len), # Empty bytes
            (MPK_2, MPK_2_LEN+1, 1, 0, out, out_len), # Unsupported bytes len
            (SH, SH_LEN, 1, 0, out, out_len), # Too few pubkeys
            (MPK_16, MPK_16_LEN, 1, 0, out, out_len), # Too many pubkeys
            (MPK_2, MPK_2_LEN, 0, 0, out, out_len), # Too low threshold
            (MPK_2, MPK_2_LEN, 17, 0, out, out_len), # Too high threshold
            (MPK_2, MPK_2_LEN, 3, 0, out, out_len), # Inconsistent threshold
            (MPK_2, MPK_2_LEN, 1, SCRIPT_HASH160, out, out_len), # Unsupported flags
            (MPK_2, MPK_2_LEN, 1, 0, None, out_len), # Null output
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_multisig_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        out, out_len = make_cbuffer('00' * 33 * 16)
        valid_args = [
            [(MPK_2, MPK_2_LEN,    1, 0, out, out_len), '51'+('21'+'11'*33)*2+'52ae'],  # 1of2
            [(MPK_2, MPK_2_LEN,    2, 0, out, out_len), '52'+('21'+'11'*33)*2+'52ae'],  # 2of2
            [(MPK_3, MPK_3_LEN,    1, 0, out, out_len), '51'+('21'+'11'*33)*3+'53ae'],  # 1of3
            [(MPK_3, MPK_3_LEN,    2, 0, out, out_len), '52'+('21'+'11'*33)*3+'53ae'],  # 2of3
            [(MPK_3, MPK_3_LEN,    3, 0, out, out_len), '53'+('21'+'11'*33)*3+'53ae'],  # 3of3
            [(MPK_15, MPK_15_LEN,  1, 0, out, out_len), '51'+('21'+'11'*33)*15+'5fae'], # 1of15
            [(MPK_15, MPK_15_LEN, 15, 0, out, out_len), '5f'+('21'+'11'*33)*15+'5fae'], # 15of15
            # 1of3 sorted
            [(SPK, SPK_LEN, 1, 0, out, out_len), '51'+ SPK_KEY_PUSH + '53ae'],
            # 1of3 sorted (SCRIPT_MULTISIG_SORTED should have no effect)
            [(SPK, SPK_LEN, 1, SCRIPT_MULTISIG_SORTED, out, out_len), '51'+ SPK_KEY_PUSH + '53ae'],
            # 1of3 sorted reverse (BIP67)
            [(RPK, SPK_LEN, 1, SCRIPT_MULTISIG_SORTED, out, out_len), '51'+ SPK_KEY_PUSH + '53ae'],
        ]
        for args, exp_script in valid_args:
            (pubkeys, pubkeys_len, threshold, flags, out, out_len) = args
            script_len = 3 + (pubkeys_len // 33 * (33 + 1))
            ret = wally_scriptpubkey_multisig_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, script_len))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(out[:script_len], exp_script)
            # Check the script is identified by scriptpubkey_get_type
            ret = wally_scriptpubkey_get_type(out, script_len)
            self.assertEqual(ret, (WALLY_OK, SCRIPT_TYPE_MULTISIG))
            # Check a too-short output buffer
            short_out, short_out_len = make_cbuffer('00' * (script_len - 1))
            short_args = (pubkeys, pubkeys_len, threshold, flags, short_out, short_out_len)
            ret = wally_scriptpubkey_multisig_from_bytes(*short_args)
            self.assertEqual(ret, (WALLY_OK, script_len))

    def test_scriptpubkey_csv_2of2_then_1_from_bytes(self):
        """Tests for creating csv 2of2 then 1 scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * 33 * 3)
        invalid_args = [
            (None, MPK_2_LEN, 1, 0, out, out_len), # Null bytes
            (MPK_2, 0, 1, 0, out, out_len), # Empty bytes
            (MPK_2, MPK_2_LEN+1, 1, 0, out, out_len), # Unsupported bytes len
            (MPK_2, MPK_2_LEN, 16, 0, out, out_len), # Too few csv blocks
            (MPK_2, MPK_2_LEN, 0x10000, 0, out, out_len), # Too many csv blocks
            (MPK_2, MPK_2_LEN, 1, SCRIPT_HASH160, out, out_len), # Unsupported flags
            (MPK_2, MPK_2_LEN, 1, 0, None, out_len), # Null output
        ]
        for args in invalid_args:
            for fn in [wally_scriptpubkey_csv_2of2_then_1_from_bytes,
                       wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt]:
                self.assertEqual(fn(*args), (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(MPK_2, MPK_2_LEN, 17, 0, out, out_len), '748c6321'+'11'*33+'ad670111b2756821'+'11'*33+'ac'],
            [(MPK_2, MPK_2_LEN, 0x8000, 0, out, out_len), '748c6321'+'11'*33+'ad6703008000b2756821'+'11'*33+'ac'],
        ]
        for args, exp_script in valid_args:
            csv_len = 1 + (args[2] > 0x7f) + (args[2] > 0x7fff)
            script_len = 2 * (33 + 1) + 9 + 1 + csv_len
            ret = wally_scriptpubkey_csv_2of2_then_1_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, script_len))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(args[4][:script_len], exp_script)
            ret = wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt(*args)
            self.assertEqual(ret, (WALLY_OK, script_len - 3))
            # Check a too-short output buffer
            short_out, short_out_len = make_cbuffer('00' * (script_len - 1))
            short_args = (args[0], args[1], args[2], args[3], short_out, short_out_len)
            ret = wally_scriptpubkey_csv_2of2_then_1_from_bytes(*short_args)
            self.assertEqual(ret, (WALLY_OK, script_len))
            short_args = (args[0], args[1], args[2], args[3], short_out, short_out_len - 3)
            ret = wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt(*short_args)
            self.assertEqual(ret, (WALLY_OK, script_len - 3))

    def test_scriptpubkey_csv_2of3_then_2_from_bytes(self):
        """Tests for creating csv 2of3 then 2 scriptPubKeys"""
        # Invalid args
        out, out_len = make_cbuffer('00' * 33 * 4)
        invalid_args = [
            (None, MPK_3_LEN, 1, 0, out, out_len), # Null bytes
            (MPK_3, 0, 1, 0, out, out_len), # Empty bytes
            (MPK_3, MPK_3_LEN+1, 1, 0, out, out_len), # Unsupported bytes len
            (MPK_3, MPK_3_LEN, 16, 0, out, out_len), # Too few csv blocks
            (MPK_3, MPK_3_LEN, 0x10000, 0, out, out_len), # Too many csv blocks
            (MPK_3, MPK_3_LEN, 1, SCRIPT_HASH160, out, out_len), # Unsupported flags
            (MPK_3, MPK_3_LEN, 1, 0, None, out_len), # Null output
        ]
        for args in invalid_args:
            ret = wally_scriptpubkey_csv_2of3_then_2_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(MPK_3, MPK_3_LEN, 17, 0, out, out_len), '748c8c635221'+'11'*33+'670111b275510068'+('21'+'11'*33)*2+'53ae'],
            [(MPK_3, MPK_3_LEN, 0x8000, 0, out, out_len), '748c8c635221'+'11'*33+'6703008000b275510068'+('21'+'11'*33)*2+'53ae'],
        ]
        for args, exp_script in valid_args:
            csv_len = 1 + (args[2] > 0x7f) + (args[2] > 0x7fff)
            script_len = 3 * (33 + 1) + 13 + 1 + csv_len
            ret = wally_scriptpubkey_csv_2of3_then_2_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, script_len))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(args[4][:script_len], exp_script)
            # Check a too-short output buffer
            short_out, short_out_len = make_cbuffer('00' * (script_len - 1))
            short_args = (args[0], args[1], args[2], args[3], short_out, short_out_len)
            ret = wally_scriptpubkey_csv_2of3_then_2_from_bytes(*short_args)
            self.assertEqual(ret, (WALLY_OK, script_len))

    def test_scriptsig_p2pkh(self):
        """Tests for creating p2pkh scriptsig"""
        # From DER
        # Invalid args
        out, out_len = make_cbuffer('00' * SCRIPTSIG_P2PKH_MAX_LEN)
        invalid_args = [
            (None, PK_LEN, SIG_DER, SIG_DER_LEN, out, out_len), # Null pubkey
            (PK, 32, SIG_DER, SIG_DER_LEN, out, out_len), # Unsupported pubkey length
            (PK, PK_LEN, None, SIG_DER_LEN, out, out_len), # Null sig
            (PK, PK_LEN, SIG_DER, 0, out, out_len), # Too short len sig
            (PK, PK_LEN, SIG_DER, 74, out, out_len), # Too long len sig
            (PK, PK_LEN, SIG_DER, SIG_DER_LEN, None, out_len), # Null output
        ]
        for args in invalid_args:
            ret = wally_scriptsig_p2pkh_from_der(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(PK, PK_LEN, SIG_DER, SIG_DER_LEN, out, out_len), '4730450220'+'11'*32+'0220'+'11'*32+'0121'+'11'*33],
            [(PKU, PKU_LEN, SIG_DER, SIG_DER_LEN, out, out_len), '4730450220'+'11'*32+'0220'+'11'*32+'0141'+'11'*65],
        ]
        for args, exp_script in valid_args:
            ret = wally_scriptsig_p2pkh_from_der(*args)
            self.assertEqual(ret, (WALLY_OK, args[1] + args[3] + 2))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(args[4][:(args[1] + args[3] + 2)], exp_script)

        # From sig
        # Invalid args
        out, out_len = make_cbuffer('00' * 140)
        invalid_args = [
            (PK, PK_LEN, SIG, SIG_LEN, 0x100, out, out_len),
            (PK, PK_LEN, SIG_LARGE, SIG_LARGE_LEN, 0xff, out, out_len), # is it correct to test it here?
        ]
        for args in invalid_args:
            ret = wally_scriptsig_p2pkh_from_sig(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            (PK, PK_LEN, SIG, SIG_LEN, 0x01, out, out_len),
            (PKU, PKU_LEN, SIG, SIG_LEN, 0x02, out, out_len),
        ]
        for args in valid_args:
            ret = wally_scriptsig_p2pkh_from_sig(*args)
            self.assertEqual(ret, (WALLY_OK, args[1] + args[3] + 9))

    def test_scriptsig_multisig(self):
        """Tests for creating multisig scriptsig"""

        def c_sighash(s):
            c_sighash = (c_uint * len(s))()
            for i, n in enumerate(s):
                c_sighash[i] = n
            return c_sighash

        # Invalid args
        out, out_len = make_cbuffer('00'*300)
        invalid_args = [
            (None, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 1, 0, out, out_len), # Null script
            (RS_1of2, 0, SIG, SIG_LEN, c_sighash([0x01]), 1, 0, out, out_len), # Empty script
            (RS_1of2, RS_1of2_LEN, None, SIG_LEN, c_sighash([0x01]), 1, 0, out, out_len), # Null bytes
            (RS_1of2, RS_1of2_LEN, SIG, 0, c_sighash([0x01]), 1, 0, out, out_len), # Empty bytes or too few sigs
            (RS_1of2, RS_1of2_LEN, SIG, SIG_LEN+1, c_sighash([0x01]), 1, 0, out, out_len), # Unsupported bytes len
            (RS_1of2, RS_1of2_LEN, SIG, 16, c_sighash([0x01]), 1, 0, out, out_len), # Too many sigs
            (RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, None, 1, 0, out, out_len), # Null sighash
            (RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 2, 0, out, out_len), # Inconsistent sighash length
            (RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 1, 1, out, out_len), # Unsupported flags
            (RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 1, 0, None, out_len), # Null output
        ]
        for args in invalid_args:
            ret = wally_scriptsig_multisig_from_bytes(*args)
            self.assertEqual(ret, (WALLY_EINVAL, 0))

        # Valid cases
        valid_args = [
            [(RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 1, 0, out, out_len),
             '00'+'4730440220'+'11'*32+'0220'+'11'*32+'01475121'+'11'*33+'21'+'11'*33+'52ae'],
            [(RS_1of2, RS_1of2_LEN, SIG, SIG_LEN, c_sighash([0x80]), 1, 0, out, out_len),
             '00'+'4730440220'+'11'*32+'0220'+'11'*32+'80475121'+'11'*33+'21'+'11'*33+'52ae'],
            [(RS_2of2, RS_2of2_LEN, SIG, SIG_LEN, c_sighash([0x01]), 1, 0, out, out_len),
             '00'+'4730440220'+'11'*32+'0220'+'11'*32+'01475221'+'11'*33+'21'+'11'*33+'52ae'],
            [(RS_2of2, RS_2of2_LEN, SIG_COUPLE, SIG_COUPLE_LEN, c_sighash([0x01, 0x02]), 2, 0, out, out_len),
             '00'+'4730440220'+'11'*32+'0220'+'11'*32+'01'+'4730440220'+'11'*32+'0220'+'11'*32+'02475221'+'11'*33+'21'+'11'*33+'52ae'],
        ]
        for args, exp_script in valid_args:
            ret = wally_scriptsig_multisig_from_bytes(*args)
            self.assertEqual(ret, (WALLY_OK, 73 + 72 * args[5]))
            exp_script, _ = make_cbuffer(exp_script)
            self.assertEqual(out[:(73 + 72 * args[5])], exp_script)

    def test_script_push_from_bytes(self):
        """Tests for encoding script pushes"""
        out, out_len = make_cbuffer('00' * 165536)
        for data, prefix in {'00' * 75: '4b',
                             '00' * 76: '4c4c',
                             '00' * 255: '4cff',
                             '00' * 256: '4d0001'}.items():

            in_, in_len = make_cbuffer(data)
            ret, written = wally_script_push_from_bytes(in_, in_len, 0, out, out_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(data)/2 + len(prefix)/2)
            self.assertEqual(h(out[:written]), utf8(prefix + data))

            # Too short out_len returns the required number of bytes
            ret, written = wally_script_push_from_bytes(in_, in_len, 0, out, 20)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, len(data)/2 + len(prefix)/2)

    def test_varint_to_bytes(self):
        out, out_len = make_cbuffer('00' * 9)

        # Invalid args
        invalid_cases = [
                (252,     None, out_len), # Null output
                (252,     out, 0),        # 2^8  short buffer
                (253,     out, 2),        # 2^16 short buffer
                (2**16-1, out, 2),        # 2^16 short buffer
                (2**32-1, out, 4),        # 2^32 short buffer
                (2**64-1, out, 8),        # 2^64 short buffer
        ]
        for value, out_buff, out_buff_len in invalid_cases:
            ret, written = wally_varint_to_bytes(value, out_buff, out_buff_len)
            self.assertEqual(ret, WALLY_EINVAL)
            ret, written = wally_varint_get_length(value)

        # Valid cases
        valid_cases = [
            (0, "00"),
            (1, "01"),
            (252, "fc"),
            (253, "fdfd00"),
            ((2**16-1) + 10, "fe09000100"),
            ((2**32-1) + 10, "ff0900000001000000"),
            (2**64-1, "ffffffffffffffffff"),
        ]
        for value, expected in valid_cases:
            ret, written = wally_varint_to_bytes(value, out, out_len)
            self.assertEqual(ret, WALLY_OK)
            expected, expected_len = make_cbuffer(expected)
            self.assertEqual(written, expected_len)
            self.assertEqual(out[:written], expected)

            ret, written = wally_varint_get_length(value)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, expected_len)

    def test_varbuff_to_bytes(self):
        varint_size = 3
        in_, in_len = make_cbuffer('aa' * 253)
        out, out_len = make_cbuffer('00' * (in_len + varint_size))

        # Invalid cases
        invalid_cases = [
            (None, in_len, out,  out_len),     # Null buffer with length
            (in_,  0,      out,  out_len),     # Buffer with 0 length
            (in_,  in_len, None, out_len),     # Null output
            (in_,  in_len, out,  out_len - 1), # Too-small output
        ]
        for buff, buff_len, out_buff, out_buff_len in invalid_cases:
            ret, written = wally_varbuff_to_bytes(buff, buff_len, out_buff, out_buff_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # Valid cases
        ret, varbuff_len = wally_varbuff_get_length(in_, in_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(varbuff_len, in_len + varint_size)

        ret, written = wally_varbuff_to_bytes(in_, in_len, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, varbuff_len)
        self.assertEqual(out[:written], make_cbuffer("fdfd00" + 'aa' * 253)[0])

    def test_wally_witness_program_from_bytes(self):
        valid_cases = [('00' * 20, 0, '0014'+'00'*20),
                       ('00' * 32, 0, '0020'+'00'*32),
                       ('00' * 50, SCRIPT_HASH160, '0014f71015b29ff2583558877ed16a59e4f8f451daa3'),
                       ('00' * 50, SCRIPT_SHA256, '0020cc2786e1f9910a9d811400edcddaf7075195f7a16b216dcbefba3bc7c4f2ae51')]

        out, out_len = make_cbuffer('00' * 100)
        for data, flags, exp_program in valid_cases:
            in_, in_len = make_cbuffer(data)
            ret, written = wally_witness_program_from_bytes(in_, in_len, flags, out, out_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(out[:written], make_cbuffer(exp_program)[0])

        invalid_cases = [('00' * 50, 0), # Invalid unhashed length
                ]
        for data, flags in invalid_cases:
            in_, in_len = make_cbuffer(data)
            ret, written = wally_witness_program_from_bytes(in_, in_len, flags, out, out_len)
            self.assertEqual(ret, WALLY_EINVAL)

if __name__ == '__main__':
    unittest.main()
