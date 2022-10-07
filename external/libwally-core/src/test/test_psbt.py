import binascii
import json
import unittest
from util import *

FLAG_GRIND_R = 0x4

class PSBTTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""
        with open(root_dir + 'src/data/psbt.json', 'r') as f:
            d = json.load(f)
            invalids = d['invalid']
            valids = d['valid']
            creators = d['creator']
            signers = d['signer']
            inval_signers = d['inval_signer']
            combiners = d['combiner']
            finalizers = d['finalizer']
            extractors = d['extractor']

        for invalid in invalids:
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(invalid.encode('utf-8'), pointer(wally_psbt())))

        for valid in valids:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(valid['psbt'].encode('utf-8'), psbt))
            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['psbt'], reser)
            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])

        for creator in creators:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(0, 2, 2, 0, psbt))

            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))
            for txin in creator['inputs']:
                tx_in = pointer(wally_tx_input())
                txid, txid_len = make_cbuffer(txin['txid'])
                ret = wally_tx_input_init_alloc(txid[::-1], txid_len, txin['vout'], 0xffffffff, None, 0, None, tx_in)
                self.assertEqual(WALLY_OK, ret)
                self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
            for txout in creator['outputs']:
                addr = txout['addr']
                amt = txout['amt']
                spk, spk_len = make_cbuffer('00' * (32 + 2))
                ret, written = wally_addr_segwit_to_bytes(addr.encode('utf-8'), 'bcrt'.encode('utf-8'), 0, spk, spk_len)
                self.assertEqual(WALLY_OK, ret)
                output = pointer(wally_tx_output())
                self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(amt, spk, written, output))
                self.assertEqual(WALLY_OK, wally_tx_add_output(tx, output))

            self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, tx))
            ret, ser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(creator['result'], ser)

        for combiner in combiners:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(combiner['combine'][0].encode('utf-8'), psbt))
            for src_b64 in combiner['combine'][1:]:
                src = pointer(wally_psbt())
                self.assertEqual(WALLY_OK, wally_psbt_from_base64(src_b64.encode('utf-8'), src))
                self.assertEqual(WALLY_OK, wally_psbt_combine(psbt, src))
                self.assertEqual(WALLY_OK, wally_psbt_free(src))
            ret, psbt_b64 = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(combiner['result'], psbt_b64)

        for signer in signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(signer['psbt'].encode('utf-8'), psbt))
            for priv in signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_OK, wally_psbt_sign(psbt, buf, buf_len, FLAG_GRIND_R))

            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            # Check that we can *demarshal* the signed PSBT (some bugs only appear here)
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(reser, psbt))
            self.assertEqual(signer['result'], reser)

        for inval_signer in inval_signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(inval_signer['psbt'].encode('utf-8'), psbt))

            for priv in inval_signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_EINVAL, wally_psbt_sign(psbt, buf, buf_len, FLAG_GRIND_R))

        for finalizer in finalizers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(finalizer['finalize'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt))
            ret, is_finalized = wally_psbt_is_finalized(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(1, is_finalized)
            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(finalizer['result'], reser)

        for extractor in extractors:
            psbt = pointer(wally_psbt())
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(extractor['extract'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, tx))
            ret, reser = wally_tx_to_hex(tx, 1)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(extractor['result'], reser)

    def test_map(self):
        """Test PSBT map helper functions"""
        m = pointer(wally_map())
        # Test keys. Once sorted we expect order k3, k2, k1
        key1, key1_len = make_cbuffer('505050')
        key2, key2_len = make_cbuffer('40404040')
        key3, key3_len = make_cbuffer('404040')
        val, val_len = make_cbuffer('ffffffff')

        # Check invalid args
        self.assertEqual(wally_map_init_alloc(0, None), WALLY_EINVAL)
        self.assertEqual(wally_map_init_alloc(0, m), WALLY_OK)

        for args in [(None, key1, key1_len, val,  val_len), # Null map
                     (m,    None, key1_len, val,  val_len), # Null key
                     (m,    key1, 0,        val,  val_len), # 0 length key
                     (m,    key1, key1_len, None, val_len), # Null value
                     (m,    key1, key1_len, val,  0)]:      # 0 length value
            self.assertEqual(wally_map_add(*args), WALLY_EINVAL)
            # TODO: wally_map_add_keypath_item

        for args in [(None, key1, key1_len), # Null map
                     (m,    None, key1_len), # Null key
                     (m,    key1, 0)]:       # 0 length key
            self.assertEqual(wally_map_find(*args), (WALLY_EINVAL, 0))

        self.assertEqual(wally_map_sort(None, 0), WALLY_EINVAL) # Null map
        self.assertEqual(wally_map_sort(m, 1),    WALLY_EINVAL) # Invalid flags

        self.assertEqual(wally_map_free(None), WALLY_OK) # Null is OK

        # Add and find each key
        for k, l, i in [(key1, key1_len, 1),
                        (key2, key2_len, 2),
                        (key3, key3_len, 3)]:
            self.assertEqual(wally_map_add(m, k, l, val, val_len), WALLY_OK)
            self.assertEqual(wally_map_find(m, k, l), (WALLY_OK, i))

        # Sort
        self.assertEqual(wally_map_sort(m, 0), WALLY_OK)

        # Verify sort order
        for k, l, i in [(key1, key1_len, 3),
                        (key2, key2_len, 2),
                        (key3, key3_len, 1)]:
            self.assertEqual(wally_map_find(m, k, l), (WALLY_OK, i))

        self.assertEqual(wally_map_free(m), WALLY_OK)

    def test_v20dot1_changes(self):
        """See https://github.com/ElementsProject/libwally-core/issues/213
           Verify that core v20.1 changes to address the segwit fee attack now work"""
        b64 = "cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBBYAFIsieXd6AAeP8TXHKZ329Z0nuSeZIgYD/ajyzV90ghQ+0zIO2mVSd3fGYhvwYjakGCY4WNYxoeYEiyJ5dwABAHICAAAAAfezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAAAAAAD9////AhAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHHcIAAAAAAAAWABSUD3a8pIYaaLvKdZxoEPFfo8vlDwAAAAABASAQJwAAAAAAABepFFyX1J/5zWzQ/mvkIah58gksvaD5hwEEFgAUyRIBhZwlI4RLT6NDHluovlrN3iAiBgIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPATJEgGFACICAq8h+ABETC5Tczuts3xhCtXAzIEUHM5iMugvwFMrtCc4EBK06cYAAACAAQAAgMMAAIAAAA=="
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_from_base64(b64.encode('utf-8'), psbt), WALLY_OK)
        buf, buf_len = make_cbuffer('00'*32)
        for priv in ['cTatuMdjH4YA4F1pAm11QdbCt88T8t2TTMoAvVGzAxWAWmQZtkBZ',
                     'cR5yyo2g1SzzwCw2QAREzF7XhYuXZS9SzTTf8A9qerri9EXZcRYS']:
            self.assertEqual(wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len), WALLY_OK)
            self.assertEqual(wally_psbt_sign(psbt, buf, buf_len, FLAG_GRIND_R), WALLY_OK)
        self.assertEqual(wally_psbt_finalize(psbt), WALLY_OK)
        ret, new64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        expected_b64 = "cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBxcWABSLInl3egAHj/E1xymd9vWdJ7knmQEIawJHMEQCIAkPXe9sdpRjSDTjJ0gIrpwGGIWJby9xSd1rS9hPe1f0AiAJgqR7PL3G/MXyUu4KZdS1Z2O14fjxstF43k634u+4GAEhA/2o8s1fdIIUPtMyDtplUnd3xmIb8GI2pBgmOFjWMaHmAAEAcgIAAAAB97Oqk3E4gOTA0WF9lUti+6FDGqao08nCXJduFzxy4s8AAAAAAP3///8CECcAAAAAAAAXqRRcl9Sf+c1s0P5r5CGoefIJLL2g+YcdwgAAAAAAABYAFJQPdrykhhpou8p1nGgQ8V+jy+UPAAAAAAEBIBAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHAQcXFgAUyRIBhZwlI4RLT6NDHluovlrN3iABCGsCRzBEAiAOzRsNZ+2Et+VGCY/nXWO7WxGI3u39kpi025cUaJXQJgIgL6KtMqPfAwXGktQFWr9SNnOrHF2xjvKQI2VdeuQbxt0BIQIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPAAiAgKvIfgAREwuU3M7rbN8YQrVwMyBFBzOYjLoL8BTK7QnOBAStOnGAAAAgAEAAIDDAACAAAA="
        self.assertEqual(new64.encode('utf-8'), expected_b64.encode('utf-8'))


if __name__ == '__main__':
    unittest.main()
