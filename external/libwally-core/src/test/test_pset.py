import json
import unittest
from util import *

class PSETTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""

        with open(root_dir + 'src/data/pset.json', 'r') as f:
            d = json.load(f)
            valids = d['valid']

        for valid in valids:
            psbt_out = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(utf8(valid['pset']), psbt_out))
            ret, b64 = wally_psbt_to_base64(psbt_out, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['pset'], b64)
            ret, length = wally_psbt_get_length(psbt_out, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])


if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
