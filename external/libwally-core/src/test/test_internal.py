import unittest
from util import *

class InternalTests(unittest.TestCase):

    def test_secp_context(self):
        """Tests for secp context functions"""
        # Allocate and free a secp context
        ctx = wally_get_new_secp_context()
        wally_secp_context_free(ctx)

        # Freeing a NULL context is a no-op
        wally_secp_context_free(None)

    def test_operations(self):
        """Tests for overriding the libraries default operations"""
        # get_operations
        # NULL output
        self.assertEqual(wally_get_operations(None), WALLY_EINVAL)
        # Incorrect struct size
        ops = wally_operations()
        ops.struct_size = 0
        self.assertEqual(wally_get_operations(byref(ops)), WALLY_EINVAL)
        # Correct struct size succeeds
        ops.struct_size = sizeof(wally_operations)
        self.assertEqual(wally_get_operations(byref(ops)), WALLY_OK)

        # set_operations
        # NULL input
        self.assertEqual(wally_set_operations(None), WALLY_EINVAL)
        # Incorrect struct size
        ops.struct_size = 0
        self.assertEqual(wally_set_operations(byref(ops)), WALLY_EINVAL)
        # Correct struct size succeeds
        ops.struct_size = sizeof(wally_operations)
        # Set a secp context function that returns NULL
        def null_secp_context():
            return None
        secp_context_fn_t = CFUNCTYPE(c_void_p)
        ops.secp_context_fn = secp_context_fn_t(null_secp_context)
        self.assertEqual(wally_set_operations(byref(ops)), WALLY_OK)

        # Verify that the function was set correctly
        self.assertEqual(wally_secp_randomize(urandom(32), 32), WALLY_ENOMEM)

        # Verify that NULL members are unchanged when setting
        # TODO: OSX function casting results in a non-null pointer on OSX
        #ops.secp_context_fn = cast(0, secp_context_fn_t)
        #self.assertEqual(wally_set_operations(byref(ops)), WALLY_OK)
        #self.assertEqual(wally_secp_randomize(urandom(32), 32), WALLY_ENOMEM)


if __name__ == '__main__':
    unittest.main()
