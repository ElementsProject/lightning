#!/usr/bin/env python3
"""Simple connect and read test

Connects to a peer, performs handshake and then just prints all the messages
it gets.

"""

from pyln.proto.wire import connect, PrivateKey, PublicKey
from binascii import unhexlify, hexlify

ls_privkey = PrivateKey(unhexlify(
    b'1111111111111111111111111111111111111111111111111111111111111111'
))
remote_pubkey = PublicKey(unhexlify(
    b'03b31e5bbf2cdbe115b485a2b480e70a1ef3951a0dc6df4b1232e0e56f3dce18d6'
))

lc = connect(ls_privkey, remote_pubkey, '127.0.0.1', 9375)

# Send an init message, with no global features, and 0b10101010 as local
# features.
lc.send_message(b'\x00\x10\x00\x00\x00\x01\xaa')

# Now just read whatever our peer decides to send us
while True:
    print(hexlify(lc.read_message()).decode('ASCII'))
