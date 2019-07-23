#!/usr/bin/env python3
"""A simple handshake and encryption test.

This script will listen on port 9736 for incoming Lightning Network protocol
connections, perform the cryptographic handshake, send 10k small pings, and
then exit, closing the connection. This is useful to check the correct
rotation of send- and receive-keys in the implementation.

"""


from pyln.proto.wire import LightningServerSocket, PrivateKey
from binascii import hexlify, unhexlify
import time
import threading

ls_privkey = PrivateKey(unhexlify(
    b'1111111111111111111111111111111111111111111111111111111111111111'
))
listener = LightningServerSocket(ls_privkey)
print("Node ID: {}".format(ls_privkey.public_key()))

listener.bind(('0.0.0.0', 9735))
listener.listen()
c, a = listener.accept()

c.send_message(b'\x00\x10\x00\x00\x00\x01\xaa')
print(c.read_message())

num_pings = 10000


def read_loop(c):
    for i in range(num_pings):
        print("Recv", i, hexlify(c.read_message()))


t = threading.Thread(target=read_loop, args=(c,))
t.daemon = True
t.start()
for i in range(num_pings):
    m = b'\x00\x12\x00\x01\x00\x01\x00'
    c.send_message(m)
    print("Sent", i, hexlify(m))
    time.sleep(0.01)

t.join()
