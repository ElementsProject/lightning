from binascii import hexlify, unhexlify
from pyln.proto.wire import PrivateKey, PublicKey, LightningConnection
import socket
from pyln.proto import wire
import threading


def test_primitives():
    raw_privkey = unhexlify('1111111111111111111111111111111111111111111111111111111111111111')
    privkey = PrivateKey(raw_privkey)
    pubkey = privkey.public_key()
    assert(hexlify(pubkey.serializeCompressed()) == b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')

    # Now try with the raw constructor once more
    pubkey = PublicKey(unhexlify(b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'))
    assert(hexlify(pubkey.serializeCompressed()) == b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')


def test_encrypt_decrypt():
    """ Test encryptWithAD and decryptWithAD primitives
    Taken from https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#initiator-tests
    """
    inp = [
        b'e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f',
        b'000000000000000000000000',
        b'9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c',
        b''
    ]
    inp = [unhexlify(i) for i in inp]
    c = wire.encryptWithAD(*inp)
    assert(hexlify(c) == b'0df6086551151f58b8afe6c195782c6a')

    # h=0x9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce
    inp[3] = c
    d = wire.decryptWithAD(*inp)
    assert(hexlify(d) == b'')


def test_handshake():
    """Go through the test vector step-by-step.
    """
    rs_privkey = PrivateKey(unhexlify('2121212121212121212121212121212121212121212121212121212121212121'))
    rs_pubkey = rs_privkey.public_key()
    assert(hexlify(rs_pubkey.serializeCompressed()) == b'028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7')

    ls_privkey = PrivateKey(unhexlify('1111111111111111111111111111111111111111111111111111111111111111'))
    ls_pubkey = ls_privkey.public_key()
    assert(hexlify(ls_pubkey.serializeCompressed()) == b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')

    c1, c2 = socket.socketpair()

    lc1 = LightningConnection(c1, rs_pubkey, ls_privkey, is_initiator=True)
    lc2 = LightningConnection(c2, ls_pubkey, rs_privkey, is_initiator=False)

    # Override the generated ephemeral key for the test:
    lc1.handshake['e'] = PrivateKey(unhexlify('1212121212121212121212121212121212121212121212121212121212121212'))
    lc2.handshake['e'] = PrivateKey(unhexlify(b'2222222222222222222222222222222222222222222222222222222222222222'))
    assert(hexlify(lc1.handshake['e'].public_key().serializeCompressed()) == b'036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7')

    assert(hexlify(lc1.handshake['h']) == b'8401b3fdcaaa710b5405400536a3d5fd7792fe8e7fe29cd8b687216fe323ecbd')
    assert(lc1.handshake['h'] == lc2.handshake['h'])
    m = lc1.handshake_act_one_initiator()
    assert(hexlify(m) == b'00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a')

    lc2.handshake_act_one_responder(m)
    assert(hexlify(lc1.handshake['h']) == b'9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce')
    assert(hexlify(lc1.handshake['h']) == hexlify(lc2.handshake['h']))

    assert(hexlify(lc1.chaining_key) == b'b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f')
    assert(hexlify(lc2.chaining_key) == b'b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f')

    m = lc2.handshake_act_two_responder()
    assert(hexlify(m) == b'0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae')
    assert(hexlify(lc2.handshake['h']) == b'90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72')

    lc1.handshake_act_two_initiator(m)
    assert(hexlify(lc1.handshake['h']) == b'90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72')

    assert(hexlify(lc1.chaining_key) == b'e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba')
    assert(hexlify(lc2.chaining_key) == b'e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba')

    m = lc1.handshake_act_three_initiator()
    assert(hexlify(m) == b'00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba')
    assert(hexlify(lc1.sk) == b'969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    assert(hexlify(lc1.rk) == b'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')
    lc2.handshake_act_three_responder(m)

    assert(lc1.rk == lc2.sk)
    assert(lc1.sk == lc2.rk)
    assert(lc1.sn == lc2.rn)
    assert(lc1.rn == lc2.sn)
    assert(hexlify(lc2.rk) == b'969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    assert(hexlify(lc2.sk) == b'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')
    lc1.sck = lc1.chaining_key
    lc2.sck = lc2.chaining_key
    lc1.rck = lc1.chaining_key
    lc2.rck = lc2.chaining_key

    assert(lc1.chaining_key == lc2.chaining_key)
    assert(hexlify(lc1.chaining_key) == b'919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01')


def test_shake():
    rs_privkey = PrivateKey(unhexlify('2121212121212121212121212121212121212121212121212121212121212121'))
    rs_pubkey = rs_privkey.public_key()
    assert(hexlify(rs_pubkey.serializeCompressed()) == b'028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7')

    ls_privkey = PrivateKey(unhexlify('1111111111111111111111111111111111111111111111111111111111111111'))
    ls_pubkey = ls_privkey.public_key()
    assert(hexlify(ls_pubkey.serializeCompressed()) == b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')

    c1, c2 = socket.socketpair()

    lc1 = LightningConnection(c1, rs_pubkey, ls_privkey, is_initiator=True)
    lc2 = LightningConnection(c2, ls_pubkey, rs_privkey, is_initiator=False)

    t = threading.Thread(target=lc2.shake)
    t.start()
    lc1.shake()
    t.join()

    assert(lc1.rk == lc2.sk)
    assert(lc1.sk == lc2.rk)
    assert(lc1.sn == lc2.rn)
    assert(lc1.rn == lc2.sn)


def test_read_key_rotation():
    ls_privkey = PrivateKey(unhexlify('1111111111111111111111111111111111111111111111111111111111111111'))
    rs_privkey = PrivateKey(unhexlify('2121212121212121212121212121212121212121212121212121212121212121'))
    rs_pubkey = rs_privkey.public_key()
    c1, c2 = socket.socketpair()
    lc = LightningConnection(c1, rs_pubkey, ls_privkey, is_initiator=True)
    # ck=0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01
    # sk=0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9
    # rk=0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442
    lc.chaining_key = unhexlify(b'919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01')
    lc.sk = unhexlify(b'969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    lc.rk = unhexlify(b'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')
    lc.sn, lc.rn = 0, 0
    lc.sck, lc.rck = lc.chaining_key, lc.chaining_key

    msg = unhexlify(b'68656c6c6f')
    lc.send_message(msg)
    m = c2.recv(18 + 21)
    assert(hexlify(m) == b'cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95')

    # Send 498 more messages, to get just below the switch threshold
    for i in range(0, 498):
        lc.send_message(msg)
        m = c2.recv(18 + 21)
    # Check the last send key against the test vector
    assert(hexlify(lc.sk) == b'969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')

    # This next message triggers the rotation:
    lc.send_message(msg)
    m = c2.recv(18 + 21)

    # Now try to send with the new keys:
    lc.send_message(msg)
    m = c2.recv(18 + 21)
    assert(hexlify(m) == b'178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8')

    lc.send_message(msg)
    m = c2.recv(18 + 21)
    assert(hexlify(m) == b'1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd')

    for i in range(0, 498):
        lc.send_message(msg)
        m = c2.recv(18 + 21)

    lc.send_message(msg)
    m = c2.recv(18 + 21)
    assert(hexlify(m) == b'4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09')

    lc.send_message(msg)
    m = c2.recv(18 + 21)
    assert(hexlify(m) == b'2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36')


def test_listen_connect():
    """Roundtrip test using the public constructors.
    """
    n1_privkey = PrivateKey(unhexlify(b'1111111111111111111111111111111111111111111111111111111111111111'))
    n2_privkey = PrivateKey(unhexlify('2121212121212121212121212121212121212121212121212121212121212121'))

    lss = wire.LightningServerSocket(n2_privkey)
    lss.bind(('0.0.0.0', 1234))
    lss.listen()
    port = lss.getsockname()[1]
    print(port)

    def connect():
        lc = wire.connect(n1_privkey, n2_privkey.public_key(), '127.0.0.1', port)
        lc.send_message(b'hello')
        m = lc.read_message()
        assert(m == b'world')

    t = threading.Thread(target=connect)
    t.daemon = True
    t.start()

    c, _ = lss.accept()
    m = c.read_message()
    assert(m == b'hello')
    c.send_message(b'world')

    t.join()
