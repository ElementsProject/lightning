#! /usr/bin/python3
from pyln.proto.message import Message, MessageNamespace
from pyln.proto.message.bolts import bolt_01_csv, bolt_02_csv, bolt_04_csv, bolt_07_csv


def test_bolt_01_csv_tlv():
    ns = MessageNamespace(bolt_01_csv)

    n1 = ns.get_tlvtype('n1')

    # FIXME: Test failure cases too!
    for t in [['0x', ''],
              ['0x21 00', '33='],
              ['0xfd0201 00', '513='],
              ['0xfd00fd 00', '253='],
              ['0xfd00ff 00', '255='],
              ['0xfe02000001 00', '33554433='],
              ['0xff0200000000000001 00', '144115188075855873='],
              ['0x01 00', 'tlv1={amount_msat=0}'],
              ['0x01 01 01', 'tlv1={amount_msat=1}'],
              ['0x01 02 0100', 'tlv1={amount_msat=256}'],
              ['0x01 03 010000', 'tlv1={amount_msat=65536}'],
              ['0x01 04 01000000', 'tlv1={amount_msat=16777216}'],
              ['0x01 05 0100000000', 'tlv1={amount_msat=4294967296}'],
              ['0x01 06 010000000000', 'tlv1={amount_msat=1099511627776}'],
              ['0x01 07 01000000000000', 'tlv1={amount_msat=281474976710656}'],
              ['0x01 08 0100000000000000', 'tlv1={amount_msat=72057594037927936}'],
              ['0x02 08 0000000000000226', 'tlv2={scid=0x0x550}'],
              ['0x03 31 023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002', 'tlv3={node_id=023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb,amount_msat_1=1,amount_msat_2=2}'],
              ['0xfd00fe 02 0226', 'tlv4={cltv_delta=550}']]:
        msg = bytes.fromhex(t[0][2:].replace(' ', ''))

        val, size = n1.val_from_bin(msg, None)
        assert size == len(msg)
        assert n1.val_to_str(val, None) == '{' + t[1] + '}'


def test_bolt_01_csv():
    ns = MessageNamespace(bolt_01_csv)
    # string [expected string]
    for t in [['init globalfeatures= features=80',
               'init globalfeatures= features=80 tlvs={}'],
              ['init globalfeatures= features=80 tlvs={}'],
              ['init globalfeatures= features=80 tlvs={networks={chains=[6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000]}}'],
              ['init globalfeatures= features=80 tlvs={networks={chains=[6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000,1fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000]}}'],
              ['error channel_id=0000000000000000000000000000000000000000000000000000000000000000 data=00'],
              ['ping num_pong_bytes=0 ignored='],
              ['ping num_pong_bytes=3 ignored=0000'],
              ['pong ignored='],
              ['pong ignored=000000']]:
        m = Message.from_str(ns, t[0])
        b = m.to_bin()
        m2 = Message.from_bin(ns, b)
        assert m2.to_str() == t[-1]


def test_bolt_02_csv():
    MessageNamespace(bolt_02_csv)
    # FIXME: Add tests.


def test_bolt_04_csv():
    MessageNamespace(bolt_04_csv)
    # FIXME: Add tests.


def test_bolt_07_csv():
    MessageNamespace(bolt_07_csv)
    # FIXME: Add tests.
