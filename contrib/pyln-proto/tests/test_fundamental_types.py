#! /usr/bin/python3
from pyln.proto.message.fundamental_types import fundamental_types
import io


def test_fundamental_types():
    expect = {'byte': [['255', b'\xff'],
                       ['0', b'\x00']],
              'u16': [['65535', b'\xff\xff'],
                      ['0', b'\x00\x00']],
              'u32': [['4294967295', b'\xff\xff\xff\xff'],
                      ['0', b'\x00\x00\x00\x00']],
              'u64': [['18446744073709551615',
                       b'\xff\xff\xff\xff\xff\xff\xff\xff'],
                      ['0', b'\x00\x00\x00\x00\x00\x00\x00\x00']],
              'tu16': [['65535', b'\xff\xff'],
                       ['256', b'\x01\x00'],
                       ['255', b'\xff'],
                       ['0', b'']],
              'tu32': [['4294967295', b'\xff\xff\xff\xff'],
                       ['65536', b'\x01\x00\x00'],
                       ['65535', b'\xff\xff'],
                       ['256', b'\x01\x00'],
                       ['255', b'\xff'],
                       ['0', b'']],
              'tu64': [['18446744073709551615',
                        b'\xff\xff\xff\xff\xff\xff\xff\xff'],
                       ['4294967296', b'\x01\x00\x00\x00\x00'],
                       ['4294967295', b'\xff\xff\xff\xff'],
                       ['65536', b'\x01\x00\x00'],
                       ['65535', b'\xff\xff'],
                       ['256', b'\x01\x00'],
                       ['255', b'\xff'],
                       ['0', b'']],
              'chain_hash': [['0102030405060708090a0b0c0d0e0f10'
                              '1112131415161718191a1b1c1d1e1f20',
                              bytes(range(1, 33))]],
              'channel_id': [['0102030405060708090a0b0c0d0e0f10'
                              '1112131415161718191a1b1c1d1e1f20',
                              bytes(range(1, 33))]],
              'sha256': [['0102030405060708090a0b0c0d0e0f10'
                          '1112131415161718191a1b1c1d1e1f20',
                          bytes(range(1, 33))]],
              'signature': [['0102030405060708090a0b0c0d0e0f10'
                             '1112131415161718191a1b1c1d1e1f20'
                             '2122232425262728292a2b2c2d2e2f30'
                             '3132333435363738393a3b3c3d3e3f40',
                             bytes(range(1, 65))]],
              'point': [['02030405060708090a0b0c0d0e0f10'
                         '1112131415161718191a1b1c1d1e1f20'
                         '2122',
                         bytes(range(2, 35))]],
              'short_channel_id': [['1x2x3', bytes([0, 0, 1, 0, 0, 2, 0, 3])]],
              'bigsize': [['0', bytes([0])],
                          ['252', bytes([252])],
                          ['253', bytes([253, 0, 253])],
                          ['65535', bytes([253, 255, 255])],
                          ['65536', bytes([254, 0, 1, 0, 0])],
                          ['4294967295', bytes([254, 255, 255, 255, 255])],
                          ['4294967296', bytes([255, 0, 0, 0, 1, 0, 0, 0, 0])]],
              'utf8': [['97', b'\x61'],
                       ['0', b'\x00']],
              'bip340sig': [['0102030405060708090a0b0c0d0e0f10'
                             '1112131415161718191a1b1c1d1e1f20'
                             '2122232425262728292a2b2c2d2e2f30'
                             '3132333435363738393a3b3c3d3e3f40',
                             bytes(range(1, 65))]],
              'point32': [['02030405060708090a0b0c0d0e0f10'
                           '1112131415161718191a1b1c1d1e1f20'
                           '21',
                           bytes(range(2, 34))]],
              }

    untested = set()
    for t in fundamental_types():
        if t.name not in expect:
            untested.add(t.name)
            continue
        for test in expect[t.name]:
            v, _ = t.val_from_str(test[0])
            assert t.val_to_str(v, None) == test[0]
            v2 = t.read(io.BytesIO(test[1]), None)
            assert v2 == v
            buf = io.BytesIO()
            t.write(buf, v, None)
            assert buf.getvalue() == test[1]

    assert untested == set()
