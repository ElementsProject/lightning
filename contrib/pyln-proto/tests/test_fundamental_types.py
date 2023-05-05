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
              's8': [['0', b'\x00'],
                     ['42', b'\x2a'],
                     ['-42', b'\xd6'],
                     ['127', b'\x7f'],
                     ['-128', b'\x80']],
              's16': [['128', b'\x00\x80'],
                      ['-129', b'\xff\x7f'],
                      ['15000', b'\x3a\x98'],
                      ['-15000', b'\xc5\x68'],
                      ['32767', b'\x7f\xff'],
                      ['-32768', b'\x80\x00']],
              's32': [['32768', b'\x00\x00\x80\x00'],
                      ['-32769', b'\xff\xff\x7f\xff'],
                      ['21000000', b'\x01\x40\x6f\x40'],
                      ['-21000000', b'\xfe\xbf\x90\xc0'],
                      ['2147483647', b'\x7f\xff\xff\xff'],
                      ['-2147483648', b'\x80\x00\x00\x00']],
              's64': [['2147483648', b'\x00\x00\x00\x00\x80\x00\x00\x00'],
                      ['-2147483649', b'\xff\xff\xff\xff\x7f\xff\xff\xff'],
                      ['500000000000', b'\x00\x00\x00\x74\x6a\x52\x88\x00'],
                      ['-500000000000', b'\xff\xff\xff\x8b\x95\xad\x78\x00'],
                      ['9223372036854775807', b'\x7f\xff\xff\xff\xff\xff\xff\xff'],
                      ['-9223372036854775808', b'\x80\x00\x00\x00\x00\x00\x00\x00']],
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
