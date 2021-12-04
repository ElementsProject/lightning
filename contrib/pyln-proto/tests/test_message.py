#! /usr/bin/python3
from pyln.proto.message import MessageNamespace, Message
import pytest
import io


def test_fundamental():
    ns = MessageNamespace()
    ns.load_csv(['msgtype,test,1',
                 'msgdata,test,test_byte,byte,',
                 'msgdata,test,test_u16,u16,',
                 'msgdata,test,test_u32,u32,',
                 'msgdata,test,test_u64,u64,',
                 'msgdata,test,test_chain_hash,chain_hash,',
                 'msgdata,test,test_channel_id,channel_id,',
                 'msgdata,test,test_sha256,sha256,',
                 'msgdata,test,test_signature,signature,',
                 'msgdata,test,test_point,point,',
                 'msgdata,test,test_short_channel_id,short_channel_id,',
                 ])

    mstr = """test
 test_byte=255
 test_u16=65535
 test_u32=4294967295
 test_u64=18446744073709551615
 test_chain_hash=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
 test_channel_id=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
 test_sha256=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
 test_signature=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
 test_point=0201030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
 test_short_channel_id=1x2x3"""
    m = Message.from_str(ns, mstr)

    # Same (ignoring whitespace differences)
    assert m.to_str().split() == mstr.split()


def test_static_array():
    ns = MessageNamespace()
    ns.load_csv(['msgtype,test1,1',
                 'msgdata,test1,test_arr,byte,4'])
    ns.load_csv(['msgtype,test2,2',
                 'msgdata,test2,test_arr,short_channel_id,4'])

    for test in [["test1 test_arr=00010203", bytes([0, 1] + [0, 1, 2, 3])],
                 ["test2 test_arr=[0x1x2,4x5x6,7x8x9,10x11x12]",
                  bytes([0, 2]
                        + [0, 0, 0, 0, 0, 1, 0, 2]
                        + [0, 0, 4, 0, 0, 5, 0, 6]
                        + [0, 0, 7, 0, 0, 8, 0, 9]
                        + [0, 0, 10, 0, 0, 11, 0, 12])]]:
        m = Message.from_str(ns, test[0])
        assert m.to_str() == test[0]
        buf = io.BytesIO()
        m.write(buf)
        assert buf.getvalue() == test[1]
        assert Message.read(ns, io.BytesIO(test[1])).to_str() == test[0]


def test_subtype():
    ns = MessageNamespace()
    ns.load_csv(['msgtype,test1,1',
                 'msgdata,test1,test_sub,channel_update_timestamps,4',
                 'subtype,channel_update_timestamps',
                 'subtypedata,'
                 + 'channel_update_timestamps,timestamp_node_id_1,u32,',
                 'subtypedata,'
                 + 'channel_update_timestamps,timestamp_node_id_2,u32,'])

    for test in [["test1 test_sub=["
                  "{timestamp_node_id_1=1,timestamp_node_id_2=2}"
                  ",{timestamp_node_id_1=3,timestamp_node_id_2=4}"
                  ",{timestamp_node_id_1=5,timestamp_node_id_2=6}"
                  ",{timestamp_node_id_1=7,timestamp_node_id_2=8}]",
                  bytes([0, 1]
                        + [0, 0, 0, 1, 0, 0, 0, 2]
                        + [0, 0, 0, 3, 0, 0, 0, 4]
                        + [0, 0, 0, 5, 0, 0, 0, 6]
                        + [0, 0, 0, 7, 0, 0, 0, 8])]]:
        m = Message.from_str(ns, test[0])
        assert m.to_str() == test[0]
        buf = io.BytesIO()
        m.write(buf)
        assert buf.getvalue() == test[1]
        assert Message.read(ns, io.BytesIO(test[1])).to_str() == test[0]

    # Test missing field logic.
    m = Message.from_str(ns, "test1", incomplete_ok=True)
    assert m.missing_fields()


def test_subtype_array():
    ns = MessageNamespace()
    ns.load_csv(['msgtype,tx_signatures,1',
                 'msgdata,tx_signatures,num_witnesses,u16,',
                 'msgdata,tx_signatures,witness_stack,witness_stack,num_witnesses',
                 'subtype,witness_stack',
                 'subtypedata,witness_stack,num_input_witness,u16,',
                 'subtypedata,witness_stack,witness_element,witness_element,num_input_witness',
                 'subtype,witness_element',
                 'subtypedata,witness_element,len,u16,',
                 'subtypedata,witness_element,witness,byte,len'])

    for test in [["tx_signatures witness_stack="
                 "[{witness_element=[{witness=3045022100ac0fdee3e157f50be3214288cb7f11b03ce33e13b39dadccfcdb1a174fd3729a02200b69b286ac9f0fc5c51f9f04ae5a9827ac11d384cc203a0eaddff37e8d15c1ac01},{witness=02d6a3c2d0cf7904ab6af54d7c959435a452b24a63194e1c4e7c337d3ebbb3017b}]}]",
                  bytes.fromhex('00010001000200483045022100ac0fdee3e157f50be3214288cb7f11b03ce33e13b39dadccfcdb1a174fd3729a02200b69b286ac9f0fc5c51f9f04ae5a9827ac11d384cc203a0eaddff37e8d15c1ac01002102d6a3c2d0cf7904ab6af54d7c959435a452b24a63194e1c4e7c337d3ebbb3017b')]]:
        m = Message.from_str(ns, test[0])
        assert m.to_str() == test[0]
        buf = io.BytesIO()
        m.write(buf)
        assert buf.getvalue().hex() == test[1].hex()
        assert Message.read(ns, io.BytesIO(test[1])).to_str() == test[0]


def test_tlv():
    ns = MessageNamespace()
    ns.load_csv(['msgtype,test1,1',
                 'msgdata,test1,tlvs,test_tlvstream,',
                 'tlvtype,test_tlvstream,tlv1,1',
                 'tlvdata,test_tlvstream,tlv1,field1,byte,4',
                 'tlvdata,test_tlvstream,tlv1,field2,u32,',
                 'tlvtype,test_tlvstream,tlv2,255',
                 'tlvdata,test_tlvstream,tlv2,field3,byte,...'])

    for test in [["test1 tlvs={tlv1={field1=01020304,field2=5}}",
                  bytes([0, 1]
                        + [1, 8, 1, 2, 3, 4, 0, 0, 0, 5])],
                 ["test1 tlvs={tlv1={field1=01020304,field2=5},tlv2={field3=01020304}}",
                  bytes([0, 1]
                        + [1, 8, 1, 2, 3, 4, 0, 0, 0, 5]
                        + [253, 0, 255, 4, 1, 2, 3, 4])],
                 ["test1 tlvs={tlv1={field1=01020304,field2=5},4=010203,tlv2={field3=01020304}}",
                  bytes([0, 1]
                        + [1, 8, 1, 2, 3, 4, 0, 0, 0, 5]
                        + [4, 3, 1, 2, 3]
                        + [253, 0, 255, 4, 1, 2, 3, 4])]]:
        m = Message.from_str(ns, test[0])
        assert m.to_str() == test[0]
        buf = io.BytesIO()
        m.write(buf)
        assert buf.getvalue() == test[1]
        assert Message.read(ns, io.BytesIO(test[1])).to_str() == test[0]

    # Ordering test (turns into canonical ordering)
    m = Message.from_str(ns, 'test1 tlvs={tlv1={field1=01020304,field2=5},tlv2={field3=01020304},4=010203}')
    buf = io.BytesIO()
    m.write(buf)
    assert buf.getvalue() == bytes([0, 1]
                                   + [1, 8, 1, 2, 3, 4, 0, 0, 0, 5]
                                   + [4, 3, 1, 2, 3]
                                   + [253, 0, 255, 4, 1, 2, 3, 4])


def test_tlv_complex():
    # A real example from the spec.
    ns = MessageNamespace(["msgtype,reply_channel_range,264,gossip_queries",
                           "msgdata,reply_channel_range,chain_hash,chain_hash,",
                           "msgdata,reply_channel_range,first_blocknum,u32,",
                           "msgdata,reply_channel_range,number_of_blocks,u32,",
                           "msgdata,reply_channel_range,full_information,byte,",
                           "msgdata,reply_channel_range,len,u16,",
                           "msgdata,reply_channel_range,encoded_short_ids,byte,len",
                           "msgdata,reply_channel_range,tlvs,reply_channel_range_tlvs,",
                           "tlvtype,reply_channel_range_tlvs,timestamps_tlv,1",
                           "tlvdata,reply_channel_range_tlvs,timestamps_tlv,encoding_type,byte,",
                           "tlvdata,reply_channel_range_tlvs,timestamps_tlv,encoded_timestamps,byte,...",
                           "tlvtype,reply_channel_range_tlvs,checksums_tlv,3",
                           "tlvdata,reply_channel_range_tlvs,checksums_tlv,checksums,channel_update_checksums,...",
                           "subtype,channel_update_timestamps",
                           "subtypedata,channel_update_timestamps,timestamp_node_id_1,u32,",
                           "subtypedata,channel_update_timestamps,timestamp_node_id_2,u32,",
                           "subtype,channel_update_checksums",
                           "subtypedata,channel_update_checksums,checksum_node_id_1,u32,",
                           "subtypedata,channel_update_checksums,checksum_node_id_2,u32,"])

    binmsg = bytes.fromhex('010806226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f000000670000000701001100000067000001000000006d000001000003101112fa300000000022d7a4a79bece840')
    msg = Message.read(ns, io.BytesIO(binmsg))
    buf = io.BytesIO()
    msg.write(buf)
    assert buf.getvalue() == binmsg


def test_message_constructor():
    ns = MessageNamespace(['msgtype,test1,1',
                           'msgdata,test1,tlvs,test_tlvstream,',
                           'tlvtype,test_tlvstream,tlv1,1',
                           'tlvdata,test_tlvstream,tlv1,field1,byte,4',
                           'tlvdata,test_tlvstream,tlv1,field2,u32,',
                           'tlvtype,test_tlvstream,tlv2,255',
                           'tlvdata,test_tlvstream,tlv2,field3,byte,...'])

    m = Message(ns.get_msgtype('test1'),
                tlvs='{tlv1={field1=01020304,field2=5}'
                ',tlv2={field3=01020304},4=010203}')
    buf = io.BytesIO()
    m.write(buf)
    assert buf.getvalue() == bytes([0, 1]
                                   + [1, 8, 1, 2, 3, 4, 0, 0, 0, 5]
                                   + [4, 3, 1, 2, 3]
                                   + [253, 0, 255, 4, 1, 2, 3, 4])


def test_dynamic_array():
    """Test that dynamic array types enforce matching lengths"""
    ns = MessageNamespace(['msgtype,test1,1',
                           'msgdata,test1,count,u16,',
                           'msgdata,test1,arr1,byte,count',
                           'msgdata,test1,arr2,u32,count'])

    # This one is fine.
    m = Message(ns.get_msgtype('test1'),
                arr1='01020304', arr2='[1,2,3,4]')
    buf = io.BytesIO()
    m.write(buf)
    assert buf.getvalue() == bytes([0, 1]
                                   + [0, 4]
                                   + [1, 2, 3, 4]
                                   + [0, 0, 0, 1,
                                      0, 0, 0, 2,
                                      0, 0, 0, 3,
                                      0, 0, 0, 4])

    # These ones are not
    with pytest.raises(ValueError, match='Inconsistent length.*count'):
        m = Message(ns.get_msgtype('test1'),
                    arr1='01020304', arr2='[1,2,3]')

    with pytest.raises(ValueError, match='Inconsistent length.*count'):
        m = Message(ns.get_msgtype('test1'),
                    arr1='01020304', arr2='[1,2,3,4,5]')
