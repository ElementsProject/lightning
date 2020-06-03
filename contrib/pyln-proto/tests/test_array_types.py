#! /usr/bin/python3
from pyln.proto.message.fundamental_types import fundamental_types
from pyln.proto.message.array_types import SizedArrayType, DynamicArrayType, EllipsisArrayType, LengthFieldType


def test_sized_array():
    # Steal two fundamental types for testing
    for t in fundamental_types():
        if t.name == 'byte':
            byte = t
        if t.name == 'u16':
            u16 = t
        if t.name == 'short_channel_id':
            scid = t

    # Simple class to make outer work.
    class dummy:
        def __init__(self, name):
            self.name = name

    for arrtype, s, b in [[SizedArrayType(dummy("test1"), "test_arr", byte, 4),
                           "00010203",
                           bytes([0, 1, 2, 3])],
                          [SizedArrayType(dummy("test2"), "test_arr", u16, 4),
                           "[0,1,2,256]",
                           bytes([0, 0, 0, 1, 0, 2, 1, 0])],
                          [SizedArrayType(dummy("test3"), "test_arr", scid, 4),
                           "[1x2x3,4x5x6,7x8x9,10x11x12]",
                           bytes([0, 0, 1, 0, 0, 2, 0, 3]
                                 + [0, 0, 4, 0, 0, 5, 0, 6]
                                 + [0, 0, 7, 0, 0, 8, 0, 9]
                                 + [0, 0, 10, 0, 0, 11, 0, 12])]]:
        v, _ = arrtype.val_from_str(s)
        assert arrtype.val_to_str(v, None) == s
        v2, _ = arrtype.val_from_bin(b, None)
        assert v2 == v
        assert arrtype.val_to_bin(v, None) == b


def test_ellipsis_array():
    # Steal two fundamental types for testing
    for t in fundamental_types():
        if t.name == 'byte':
            byte = t
        if t.name == 'u16':
            u16 = t
        if t.name == 'short_channel_id':
            scid = t

    # Simple class to make outer work.
    class dummy:
        def __init__(self, name):
            self.name = name

    for test in [[EllipsisArrayType(dummy("test1"), "test_arr", byte),
                  "00010203",
                  bytes([0, 1, 2, 3])],
                 [EllipsisArrayType(dummy("test2"), "test_arr", u16),
                  "[0,1,2,256]",
                  bytes([0, 0, 0, 1, 0, 2, 1, 0])],
                 [EllipsisArrayType(dummy("test3"), "test_arr", scid),
                  "[1x2x3,4x5x6,7x8x9,10x11x12]",
                  bytes([0, 0, 1, 0, 0, 2, 0, 3]
                        + [0, 0, 4, 0, 0, 5, 0, 6]
                        + [0, 0, 7, 0, 0, 8, 0, 9]
                        + [0, 0, 10, 0, 0, 11, 0, 12])]]:
        v, _ = test[0].val_from_str(test[1])
        assert test[0].val_to_str(v, None) == test[1]
        v2, _ = test[0].val_from_bin(test[2], None)
        assert v2 == v
        assert test[0].val_to_bin(v, None) == test[2]


def test_dynamic_array():
    # Steal two fundamental types for testing
    for t in fundamental_types():
        if t.name == 'byte':
            byte = t
        if t.name == 'u16':
            u16 = t
        if t.name == 'short_channel_id':
            scid = t

    # Simple class to make outer.
    class dummy:
        def __init__(self, name):
            self.name = name

    class field_dummy:
        def __init__(self, name, ftype):
            self.fieldtype = ftype
            self.name = name

    lenfield = field_dummy('lenfield', LengthFieldType(u16))

    for test in [[DynamicArrayType(dummy("test1"), "test_arr", byte,
                                   lenfield),
                  "00010203",
                  bytes([0, 1, 2, 3])],
                 [DynamicArrayType(dummy("test2"), "test_arr", u16,
                                   lenfield),
                  "[0,1,2,256]",
                  bytes([0, 0, 0, 1, 0, 2, 1, 0])],
                 [DynamicArrayType(dummy("test3"), "test_arr", scid,
                                   lenfield),
                  "[1x2x3,4x5x6,7x8x9,10x11x12]",
                  bytes([0, 0, 1, 0, 0, 2, 0, 3]
                        + [0, 0, 4, 0, 0, 5, 0, 6]
                        + [0, 0, 7, 0, 0, 8, 0, 9]
                        + [0, 0, 10, 0, 0, 11, 0, 12])]]:

        lenfield.fieldtype.add_length_for(field_dummy(test[1], test[0]))
        v, _ = test[0].val_from_str(test[1])
        otherfields = {test[1]: v}
        assert test[0].val_to_str(v, otherfields) == test[1]
        v2, _ = test[0].val_from_bin(test[2], otherfields)
        assert v2 == v
        assert test[0].val_to_bin(v, otherfields) == test[2]
        lenfield.fieldtype.len_for = []
