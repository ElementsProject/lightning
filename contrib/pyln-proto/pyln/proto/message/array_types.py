from .fundamental_types import FieldType, IntegerType, split_field


class ArrayType(FieldType):
    """Abstract class for the different kinds of arrays.

These are not in the namespace, but generated when a message says it
wants an array of some type.

    """
    def __init__(self, outer, name, elemtype):
        super().__init__("{}.{}".format(outer.name, name))
        self.elemtype = elemtype

    def val_from_str(self, s):
        # Simple arrays of bytes don't need commas
        if self.elemtype.name == 'byte':
            a, b = split_field(s)
            return [b for b in bytes.fromhex(a)], b

        if not s.startswith('['):
            raise ValueError("array of {} must be wrapped in '[]': bad {}"
                             .format(self.elemtype.name, s))
        s = s[1:]
        ret = []
        while not s.startswith(']'):
            val, s = self.elemtype.val_from_str(s)
            ret.append(val)
            if s[0] == ',':
                s = s[1:]
        return ret, s[1:]

    def val_to_str(self, v, otherfields):
        if self.elemtype.name == 'byte':
            return bytes(v).hex()

        s = ''
        sep = ''
        for i in v:
            s += sep + self.elemtype.val_to_str(i, otherfields)
            sep = ','

        return '[' + s + ']'

    def val_to_bin(self, v, otherfields):
        b = bytes()
        for i in v:
            b += self.elemtype.val_to_bin(i, otherfields)
        return b

    def arr_from_bin(self, bytestream, otherfields, arraysize):
        """arraysize None means take rest of bytestream exactly"""
        totsize = 0
        vals = []
        i = 0
        while True:
            if arraysize is None and totsize == len(bytestream):
                return vals, totsize
            elif i == arraysize:
                return vals, totsize
            val, size = self.elemtype.val_from_bin(bytestream[totsize:],
                                                   otherfields)
            totsize += size
            i += 1
            vals.append(val)


class SizedArrayType(ArrayType):
    """A fixed-size array"""
    def __init__(self, outer, name, elemtype, arraysize):
        super().__init__(outer, name, elemtype)
        self.arraysize = arraysize

    def val_to_str(self, v, otherfields):
        if len(v) != self.arraysize:
            raise ValueError("Length of {} != {}", v, self.arraysize)
        return super().val_to_str(v, otherfields)

    def val_from_str(self, s):
        a, b = super().val_from_str(s)
        if len(a) != self.arraysize:
            raise ValueError("Length of {} != {}", s, self.arraysize)
        return a, b

    def val_to_bin(self, v, otherfields):
        if len(v) != self.arraysize:
            raise ValueError("Length of {} != {}", v, self.arraysize)
        return super().val_to_bin(v, otherfields)

    def val_from_bin(self, bytestream, otherfields):
        return super().arr_from_bin(bytestream, otherfields, self.arraysize)


class EllipsisArrayType(ArrayType):
    """This is used for ... fields at the end of a tlv: the array ends
when the tlv ends"""
    def __init__(self, tlv, name, elemtype):
        super().__init__(tlv, name, elemtype)

    def val_from_bin(self, bytestream, otherfields):
        """Takes rest of bytestream"""
        return super().arr_from_bin(bytestream, otherfields, None)

    def only_at_tlv_end(self):
        """These only make sense at the end of a TLV"""
        return True


class LengthFieldType(FieldType):
    """Special type to indicate this serves as a length field for others"""
    def __init__(self, inttype):
        if type(inttype) is not IntegerType:
            raise ValueError("{} cannot be a length; not an integer!"
                             .format(self.name))
        super().__init__(inttype.name)
        self.underlying_type = inttype
        # You can be length for more than one field!
        self.len_for = []

    def is_optional(self):
        """This field value is always implies, never specified directly"""
        return True

    def add_length_for(self, field):
        assert isinstance(field.fieldtype, DynamicArrayType)
        self.len_for.append(field)

    def calc_value(self, otherfields):
        """Calculate length value from field(s) themselves"""
        if self.len_fields_bad('', otherfields):
            raise ValueError("Lengths of fields {} not equal!"
                             .format(self.len_for))

        return len(otherfields[self.len_for[0].name])

    def _maybe_calc_value(self, fieldname, otherfields):
        # Perhaps we're just demarshalling from binary now, so we actually
        # stored it.  Remove, and we'll calc from now on.
        if fieldname in otherfields:
            v = otherfields[fieldname]
            del otherfields[fieldname]
            return v
        return self.calc_value(otherfields)

    def val_to_bin(self, _, otherfields):
        return self.underlying_type.val_to_bin(self.calc_value(otherfields),
                                               otherfields)

    def val_to_str(self, _, otherfields):
        return self.underlying_type.val_to_str(self.calc_value(otherfields),
                                               otherfields)

    def name_and_val(self, name, v):
        """We don't print out length fields when printing out messages:
they're implied by the length of other fields"""
        return ''

    def val_from_bin(self, bytestream, otherfields):
        """We store this, but it'll be removed from the fields as soon as it's used (i.e. by DynamicArrayType's val_from_bin)"""
        return self.underlying_type.val_from_bin(bytestream, otherfields)

    def val_from_str(self, s):
        raise ValueError('{} is implied, cannot be specified'.format(self))

    def len_fields_bad(self, fieldname, otherfields):
        """fieldname is the name to return if this length is bad"""
        mylen = None
        for lens in self.len_for:
            if mylen is not None:
                if mylen != len(otherfields[lens.name]):
                    return [fieldname]
            # Field might be missing!
            if lens.name in otherfields:
                mylen = len(otherfields[lens.name])
        return []


class DynamicArrayType(ArrayType):
    """This is used for arrays where another field controls the size"""
    def __init__(self, outer, name, elemtype, lenfield):
        super().__init__(outer, name, elemtype)
        assert type(lenfield.fieldtype) is LengthFieldType
        self.lenfield = lenfield

    def val_from_bin(self, bytestream, otherfields):
        return super().arr_from_bin(bytestream, otherfields,
                                    self.lenfield.fieldtype._maybe_calc_value(self.lenfield.name, otherfields))
