from .fundamental_types import FieldType, IntegerType, split_field
from typing import List, Optional, Dict, Tuple, TYPE_CHECKING, Any, Union, cast
from io import BufferedIOBase
if TYPE_CHECKING:
    from .message import SubtypeType, TlvMessageType, MessageTypeField


class ArrayType(FieldType):
    """Abstract class for the different kinds of arrays.

These are not in the namespace, but generated when a message says it
wants an array of some type.

    """
    def __init__(self, outer: 'SubtypeType', name: str, elemtype: FieldType):
        super().__init__("{}.{}".format(outer.name, name))
        self.elemtype = elemtype

    def val_from_str(self, s: str) -> Tuple[List[Any], str]:
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

    def val_to_str(self, v: List[Any], otherfields: Dict[str, Any]) -> str:
        if self.elemtype.name == 'byte':
            return bytes(v).hex()

        s = ','.join(self.elemtype.val_to_str(i, otherfields) for i in v)
        return '[' + s + ']'

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> Union[str, List[Any]]:
        """Convert to a python object: for arrays, this means a list (or hex, if bytes)"""
        if self.elemtype.name == 'byte':
            return bytes(v).hex()

        return [self.elemtype.val_to_py(i, otherfields) for i in v]

    def write(self, io_out: BufferedIOBase, vals: List[Any], otherfields: Dict[str, Any]) -> None:
        name = self.name.split('.')[1]
        if otherfields and name in otherfields:
            otherfields = otherfields[name]
        for i, val in enumerate(vals):
            if isinstance(otherfields, list) and len(otherfields) > i:
                fields = otherfields[i]
            else:
                fields = otherfields
            self.elemtype.write(io_out, val, fields)

    def read_arr(self, io_in: BufferedIOBase, otherfields: Dict[str, Any], arraysize: Optional[int]) -> List[Any]:
        """arraysize None means take rest of io entirely and exactly"""
        vals: List[Any] = []
        while arraysize is None or len(vals) < arraysize:
            # Throws an exception on partial read, so None means completely empty.
            val = self.elemtype.read(io_in, otherfields)
            if val is None:
                if arraysize is not None:
                    raise ValueError('{}: not enough remaining to read'
                                     .format(self))
                break

            vals.append(val)

        return vals


class SizedArrayType(ArrayType):
    """A fixed-size array"""
    def __init__(self, outer: 'SubtypeType', name: str, elemtype: FieldType, arraysize: int):
        super().__init__(outer, name, elemtype)
        self.arraysize = arraysize

    def val_to_str(self, v: List[Any], otherfields: Dict[str, Any]) -> str:
        if len(v) != self.arraysize:
            raise ValueError("Length of {} != {}", v, self.arraysize)
        return super().val_to_str(v, otherfields)

    def val_from_str(self, s: str) -> Tuple[List[Any], str]:
        a, b = super().val_from_str(s)
        if len(a) != self.arraysize:
            raise ValueError("Length of {} != {}", s, self.arraysize)
        return a, b

    def write(self, io_out: BufferedIOBase, v: List[Any], otherfields: Dict[str, Any]) -> None:
        if len(v) != self.arraysize:
            raise ValueError("Length of {} != {}", v, self.arraysize)
        return super().write(io_out, v, otherfields)

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> List[Any]:
        return super().read_arr(io_in, otherfields, self.arraysize)


class EllipsisArrayType(ArrayType):
    """This is used for ... fields at the end of a tlv: the array ends
when the tlv ends"""
    def __init__(self, tlv: 'TlvMessageType', name: str, elemtype: FieldType):
        super().__init__(tlv, name, elemtype)

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> List[Any]:
        """Takes rest of bytestream"""
        return super().read_arr(io_in, otherfields, None)

    def only_at_tlv_end(self) -> bool:
        """These only make sense at the end of a TLV"""
        return True


class LengthFieldType(FieldType):
    """Special type to indicate this serves as a length field for others"""
    def __init__(self, inttype: IntegerType):
        if type(inttype) is not IntegerType:
            raise ValueError("{} cannot be a length; not an integer!"
                             .format(self.name))
        super().__init__(inttype.name)
        self.underlying_type = inttype
        # You can be length for more than one field!
        self.len_for: List['MessageTypeField'] = []

    def is_optional(self) -> bool:
        """This field value is always implies, never specified directly"""
        return True

    def add_length_for(self, field: 'MessageTypeField') -> None:
        assert isinstance(field.fieldtype, DynamicArrayType)
        self.len_for.append(field)

    def calc_value(self, otherfields: Dict[str, Any]) -> int:
        """Calculate length value from field(s) themselves"""
        if self.len_fields_bad('', otherfields):
            raise ValueError("Lengths of fields {} not equal!"
                             .format(self.len_for))

        return len(otherfields[self.len_for[0].name])

    def _maybe_calc_value(self, fieldname: str, otherfields: Dict[str, Any]) -> int:
        # Perhaps we're just demarshalling from binary now, so we actually
        # stored it.  Remove, and we'll calc from now on.
        if fieldname in otherfields:
            v = otherfields[fieldname]
            del otherfields[fieldname]
            return v
        return self.calc_value(otherfields)

    def val_to_str(self, _, otherfields: Dict[str, Any]) -> str:
        return self.underlying_type.val_to_str(self.calc_value(otherfields),
                                               otherfields)

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> int:
        """Convert to a python object: for integer fields, this means an int"""
        return self.underlying_type.val_to_py(self.calc_value(otherfields),
                                              otherfields)

    def name_and_val(self, name: str, v: int) -> str:
        """We don't print out length fields when printing out messages:
they're implied by the length of other fields"""
        return ''

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Optional[int]:
        """We store this, but it'll be removed from the fields as soon as it's used (i.e. by DynamicArrayType's val_from_bin)"""
        return self.underlying_type.read(io_in, otherfields)

    def write(self, io_out: BufferedIOBase, _, otherfields: Dict[str, Any]) -> None:
        self.underlying_type.write(io_out, self.calc_value(otherfields),
                                   otherfields)

    def val_from_str(self, s: str):
        raise ValueError('{} is implied, cannot be specified'.format(self))

    def len_fields_bad(self, fieldname: str, otherfields: Dict[str, Any]) -> List[str]:
        """fieldname is the name to return if this length is bad"""
        mylen = None
        for lens in self.len_for:
            if mylen is not None:
                if mylen != len(otherfields[lens.name]):
                    return [fieldname]
            # Field might be missing!
            if otherfields and lens.name in otherfields:
                mylen = len(otherfields[lens.name])
        return []


class DynamicArrayType(ArrayType):
    """This is used for arrays where another field controls the size"""
    def __init__(self, outer: 'SubtypeType', name: str, elemtype: FieldType, lenfield: 'MessageTypeField'):
        super().__init__(outer, name, elemtype)
        assert type(lenfield.fieldtype) is LengthFieldType
        self.lenfield = lenfield

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> List[Any]:
        return super().read_arr(io_in, otherfields,
                                cast(LengthFieldType, self.lenfield.fieldtype)._maybe_calc_value(self.lenfield.name, otherfields))
