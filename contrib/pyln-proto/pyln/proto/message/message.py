import struct
from io import BufferedIOBase, BytesIO
from .fundamental_types import fundamental_types, BigSizeType, split_field, try_unpack, FieldType, IntegerType
from .array_types import (
    SizedArrayType, DynamicArrayType, LengthFieldType, EllipsisArrayType
)
from typing import Dict, List, Optional, Tuple, Any, Union, Callable, cast


class MessageNamespace(object):
    """A class which contains all FieldTypes and Messages in a particular
domain, such as within a given BOLT"""
    def __init__(self, csv_lines: List[str] = []):
        self.subtypes: Dict[str, SubtypeType] = {}
        self.fundamentaltypes: Dict[str, FieldType] = {}
        self.tlvtypes: Dict[str, TlvStreamType] = {}
        self.messagetypes: Dict[str, MessageType] = {}

        # For convenience, basic types go in every namespace
        for t in fundamental_types():
            self.add_fundamentaltype(t)

        self.load_csv(csv_lines)

    def __add__(self, other: 'MessageNamespace'):
        ret = MessageNamespace()
        ret.subtypes = self.subtypes.copy()
        for v in other.subtypes.values():
            ret.add_subtype(v)
        ret.tlvtypes = self.tlvtypes.copy()
        for tlv in other.tlvtypes.values():
            ret.add_tlvtype(tlv)
        ret.messagetypes = self.messagetypes.copy()
        for v in other.messagetypes.values():
            ret.add_messagetype(v)
        return ret

    def _check_unique(self, name: str) -> None:
        """Raise an exception if name already used"""
        funtype = self.get_fundamentaltype(name)
        if funtype:
            raise ValueError('Already have {}'.format(funtype))
        subtype = self.get_subtype(name)
        if subtype:
            raise ValueError('Already have {}'.format(subtype))
        tlvtype = self.get_tlvtype(name)
        if tlvtype:
            raise ValueError('Already have {}'.format(tlvtype))

    def add_subtype(self, t: 'SubtypeType') -> None:
        self._check_unique(t.name)
        self.subtypes[t.name] = t

    def add_fundamentaltype(self, t: FieldType) -> None:
        self._check_unique(t.name)
        self.fundamentaltypes[t.name] = t

    def add_tlvtype(self, t: 'TlvStreamType') -> None:
        self._check_unique(t.name)
        self.tlvtypes[t.name] = t

    def add_messagetype(self, m: 'MessageType') -> None:
        if self.get_msgtype(m.name):
            raise ValueError('{}: message already exists'.format(m.name))
        if self.get_msgtype_by_number(m.number):
            raise ValueError('{}: message {} already number {}'.format(
                m.name, self.get_msgtype_by_number(m.number), m.number))
        self.messagetypes[m.name] = m

    def get_msgtype(self, name: str) -> Optional['MessageType']:
        if name in self.messagetypes:
            return self.messagetypes[name]
        return None

    def get_msgtype_by_number(self, num: int) -> Optional['MessageType']:
        for m in self.messagetypes.values():
            if m.number == num:
                return m
        return None

    def get_fundamentaltype(self, name: str) -> Optional[FieldType]:
        if name in self.fundamentaltypes:
            return self.fundamentaltypes[name]
        return None

    def get_subtype(self, name: str) -> Optional['SubtypeType']:
        if name in self.subtypes:
            return self.subtypes[name]
        return None

    def get_tlvtype(self, name: str) -> Optional['TlvStreamType']:
        if name in self.tlvtypes:
            return self.tlvtypes[name]
        return None

    def load_csv(self, lines: List[str]) -> None:
        """Load a series of comma-separate-value lines into the namespace"""
        vals: Dict[str, List[List[str]]] = {'msgtype': [],
                                            'msgdata': [],
                                            'tlvtype': [],
                                            'tlvdata': [],
                                            'subtype': [],
                                            'subtypedata': []}
        for l in lines:
            parts = l.split(',')
            if parts[0] not in vals:
                raise ValueError("Unknown type {} in {}".format(parts[0], l))
            vals[parts[0]].append(parts[1:])

        # Types can refer to other types, so add data last.
        for parts in vals['msgtype']:
            self.add_messagetype(MessageType.msgtype_from_csv(parts))

        for parts in vals['subtype']:
            self.add_subtype(SubtypeType.subtype_from_csv(parts))

        for parts in vals['tlvtype']:
            TlvStreamType.tlvtype_from_csv(self, parts)

        for parts in vals['msgdata']:
            MessageType.msgfield_from_csv(self, parts)

        for parts in vals['subtypedata']:
            SubtypeType.subfield_from_csv(self, parts)

        for parts in vals['tlvdata']:
            TlvStreamType.tlvfield_from_csv(self, parts)


class MessageTypeField(object):
    """A field within a particular message type or subtype"""
    def __init__(self, ownername: str, name: str, fieldtype: FieldType, option: Optional[str] = None):
        self.full_name = "{}.{}".format(ownername, name)
        self.name = name
        self.fieldtype = fieldtype
        self.option = option

    def missing_fields(self, fieldvals: Dict[str, Any]):
        """Return this field if it's not in fields"""
        if self.name not in fieldvals and not self.option and not self.fieldtype.is_optional():
            return [self]
        return []

    def len_fields_bad(self, fieldname: str, otherfields: Dict[str, Any]) -> List[str]:
        return self.fieldtype.len_fields_bad(fieldname, otherfields)

    def __str__(self):
        return self.full_name

    def __repr__(self):
        """Yuck, but this is what format() uses for lists"""
        return self.full_name


class SubtypeType(FieldType):
    """This defines a 'subtype' in BOLT-speak.  It consists of fields of
other types.  Since 'msgtype' is almost identical, it inherits from this too.

    """
    def __init__(self, name: str):
        super().__init__(name)
        self.fields: List[MessageTypeField] = []

    def find_field(self, fieldname: str) -> Optional[MessageTypeField]:
        for f in self.fields:
            if f.name == fieldname:
                return f
        return None

    def add_field(self, field: MessageTypeField) -> None:
        if self.find_field(field.name):
            raise ValueError("{}: duplicate field {}".format(self, field))
        self.fields.append(field)

    def __str__(self):
        return "subtype-{}".format(self.name)

    def len_fields_bad(self, fieldname: str, otherfields: Dict[str, Any]) -> List[str]:
        bad_fields: List[str] = []
        for f in self.fields:
            bad_fields += f.len_fields_bad('{}.{}'.format(fieldname, f.name),
                                           otherfields)

        return bad_fields

    @staticmethod
    def subtype_from_csv(parts: List[str]) -> 'SubtypeType':
        """e.g subtype,channel_update_timestamps"""
        if len(parts) != 1:
            raise ValueError("subtype expected 2 CSV parts, not {}"
                             .format(parts))
        return SubtypeType(parts[0])

    def _field_from_csv(self, namespace: MessageNamespace, parts: List[str], option: str = None) -> MessageTypeField:
        """Takes msgdata/subtypedata after first two fields
        e.g. [...]timestamp_node_id_1,u32,

        """
        basetype = namespace.get_fundamentaltype(parts[1])
        if basetype is None:
            basetype = namespace.get_subtype(parts[1])
        if basetype is None:
            basetype = namespace.get_tlvtype(parts[1])
        if basetype is None:
            raise ValueError('Unknown type {}'.format(parts[1]))

        # Fixed number, or another field.
        if parts[2] != '':
            lenfield = self.find_field(parts[2])
            if lenfield is not None:
                # If we didn't know that field was a length, we do now!
                if not isinstance(lenfield.fieldtype, LengthFieldType):
                    assert isinstance(lenfield.fieldtype, IntegerType)
                    lenfield.fieldtype = LengthFieldType(lenfield.fieldtype)
                field = MessageTypeField(self.name, parts[0],
                                         DynamicArrayType(self,
                                                          parts[0],
                                                          basetype,
                                                          lenfield),
                                         option)
                lenfield.fieldtype.add_length_for(field)
            elif parts[2] == '...':
                # ... is only valid for a TLV.
                assert isinstance(self, TlvMessageType)
                field = MessageTypeField(self.name, parts[0],
                                         EllipsisArrayType(self,
                                                           parts[0], basetype),
                                         option)
            else:
                field = MessageTypeField(self.name, parts[0],
                                         SizedArrayType(self,
                                                        parts[0], basetype,
                                                        int(parts[2])),
                                         option)
        else:
            field = MessageTypeField(self.name, parts[0], basetype, option)

        return field

    def val_from_str(self, s: str) -> Tuple[Dict[str, Any], str]:
        if not s.startswith('{'):
            raise ValueError("subtype {} must be wrapped in '{{}}': bad {}"
                             .format(self, s))
        s = s[1:]
        ret: Dict[str, Any] = {}
        # FIXME: perhaps allow unlabelled fields to imply assign fields in order?
        while not s.startswith('}'):
            fieldname, s = s.split('=', 1)
            f = self.find_field(fieldname)
            if f is None:
                raise ValueError("Unknown field name '{}'. Expected one of [{}])".format(fieldname, ','.join(str(f) for f in self.fields)))
            ret[fieldname], s = f.fieldtype.val_from_str(s)
            if s[0] == ',':
                s = s[1:]

        # All non-optional fields must be specified.
        for f in self.fields:
            if not f.fieldtype.is_optional() and f.name not in ret:
                raise ValueError("{} missing field {}".format(self, f))

        return ret, s[1:]

    def _raise_if_badvals(self, v: Dict[str, Any]) -> None:
        # Every non-optional value must be specified, and no others.
        defined = set([f.name for f in self.fields])
        have = set(v)

        unknown = have.difference(defined)
        if unknown:
            raise ValueError("Unknown fields specified: {}".format(unknown))

        for f in defined.difference(have):
            field = self.find_field(f)
            assert field
            if not field.fieldtype.is_optional():
                raise ValueError("Missing value for {}".format(field))

    def val_to_str(self, v: Dict[str, Any], otherfields: Dict[str, Any]) -> str:
        self._raise_if_badvals(v)
        s = ''
        sep = ''
        for fname, val in v.items():
            field = self.find_field(fname)
            assert field
            s += sep + fname + '=' + field.fieldtype.val_to_str(val, otherfields)
            sep = ','

        return '{' + s + '}'

    def val_to_py(self, val: Dict[str, Any], otherfields: Dict[str, Any]) -> Dict[str, Any]:
        ret: Dict[str, Any] = {}
        for k, v in val.items():
            field = self.find_field(k)
            assert field
            ret[k] = field.fieldtype.val_to_py(v, val)
        return ret

    def write(self, io_out: BufferedIOBase, v: Dict[str, Any], otherfields: Dict[str, Any]) -> None:
        self._raise_if_badvals(v)
        for f in self.fields:
            if f.name in v:
                val = v[f.name]
            else:
                if f.option is not None:
                    raise ValueError("Missing field {} {}".format(f.name, otherfields))
                val = None

            if type(f.fieldtype) is SubtypeType:
                otherfields = otherfields[f.name]
            f.fieldtype.write(io_out, val, otherfields)

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vals: Dict[str, Any] = {}
        for field in self.fields:
            val = field.fieldtype.read(io_in, vals)
            if val is None:
                # If first field fails to read, we return None.
                if field == self.fields[0]:
                    return None
                # Might only exist with certain options available
                if field.option is not None:
                    break
                # Otherwise, we only read part of it!
                raise ValueError("{}.{}: short read".format(self, field))
            vals[field.name] = val

        return vals

    @staticmethod
    def subfield_from_csv(namespace: MessageNamespace, parts: List[str]) -> None:
        """e.g
subtypedata,channel_update_timestamps,timestamp_node_id_1,u32,"""
        if len(parts) != 4:
            raise ValueError("subtypedata expected 4 CSV parts, not {}"
                             .format(parts))
        subtype = namespace.get_subtype(parts[0])
        if subtype is None:
            raise ValueError("unknown subtype {}".format(parts[0]))

        field = subtype._field_from_csv(namespace, parts[1:])
        if field.fieldtype.only_at_tlv_end():
            raise ValueError("{}: cannot have TLV field {}"
                             .format(subtype, field))
        subtype.add_field(field)


class MessageType(SubtypeType):
    """Each MessageType has a specific value, eg 17 is error"""
    # * 0x8000 (BADONION): unparsable onion encrypted by sending peer
    # * 0x4000 (PERM): permanent failure (otherwise transient)
    # * 0x2000 (NODE): node failure (otherwise channel)
    # * 0x1000 (UPDATE): new channel update enclosed
    onion_types = {'BADONION': 0x8000,
                   'PERM': 0x4000,
                   'NODE': 0x2000,
                   'UPDATE': 0x1000}

    def __init__(self, name: str, value: str, option: Optional[str] = None):
        super().__init__(name)
        self.number = self.parse_value(value)
        self.option = option

    def parse_value(self, value: str) -> int:
        result = 0
        for token in value.split('|'):
            if token in self.onion_types.keys():
                result |= self.onion_types[token]
            else:
                result |= int(token)

        return result

    def __str__(self):
        return "msgtype-{}".format(self.name)

    @staticmethod
    def msgtype_from_csv(parts: List[str]) -> 'MessageType':
        """e.g msgtype,open_channel,32,option_foo"""
        option = None
        if len(parts) == 3:
            option = parts[2]
        elif len(parts) < 2 or len(parts) > 3:
            raise ValueError("msgtype expected 3 CSV parts, not {}"
                             .format(parts))
        return MessageType(parts[0], parts[1], option)

    @staticmethod
    def msgfield_from_csv(namespace: MessageNamespace, parts: List[str]) -> None:
        """e.g msgdata,open_channel,temporary_channel_id,byte,32[,opt]"""
        option = None
        if len(parts) == 5:
            option = parts[4]
        elif len(parts) != 4:
            raise ValueError("msgdata expected 4 CSV parts, not {}"
                             .format(parts))
        messagetype = namespace.get_msgtype(parts[0])
        if messagetype is None:
            raise ValueError("unknown subtype {}".format(parts[0]))

        field = messagetype._field_from_csv(namespace, parts[1:4],
                                            option=option)
        messagetype.add_field(field)


class TlvMessageType(MessageType):
    """A 'tlvtype' in BOLT-speak"""

    def __init__(self, name: str, value: str):
        super().__init__(name, value)

    def __str__(self):
        return "tlvmsgtype-{}".format(self.name)


class TlvStreamType(FieldType):
    """A TlvStreamType's fields are TlvMessageTypes.  In the CSV format
these are created implicitly, when a tlvtype line (which defines a
TlvMessageType within the TlvType, confusingly) refers to them.

    """
    def __init__(self, name):
        super().__init__(name)
        self.fields: List[TlvMessageType] = []

    def __str__(self):
        return "tlvstreamtype-{}".format(self.name)

    def find_field(self, fieldname: str) -> Optional[TlvMessageType]:
        for f in self.fields:
            if f.name == fieldname:
                return f
        return None

    def find_field_by_number(self, num: int) -> Optional[TlvMessageType]:
        for f in self.fields:
            if f.number == num:
                return f
        return None

    def add_field(self, field: TlvMessageType) -> None:
        if self.find_field(field.name):
            raise ValueError("{}: duplicate field {}".format(self, field))
        self.fields.append(field)

    def is_optional(self) -> bool:
        """You can omit a tlvstream= altogether"""
        return True

    @staticmethod
    def tlvtype_from_csv(namespace: MessageNamespace, parts: List[str]) -> None:
        """e.g tlvtype,reply_channel_range_tlvs,timestamps_tlv,1"""
        if len(parts) != 3:
            raise ValueError("tlvtype expected 4 CSV parts, not {}"
                             .format(parts))
        tlvstream = namespace.get_tlvtype(parts[0])
        if tlvstream is None:
            tlvstream = TlvStreamType(parts[0])
            namespace.add_tlvtype(tlvstream)

        tlvstream.add_field(TlvMessageType(parts[1], parts[2]))

    @staticmethod
    def tlvfield_from_csv(namespace: MessageNamespace, parts: List[str]) -> None:
        """e.g
tlvdata,reply_channel_range_tlvs,timestamps_tlv,encoding_type,u8,

        """
        if len(parts) != 5:
            raise ValueError("tlvdata expected 6 CSV parts, not {}"
                             .format(parts))

        tlvstream = namespace.get_tlvtype(parts[0])
        if tlvstream is None:
            raise ValueError("unknown tlvtype {}".format(parts[0]))

        field = tlvstream.find_field(parts[1])
        if field is None:
            raise ValueError("Unknown tlv field {}.{}"
                             .format(tlvstream, parts[1]))

        subfield = field._field_from_csv(namespace, parts[2:])
        field.add_field(subfield)

    def val_from_str(self, s: str) -> Tuple[Dict[str, Any], str]:
        """{fieldname={...},...}.  Returns dict of fieldname->val"""
        if not s.startswith('{'):
            raise ValueError("tlvtype {} must be wrapped in '{{}}': bad {}"
                             .format(self, s))
        s = s[1:]
        ret: Dict[str, Any] = {}
        while not s.startswith('}'):
            fieldname, s = s.split('=', 1)
            f = self.find_field(fieldname)
            if f is None:
                # Unknown fields are number=hexstring
                hexstring, s = split_field(s)
                # Make sure it is actually a valid int!
                ret[str(int(fieldname))] = bytes.fromhex(hexstring)
            else:
                ret[fieldname], s = f.val_from_str(s)
            if s[0] == ',':
                s = s[1:]

        return ret, s[1:]

    def val_to_str(self, v: Dict[str, Any], otherfields: Dict[str, Any]) -> str:
        s = ''
        sep = ''
        for fieldname in v:
            f = self.find_field(fieldname)
            s += sep
            if f is None:
                s += str(int(fieldname)) + '=' + v[fieldname].hex()
            else:
                s += f.name + '=' + f.val_to_str(v[fieldname], otherfields)
            sep = ','

        return '{' + s + '}'

    def val_to_py(self, val: Dict[str, Any], otherfields: Dict[str, Any]) -> Dict[str, Any]:
        ret: Dict[str, Any] = {}
        for k, v in val.items():
            field = self.find_field(k)
            if field:
                ret[k] = field.val_to_py(v, val)
            else:
                # Unknown TLV, index by number.
                assert isinstance(k, int)
                ret[k] = v.hex()
        return ret

    def write(self, io_out: BufferedIOBase, v: Optional[Dict[str, Any]], otherfields: Dict[str, Any]) -> None:
        # If they didn't specify this tlvstream, it's empty.
        if v is None:
            return

        # Make a tuple of (fieldnum, val_to_bin, val) so we can sort into
        # ascending order as TLV spec requires.
        def write_raw_val(iobuf: BufferedIOBase, val: Any, otherfields: Dict[str, Any]) -> None:
            iobuf.write(val)

        def get_value(tup):
            """Get value from num, fun, val tuple"""
            return tup[0]

        ordered: List[Tuple[int,
                            Callable[[BufferedIOBase, Any, Dict[str, Any]], None],
                            Any]] = []
        for fieldname in v:
            f = self.find_field(fieldname)
            if f is None:
                # fieldname can be an integer for a raw field.
                ordered.append((int(fieldname), write_raw_val, v[fieldname]))
            else:
                ordered.append((f.number, f.write, v[fieldname]))

        ordered.sort(key=get_value)

        for typenum, writefunc, val in ordered:
            buf = BytesIO()
            writefunc(cast(BufferedIOBase, buf), val, val)
            BigSizeType.write(io_out, typenum)
            BigSizeType.write(io_out, len(buf.getvalue()))
            io_out.write(buf.getvalue())

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Dict[Union[str, int], Any]:
        vals: Dict[Union[str, int], Any] = {}

        while True:
            tlv_type = BigSizeType.read(io_in)
            if tlv_type is None:
                return vals

            tlv_len = BigSizeType.read(io_in)
            if tlv_len is None:
                raise ValueError("{}: truncated tlv_len field".format(self))
            binval = io_in.read(tlv_len)
            if len(binval) != tlv_len:
                raise ValueError("{}: truncated tlv {} value"
                                 .format(tlv_type, self))
            f = self.find_field_by_number(tlv_type)
            if f is None:
                # Raw fields are allowed, just index by number.
                vals[tlv_type] = binval
            else:
                # FIXME: Why doesn't mypy think BytesIO is a valid BufferedIOBase?
                vals[f.name] = f.read(cast(BufferedIOBase, BytesIO(binval)), otherfields)

    def name_and_val(self, name: str, v: Dict[str, Any]) -> str:
        """This is overridden by LengthFieldType to return nothing"""
        return " {}={}".format(name, self.val_to_str(v, {}))


class Message(object):
    """A particular message instance"""
    def __init__(self, messagetype: MessageType, **kwargs):
        """MessageType is the type of this msg, with fields.  Fields can either be valid values for the type, or if they are strings they are converted according to the field type"""
        self.messagetype = messagetype
        self.fields: Dict[str, Any] = {}

        # Convert arguments from strings to values if necessary.
        for field in kwargs:
            self.set_field(field, kwargs[field])

        bad_lens = self.messagetype.len_fields_bad(self.messagetype.name,
                                                   self.fields)
        if bad_lens:
            raise ValueError("Inconsistent length fields: {}".format(bad_lens))

    def set_field(self, field: str, val: Any) -> None:
        f = self.messagetype.find_field(field)
        if f is None:
            raise ValueError("Unknown field {}".format(field))
        if isinstance(f.fieldtype, LengthFieldType):
            raise ValueError("Cannot specify implied length field {}".format(field))
        if isinstance(val, str):
            val, remainder = f.fieldtype.val_from_str(val)
            if remainder != '':
                raise ValueError('Unexpected {} at end of initializer for {}'.format(remainder, field))
        self.fields[field] = val

    def missing_fields(self) -> List[str]:
        """Are any required fields missing?"""
        missing: List[str] = []
        for ftype in self.messagetype.fields:
            missing += ftype.missing_fields(self.fields)

        return missing

    @staticmethod
    def read(namespace: MessageNamespace, io_in: BufferedIOBase) -> Optional['Message']:
        """Read and decode a Message within that namespace.

Returns None on EOF

        """
        typenum = try_unpack('message_type', io_in, ">H", empty_ok=True)
        if typenum is None:
            return None

        mtype = namespace.get_msgtype_by_number(typenum)
        if mtype is None:
            raise ValueError('Unknown message type number {}'.format(typenum))

        fields: Dict[str, Any] = {}
        for f in mtype.fields:
            fields[f.name] = f.fieldtype.read(io_in, fields)
            if fields[f.name] is None:
                # optional fields are OK to be missing at end!
                if f.option is not None:
                    del fields[f.name]
                    break
                raise ValueError('{}: truncated at field {}'
                                 .format(mtype, f.name))

        return Message(mtype, **fields)

    @staticmethod
    def from_str(namespace: MessageNamespace, s: str, incomplete_ok=False) -> 'Message':
        """Decode a string to a Message within that namespace.

Format is msgname [ field=...]*.

        """
        parts = s.split()

        mtype = namespace.get_msgtype(parts[0])
        if mtype is None:
            raise ValueError('Unknown message type name {}'.format(parts[0]))

        args = {}
        for p in parts[1:]:
            assign = p.split('=', 1)
            args[assign[0]] = assign[1]

        m = Message(mtype, **args)

        if not incomplete_ok:
            missing = m.missing_fields()
            if len(missing):
                raise ValueError('Missing fields: {}'.format(missing))

        return m

    def write(self, io_out: BufferedIOBase) -> None:
        """Write a Message into its wire format.

Must not have missing fields.

        """
        if self.missing_fields():
            raise ValueError('Missing fields: {}'
                             .format(self.missing_fields()))

        io_out.write(struct.pack(">H", self.messagetype.number))
        for f in self.messagetype.fields:
            # Optional fields get val == None.  Usually this means they don't
            # write anything, but length fields are an exception: they intuit
            # their value from other fields.
            if f.name in self.fields:
                val = self.fields[f.name]
            else:
                # If this isn't present, and it's marked optional, don't write.
                if f.option is not None:
                    return
                val = None
            f.fieldtype.write(io_out, val, self.fields)

    def to_str(self) -> str:
        """Encode a Message into a string"""
        ret = "{}".format(self.messagetype.name)
        for f in self.messagetype.fields:
            if f.name in self.fields:
                ret += f.fieldtype.name_and_val(f.name, self.fields[f.name])
        return ret

    def to_py(self) -> Dict[str, Any]:
        """Convert to a Python native object: dicts, lists, strings, ints"""
        ret: Dict[str, Union[Dict[str, Any], List[Any], str, int]] = {}
        for f, v in self.fields.items():
            field = self.messagetype.find_field(f)
            assert field
            ret[f] = field.fieldtype.val_to_py(v, self.fields)

        return ret
