import struct
import io
from .fundamental_types import fundamental_types, BigSizeType, split_field, try_unpack
from .array_types import (
    SizedArrayType, DynamicArrayType, LengthFieldType, EllipsisArrayType
)


class MessageNamespace(object):
    """A class which contains all FieldTypes and Messages in a particular
domain, such as within a given BOLT"""
    def __init__(self, csv_lines=[]):
        self.subtypes = {}
        self.fundamentaltypes = {}
        self.tlvtypes = {}
        self.messagetypes = {}

        # For convenience, basic types go in every namespace
        for t in fundamental_types():
            self.add_fundamentaltype(t)

        self.load_csv(csv_lines)

    def add_subtype(self, t):
        prev = self.get_type(t.name)
        if prev:
            return ValueError('Already have {}'.format(prev))
        self.subtypes[t.name] = t

    def add_fundamentaltype(self, t):
        assert not self.get_type(t.name)
        self.fundamentaltypes[t.name] = t

    def add_tlvtype(self, t):
        prev = self.get_type(t.name)
        if prev:
            return ValueError('Already have {}'.format(prev))
        self.tlvtypes[t.name] = t

    def add_messagetype(self, m):
        if self.get_msgtype(m.name):
            return ValueError('{}: message already exists'.format(m.name))
        if self.get_msgtype_by_number(m.number):
            return ValueError('{}: message {} already number {}'.format(
                m.name, self.get_msg_by_number(m.number), m.number))
        self.messagetypes[m.name] = m

    def get_msgtype(self, name):
        if name in self.messagetypes:
            return self.messagetypes[name]
        return None

    def get_msgtype_by_number(self, num):
        for m in self.messagetypes.values():
            if m.number == num:
                return m
        return None

    def get_fundamentaltype(self, name):
        if name in self.fundamentaltypes:
            return self.fundamentaltypes[name]
        return None

    def get_subtype(self, name):
        if name in self.subtypes:
            return self.subtypes[name]
        return None

    def get_tlvtype(self, name):
        if name in self.tlvtypes:
            return self.tlvtypes[name]
        return None

    def get_type(self, name):
        t = self.get_fundamentaltype(name)
        if not t:
            t = self.get_subtype(name)
        if not t:
            t = self.get_tlvtype(name)
        return t

    def get_tlv_by_number(self, num):
        for t in self.tlvtypes:
            if t.number == num:
                return t
        return None

    def load_csv(self, lines):
        """Load a series of comma-separate-value lines into the namespace"""
        vals = {'msgtype': [],
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
            self.add_messagetype(MessageType.type_from_csv(parts))

        for parts in vals['subtype']:
            self.add_subtype(SubtypeType.type_from_csv(parts))

        for parts in vals['tlvtype']:
            TlvStreamType.type_from_csv(self, parts)

        for parts in vals['msgdata']:
            MessageType.field_from_csv(self, parts)

        for parts in vals['subtypedata']:
            SubtypeType.field_from_csv(self, parts)

        for parts in vals['tlvdata']:
            TlvStreamType.field_from_csv(self, parts)


class MessageTypeField(object):
    """A field within a particular message type or subtype"""
    def __init__(self, ownername, name, fieldtype, option=None):
        self.full_name = "{}.{}".format(ownername, name)
        self.name = name
        self.fieldtype = fieldtype
        self.option = option

    def missing_fields(self, fields):
        """Return this field if it's not in fields"""
        if self.name not in fields and not self.fieldtype.is_optional():
            return [self]
        return []

    def len_fields_bad(self, fieldname, otherfields):
        return self.fieldtype.len_fields_bad(fieldname, otherfields)

    def __str__(self):
        return self.full_name

    def __repr__(self):
        """Yuck, but this is what format() uses for lists"""
        return self.full_name


class SubtypeType(object):
    """This defines a 'subtype' in BOLT-speak.  It consists of fields of
other types.  Since 'msgtype' and 'tlvtype' are almost identical, they
inherit from this too.

    """
    def __init__(self, name):
        self.name = name
        self.fields = []

    def find_field(self, fieldname):
        for f in self.fields:
            if f.name == fieldname:
                return f
        return None

    def add_field(self, field):
        if self.find_field(field.name):
            raise ValueError("{}: duplicate field {}".format(self, field))
        self.fields.append(field)

    def __str__(self):
        return "subtype-{}".format(self.name)

    def len_fields_bad(self, fieldname, otherfields):
        bad_fields = []
        for f in self.fields:
            bad_fields += f.len_fields_bad('{}.{}'.format(fieldname, f.name),
                                           otherfields)

        return bad_fields

    @staticmethod
    def type_from_csv(parts):
        """e.g subtype,channel_update_timestamps"""
        if len(parts) != 1:
            raise ValueError("subtype expected 2 CSV parts, not {}"
                             .format(parts))
        return SubtypeType(parts[0])

    def _field_from_csv(self, namespace, parts, ellipsisok=False, option=None):
        """Takes msgdata/subtypedata after first two fields
        e.g. [...]timestamp_node_id_1,u32,

        """
        basetype = namespace.get_type(parts[1])
        if not basetype:
            raise ValueError('Unknown type {}'.format(parts[1]))

        # Fixed number, or another field.
        if parts[2] != '':
            lenfield = self.find_field(parts[2])
            if lenfield is not None:
                # If we didn't know that field was a length, we do now!
                if type(lenfield.fieldtype) is not LengthFieldType:
                    lenfield.fieldtype = LengthFieldType(lenfield.fieldtype)
                field = MessageTypeField(self.name, parts[0],
                                         DynamicArrayType(self,
                                                          parts[0],
                                                          basetype,
                                                          lenfield),
                                         option)
                lenfield.fieldtype.add_length_for(field)
            elif ellipsisok and parts[2] == '...':
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

    def val_from_str(self, s):
        if not s.startswith('{'):
            raise ValueError("subtype {} must be wrapped in '{{}}': bad {}"
                             .format(self, s))
        s = s[1:]
        ret = {}
        # FIXME: perhaps allow unlabelled fields to imply assign fields in order?
        while not s.startswith('}'):
            fieldname, s = s.split('=', 1)
            f = self.find_field(fieldname)
            if f is None:
                raise ValueError("Unknown field name {}".format(fieldname))
            ret[fieldname], s = f.fieldtype.val_from_str(s)
            if s[0] == ',':
                s = s[1:]

        # All non-optional fields must be specified.
        for f in self.fields:
            if not f.fieldtype.is_optional() and f.name not in ret:
                raise ValueError("{} missing field {}".format(self, f))

        return ret, s[1:]

    def _raise_if_badvals(self, v):
        # Every non-optional value must be specified, and no others.
        defined = set([f.name for f in self.fields])
        have = set(v)

        unknown = have.difference(defined)
        if unknown:
            raise ValueError("Unknown fields specified: {}".format(unknown))

        for f in defined.difference(have):
            if not f.fieldtype.is_optional():
                raise ValueError("Missing value for {}".format(f))

    def val_to_str(self, v, otherfields):
        self._raise_if_badvals(v)
        s = ''
        sep = ''
        for fname, val in v.items():
            field = self.find_field(fname)
            s += sep + fname + '=' + field.fieldtype.val_to_str(val, otherfields)
            sep = ','

        return '{' + s + '}'

    def write(self, io_out, v, otherfields):
        self._raise_if_badvals(v)
        for fname, val in v.items():
            field = self.find_field(fname)
            field.fieldtype.write(io_out, val, otherfields)

    def read(self, io_in, otherfields):
        vals = {}
        for field in self.fields:
            val = field.fieldtype.read(io_in, otherfields)
            if val is None:
                raise ValueError("{}.{}: short read".format(self, field))
            vals[field.name] = val

        return vals

    @staticmethod
    def field_from_csv(namespace, parts):
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

    def __init__(self, name, value, option=None):
        super().__init__(name)
        self.number = self.parse_value(value)
        self.option = option

    def parse_value(self, value):
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
    def type_from_csv(parts):
        """e.g msgtype,open_channel,32,option_foo"""
        option = None
        if len(parts) == 3:
            option = parts[2]
        elif len(parts) < 2 or len(parts) > 3:
            raise ValueError("msgtype expected 3 CSV parts, not {}"
                             .format(parts))
        return MessageType(parts[0], parts[1], option)

    @staticmethod
    def field_from_csv(namespace, parts):
        """e.g msgdata,open_channel,temporary_channel_id,byte,32[,opt]"""
        option = None
        if len(parts) == 5:
            option = parts[4]
        elif len(parts) != 4:
            raise ValueError("msgdata expected 4 CSV parts, not {}"
                             .format(parts))
        messagetype = namespace.get_msgtype(parts[0])
        if not messagetype:
            raise ValueError("unknown subtype {}".format(parts[0]))

        field = messagetype._field_from_csv(namespace, parts[1:4],
                                            option=option)
        messagetype.add_field(field)


class TlvStreamType(SubtypeType):
    """A TlvStreamType is just a Subtype, but its fields are
TlvMessageTypes.  In the CSV format these are created implicitly, when
a tlvtype line (which defines a TlvMessageType within the TlvType,
confusingly) refers to them.

    """
    def __init__(self, name):
        super().__init__(name)

    def __str__(self):
        return "tlvstreamtype-{}".format(self.name)

    def find_field_by_number(self, num):
        for f in self.fields:
            if f.number == num:
                return f
        return None

    def is_optional(self):
        """You can omit a tlvstream= altogether"""
        return True

    @staticmethod
    def type_from_csv(namespace, parts):
        """e.g tlvtype,reply_channel_range_tlvs,timestamps_tlv,1"""
        if len(parts) != 3:
            raise ValueError("tlvtype expected 4 CSV parts, not {}"
                             .format(parts))
        tlvstream = namespace.get_tlvtype(parts[0])
        if not tlvstream:
            tlvstream = TlvStreamType(parts[0])
            namespace.add_tlvtype(tlvstream)

        tlvstream.add_field(TlvMessageType(parts[1], parts[2]))

    @staticmethod
    def field_from_csv(namespace, parts):
        """e.g
tlvdata,reply_channel_range_tlvs,timestamps_tlv,encoding_type,u8,

        """
        if len(parts) != 5:
            raise ValueError("tlvdata expected 6 CSV parts, not {}"
                             .format(parts))

        tlvstream = namespace.get_tlvtype(parts[0])
        if not tlvstream:
            raise ValueError("unknown tlvtype {}".format(parts[0]))

        field = tlvstream.find_field(parts[1])
        if field is None:
            raise ValueError("Unknown tlv field {}.{}"
                             .format(tlvstream, parts[1]))

        subfield = field._field_from_csv(namespace, parts[2:], ellipsisok=True)
        field.add_field(subfield)

    def val_from_str(self, s):
        """{fieldname={...},...}.  Returns dict of fieldname->val"""
        if not s.startswith('{'):
            raise ValueError("tlvtype {} must be wrapped in '{{}}': bad {}"
                             .format(self, s))
        s = s[1:]
        ret = {}
        while not s.startswith('}'):
            fieldname, s = s.split('=', 1)
            f = self.find_field(fieldname)
            if f is None:
                # Unknown fields are number=hexstring
                hexstring, s = split_field(s)
                ret[int(fieldname)] = bytes.fromhex(hexstring)
            else:
                ret[fieldname], s = f.val_from_str(s)
            if s[0] == ',':
                s = s[1:]

        return ret, s[1:]

    def val_to_str(self, v, otherfields):
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

    def write(self, iobuf, v, otherfields):
        # If they didn't specify this tlvstream, it's empty.
        if v is None:
            return

        # Make a tuple of (fieldnum, val_to_bin, val) so we can sort into
        # ascending order as TLV spec requires.
        def write_raw_val(iobuf, val, otherfields):
            iobuf.write(val)

        def get_value(tup):
            """Get value from num, fun, val tuple"""
            return tup[0]

        ordered = []
        for fieldname in v:
            f = self.find_field(fieldname)
            if f is None:
                # fieldname can be an integer for a raw field.
                ordered.append((int(fieldname), write_raw_val, v[fieldname]))
            else:
                ordered.append((f.number, f.write, v[fieldname]))

        ordered.sort(key=get_value)

        for typenum, writefunc, val in ordered:
            buf = io.BytesIO()
            writefunc(buf, val, otherfields)
            BigSizeType.write(iobuf, typenum)
            BigSizeType.write(iobuf, len(buf.getvalue()))
            iobuf.write(buf.getvalue())

    def read(self, io_in, otherfields):
        vals = {}

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
                vals[f.name] = f.read(io.BytesIO(binval), otherfields)

    def name_and_val(self, name, v):
        """This is overridden by LengthFieldType to return nothing"""
        return " {}={}".format(name, self.val_to_str(v, None))


class TlvMessageType(MessageType):
    """A 'tlvtype' in BOLT-speak"""

    def __init__(self, name, value):
        super().__init__(name, value)

    def __str__(self):
        return "tlvmsgtype-{}".format(self.name)


class Message(object):
    """A particular message instance"""
    def __init__(self, messagetype, **kwargs):
        """MessageType is the type of this msg, with fields.  Fields can either be valid values for the type, or if they are strings they are converted according to the field type"""
        self.messagetype = messagetype
        self.fields = {}

        # Convert arguments from strings to values if necessary.
        for field in kwargs:
            f = self.messagetype.find_field(field)
            if f is None:
                raise ValueError("Unknown field {}".format(field))

            v = kwargs[field]
            if isinstance(v, str):
                v, remainder = f.fieldtype.val_from_str(v)
                if remainder != '':
                    raise ValueError('Unexpected {} at end of initializer for {}'.format(remainder, field))
            self.fields[field] = v

        bad_lens = self.messagetype.len_fields_bad(self.messagetype.name,
                                                   self.fields)
        if bad_lens:
            raise ValueError("Inconsistent length fields: {}".format(bad_lens))

    def missing_fields(self):
        """Are any required fields missing?"""
        missing = []
        for ftype in self.messagetype.fields:
            missing += ftype.missing_fields(self.fields)

        return missing

    @staticmethod
    def read(namespace, io_in):
        """Read and decode a Message within that namespace.

Returns None on EOF

        """
        typenum = try_unpack('message_type', io_in, ">H", empty_ok=True)
        if typenum is None:
            return None

        mtype = namespace.get_msgtype_by_number(typenum)
        if not mtype:
            raise ValueError('Unknown message type number {}'.format(typenum))

        fields = {}
        for f in mtype.fields:
            fields[f.name] = f.fieldtype.read(io_in, fields)
            if fields[f.name] is None:
                # optional fields are OK to be missing at end!
                raise ValueError('{}: truncated at field {}'
                                 .format(mtype, f.name))

        return Message(mtype, **fields)

    @staticmethod
    def from_str(namespace, s, incomplete_ok=False):
        """Decode a string to a Message within that namespace.

Format is msgname [ field=...]*.

        """
        parts = s.split()

        mtype = namespace.get_msgtype(parts[0])
        if not mtype:
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

    def write(self, io_out):
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
                val = None
            f.fieldtype.write(io_out, val, self.fields)

    def to_str(self):
        """Encode a Message into a string"""
        ret = "{}".format(self.messagetype.name)
        for f in self.messagetype.fields:
            if f.name in self.fields:
                ret += f.fieldtype.name_and_val(f.name, self.fields[f.name])
        return ret
