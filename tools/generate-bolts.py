#! /usr/bin/env python3
# Script to parse spec output CSVs and produce C files.
# Released by lisa neigut under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
#
# Reads from stdin, outputs C header or body file.
#
# Standard message types:
#   msgtype,<msgname>,<value>[,<option>]
#   msgdata,<msgname>,<fieldname>,<typename>,[<count>][,<option>]
#
# TLV types:
#   tlvtype,<tlvstreamname>,<tlvname>,<value>[,<option>]
#   tlvdata,<tlvstreamname>,<tlvname>,<fieldname>,<typename>,[<count>][,<option>]
#
# Subtypes:
#   subtype,<subtypename>
#   subtypedata,<subtypename>,<fieldname>,<typename>,[<count>]

from argparse import ArgumentParser, REMAINDER
import copy
import fileinput
from mako.template import Template
import os
import re
import sys


# Generator to give us one line at a time.
def next_line(args, lines):
    if lines is None:
        lines = fileinput.input(args)

    for i, line in enumerate(lines):
        yield i + 1, line.strip()


# Class definitions, to keep things classy
class Field(object):
    def __init__(self, name, type_obj, extension=False,
                 field_comments=[], optional=False):
        self.name = name
        self.type_obj = type_obj
        self.count = 1
        self.len_field_of = None
        self.len_field = None

        self.is_extension = extension
        self.is_optional = optional
        self.field_comments = field_comments

    def add_count(self, count):
        self.count = int(count)

    def add_len_field(self, len_field):
        self.count = False
        # we cache our len-field's name
        self.len_field = len_field.name
        # the len-field caches our name
        len_field.len_field_of = self.name

    def is_array(self):
        return self.count > 1

    def is_varlen(self):
        return not self.count

    def is_optional(self):
        return self.is_optional

    def is_extension(self):
        return self.is_extension

    def size(self):
        if self.count:
            return self.count
        return self.len_field

    def needs_context(self):
        """ A field needs a context if its type needs context
            or if it's varsized """
        return self.is_varlen() or self.type_obj.needs_context()

    def arg_desc_to(self):
        if self.len_field_of:
            return ''
        type_name = self.type_obj.type_name()
        if self.is_array():
            return ', const {} {}[{}]'.format(type_name, self.name, self.count)
        if self.type_obj.is_assignable() and not self.is_varlen():
            return ', {} {}'.format(type_name, self.name)
        if self.is_varlen() and self.type_obj.is_varsize():
            return ', const {} **{}'.format(type_name, self.name)
        return ', const {} *{}'.format(type_name, self.name)

    def arg_desc_from(self):
        if self.len_field_of:
            return ''
        type_name = self.type_obj.type_name()
        if self.is_array():
            return ', {} {}[{}]'.format(type_name, self.name, self.count)
        ptrs = '*'
        if self.is_varlen() or self.is_optional or self.type_obj.is_varsize():
            ptrs += '*'
        if self.is_varlen() and self.type_obj.is_varsize():
            ptrs += '*'
        return ', {} {}{}'.format(type_name, ptrs, self.name)


class FieldSet(object):
    def __init__(self):
        self.fields = {}
        self.extension_fields = False
        self.len_fields = {}

    def add_data_field(self, field_name, type_obj, count=1,
                       is_extension=[], comments=[], optional=False):
        if is_extension:
            self.extension_fields = True

        field = Field(field_name, type_obj, extension=bool(is_extension),
                      field_comments=comments, optional=optional)
        if bool(count):
            try:
                field.add_count(int(count))
            except ValueError:
                len_field = self.find_data_field(count)
                if not len_field:
                    raise ValueError("No length field found with name {} for {}:{}"
                                     .format(count, self.name, field_name))
                field.add_len_field(len_field)
                self.len_fields[len_field.name] = len_field

        self.fields[field_name] = field

    def find_data_field(self, field_name):
        return self.fields[field_name]

    def get_len_fields(self):
        return list(self.len_fields.values())

    def has_len_fields(self):
        return bool(self.len_fields)

    def needs_context(self):
        return any([field.needs_context() for field in self.fields.values()])


class Type(FieldSet):
    assignables = [
        'u8',
        'u16',
        'u32',
        'u64',
        'bool',
        'amount_sat',
        'amount_msat',
        # FIXME: omits var_int
    ]

    typedefs = [
        'u8',
        'u16',
        'u32',
        'u64',
        'bool',
        'secp256k1_ecdsa_signature',
    ]

    # Externally defined variable size types (require a context)
    varsize_types = [
        'peer_features',
        'gossip_getnodes_entry',
        'gossip_getchannels_entry',
        'failed_htlc',
        'utxo',
        'bitcoin_tx',
        'wirestring',
        'per_peer_state',
    ]

    # Some BOLT types are re-typed based on their field name
    # ('fieldname partial', 'original type'): ('true type', 'collapse array?')
    name_field_map = {
        ('txid', 'sha256'): ('bitcoin_txid', False),
        ('amt', 'u64'): ('amount_msat', False),
        ('msat', 'u64'): ('amount_msat', False),
        ('satoshis', 'u64'): ('amount_sat', False),
        ('node_id', 'pubkey'): ('node_id', False),
        ('temporary_channel_id', 'u8'): ('channel_id', True),
        ('secret', 'u8'): ('secret', True),
        ('preimage', 'u8'): ('preimage', True),
    }

    # For BOLT specified types, a few type names need to be simply 'remapped'
    # 'original type': 'true type'
    name_remap = {
        'byte': 'u8',
        'signature': 'secp256k1_ecdsa_signature',
        'chain_hash': 'bitcoin_blkid',
        'point': 'pubkey',
        # FIXME: omits 'pad'
    }

    @staticmethod
    def true_type(type_name, field_name=None):
        """ Returns 'true' type of a given type and a flag if
            we've remapped a variable size/array type to a single struct
            (an example of this is 'temporary_channel_id' which is specified
            as a 32*byte, but we re-map it to a channel_id
        """
        if type_name in Type.name_remap:
            type_name = Type.name_remap[type_name]

        if field_name:
            for (partial, t), true_type in Type.name_field_map.items():
                if partial in field_name and t == type_name:
                    return true_type
        return (type_name, False)

    def __init__(self, name):
        FieldSet.__init__(self)
        self.name = name
        self.depends_on = {}
        # FIXME: internal msgs can be enums
        self.is_enum = False
        self.type_comments = []

    def add_data_field(self, field_name, type_obj, count=2,
                       is_extension=[], comments=[], optional=False):
        FieldSet.add_data_field(self, field_name, type_obj, count,
                                is_extension, comments=comments, optional=optional)
        if type_obj.name not in self.depends_on:
            self.depends_on[type_obj.name] = type_obj

    def type_name(self):
        if self.name in self.typedefs:
            return self.name
        prefix = 'enum ' if self.is_enum else 'struct '
        return prefix + self.name

    # We only accelerate the u8 case: it's common and trivial.
    def has_array_helper(self):
        return self.name in ['u8']

    def struct_name(self):
        return self.name

    def subtype_deps(self):
        return [dep for dep in self.depends_on.values() if dep.is_subtype()]

    def is_subtype(self):
        return bool(self.fields)

    def needs_context(self):
        return self.is_varsize() or any([field.needs_context() for field in self.fields.values()])

    def is_assignable(self):
        """ Generally typedef's and enums """
        return self.name in self.assignables or self.is_enum

    def is_varsize(self):
        """ A type is variably sized if it's marked as such (in varsize_types)
            or it contains a field of variable length """
        return self.name in self.varsize_types or self.has_len_fields()

    def add_comments(self, comments):
        self.type_comments = comments


class Message(FieldSet):
    def __init__(self, name, number, option=[], enum_prefix='wire',
                 struct_prefix=None, comments=[]):
        FieldSet.__init__(self)
        self.name = name
        self.number = number
        self.enum_prefix = enum_prefix
        self.option = option[0] if len(option) else None
        self.struct_prefix = struct_prefix
        self.enumname = None
        self.msg_comments = comments

    def has_option(self):
        return self.option is not None

    def enum_name(self):
        name = self.enumname if self.enumname else self.name
        return "{}_{}".format(self.enum_prefix, name).upper()

    def struct_name(self):
        if self.struct_prefix:
            return self.struct_prefix + "_" + self.name
        return self.name


class Tlv(object):
    def __init__(self, name):
        self.name = name
        self.messages = {}

    def add_message(self, tokens, comments=[]):
        """ tokens -> (name, value[, option]) """
        self.messages[tokens[0]] = Message(tokens[0], tokens[1], option=tokens[2:],
                                           enum_prefix=self.name, struct_prefix=self.name,
                                           comments=comments)

    def find_message(self, name):
        return self.messages[name]


class Master(object):
    types = {}
    tlvs = {}
    messages = {}
    extension_msgs = {}
    inclusions = []
    top_comments = []

    def add_comments(self, comments):
        self.top_comments += comments

    def add_include(self, inclusion):
        self.inclusions.append(inclusion)

    def add_tlv(self, tlv_name):
        if tlv_name not in self.tlvs:
            self.tlvs[tlv_name] = Tlv(tlv_name)
        return self.tlvs[tlv_name]

    def add_message(self, tokens, comments=[]):
        """ tokens -> (name, value[, option])"""
        self.messages[tokens[0]] = Message(tokens[0], tokens[1], option=tokens[2:],
                                           comments=comments)

    def add_extension_msg(self, name, msg):
        self.extension_msgs[name] = msg

    def add_type(self, type_name, field_name=None):
        optional = False
        if type_name.startswith('?'):
            type_name = type_name[1:]
            optional = True
        # Check for special type name re-mapping
        type_name, collapse_original = Type.true_type(type_name, field_name)

        if type_name not in self.types:
            self.types[type_name] = Type(type_name)
        return self.types[type_name], collapse_original, optional

    def find_type(self, type_name):
        return self.types[type_name]

    def find_message(self, msg_name):
        if msg_name in self.messages:
            return self.messages[msg_name]
        if msg_name in self.extension_msgs:
            return self.extension_msgs[msg_name]
        return None

    def find_tlv(self, tlv_name):
        return self.tlvs[tlv_name]

    def get_ordered_subtypes(self):
        """ We want to order subtypes such that the 'no dependency'
        types are printed first """
        subtypes = [s for s in self.types.values() if s.is_subtype()]

        # Start with subtypes without subtype dependencies
        sorted_types = [s for s in subtypes if not len(s.subtype_deps())]
        unsorted = [s for s in subtypes if len(s.subtype_deps())]
        while len(unsorted):
            names = [s.name for s in sorted_types]
            for s in list(unsorted):
                if all([dependency.name in names for dependency in s.subtype_deps()]):
                    sorted_types.append(s)
                    unsorted.remove(s)
        return sorted_types

    def tlv_messages(self):
        return [m for tlv in self.tlvs.values() for m in tlv.messages.values()]

    def find_template(self, options):
        dirpath = os.path.dirname(os.path.abspath(__file__))
        filename = dirpath + '/gen/{}{}_template'.format(
            'print_' if options.print_wire else '', options.page)

        return Template(filename=filename)

    def write(self, options, output):
        template = self.find_template(options)
        enum_sets = []
        enum_sets.append({
            'name': options.enum_name,
            'set': self.messages.values(),
        })
        for tlv in self.tlvs.values():
            enum_sets.append({
                'name': tlv.name,
                'set': tlv.messages.values(),
            })
        stuff = {}
        stuff['top_comments'] = self.top_comments
        stuff['options'] = options
        stuff['idem'] = re.sub(r'[^A-Z]+', '_', options.header_filename.upper())
        stuff['header_filename'] = options.header_filename
        stuff['includes'] = self.inclusions
        stuff['enum_sets'] = enum_sets
        subtypes = self.get_ordered_subtypes()
        stuff['structs'] = subtypes + self.tlv_messages()
        stuff['tlvs'] = self.tlvs.values()
        stuff['messages'] = list(self.messages.values()) + list(self.extension_msgs.values())
        stuff['subtypes'] = subtypes

        print(template.render(**stuff), file=output)


def main(options, args=None, output=sys.stdout, lines=None):
    genline = next_line(args, lines)

    comment_set = []

    # Create a new 'master' that serves as the coordinator for the file generation
    master = Master()
    try:
        while True:
            ln, line = next(genline)
            tokens = line.split(',')
            token_type = tokens[0]

            if not bool(line):
                master.add_comments(comment_set)
                comment_set = []
                continue

            if token_type == 'subtype':
                subtype, _, _ = master.add_type(tokens[1])

                subtype.add_comments(list(comment_set))
                comment_set = []
            elif token_type == 'subtypedata':
                subtype = master.find_type(tokens[1])
                if not subtype:
                    raise ValueError('Unknown subtype {} for data.\nat {}:{}'
                                     .format(tokens[1], ln, line))
                type_obj, collapse, optional = master.add_type(tokens[3], tokens[2])
                if optional:
                    raise ValueError('Subtypes cannot have optional fields {}.{}\n at {}:{}'
                                     .format(subtype.name, tokens[2], ln, line))
                if collapse:
                    count = 1
                else:
                    count = tokens[4]

                subtype.add_data_field(tokens[2], type_obj, count, comments=list(comment_set),
                                       optional=optional)
                comment_set = []
            elif token_type == 'tlvtype':
                tlv = master.add_tlv(tokens[1])
                tlv.add_message(tokens[2:], comments=list(comment_set))

                comment_set = []
            elif token_type == 'tlvdata':
                type_obj, collapse, optional = master.add_type(tokens[4], tokens[3])
                if optional:
                    raise ValueError('TLV messages cannot have optional fields {}.{}\n at {}:{}'
                                     .format(tokens[2], tokens[3], ln, line))

                tlv = master.find_tlv(tokens[1])
                if not tlv:
                    raise ValueError('tlvdata for unknown tlv {}.\nat {}:{}'
                                     .format(tokens[1], ln, line))
                msg = tlv.find_message(tokens[2])
                if not msg:
                    raise ValueError('tlvdata for unknown tlv-message {}.\nat {}:{}'
                                     .format(tokens[2], ln, line))
                if collapse:
                    count = 1
                else:
                    count = tokens[5]

                msg.add_data_field(tokens[3], type_obj, count, comments=list(comment_set),
                                   optional=optional)
                comment_set = []
            elif token_type == 'msgtype':
                master.add_message(tokens[1:], comments=list(comment_set))
                comment_set = []
            elif token_type == 'msgdata':
                msg = master.find_message(tokens[1])
                if not msg:
                    raise ValueError('Unknown message type {}. {}:{}'.format(tokens[1], ln, line))
                type_obj, collapse, optional = master.add_type(tokens[3], tokens[2])

                # if this is an 'extension' field*, we want to add a new 'message' type
                # in the future, extensions will be handled as TLV's
                #
                # *(in the spec they're called 'optional', but that term is overloaded
                #   in that internal wire messages have 'optional' fields that are treated
                #   differently. for the sake of clarity here, for bolt-wire messages,
                #   we'll refer to 'optional' message fields as 'extensions')
                #
                if bool(tokens[5:]):  # is an extension field
                    extension_name = "{}_{}".format(tokens[1], tokens[5])
                    orig_msg = msg
                    msg = master.find_message(extension_name)
                    if not msg:
                        msg = copy.deepcopy(orig_msg)
                        msg.enumname = msg.name
                        msg.name = extension_name
                        master.add_extension_msg(msg.name, msg)

                if collapse:
                    count = 1
                else:
                    count = tokens[4]

                msg.add_data_field(tokens[2], type_obj, count, comments=list(comment_set),
                                   optional=optional)
                comment_set = []
            elif token_type.startswith('#include'):
                master.add_include(token_type)
            elif token_type.startswith('#'):
                comment_set.append(token_type[1:])
            else:
                raise ValueError("Unknown token type {} on line {}:{}".format(token_type, ln, line))

    except StopIteration:
        pass

    master.write(options, output)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-s", "--expose-subtypes", help="print subtypes in header",
                        action="store_true", default=False)
    parser.add_argument("-P", "--print_wire", help="generate wire printing source files",
                        action="store_true", default=False)
    parser.add_argument("--page", choices=['header', 'impl'], help="page to print")
    parser.add_argument('header_filename', help='The filename of the header')
    parser.add_argument('enum_name', help='The name of the enum to produce')
    parser.add_argument("files", help='Files to read in (or stdin)', nargs=REMAINDER)
    parsed_args = parser.parse_args()

    main(parsed_args, parsed_args.files)
