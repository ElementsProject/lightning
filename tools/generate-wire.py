#! /usr/bin/env python3
# Read from stdin, spit out C header or body.

import argparse
import copy
import fileinput
import re

from collections import namedtuple

Enumtype = namedtuple('Enumtype', ['name', 'value'])

type2size = {
    'pad': 1,
    'struct channel_id': 32,
    'struct short_channel_id': 8,
    'struct ipv6': 16,
    'secp256k1_ecdsa_signature': 64,
    'struct preimage': 32,
    'struct pubkey': 33,
    'struct sha256': 32,
    'struct bitcoin_blkid': 32,
    'struct bitcoin_txid': 32,
    'struct secret': 32,
    'u64': 8,
    'u32': 4,
    'u16': 2,
    'u8': 1,
    'bool': 1
}

# These struct array helpers require a context to allocate from.
varlen_structs = [
    'peer_features',
    'gossip_getnodes_entry',
    'failed_htlc',
    'utxo',
    'bitcoin_tx',
    'wirestring',
]


class FieldType(object):
    def __init__(self, name):
        self.name = name

    def is_assignable(self):
        return self.name in ['u8', 'u16', 'u32', 'u64', 'bool'] or self.name.startswith('enum ')

    # We only accelerate the u8 case: it's common and trivial.
    def has_array_helper(self):
        return self.name in ['u8']

    # Returns base size
    @staticmethod
    def _typesize(typename):
        if typename in type2size:
            return type2size[typename]
        elif typename.startswith('struct ') or typename.startswith('enum '):
            # We allow unknown structures/enums, for extensibility (can only happen
            # if explicitly specified in csv)
            return 0
        else:
            raise ValueError('Unknown typename {}'.format(typename))


# Full (message, fieldname)-mappings
typemap = {
    ('update_fail_htlc', 'reason'): FieldType('u8'),
    ('node_announcement', 'alias'): FieldType('u8'),
    ('update_add_htlc', 'onion_routing_packet'): FieldType('u8'),
    ('update_fulfill_htlc', 'payment_preimage'): FieldType('struct preimage'),
    ('error', 'data'): FieldType('u8'),
    ('shutdown', 'scriptpubkey'): FieldType('u8'),
    ('node_announcement', 'rgb_color'): FieldType('u8'),
    ('node_announcement', 'addresses'): FieldType('u8'),
    ('node_announcement', 'ipv6'): FieldType('struct ipv6'),
    ('announcement_signatures', 'short_channel_id'): FieldType('struct short_channel_id'),
    ('channel_announcement', 'short_channel_id'): FieldType('struct short_channel_id'),
    ('channel_update', 'short_channel_id'): FieldType('struct short_channel_id'),
    ('revoke_and_ack', 'per_commitment_secret'): FieldType('struct secret')
}

# Partial names that map to a datatype
partialtypemap = {
    'signature': FieldType('secp256k1_ecdsa_signature'),
    'features': FieldType('u8'),
    'channel_id': FieldType('struct channel_id'),
    'chain_hash': FieldType('struct bitcoin_blkid'),
    'funding_txid': FieldType('struct bitcoin_txid'),
    'pad': FieldType('pad'),
}

# Size to typename match
sizetypemap = {
    33: FieldType('struct pubkey'),
    32: FieldType('struct sha256'),
    8: FieldType('u64'),
    4: FieldType('u32'),
    2: FieldType('u16'),
    1: FieldType('u8')
}


# It would be nicer if we had put '*u8' in spec and disallowed bare lenvar.
# In practice we only recognize lenvar when it's the previous field.

# size := baresize | arraysize
# baresize := simplesize | lenvar
# simplesize := number | type
# arraysize := length '*' type
# length := lenvar | number
class Field(object):
    def __init__(self, message, name, size, comments, prevname):
        self.message = message
        self.comments = comments
        self.name = name
        self.is_len_var = False
        self.lenvar = None
        self.num_elems = 1
        self.optional = False

        # ? means optional field (not supported for arrays)
        if size.startswith('?'):
            self.optional = True
            size = size[1:]
        # If it's an arraysize, swallow prefix.
        elif '*' in size:
            number = size.split('*')[0]
            if number == prevname:
                self.lenvar = number
            else:
                self.num_elems = int(number)
            size = size.split('*')[1]
        elif options.bolt and size == prevname:
            # Raw length field, implies u8.
            self.lenvar = size
            size = '1'

        # Bolts use just a number: Guess type based on size.
        if options.bolt:
            base_size = int(size)
            self.fieldtype = Field._guess_type(message, self.name, base_size)
            # There are some arrays which we have to guess, based on sizes.
            tsize = FieldType._typesize(self.fieldtype.name)
            if base_size % tsize != 0:
                raise ValueError('Invalid size {} for {}.{} not a multiple of {}'
                                 .format(base_size,
                                         self.message,
                                         self.name,
                                         tsize))
            self.num_elems = int(base_size / tsize)
        else:
            # Real typename.
            self.fieldtype = FieldType(size)

    def basetype(self):
        base = self.fieldtype.name
        if base.startswith('struct '):
            base = base[7:]
        elif base.startswith('enum '):
            base = base[5:]
        return base

    def is_padding(self):
        return self.name.startswith('pad')

    # Padding is always treated as an array.
    def is_array(self):
        return self.num_elems > 1 or self.is_padding()

    def is_variable_size(self):
        return self.lenvar is not None

    def needs_ptr_to_ptr(self):
        return self.is_variable_size() or self.optional

    def is_assignable(self):
        if self.is_array() or self.needs_ptr_to_ptr():
            return False
        return self.fieldtype.is_assignable()

    def has_array_helper(self):
        return self.fieldtype.has_array_helper()

    # Returns FieldType
    @staticmethod
    def _guess_type(message, fieldname, base_size):
        # Check for full (message, fieldname)-matches
        if (message, fieldname) in typemap:
            return typemap[(message, fieldname)]

        # Check for partial field names
        for k, v in partialtypemap.items():
            if k in fieldname:
                return v

        # Check for size matches
        if base_size in sizetypemap:
            return sizetypemap[base_size]

        raise ValueError('Unknown size {} for {}'.format(base_size, fieldname))


fromwire_impl_templ = """bool fromwire_{name}({ctx}const void *p{args})
{{
{fields}
\tconst u8 *cursor = p;
\tsize_t plen = tal_count(p);

\tif (fromwire_u16(&cursor, &plen) != {enum.name})
\t\treturn false;
{subcalls}
\treturn cursor != NULL;
}}
"""

fromwire_header_templ = """bool fromwire_{name}({ctx}const void *p{args});
"""

towire_header_templ = """u8 *towire_{name}(const tal_t *ctx{args});
"""
towire_impl_templ = """u8 *towire_{name}(const tal_t *ctx{args})
{{
{field_decls}
\tu8 *p = tal_arr(ctx, u8, 0);
\ttowire_u16(&p, {enumname});
{subcalls}

\treturn memcheck(p, tal_count(p));
}}
"""

printwire_header_templ = """void printwire_{name}(const char *fieldname, const u8 *cursor);
"""
printwire_impl_templ = """void printwire_{name}(const char *fieldname, const u8 *cursor)
{{
\tsize_t plen = tal_count(cursor);

\tif (fromwire_u16(&cursor, &plen) != {enum.name}) {{
\t\tprintf("WRONG TYPE?!\\n");
\t\treturn;
\t}}

{subcalls}

\tif (plen != 0)
\t\tprintf("EXTRA: %s\\n", tal_hexstr(NULL, cursor, plen));
}}
"""


class CCode(object):
    """Simple class to create indented C code"""
    def __init__(self):
        self.indent = 1
        self.single_indent = False
        self.code = []

    def append(self, lines):
        for line in lines.split('\n'):
            # Let us to the indenting please!
            assert '\t' not in line

            # Special case: } by itself is pre-unindented.
            if line == '}':
                self.indent -= 1
                self.code.append("\t" * self.indent + line)
                continue

            self.code.append("\t" * self.indent + line)
            if self.single_indent:
                self.indent -= 1
                self.single_indent = False

            if line.endswith('{'):
                self.indent += 1
            elif line.endswith('}'):
                self.indent -= 1
            elif line.startswith('for') or line.startswith('if'):
                self.indent += 1
                self.single_indent = True

    def __str__(self):
        assert self.indent == 1
        assert not self.single_indent
        return '\n'.join(self.code)


class Message(object):
    def __init__(self, name, enum, comments):
        self.name = name
        self.enum = enum
        self.comments = comments
        self.fields = []
        self.has_variable_fields = False

    def checkLenField(self, field):
        # Optional fields don't have a len.
        if field.optional:
            return
        for f in self.fields:
            if f.name == field.lenvar:
                if f.fieldtype.name != 'u16':
                    raise ValueError('Field {} has non-u16 length variable {} (type {})'
                                     .format(field.name, field.lenvar, f.fieldtype.name))

                if f.is_array() or f.needs_ptr_to_ptr():
                    raise ValueError('Field {} has non-simple length variable {}'
                                     .format(field.name, field.lenvar))
                f.is_len_var = True
                f.lenvar_for = field
                return
        raise ValueError('Field {} unknown length variable {}'
                         .format(field.name, field.lenvar))

    def addField(self, field):
        # We assume field lengths are 16 bit, to avoid overflow issues and
        # massive allocations.
        if field.is_variable_size():
            self.checkLenField(field)
            self.has_variable_fields = True
        elif field.basetype() in varlen_structs or field.optional:
            self.has_variable_fields = True
        self.fields.append(field)

    def print_fromwire_array(self, subcalls, basetype, f, name, num_elems):
        if f.has_array_helper():
            subcalls.append('fromwire_{}_array(&cursor, &plen, {}, {});'
                            .format(basetype, name, num_elems))
        else:
            subcalls.append('for (size_t i = 0; i < {}; i++)'
                            .format(num_elems))
            if f.fieldtype.is_assignable():
                subcalls.append('({})[i] = fromwire_{}(&cursor, &plen);'
                                .format(name, basetype))
            elif basetype in varlen_structs:
                subcalls.append('({})[i] = fromwire_{}(ctx, &cursor, &plen);'
                                .format(name, basetype))
            else:
                subcalls.append('fromwire_{}(&cursor, &plen, {} + i);'
                                .format(basetype, name))

    def print_fromwire(self, is_header):
        ctx_arg = 'const tal_t *ctx, ' if self.has_variable_fields else ''

        args = []

        for f in self.fields:
            if f.is_len_var or f.is_padding():
                continue
            elif f.is_array():
                args.append(', {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            else:
                ptrs = '*'
                # If we're handing a variable array, we need a ptr-to-ptr.
                if f.needs_ptr_to_ptr():
                    ptrs += '*'
                # If each type is a variable length, we need a ptr to that.
                if f.basetype() in varlen_structs:
                    ptrs += '*'

                args.append(', {} {}{}'.format(f.fieldtype.name, ptrs, f.name))

        template = fromwire_header_templ if is_header else fromwire_impl_templ
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]

        subcalls = CCode()
        for f in self.fields:
            basetype = f.basetype()

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('fromwire_pad(&cursor, &plen, {});'
                                .format(f.num_elems))
            elif f.is_array():
                self.print_fromwire_array(subcalls, basetype, f, f.name,
                                          f.num_elems)
            elif f.is_variable_size():
                subcalls.append("//2nd case {name}".format(name=f.name))
                typename = f.fieldtype.name
                # If structs are varlen, need array of ptrs to them.
                if basetype in varlen_structs:
                    typename += ' *'
                subcalls.append('*{} = {} ? tal_arr(ctx, {}, {}) : NULL;'
                                .format(f.name, f.lenvar, typename, f.lenvar))

                self.print_fromwire_array(subcalls, basetype, f, '*' + f.name,
                                          f.lenvar)
            else:
                if f.optional:
                    subcalls.append("if (!fromwire_bool(&cursor, &plen))\n"
                                    "*{} = NULL;\n"
                                    "else {{\n"
                                    "*{} = tal(ctx, {});\n"
                                    "fromwire_{}(&cursor, &plen, *{});\n"
                                    "}}"
                                    .format(f.name, f.name, f.fieldtype.name,
                                            basetype, f.name))
                elif f.is_assignable():
                    subcalls.append("//3th case {name}".format(name=f.name))
                    if f.is_len_var:
                        subcalls.append('{} = fromwire_{}(&cursor, &plen);'
                                        .format(f.name, basetype))
                    else:
                        subcalls.append('*{} = fromwire_{}(&cursor, &plen);'
                                        .format(f.name, basetype))
                elif basetype in varlen_structs:
                    subcalls.append('*{} = fromwire_{}(ctx, &cursor, &plen);'
                                    .format(f.name, basetype))
                else:
                    subcalls.append('fromwire_{}(&cursor, &plen, {});'
                                    .format(basetype, f.name))

        return template.format(
            name=self.name,
            ctx=ctx_arg,
            args=''.join(args),
            fields=''.join(fields),
            enum=self.enum,
            subcalls=str(subcalls)
        )

    def print_towire_array(self, subcalls, basetype, f, num_elems):
        if f.has_array_helper():
            subcalls.append('towire_{}_array(&p, {}, {});'
                            .format(basetype, f.name, num_elems))
        else:
            subcalls.append('for (size_t i = 0; i < {}; i++)'
                            .format(num_elems))
            if f.fieldtype.is_assignable() or basetype in varlen_structs:
                subcalls.append('towire_{}(&p, {}[i]);'
                                .format(basetype, f.name))
            else:
                subcalls.append('towire_{}(&p, {} + i);'
                                .format(basetype, f.name))

    def print_towire(self, is_header):
        template = towire_header_templ if is_header else towire_impl_templ
        args = []
        for f in self.fields:
            if f.is_padding() or f.is_len_var:
                continue
            if f.is_array():
                args.append(', const {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            elif f.is_assignable():
                args.append(', {} {}'.format(f.fieldtype.name, f.name))
            elif f.is_variable_size() and f.basetype() in varlen_structs:
                args.append(', const {} **{}'.format(f.fieldtype.name, f.name))
            else:
                args.append(', const {} *{}'.format(f.fieldtype.name, f.name))

        field_decls = []
        for f in self.fields:
            if f.is_len_var:
                field_decls.append('\t{0} {1} = tal_count({2});'.format(
                    f.fieldtype.name, f.name, f.lenvar_for.name
                ))

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.name
            if basetype.startswith('struct '):
                basetype = basetype[7:]
            elif basetype.startswith('enum '):
                basetype = basetype[5:]

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('towire_pad(&p, {});'
                                .format(f.num_elems))
            elif f.is_array():
                self.print_towire_array(subcalls, basetype, f, f.num_elems)
            elif f.is_variable_size():
                self.print_towire_array(subcalls, basetype, f, f.lenvar)
            else:
                if f.optional:
                    subcalls.append("if (!{})\n"
                                    "towire_bool(&p, false);\n"
                                    "else {{\n"
                                    "towire_bool(&p, true);\n"
                                    "towire_{}(&p, {});\n"
                                    "}}".format(f.name, basetype, f.name))
                else:
                    subcalls.append('towire_{}(&p, {});'
                                    .format(basetype, f.name))

        return template.format(
            name=self.name,
            args=''.join(args),
            enumname=self.enum.name,
            field_decls='\n'.join(field_decls),
            subcalls=str(subcalls),
        )

    def add_truncate_check(self, subcalls):
        # Report if truncated, otherwise print.
        subcalls.append('if (!cursor) {\n'
                        'printf("**TRUNCATED**\\n");\n'
                        'return;\n'
                        '}')

    def print_printwire_array(self, subcalls, basetype, f, num_elems):
        if f.has_array_helper():
            subcalls.append('printwire_{}_array(tal_fmt(NULL, "%s.{}", fieldname), &cursor, &plen, {});'
                            .format(basetype, f.name, num_elems))
        else:
            subcalls.append('printf("[");')
            subcalls.append('for (size_t i = 0; i < {}; i++) {{'
                            .format(num_elems))
            subcalls.append('{} v;'.format(f.fieldtype.name))
            if f.fieldtype.is_assignable():
                subcalls.append('v = fromwire_{}(&cursor, plen);'
                                .format(f.fieldtype.name, basetype))
            else:
                # We don't handle this yet!
                assert(basetype not in varlen_structs)

                subcalls.append('fromwire_{}(&cursor, &plen, &v);'
                                .format(basetype))

            self.add_truncate_check(subcalls)

            subcalls.append('printwire_{}(tal_fmt(NULL, "%s.{}", fieldname), &v);'
                            .format(basetype, f.name))
            subcalls.append('}')
            subcalls.append('printf("]");')

    def print_printwire(self, is_header):
        template = printwire_header_templ if is_header else printwire_impl_templ
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]

        subcalls = CCode()
        for f in self.fields:
            basetype = f.basetype()

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_len_var:
                subcalls.append('{} {} = fromwire_{}(&cursor, &plen);'
                                .format(f.fieldtype.name, f.name, basetype))
                self.add_truncate_check(subcalls)
                continue

            subcalls.append('printf("{}=");'.format(f.name))
            if f.is_padding():
                subcalls.append('printwire_pad(tal_fmt(NULL, "%s.{}", fieldname), &cursor, &plen, {});'
                                .format(f.name, f.num_elems))
                self.add_truncate_check(subcalls)
            elif f.is_array():
                self.print_printwire_array(subcalls, basetype, f, f.num_elems)
                self.add_truncate_check(subcalls)
            elif f.is_variable_size():
                self.print_printwire_array(subcalls, basetype, f, f.lenvar)
                self.add_truncate_check(subcalls)
            else:
                if f.optional:
                    subcalls.append("if (fromwire_bool(&cursor, &plen)) {")

                if f.is_assignable():
                    subcalls.append('{} {} = fromwire_{}(&cursor, &plen);'
                                    .format(f.fieldtype.name, f.name, basetype))
                else:
                    # Don't handle these yet.
                    assert(basetype not in varlen_structs)
                    subcalls.append('{} {};'.
                                    format(f.fieldtype.name, f.name))
                    subcalls.append('fromwire_{}(&cursor, &plen, &{});'
                                    .format(basetype, f.name))

                self.add_truncate_check(subcalls)
                subcalls.append('printwire_{}(tal_fmt(NULL, "%s.{}", fieldname), &{});'
                                .format(basetype, f.name, f.name))
                if f.optional:
                    subcalls.append("} else {")
                    self.add_truncate_check(subcalls)
                    subcalls.append("}")

        return template.format(
            name=self.name,
            fields=''.join(fields),
            enum=self.enum,
            subcalls=str(subcalls)
        )


def find_message(messages, name):
    for m in messages:
        if m.name == name:
            return m

    return None


def find_message_with_option(messages, optional_messages, name, option):
    fullname = name + "_" + option.replace('-', '_')

    base = find_message(messages, name)
    if not base:
        raise ValueError('Unknown message {}'.format(name))

    m = find_message(optional_messages, fullname)
    if not m:
        # Add a new option.
        m = copy.deepcopy(base)
        m.name = fullname
        optional_messages.append(m)
    return m


parser = argparse.ArgumentParser(description='Generate C from CSV')
parser.add_argument('--header', action='store_true', help="Create wire header")
parser.add_argument('--bolt', action='store_true', help="Generate wire-format for BOLT")
parser.add_argument('--printwire', action='store_true', help="Create print routines")
parser.add_argument('headerfilename', help='The filename of the header')
parser.add_argument('enumname', help='The name of the enum to produce')
parser.add_argument('files', nargs='*', help='Files to read in (or stdin)')
options = parser.parse_args()

# Maps message names to messages
messages = []
messages_with_option = []
comments = []
includes = []
prevfield = None

# Read csv lines.  Single comma is the message values, more is offset/len.
for line in fileinput.input(options.files):
    # #include gets inserted into header
    if line.startswith('#include '):
        includes.append(line)
        continue

    by_comments = line.rstrip().split('#')

    # Emit a comment if they included one
    if by_comments[1:]:
        comments.append(' '.join(by_comments[1:]))

    parts = by_comments[0].split(',')
    if parts == ['']:
        continue

    if len(parts) == 2:
        # eg commit_sig,132
        messages.append(Message(parts[0], Enumtype("WIRE_" + parts[0].upper(), parts[1]), comments))
        comments = []
        prevfield = None
    else:
        if len(parts) == 4:
            # eg commit_sig,0,channel-id,8 OR
            #    commit_sig,0,channel-id,u64
            m = find_message(messages, parts[0])
            if m is None:
                raise ValueError('Unknown message {}'.format(parts[0]))
        elif len(parts) == 5:
            # eg.
            # channel_reestablish,48,your_last_per_commitment_secret,32,option209
            m = find_message_with_option(messages, messages_with_option, parts[0], parts[4])
        else:
            raise ValueError('Line {} malformed'.format(line.rstrip()))

        f = Field(m.name, parts[2], parts[3], comments, prevfield)
        m.addField(f)
        # If it used prevfield as lenvar, keep that for next
        # time (multiple fields can use the same lenvar).
        if not f.lenvar:
            prevfield = parts[2]
        comments = []

header_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#ifndef LIGHTNING_{idem}
#define LIGHTNING_{idem}
#include <ccan/tal/tal.h>
#include <wire/wire.h>
{includes}
enum {enumname} {{
{enums}}};
const char *{enumname}_name(int e);

{func_decls}
#endif /* LIGHTNING_{idem} */
"""

impl_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#include <{headerfilename}>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>

const char *{enumname}_name(int e)
{{
\tstatic char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

\tswitch ((enum {enumname})e) {{
\t{cases}
\t}}

\tsnprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
\treturn invalidbuf;
}}

{func_decls}
"""

print_header_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#ifndef LIGHTNING_{idem}
#define LIGHTNING_{idem}
#include <ccan/tal/tal.h>
#include <devtools/print_wire.h>
{includes}

void print{enumname}_message(const u8 *msg);

{func_decls}
#endif /* LIGHTNING_{idem} */
"""

print_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#include "{headerfilename}"
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <stdio.h>

void print{enumname}_message(const u8 *msg)
{{
\tswitch ((enum {enumname})fromwire_peektype(msg)) {{
\t{printcases}
\t}}

\tprintf("UNKNOWN: %s\\n", tal_hex(msg, msg));
}}

{func_decls}
"""

idem = re.sub(r'[^A-Z]+', '_', options.headerfilename.upper())
if options.printwire:
    if options.header:
        template = print_header_template
    else:
        template = print_template
elif options.header:
    template = header_template
else:
    template = impl_template

# Dump out enum, sorted by value order.
enums = ""
for m in messages:
    for c in m.comments:
        enums += '\t/*{} */\n'.format(c)
    enums += '\t{} = {},\n'.format(m.enum.name, m.enum.value)
includes = '\n'.join(includes)
cases = ['case {enum.name}: return "{enum.name}";'.format(enum=m.enum) for m in messages]
printcases = ['case {enum.name}: printf("{enum.name}:\\n"); printwire_{name}("{name}", msg); return;'.format(enum=m.enum, name=m.name) for m in messages]

if options.printwire:
    decls = [m.print_printwire(options.header) for m in messages + messages_with_option]
else:
    fromwire_decls = [m.print_fromwire(options.header) for m in messages + messages_with_option]
    towire_decls = towire_decls = [m.print_towire(options.header) for m in messages + messages_with_option]
    decls = fromwire_decls + towire_decls

print(template.format(
    headerfilename=options.headerfilename,
    cases='\n\t'.join(cases),
    printcases='\n\t'.join(printcases),
    idem=idem,
    includes=includes,
    enumname=options.enumname,
    enums=enums,
    func_decls='\n'.join(decls)))
