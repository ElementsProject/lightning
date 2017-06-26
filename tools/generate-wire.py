#! /usr/bin/python3
# Read from stdin, spit out C header or body.

import argparse
from collections import namedtuple
import fileinput
import re

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
    'u64': 8,
    'u32': 4,
    'u16': 2,
    'u8': 1,
    'bool': 1
}

# These struct array helpers require a context to allocate from.
varlen_structs = [
    'gossip_getnodes_entry',
    'failed_htlc',
]

class FieldType(object):
    def __init__(self,name):
        self.name = name
        self.tsize = FieldType._typesize(name)

    def is_assignable(self):
        return self.name in ['u8', 'u16', 'u32', 'u64', 'bool']

    # We only accelerate the u8 case: it's common and trivial.
    def has_array_helper(self):
        return self.name in ['u8']

    # Returns base size
    @staticmethod
    def _typesize(typename):
        if typename in type2size:
            return type2size[typename]
        elif typename.startswith('struct ') or typename.startswith('enum '):
            # We allow unknown structures/enums, for extensiblity (can only happen
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
    ('node_announcement', 'alias'): FieldType('u8'),
    ('announcement_signatures', 'short_channel_id'): FieldType('struct short_channel_id'),
    ('channel_announcement', 'short_channel_id'): FieldType('struct short_channel_id'),
    ('channel_update', 'short_channel_id'): FieldType('struct short_channel_id')
}

# Partial names that map to a datatype
partialtypemap = {
    'signature': FieldType('secp256k1_ecdsa_signature'),
    'features': FieldType('u8'),
    'channel_id': FieldType('struct channel_id'),
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

        # If it's an arraysize, swallow prefix.
        if '*' in size:
            number = size.split('*')[0]
            if number == prevname:
                self.lenvar = number
            else:
                self.num_elems = int(number)
            size = size.split('*')[1]
        else:
            if size == prevname:
                # Raw length field, implies u8.
                self.lenvar = size
                size = 'u8'

        try:
            # Just a number?  Guess based on size.
            base_size = int(size)
            self.fieldtype = Field._guess_type(message,self.name,base_size)
            # There are some arrays which we have to guess, based on sizes.
            if base_size % self.fieldtype.tsize != 0:
                raise ValueError('Invalid size {} for {}.{} not a multiple of {}'
                                 .format(base_size,
                                         self.message,
                                         self.name,
                                         self.fieldtype.tsize))
            self.num_elems = int(base_size / self.fieldtype.tsize)

        except ValueError:
            # Not a number; must be a type.
            self.fieldtype = FieldType(size)

    def is_padding(self):
        return self.name.startswith('pad')

    # Padding is always treated as an array.
    def is_array(self):
        return self.num_elems > 1 or self.is_padding()

    def is_variable_size(self):
        return self.lenvar is not None

    def is_assignable(self):
        if self.is_array() or self.is_variable_size():
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

        raise ValueError('Unknown size {} for {}'.format(base_size,fieldname))

fromwire_impl_templ = """bool fromwire_{name}({ctx}const void *p, size_t *plen{args})
{{
{fields}
	const u8 *cursor = p;
	size_t tmp_len;

	if (!plen) {{
		tmp_len = tal_count(p);
		plen = &tmp_len;
	}}
	if (fromwire_u16(&cursor, plen) != {enum.name})
		return false;
{subcalls}
	return cursor != NULL;
}}
"""

fromwire_header_templ = """bool fromwire_{name}({ctx}const void *p, size_t *plen{args});
"""

towire_header_templ = """u8 *towire_{name}(const tal_t *ctx{args});
"""
towire_impl_templ = """u8 *towire_{name}(const tal_t *ctx{args})
{{
{field_decls}
	u8 *p = tal_arr(ctx, u8, 0);
	towire_u16(&p, {enumname});
{subcalls}

	return memcheck(p, tal_count(p));
}}
"""
class Message(object):
    def __init__(self,name,enum,comments):
        self.name = name
        self.enum = enum
        self.comments = comments
        self.fields = []
        self.has_variable_fields = False

    def checkLenField(self, field):
        for f in self.fields:
            if f.name == field.lenvar:
                if f.fieldtype.name != 'u16':
                    raise ValueError('Field {} has non-u16 length variable {}'
                                     .format(field.name, field.lenvar))

                if f.is_array() or f.is_variable_size():
                    raise ValueError('Field {} has non-simple length variable {}'
                                     .format(field.name, field.lenvar))
                f.is_len_var = True;
                f.lenvar_for = field
                return
        raise ValueError('Field {} unknown length variable {}'
                         .format(field.name, field.lenvar))

    def addField(self,field):
        # We assume field lengths are 16 bit, to avoid overflow issues and
        # massive allocations.
        if field.is_variable_size():
            self.checkLenField(field)
            self.has_variable_fields = True
        self.fields.append(field)

    def print_fromwire_array(self, subcalls, basetype, f, name, num_elems):
        if f.has_array_helper():
            subcalls.append('\tfromwire_{}_array(&cursor, plen, {}, {});'
                            .format(basetype, name, num_elems))
        else:
            subcalls.append('\tfor (size_t i = 0; i < {}; i++)'
                            .format(num_elems))
            if f.fieldtype.is_assignable():
                subcalls.append('\t\t({})[i] = fromwire_{}(&cursor, plen);'
                                .format(name, basetype))
            else:
                ctx = "ctx, " if basetype in varlen_structs else ""
                subcalls.append('\t\tfromwire_{}({}&cursor, plen, {} + i);'
                                .format(basetype, ctx, name))

    def print_fromwire(self,is_header):
        ctx_arg = 'const tal_t *ctx, ' if self.has_variable_fields else ''

        args = []
        
        for f in self.fields:
            if f.is_len_var or f.is_padding():
                continue
            elif f.is_array():
                args.append(', {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            elif f.is_variable_size():
                args.append(', {} **{}'.format(f.fieldtype.name, f.name))
            else:
                args.append(', {} *{}'.format(f.fieldtype.name, f.name))

        template = fromwire_header_templ if is_header else fromwire_impl_templ
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]

        subcalls = []
        for f in self.fields:
            basetype=f.fieldtype.name
            if f.fieldtype.name.startswith('struct '):
                basetype=f.fieldtype.name[7:]
            elif f.fieldtype.name.startswith('enum '):
                basetype=f.fieldtype.name[5:]

            for c in f.comments:
                subcalls.append('\t/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('\tfromwire_pad(&cursor, plen, {});'
                                .format(f.num_elems))
            elif f.is_array():
                self.print_fromwire_array(subcalls, basetype, f, f.name,
                                          f.num_elems)
            elif f.is_variable_size():
                subcalls.append("\t//2th case {name}".format(name=f.name))
                subcalls.append('\t*{} = {} ? tal_arr(ctx, {}, {}) : NULL;'
                                .format(f.name, f.lenvar, f.fieldtype.name, f.lenvar))

                self.print_fromwire_array(subcalls, basetype, f, '*'+f.name,
                                          f.lenvar)
            elif f.is_assignable():
                subcalls.append("\t//3th case {name}".format(name=f.name))
                if f.is_len_var:
                    subcalls.append('\t{} = fromwire_{}(&cursor, plen);'
                                    .format(f.name, basetype))
                else:
                    subcalls.append('\t*{} = fromwire_{}(&cursor, plen);'
                                    .format(f.name, basetype))
            else:
                subcalls.append("\t//4th case {name}".format(name=f.name))
                subcalls.append('\tfromwire_{}(&cursor, plen, {});'
                                .format(basetype, f.name))

        return template.format(
            name=self.name,
            ctx=ctx_arg,
            args=''.join(args),
            fields=''.join(fields),
            enum=self.enum,
            subcalls='\n'.join(subcalls)
        )

    def print_towire_array(self, subcalls, basetype, f, num_elems):
        if f.has_array_helper():
            subcalls.append('\ttowire_{}_array(&p, {}, {});'
                            .format(basetype, f.name, num_elems))
        else:
            subcalls.append('\tfor (size_t i = 0; i < {}; i++)\n'
                            .format(num_elems))
            if f.fieldtype.is_assignable():
                subcalls.append('\t\ttowire_{}(&p, {}[i]);'
                                .format(basetype, f.name))
            else:
                subcalls.append('\t\ttowire_{}(&p, {} + i);'
                            .format(basetype, f.name))

    def print_towire(self,is_header):
        template = towire_header_templ if is_header else towire_impl_templ
        args = []
        for f in self.fields:
            if f.is_padding() or f.is_len_var:
                continue
            if f.is_array():
                args.append(', const {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            elif f.is_assignable():
                args.append(', {} {}'.format(f.fieldtype.name, f.name))
            else:
                args.append(', const {} *{}'.format(f.fieldtype.name, f.name))

        field_decls = []
        for f in self.fields:
            if f.is_len_var:
                field_decls.append('\t{0} {1} = tal_count({2});'.format(
                    f.fieldtype.name, f.name, f.lenvar_for.name
                ));

        subcalls = []
        for f in self.fields:
            basetype=f.fieldtype.name
            if basetype.startswith('struct '):
                basetype=basetype[7:]
            elif basetype.startswith('enum '):
                basetype=basetype[5:]

            for c in f.comments:
                subcalls.append('\t/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('\ttowire_pad(&p, {});'
                      .format(f.num_elems))
            elif f.is_array():
                self.print_towire_array(subcalls, basetype, f, f.num_elems)
            elif f.is_variable_size():
                self.print_towire_array(subcalls, basetype, f, f.lenvar)
            else:
                subcalls.append('\ttowire_{}(&p, {});'
                      .format(basetype, f.name))

        return template.format(
            name=self.name,
            args=''.join(args),
            enumname=self.enum.name,
            field_decls='\n'.join(field_decls),
            subcalls='\n'.join(subcalls),
        )

parser = argparse.ArgumentParser(description='Generate C from from CSV')
parser.add_argument('--header', action='store_true', help="Create wire header")
parser.add_argument('headerfilename', help='The filename of the header')
parser.add_argument('enumname', help='The name of the enum to produce')
parser.add_argument('files', nargs='*', help='Files to read in (or stdin)')
options = parser.parse_args()

# Maps message names to messages
messages = []
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
        messages.append(Message(parts[0],Enumtype("WIRE_" + parts[0].upper(), parts[1]), comments))
        comments=[]
        prevfield = None
    elif len(parts) == 4:
        # eg commit_sig,0,channel-id,8 OR
        #    commit_sig,0,channel-id,u64
        for m in messages:
            if m.name == parts[0]:
                f = Field(parts[0], parts[2], parts[3], comments, prevfield)
                m.addField(f)
                # If it used prevfield as lenvar, keep that for next
                # time (multiple fields can use the same lenvar).
                if not f.lenvar:
                    prevfield = parts[2]
                break
        comments=[]
    else:
        raise ValueError('Line {} malformed'.format(line.rstrip()))
        

header_template = """#ifndef LIGHTNING_{idem}
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

impl_template = """#include <{headerfilename}>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>

const char *{enumname}_name(int e)
{{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	switch ((enum {enumname})e) {{
	{cases}
	}}

	sprintf(invalidbuf, "INVALID %i", e);
	return invalidbuf;
}}

{func_decls}
"""

idem = re.sub(r'[^A-Z]+', '_', options.headerfilename.upper())
template = header_template if options.header else impl_template

# Dump out enum, sorted by value order.
enums = ""
for m in messages:
    for c in m.comments:
        enums += '\t/*{} */\n'.format(c)
    enums += '\t{} = {},\n'.format(m.enum.name, m.enum.value)
includes = '\n'.join(includes)
cases = ['case {enum.name}: return "{enum.name}";'.format(enum=m.enum) for m in messages]

fromwire_decls = [m.print_fromwire(options.header) for m in messages]
towire_decls = [m.print_towire(options.header) for m in messages]

print(template.format(
    headerfilename=options.headerfilename,
    cases='\n\t'.join(cases),
    idem=idem,
    includes=includes,
    enumname=options.enumname,
    enums=enums,
    func_decls='\n'.join(fromwire_decls + towire_decls),
))
