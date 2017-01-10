#! /usr/bin/python3
# Read from stdin, spit out C header or body.

import argparse
from collections import namedtuple
import fileinput
import re

Enumtype = namedtuple('Enumtype', ['name', 'value'])

class FieldType(object):
    def __init__(self,name):
        self.name = name
        self.tsize = FieldType._typesize(name)

    def is_assignable(self):
        return self.name == 'u8' or self.name == 'u16' or self.name == 'u32' or self.name == 'u64' or self.name == 'bool'

    # Returns base size
    @staticmethod
    def _typesize(typename):
        if typename == 'pad':
            return 1
        elif typename == 'struct channel_id':
            return 8
        elif typename == 'struct ipv6':
            return 16
        elif typename == 'struct signature':
            return 64
        elif typename == 'struct pubkey':
            return 33
        elif typename == 'struct sha256':
            return 32
        elif typename == 'u64':
            return 8
        elif typename == 'u32':
            return 4
        elif typename == 'u16':
            return 2
        elif typename == 'u8':
            return 1
        elif typename == 'bool':
            return 1
        else:
            # We allow unknown structures, for extensiblity (can only happen
            # if explicitly specified in csv)
            if typename.startswith('struct '):
                return 0
            raise ValueError('Unknown typename {}'.format(typename))

class Field(object):
    def __init__(self,message,name,size,comments,typename=None):
        self.message = message
        self.comments = comments
        self.name = name.replace('-', '_')
        self.is_len_var = False
        self.is_unknown = False
        self.lenvar = None

        # Size could be a literal number (eg. 33), or a field (eg 'len'), or
        # a multiplier of a field (eg. num-htlc-timeouts*64).
        try:
            base_size = int(size)
        except ValueError:
            # If it's a multiplicitive expression, must end in basesize.
            if '*' in size:
                base_size = int(size.split('*')[1])
                self.lenvar = size.split('*')[0]
            else:
                base_size = 0
                self.lenvar = size
            self.lenvar = self.lenvar.replace('-','_')

        if typename is None:
            self.fieldtype = Field._guess_type(message,self.name,base_size)
        else:
            self.fieldtype = FieldType(typename)

        # Unknown types are assumed to have base_size: div by 0 if that's unknown.
        if self.fieldtype.tsize == 0:
            self.is_unknown = True
            self.fieldtype.tsize = base_size

        if base_size % self.fieldtype.tsize != 0:
            raise ValueError('Invalid size {} for {}.{} not a multiple of {}'.format(base_size,self.message,self.name,self.fieldtype.tsize))
        self.num_elems = int(base_size / self.fieldtype.tsize)

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

    # Returns FieldType
    @staticmethod
    def _guess_type(message, fieldname, base_size):
        if fieldname.startswith('pad'):
            return FieldType('pad')

        if fieldname.endswith('channel_id'):
            return FieldType('struct channel_id')

        if message == 'node_announcement' and fieldname == 'ipv6':
            return FieldType('struct ipv6')

        if message == 'node_announcement' and fieldname == 'alias':
            return FieldType('u8')

        if fieldname.endswith('features'):
            return FieldType('u8')
    
        # We translate signatures and pubkeys.
        if 'signature' in fieldname:
            return FieldType('struct signature')

        # We whitelist specific things here, otherwise we'd treat everything
        # as a u8 array.
        if message == 'update_fail_htlc' and fieldname == 'reason':
            return FieldType('u8')
        if message == 'update_add_htlc' and fieldname == 'onion_routing_packet':
            return FieldType('u8')
        if message == 'node_announcement' and fieldname == 'alias':
            return FieldType('u8')
        if message == 'error' and fieldname == 'data':
            return FieldType('u8')
        if message == 'shutdown' and fieldname == 'scriptpubkey':
            return FieldType('u8')
        if message == 'node_announcement' and fieldname == 'rgb_color':
            return FieldType('u8')
        if message == 'node_announcement' and fieldname == 'addresses':
            return FieldType('u8')
    
        # The remainder should be fixed sizes.
        if base_size == 33:
            return FieldType('struct pubkey')
        if base_size == 32:
            return FieldType('struct sha256')
        if base_size == 8:
            return FieldType('u64')
        if base_size == 4:
            return FieldType('u32')
        if base_size == 2:
            return FieldType('u16')
        if base_size == 1:
            return FieldType('u8')

        raise ValueError('Unknown size {} for {}'.format(base_size,fieldname))

class Message(object):
    def __init__(self,name,enum,comments):
        self.name = name
        self.enum = enum
        self.comments = comments
        self.fields = []
        self.has_variable_fields = False

    def checkLenField(self,field):
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
        elif field.is_unknown:
            self.has_variable_fields = True
        self.fields.append(field)

    def print_fromwire(self,is_header):
        if self.has_variable_fields:
            ctx_arg = 'const tal_t *ctx, '
        else:
            ctx_arg = ''

        print('bool fromwire_{}({}const void *p, size_t *plen'
              .format(self.name, ctx_arg), end='')

        for f in self.fields:
            if f.is_len_var:
                continue
            if f.is_padding():
                continue
            if f.is_array():
                print(', {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems), end='')
            elif f.is_variable_size() or f.is_unknown:
                print(', {} **{}'.format(f.fieldtype.name, f.name), end='')
            else:
                print(', {} *{}'.format(f.fieldtype.name, f.name), end='')

        if is_header:
            print(');')
            return

        print(')\n'
              '{')

        for f in self.fields:
            if f.is_len_var:
                print('\t{} {};'.format(f.fieldtype.name, f.name));

        print('\tconst u8 *cursor = p;\n'
              '\tsize_t tmp_len;\n'
              '\n'
              '\tif (!plen) {{\n'
              '\t\ttmp_len = tal_count(p);\n'
              '\t\tplen = &tmp_len;\n'
              '\t}}\n'
              '\tif (fromwire_u16(&cursor, plen) != {})\n'
              '\t\treturn false;'
              .format(self.enum.name))

        for f in self.fields:
            basetype=f.fieldtype.name
            if f.fieldtype.name.startswith('struct '):
                basetype=f.fieldtype.name[7:]

            for c in f.comments:
                print('\t/*{} */'.format(c))

            if f.is_unknown:
                print('\t*{} = fromwire_{}(ctx, &cursor, plen);'
                      .format(f.name, basetype))
            elif f.is_padding():
                print('\tfromwire_pad(&cursor, plen, {});'
                      .format(f.num_elems))
            elif f.is_array():
                print("\t//1th case", f.name)
                print('\tfromwire_{}_array(&cursor, plen, {}, {});'
                      .format(basetype, f.name, f.num_elems))
            elif f.is_variable_size():
                print("\t//2th case", f.name)
                print('\t*{} = tal_arr(ctx, {}, {});'
                      .format(f.name, f.fieldtype.name, f.lenvar))
                print('\tfromwire_{}_array(&cursor, plen, *{}, {});'
                      .format(basetype, f.name, f.lenvar))
            elif f.is_assignable():
                print("\t//3th case", f.name)
                if f.is_len_var:
                    print('\t{} = fromwire_{}(&cursor, plen);'
                          .format(f.name, basetype))
                else:
                    print('\t*{} = fromwire_{}(&cursor, plen);'
                          .format(f.name, basetype))
            else:
                print("\t//4th case", f.name)
                print('\tfromwire_{}(&cursor, plen, {});'
                      .format(basetype, f.name))

        print('\n'
              '\treturn cursor != NULL;\n'
              '}\n')

    def print_towire(self,is_header):
        print('u8 *towire_{}(const tal_t *ctx'
              .format(self.name), end='')

        for f in self.fields:
            if f.is_padding() or f.is_len_var:
                continue
            if f.is_array():
                print(', const {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems), end='')
            elif f.is_assignable():
                print(', {} {}'.format(f.fieldtype.name, f.name), end='')
            else:
                print(', const {} *{}'.format(f.fieldtype.name, f.name), end='')

        if is_header:
            print(');')
            return

        print(')\n'
              '{\n')
        for f in self.fields:
            if f.is_len_var:
                print('\t{0} {1} = {2} ? tal_count({2}) : 0;'
                      .format(f.fieldtype.name, f.name, f.lenvar_for.name));

        print('\tu8 *p = tal_arr(ctx, u8, 0);\n'
              ''
              '\ttowire_u16(&p, {});'.format(self.enum.name))

        for f in self.fields:
            basetype=f.fieldtype.name
            if f.fieldtype.name.startswith('struct '):
                basetype=f.fieldtype.name[7:]

            for c in f.comments:
                print('\t/*{} */'.format(c))

            if f.is_padding():
                print('\ttowire_pad(&p, {});'
                      .format(f.num_elems))
            elif f.is_array():
                print('\ttowire_{}_array(&p, {}, {});'
                      .format(basetype, f.name, f.num_elems))
            elif f.is_variable_size():
                print('\ttowire_{}_array(&p, {}, {});'
                      .format(basetype, f.name, f.lenvar))
            else:
                print('\ttowire_{}(&p, {});'
                      .format(basetype, f.name))

        # Make sure we haven't encoded any uninitialzied fields!
        print('\n'
              '\treturn memcheck(p, tal_count(p));\n'
              '}\n')
   
parser = argparse.ArgumentParser(description='Generate C from from CSV')
parser.add_argument('--header', action='store_true', help="Create wire header")
parser.add_argument('headerfilename', help='The filename of the header')
parser.add_argument('enumname', help='The name of the enum to produce')
parser.add_argument('files', nargs='*', help='Files to read in (or stdin)')
options = parser.parse_args()

if options.header:
    idem = re.sub(r'[^A-Z]+', '_', options.headerfilename.upper())
    print('#ifndef LIGHTNING_{0}\n'
          '#define LIGHTNING_{0}\n'
          '#include <ccan/tal/tal.h>\n'
          '#include <wire/wire.h>'.format(idem))
else:
    print('#include <{}>\n'
          '#include <ccan/mem/mem.h>\n'
          '#include <ccan/tal/str/str.h>\n'
          '#include <stdio.h>\n'
          ''.format(options.headerfilename))

# Maps message names to messages
messages = []
comments = []
includes = []

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
    else:
        # eg commit_sig,0,channel-id,8 OR
        #    commit_sig,0,channel-id,8,u64
        for m in messages:
            if m.name == parts[0]:
                if len(parts) == 4:
                    m.addField(Field(parts[0], parts[2], parts[3], comments))
                else:
                    m.addField(Field(parts[0], parts[2], parts[3], comments,
                                     parts[4]))
                break
        comments=[]

if options.header:
    for i in includes:
        print(i, end='')

    print('')

    # Dump out enum, sorted by value order.
    print('enum {} {{'.format(options.enumname))
    for m in messages:
        for c in m.comments:
            print('\t/*{} */'.format(c))
        print('\t{} = {},'.format(m.enum.name, m.enum.value))
    print('};')
    print('const char *{}_name(int e);'.format(options.enumname))
else:
    print('const char *{}_name(int e)'.format(options.enumname))
    print('{{\n'
          '\tstatic char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];\n'
          '\n'
          '\tswitch ((enum {})e) {{'.format(options.enumname));
    for m in messages:
        print('\tcase {0}: return "{0}";'.format(m.enum.name))
    print('\t}\n'
          '\n'
          '\tsprintf(invalidbuf, "INVALID %i", e);\n'
          '\treturn invalidbuf;\n'
          '}\n'
          '')

for m in messages:
    m.print_fromwire(options.header)

for m in messages:
    m.print_towire(options.header)
    
if options.header:
    print('#endif /* LIGHTNING_{} */\n'.format(idem))
