#! /usr/bin/python3
# Read from stdin, spit out C header or body.

from optparse import OptionParser
from collections import namedtuple
import fileinput
import re

Enumtype = namedtuple('Enumtype', ['name', 'value'])

class Field(object):
    def __init__(self,message,name,size,comments):
        self.message = message
        self.comments = comments
        self.name = name.replace('-', '_')
        self.is_len_var = False
        (self.typename, self.basesize) = Field._guess_type(message,self.name,size)

        try:
            if int(size) % self.basesize != 0:
                raise ValueError('Invalid size {} for {}.{} not a multiple of {}'.format(size,self.message,self.name,self.basesize))
            self.num_elems = int(int(size) / self.basesize)
        except ValueError:
            self.num_elems = 0
            # If it's a multiplicitive expression, must end in basesize.
            if '*' in size:
                tail='*' + str(self.basesize)
                if not size.endswith(tail):
                    raise ValueError('Invalid size {} for {}.{} not a multiple of {}'.format(size,self.message,self.name,self.basesize))
                size = size[:-len(tail)]
            else:
                if self.basesize != 1:
                    raise ValueError('Invalid size {} for {}.{} not expressed as a multiple of {}'.format(size,self.message,self.name,self.basesize))

            self.lenvar = size.replace('-','_')

    def is_padding(self):
        return self.name.startswith('pad')

    # Padding is always treated as an array.
    def is_array(self):
        return self.num_elems > 1 or self.is_padding()

    def is_variable_size(self):
        return self.num_elems == 0

    def is_assignable(self):
        if self.is_array() or self.is_variable_size():
            return False
        return self.typename == 'u8' or self.typename == 'u16' or self.typename == 'u32' or self.typename == 'u64'

    # Returns typename and base size
    @staticmethod
    def _guess_type(message, fieldname, sizestr):
        if fieldname.startswith('pad'):
            return ('pad',1)

        if fieldname.endswith('channel_id'):
            return ('struct channel_id',8)

        if message == 'node_announcement' and fieldname == 'ipv6':
            return ('struct ipv6',16)

        if message == 'node_announcement' and fieldname == 'alias':
            return ('u8',1)

        if fieldname.endswith('features'):
            return ('u8',1)

        if fieldname == 'addresses':
            return ('u8', 1)
    
        # We translate signatures and pubkeys.
        if 'signature' in fieldname:
            return ('struct signature',64)

        # The remainder should be fixed sizes.
        if sizestr == '33':
            return ('struct pubkey',33)
        if sizestr == '32':
            return ('struct sha256',32)
        if sizestr == '8':
            return ('u64',8)
        if sizestr == '4':
            return ('u32',4)
        if sizestr == '2':
            return ('u16',2)
        if sizestr == '1':
            return ('u8',1)

        # We whitelist specific things here, otherwise we'd treat everything
        # as a u8 array.
        if message == 'update_fail_htlc' and fieldname == 'reason':
            return ('u8', 1)
        if message == 'update_add_htlc' and fieldname == 'onion_routing_packet':
            return ('u8', 1)
        if message == 'node_announcement' and fieldname == 'alias':
            return ('u8',1)
        if message == 'error' and fieldname == 'data':
            return ('u8',1)
        if message == 'shutdown' and fieldname == 'scriptpubkey':
            return ('u8',1)
        if message == 'node_announcement' and fieldname == 'rgb_color':
            return ('u8',1)
    
        raise ValueError('Unknown size {} for {}'.format(sizestr,fieldname))

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
                if f.typename != 'u16':
                    raise ValueError('Field {} has non-u16 length variable {}'
                                     .format(field.name, field.lenvar))

                if f.is_array() or f.is_variable_size():
                    raise ValueError('Field {} has non-simple length variable {}'
                                     .format(field.name, field.lenvar))
                f.is_len_var = True;
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
                print(', {} {}[{}]'.format(f.typename, f.name, f.num_elems), end='')
            elif f.is_variable_size():
                print(', {} **{}'.format(f.typename, f.name), end='')
            else:
                print(', {} *{}'.format(f.typename, f.name), end='')

        if is_header:
            print(');')
            return

        print(')\n'
              '{')

        for f in self.fields:
            if f.is_len_var:
                print('\t{} {};'.format(f.typename, f.name));

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
            basetype=f.typename
            if f.typename.startswith('struct '):
                basetype=f.typename[7:]

            for c in f.comments:
                print('\t/*{} */'.format(c))

            if f.is_padding():
                print('\tfromwire_pad(&cursor, plen, {});'
                      .format(f.num_elems))
            elif f.is_array():
                print("\t//1th case", f.name)
                print('\tfromwire_{}_array(&cursor, plen, {}, {});'
                      .format(basetype, f.name, f.num_elems))
            elif f.is_variable_size():
                print("\t//2th case", f.name)
                print('\t*{} = tal_arr(ctx, {}, {});'
                      .format(f.name, f.typename, f.lenvar))
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
            if f.is_padding():
                continue
            if f.is_array():
                print(', const {} {}[{}]'.format(f.typename, f.name, f.num_elems), end='')
            elif f.is_assignable():
                print(', {} {}'.format(f.typename, f.name), end='')
            else:
                print(', const {} *{}'.format(f.typename, f.name), end='')

        if is_header:
            print(');')
            return

        print(')\n'
              '{{\n'
              '\tu8 *p = tal_arr(ctx, u8, 0);\n'
              ''
              '\ttowire_u16(&p, {});'.format(self.enum.name))

        for f in self.fields:
            basetype=f.typename
            if f.typename.startswith('struct '):
                basetype=f.typename[7:]

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
   
parser = OptionParser()
parser.add_option("--header",
                  action="store_true", dest="output_header", default=False,
                  help="Create wire header")

(options, args) = parser.parse_args()

if len(args) != 2:
    parser.error("Expect headerfilename and enumname")

if options.output_header:
    idem = re.sub(r'[^A-Z]+', '_', args[0].upper())
    print('#ifndef LIGHTNING_{0}\n'
          '#define LIGHTNING_{0}\n'
          '#include <ccan/tal/tal.h>\n'
          '#include <wire/wire.h>\n'
          ''.format(idem))
else:
    print('#include <{}>\n'
          '#include <ccan/mem/mem.h>\n'
          ''.format(args[0]))

# Maps message names to messages
messages = []
comments = []

# Read csv lines.  Single comma is the message values, more is offset/len.
for line in fileinput.input(args[2:]):
    by_comments = line.rstrip().split('#')

    # Emit a comment if they included one
    if by_comments[1:]:
        comments.append(' '.join(by_comments[1:]))

    parts = by_comments[0].split(',')
    if parts == ['']:
        continue

    if len(parts) == 2:
        # eg commit_sig,132
        messages.append(Message(parts[0],Enumtype("WIRE_" + parts[0].upper(), int(parts[1],0)),comments))
        comments=[]
    else:
        # eg commit_sig,0,channel-id,8
        for m in messages:
            if m.name == parts[0]:
                m.addField(Field(parts[0], parts[2], parts[3], comments))
                break
        comments=[]

if options.output_header:
    # Dump out enum, sorted by value order.
    print('enum {} {{'.format(args[1]))
    for m in messages:
        for c in m.comments:
            print('\t/*{} */'.format(c))
        print('\t{} = {},'.format(m.enum.name, m.enum.value))
    print('};')

for m in messages:
    m.print_fromwire(options.output_header)

for m in messages:
    m.print_towire(options.output_header)
    
if options.output_header:
    print('#endif /* LIGHTNING_{} */\n'.format(idem))
