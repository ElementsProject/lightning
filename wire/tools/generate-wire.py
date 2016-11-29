#! /usr/bin/python3
# Read from stdin, spit out C header or body.

from optparse import OptionParser
from collections import namedtuple
import fileinput
import re

Enumtype = namedtuple('Enumtype', ['name', 'value'])

class Field(object):
    def __init__(self,message,name,size):
        self.message = message
        self.name = name.replace('-', '_')
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

        if fieldname.endswith('features'):
            return ('u8',1)
    
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
    def __init__(self,name,enum):
        self.name = name
        self.enum = enum
        self.fields = []

    def checkLenField(self,field):
        for f in self.fields:
            if f.name == field.lenvar:
                if f.typename != 'u16':
                    raise ValueError('Field {} has non-u16 length variable {}'
                                     .format(field.name, field.lenvar))

                if f.is_array() or f.is_variable_size():
                    raise ValueError('Field {} has non-simple length variable {}'
                                     .format(field.name, field.lenvar))
                return
        raise ValueError('Field {} unknown length variable {}'
                         .format(field.name, field.lenvar))

    def addField(self,field):
        # We assume field lengths are 16 bit, to avoid overflow issues and
        # massive allocations.
        if field.is_variable_size():
            self.checkLenField(field)
        self.fields.append(field)

    def print_structure(self):
        print('struct msg_{} {{'.format(self.name));

        for f in self.fields:
            # If size isn't known, it's a pointer.
            if f.is_array():
                print('\t{} {}[{}];'.format(f.typename, f.name, f.num_elems))
            elif f.is_variable_size():
                print('\t{} *{};'.format(f.typename, f.name))
            else:
                print('\t{} {};'.format(f.typename, f.name))

        print('};')

    def print_fromwire(self,is_header):
        print('struct msg_{} *fromwire_{}(const tal_t *ctx, const void *p, size_t *len)'.format(self.name,self.name), end='')

        if is_header:
            print(';')
            return

        print('\n'
              '{{\n'
              '\tconst u8 *cursor = p;\n'
              '\tstruct msg_{} *in = tal(ctx, struct msg_{});\n'
              ''.format(self.name, self.name));

        for f in self.fields:
            basetype=f.typename
            if f.typename.startswith('struct '):
                basetype=f.typename[7:]

            if f.is_array():
                print('\tfromwire_{}_array(&cursor, len, in->{}, {});'
                      .format(basetype, f.name, f.num_elems))
            elif f.is_variable_size():
                print('\tin->{} = tal_arr(in, {}, in->{});'
                      .format(f.name, f.typename, f.lenvar))
                print('\tfromwire_{}_array(&cursor, len, in->{}, in->{});'
                      .format(basetype, f.name, f.lenvar))
            elif f.is_assignable():
                print('\tin->{} = fromwire_{}(&cursor, len);'
                      .format(f.name, basetype))
            else:
                print('\tfromwire_{}(&cursor, len, &in->{});'
                      .format(basetype, f.name))

        print('\n'
              '\tif (!cursor)\n'
              '\t\treturn tal_free(in);\n'
              '\treturn in;\n'
              '}\n')
   
    def print_towire(self,is_header):
        print('u8 *towire_{}(const tal_t *ctx, const struct msg_{} *out)'.format(self.name,self.name), end='')

        if is_header:
            print(';')
            return
    
        print('\n'
              '{\n'
              '\tu8 *p = tal_arr(ctx, u8, 0);\n'
              '')

        for f in self.fields:
            basetype=f.typename
            if f.typename.startswith('struct '):
                basetype=f.typename[7:]

            if f.is_array():
                print('\ttowire_{}_array(&p, out->{}, {});'
                      .format(basetype, f.name, f.num_elems))
            elif f.is_variable_size():
                print('\ttowire_{}_array(&p, out->{}, out->{});'
                      .format(basetype, f.name, f.lenvar))
            elif f.is_assignable():
                print('\ttowire_{}(&p, out->{});'
                      .format(basetype, f.name))
            else:
                print('\ttowire_{}(&p, &out->{});'
                      .format(basetype, f.name))

        print('\n'
              '\treturn p;\n'
              '}\n')
   
parser = OptionParser()
parser.add_option("--header",
                  action="store_true", dest="output_header", default=False,
                  help="Create gen_wire.h")

(options, args) = parser.parse_args()

if options.output_header:
    print('#ifndef LIGHTNING_WIRE_GEN_WIRE_H\n'
          '#define LIGHTNING_WIRE_GEN_WIRE_H\n'
          '#include <ccan/tal/tal.h>\n'
          '#include <wire/wire.h>\n'
          '\n'
          'typedef u8 pad;\n'
          '')
else:
    print('#include "gen_wire.h"\n'
          '')

# Maps message names to messages
messages = { }

# Read csv lines.  Single comma is the message values, more is offset/len.
for line in fileinput.input(args):
    parts = line.rstrip().split(',')

    if len(parts) == 2:
        # eg commit_sig,132
        messages[parts[0]] = Message(parts[0],Enumtype("WIRE_" + parts[0].upper(), int(parts[1])))
    else:
        # eg commit_sig,0,channel-id,8
        messages[parts[0]].addField(Field(parts[0], parts[2], parts[3]))

if options.output_header:
    # Dump out enum, sorted by value order.
    print('enum wire_type {')
    for m in sorted(messages.values(),key=lambda x:x.enum.value):
        print('\t{} = {},'.format(m.enum.name, m.enum.value))
    print('};')

    # Dump out structure definitions.
    for m in messages.values():
        m.print_structure()

for m in messages.values():
    m.print_fromwire(options.output_header)

for m in messages.values():
    m.print_towire(options.output_header)
    
if options.output_header:
    print('#endif /* LIGHTNING_WIRE_GEN_WIRE_H */\n')
