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
    'struct node_id': 33,
    'struct sha256': 32,
    'struct bitcoin_blkid': 32,
    'struct bitcoin_txid': 32,
    'struct secret': 32,
    'struct amount_msat': 8,
    'struct amount_sat': 8,
    'u64': 8,
    'u32': 4,
    'u16': 2,
    'u8': 1,
    'bool': 1,
    'var_int': 8,
}

# These struct array helpers require a context to allocate from.
varlen_structs = [
    'peer_features',
    'gossip_getnodes_entry',
    'gossip_getchannels_entry',
    'failed_htlc',
    'utxo',
    'bitcoin_tx',
    'wirestring',
    'per_peer_state',
]


class FieldType(object):
    def __init__(self, name):
        self.name = name

    def is_var_int(self):
        return self.name == 'var_int'

    def is_assignable(self):
        return self.name in ['u8', 'u16', 'u32', 'u64', 'bool', 'struct amount_msat', 'struct amount_sat', 'var_int'] or self.name.startswith('enum ')

    def needs_ptr(self):
        return not self.is_assignable()

    # We only accelerate the u8 case: it's common and trivial.
    def has_array_helper(self):
        return self.name in ['u8']

    def base(self):
        basetype = self.name
        if basetype.startswith('struct '):
            basetype = basetype[7:]
        elif basetype.startswith('enum '):
            basetype = basetype[5:]
        elif self.name == 'var_int':
            return 'u64'
        return basetype

    def is_subtype(self):
        for subtype in subtypes:
            if subtype.name == self.base():
                return True
        return False

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
    ('revoke_and_ack', 'per_commitment_secret'): FieldType('struct secret'),
    ('channel_reestablish_option_data_loss_protect', 'your_last_per_commitment_secret'): FieldType('struct secret'),
    ('channel_update', 'fee_base_msat'): FieldType('u32'),
    ('final_incorrect_htlc_amount', 'incoming_htlc_amt'): FieldType('struct amount_msat'),
}

# Partial names that map to a datatype
partialtypemap = {
    'signature': FieldType('secp256k1_ecdsa_signature'),
    'features': FieldType('u8'),
    'channel_id': FieldType('struct channel_id'),
    'chain_hash': FieldType('struct bitcoin_blkid'),
    'funding_txid': FieldType('struct bitcoin_txid'),
    'pad': FieldType('pad'),
    'msat': FieldType('struct amount_msat'),
    'satoshis': FieldType('struct amount_sat'),
    'node_id': FieldType('struct node_id'),
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
    def __init__(self, message, name, size, comments, prevname, includes):
        self.message = message
        self.comments = comments
        self.name = name
        self.is_len_var = False
        self.lenvar = None
        self.num_elems = 1
        self.optional = False
        self.is_tlv = False
        self.is_subtype = False

        if name.endswith('_tlv'):
            self.is_tlv = True
            if self.name not in tlv_fields:
                tlv_fields[self.name] = []

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
            if size == 'var_int':
                base_size = 8
                self.fieldtype = FieldType(size)
            else:
                try:
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
                except ValueError:  # for subtypes
                    self.fieldtype = FieldType('struct {}'.format(name))
                    self.is_subtype = True

        else:
            # Real typename.
            self.fieldtype = FieldType(size)

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

fromwire_tlv_impl_templ = """static bool fromwire_{tlv_name}_{name}({ctx}{args})
{{

\tsize_t start_len = *plen;
{fields}
\tif (start_len < len)
\t\treturn false;
{subcalls}
\treturn cursor != NULL && (start_len - *plen == len);
}}
"""

fromwire_subtype_impl_templ = """{static}bool fromwire_{name}({ctx}{args})
{{

{fields}
{subcalls}
\treturn cursor != NULL;
}}
"""

fromwire_subtype_header_templ = """bool fromwire_{name}({ctx}{args});"""

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

towire_tlv_templ = """u8 *towire_{name}(const tal_t *ctx{args})
{{
{field_decls}
\tu8 *p = tal_arr(ctx, u8, 0);
\ttowire_u16(&p, {enumname});
\ttowire_u16(&p, {len});
{subcalls}

\treturn memcheck(p, tal_count(p));
}}
"""

fromwire_tlv_templ = """bool frowire_{name}({ctx}const void *p{args})
{{
{fields}
\tconst u8 *cursor = p;
\tsize_t plen = tal_count(p);

\tif (frmwire_u16(&cursor, &plen) != {enum.name})
\t\treturn false;
{subcalls}
\treturn cursor != NULL;
}}
"""

printwire_header_templ = """void printwire_{name}(const char *fieldname, const u8 *cursor);
"""

printwire_toplevel_tmpl = """\tsize_t plen = tal_count(cursor);

\tif (fromwire_u16(&cursor, &plen) != {enum.name}) {{
\t\tprintf("WRONG TYPE?!\\n");
\t\treturn;
\t}}"""

printwire_impl_templ = """{is_internal}void printwire_{name}(const char *fieldname, const u8 *{cursor_ptr}cursor{tlv_args})
{{
{toplevel_msg_setup}{subcalls}{lencheck}
}}
"""

printwire_lencheck = """
\tif (plen != 0)
\t\tprintf("EXTRA: %s\\n", tal_hexstr(NULL, cursor, plen));
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
    def __init__(self, name, enum, comments, is_tlv=False):
        self.name = name
        self.enum = enum
        self.comments = comments
        self.fields = []
        self.has_variable_fields = False
        self.is_tlv = is_tlv

    def checkLenField(self, field):
        # Optional fields don't have a len.
        if field.optional:
            return
        for f in self.fields:
            if f.name == field.lenvar:
                if not (f.fieldtype.name == 'u16' or f.fieldtype.name == 'var_int') and options.bolt:
                    raise ValueError('Field {} has non-u16 and non-var_int length variable {} (type {})'
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
        elif field.fieldtype.base() in varlen_structs or field.optional:
            self.has_variable_fields = True
        self.fields.append(field)

    def print_fromwire_array(self, ctx, subcalls, basetype, f, name, num_elems, is_embedded=False):
        p_ref = '' if is_embedded else '&'
        if f.has_array_helper():
            subcalls.append('fromwire_{}_array({}cursor, {}plen, {}, {});'
                            .format(basetype, p_ref, p_ref, name, num_elems))
        else:
            subcalls.append('for (size_t i = 0; i < {}; i++)'
                            .format(num_elems))
            if f.fieldtype.is_assignable():
                subcalls.append('({})[i] = fromwire_{}({}cursor, {}plen);'
                                .format(name, basetype, p_ref, p_ref))
            elif basetype in varlen_structs:
                subcalls.append('({})[i] = fromwire_{}({}, {}cursor, {}plen);'
                                .format(name, basetype, ctx, p_ref, p_ref))
            else:
                ctx_arg = ctx + ', ' if f.fieldtype.is_subtype() else ''
                subcalls.append('fromwire_{}({}{}cursor, {}plen, {} + i);'
                                .format(basetype, ctx_arg, p_ref, p_ref, name))

    def print_fromwire(self, is_header):
        ctx_arg = 'const tal_t *ctx, ' if self.has_variable_fields else ''

        args = []

        for f in self.fields:
            if f.is_len_var or f.is_padding():
                continue
            elif f.is_array():
                args.append(', {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            elif f.is_tlv:
                args.append(', struct {} *{}'.format(f.name, f.name))
            else:
                ptrs = '*'
                # If we're handing a variable array, we need a ptr-to-ptr.
                if f.needs_ptr_to_ptr():
                    ptrs += '*'
                # If each type is a variable length, we need a ptr to that,
                # unless it's already optional, so we got one above.
                if not f.optional and f.fieldtype.base() in varlen_structs:
                    ptrs += '*'

                args.append(', {} {}{}'.format(f.fieldtype.name, ptrs, f.name))

        template = fromwire_header_templ if is_header else fromwire_impl_templ
        fields = ['\t{} {};\n'.format(f.fieldtype.base(), f.name) for f in self.fields if f.is_len_var]

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()
            if f.fieldtype.is_var_int():
                basetype = 'var_int'

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('fromwire_pad(&cursor, &plen, {});'
                                .format(f.num_elems))
            elif f.is_array():
                self.print_fromwire_array('ctx', subcalls, basetype, f, f.name,
                                          f.num_elems)
            elif f.is_tlv:
                if not f.is_variable_size():
                    raise TypeError('TLV {} not variable size'.format(f.name))
                subcalls.append('struct {tlv_name} *_tlv = fromwire__{tlv_name}(ctx, &cursor, &plen, &{tlv_len});'
                                .format(tlv_name=f.name, tlv_len=f.lenvar))
                subcalls.append('if (!_tlv)')
                subcalls.append('return false;')
                subcalls.append('*{tlv_name} = *_tlv;'.format(tlv_name=f.name))
            elif f.is_variable_size():
                subcalls.append("//2nd case {name}".format(name=f.name))
                typename = f.fieldtype.name
                # If structs are varlen, need array of ptrs to them.
                if basetype in varlen_structs:
                    typename += ' *'
                subcalls.append('*{} = {} ? tal_arr(ctx, {}, {}) : NULL;'
                                .format(f.name, f.lenvar, typename, f.lenvar))

                # Allocate these off the array itself, if they need alloc.
                self.print_fromwire_array('*' + f.name, subcalls, basetype, f,
                                          '*' + f.name, f.lenvar)
            else:
                if f.optional:
                    assignable = f.fieldtype.is_assignable()
                    # Optional varlens don't need to be derefed twice.
                    if basetype in varlen_structs:
                        deref = ''
                    else:
                        deref = '*'
                else:
                    deref = ''
                    assignable = f.is_assignable()

                if assignable:
                    if f.is_len_var:
                        s = '{} = fromwire_{}(&cursor, &plen);'.format(f.name, basetype)
                    else:
                        s = '{}*{} = fromwire_{}(&cursor, &plen);'.format(deref, f.name, basetype)
                elif basetype in varlen_structs:
                    s = '{}*{} = fromwire_{}(ctx, &cursor, &plen);'.format(deref, f.name, basetype)
                else:
                    s = 'fromwire_{}(&cursor, &plen, {}{});'.format(basetype, deref, f.name)

                if f.optional:
                    subcalls.append("if (!fromwire_bool(&cursor, &plen))\n"
                                    "*{} = NULL;\n"
                                    "else {{\n"
                                    "*{} = tal(ctx, {});\n"
                                    "{}\n"
                                    "}}"
                                    .format(f.name, f.name, f.fieldtype.name,
                                            s))
                else:
                    subcalls.append(s)

        return template.format(
            name=self.name,
            ctx=ctx_arg,
            args=''.join(args),
            fields=''.join(fields),
            enum=self.enum,
            subcalls=str(subcalls)
        )

    def print_towire_array(self, subcalls, basetype, f, num_elems, is_tlv=False):
        p_ref = '' if is_tlv else '&'
        msg_name = self.name + '->' if is_tlv else ''
        if f.has_array_helper():
            subcalls.append('towire_{}_array({}p, {}{}, {});'
                            .format(basetype, p_ref, msg_name, f.name, num_elems))
        else:
            subcalls.append('for (size_t i = 0; i < {}; i++)'
                            .format(num_elems))
            if f.fieldtype.is_assignable() or basetype in varlen_structs:
                subcalls.append('towire_{}({}p, {}{}[i]);'
                                .format(basetype, p_ref, msg_name, f.name))
            else:
                subcalls.append('towire_{}({}p, {}{} + i);'
                                .format(basetype, p_ref, msg_name, f.name))

    def find_tlv_lenvar_field(self, tlv_name):
        return [f for f in self.fields if f.is_len_var and f.lenvar_for.is_tlv and f.lenvar_for.name == tlv_name][0]

    def print_towire(self, is_header):
        template = towire_header_templ if is_header else towire_impl_templ
        args = []
        for f in self.fields:
            if f.is_padding() or f.is_len_var:
                continue
            if f.is_array():
                args.append(', const {} {}[{}]'.format(f.fieldtype.name, f.name, f.num_elems))
            elif f.is_tlv:
                args.append(', const struct {} *{}'.format(f.name, f.name))
            elif f.is_assignable():
                args.append(', {} {}'.format(f.fieldtype.name, f.name))
            elif f.is_variable_size() and f.fieldtype.base() in varlen_structs:
                args.append(', const {} **{}'.format(f.fieldtype.name, f.name))
            else:
                args.append(', const {} *{}'.format(f.fieldtype.name, f.name))

        field_decls = []
        for f in self.fields:
            if f.is_len_var:
                if f.lenvar_for.is_tlv:
                    # used below...
                    field_decls.append('\t{0} {1};'.format(f.fieldtype.base(), f.name))
                else:
                    field_decls.append('\t{0} {1} = tal_count({2});'.format(
                        f.fieldtype.name, f.name, f.lenvar_for.name
                    ))

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('towire_pad(&p, {});'
                                .format(f.num_elems))
            elif f.is_array():
                self.print_towire_array(subcalls, basetype, f, f.num_elems)
            elif f.is_len_var and f.lenvar_for.is_tlv:
                continue  # taken care of below
            elif f.is_tlv:
                if not f.is_variable_size():
                    raise ValueError('TLV {} not variable size'.format(f.name))
                lenvar_field = self.find_tlv_lenvar_field(f.name)
                subcalls.append('/* ~~build TLV for {} ~~*/'.format(f.name))
                subcalls.append("u8 *{tlv_name}_buffer = tal_arr(ctx, u8, 0);\n"
                                "towire__{tlv_name}(ctx, &{tlv_name}_buffer, {tlv_name});\n"
                                "{lenvar_field} = tal_count({tlv_name}_buffer);\n"
                                "towire_{lenvar_fieldtype}(&p, {lenvar_field});\n"
                                "towire_u8_array(&p, {tlv_name}_buffer, {lenvar_field});\n".format(
                                    tlv_name=f.name,
                                    lenvar_field=lenvar_field.name,
                                    lenvar_fieldtype=lenvar_field.fieldtype.name))
            elif f.is_variable_size():
                self.print_towire_array(subcalls, basetype, f, f.lenvar)
            else:
                if f.optional:
                    if f.fieldtype.is_assignable():
                        deref = '*'
                    else:
                        deref = ''
                    subcalls.append("if (!{})\n"
                                    "towire_bool(&p, false);\n"
                                    "else {{\n"
                                    "towire_bool(&p, true);\n"
                                    "towire_{}(&p, {}{});\n"
                                    "}}".format(f.name, basetype, deref, f.name))
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

    def add_truncate_check(self, subcalls, ref):
        # Report if truncated, otherwise print.
        call = 'if (!{}cursor) {{\nprintf("**TRUNCATED**\\n");\nreturn;\n}}'.format(ref)
        subcalls.append(call)

    def print_printwire_array(self, subcalls, basetype, f, num_elems, ref):
        truncate_check_ref = '' if ref else '*'
        if f.has_array_helper():
            subcalls.append('printwire_{}_array(tal_fmt(NULL, "%s.{}", fieldname), {}cursor, {}plen, {});'
                            .format(basetype, f.name, ref, ref, num_elems))
        else:
            subcalls.append('printf("[");')
            subcalls.append('for (size_t i = 0; i < {}; i++) {{'
                            .format(num_elems))
            subcalls.append('{} v;'.format(f.fieldtype.name))
            if f.fieldtype.is_assignable():
                subcalls.append('v = fromwire_{}({}cursor, {}plen);'
                                .format(f.fieldtype.name, basetype, ref, ref))
            else:
                # We don't handle this yet!
                assert(basetype not in varlen_structs)

                subcalls.append('fromwire_{}({}cursor, {}plen, &v);'
                                .format(basetype, ref, ref))

            self.add_truncate_check(subcalls, truncate_check_ref)

            subcalls.append('printwire_{}(tal_fmt(NULL, "%s.{}", fieldname), &v);'
                            .format(basetype, f.name))
            subcalls.append('}')
            subcalls.append('printf("]");')

    def print_printwire(self, is_header, is_embedded=False):
        template = printwire_header_templ if is_header else printwire_impl_templ
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]

        tlv_args = '' if not is_embedded else ', size_t *plen'
        ref = '&' if not is_embedded else ''
        truncate_check_ref = '' if not is_embedded else '*'

        toplevel_msg_setup = ''
        if not is_embedded:
            toplevel_msg_setup = printwire_toplevel_tmpl.format(enum=self.enum)

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_len_var:
                if f.fieldtype.is_var_int():
                    subcalls.append('{} {} = fromwire_{}({}cursor, {}plen);'
                                    .format(basetype, f.name, 'var_int', ref, ref))
                else:
                    subcalls.append('{} {} = fromwire_{}({}cursor, {}plen);'
                                    .format(f.fieldtype.name, f.name, basetype, ref, ref))
                self.add_truncate_check(subcalls, truncate_check_ref)
                continue

            subcalls.append('printf("{}=");'.format(f.name))
            if f.is_padding():
                subcalls.append('printwire_pad(tal_fmt(NULL, "%s.{}", fieldname), {}cursor, {}plen, {});'
                                .format(f.name, ref, ref, f.num_elems))
                self.add_truncate_check(subcalls, truncate_check_ref)
            elif f.is_array():
                self.print_printwire_array(subcalls, basetype, f, f.num_elems, ref)
                self.add_truncate_check(subcalls, truncate_check_ref)
            elif f.fieldtype.is_subtype():
                Subtype._inner_print_printwire_array(subcalls, basetype, f, f.lenvar, ref)
            elif f.is_variable_size():
                self.print_printwire_array(subcalls, basetype, f, f.lenvar, ref)
                self.add_truncate_check(subcalls, truncate_check_ref)
            else:
                if f.optional:
                    subcalls.append("if (fromwire_bool({}cursor, {}plen)) {".format(ref, ref))

                if f.is_assignable():
                    subcalls.append('{} {} = fromwire_{}({}cursor, {}plen);'
                                    .format(f.fieldtype.name, f.name, basetype, ref, ref))
                else:
                    # Don't handle these yet.
                    assert(basetype not in varlen_structs)
                    subcalls.append('{} {};'.
                                    format(f.fieldtype.name, f.name))
                    subcalls.append('fromwire_{}({}cursor, {}plen, &{});'
                                    .format(basetype, ref, ref, f.name))

                self.add_truncate_check(subcalls, truncate_check_ref)
                subcalls.append('printwire_{}(tal_fmt(NULL, "%s.{}", fieldname), &{});'
                                .format(basetype, f.name, f.name))
                if f.optional:
                    subcalls.append("} else {")
                    self.add_truncate_check(subcalls, truncate_check_ref)
                    subcalls.append("}")

        len_check = '' if is_embedded else printwire_lencheck
        return template.format(
            tlv_args=tlv_args,
            name=self.name,
            fields=''.join(fields),
            toplevel_msg_setup=toplevel_msg_setup,
            subcalls=str(subcalls),
            lencheck=len_check,
            cursor_ptr=('' if not is_embedded else '*'),
            is_internal=('' if not is_embedded else 'static ')
        )


class TlvMessage(Message):
    def __init__(self, name, enum, comments):
        super().__init__(name, enum, comments, is_tlv=True)

    def print_struct(self):
        return TlvMessage._inner_print_struct('tlv_msg_' + self.name, self.fields)

    @staticmethod
    def _inner_print_struct(struct_name, fields):
        """ returns a string representation of this message as
        a struct"""
        fmt_fields = CCode()
        for f in fields:
            if f.is_len_var or f.is_padding():
                # there is no ethical padding under structs
                continue
            elif f.is_variable_size():
                fmt_fields.append('{} *{};'.format(f.fieldtype.name, f.name))
            elif f.is_array():
                fmt_fields.append('{} {}[{}];'.format(f.fieldtype.name, f.name, f.num_elems))
            else:
                fmt_fields.append('{} {};'.format(f.fieldtype.name, f.name))

        return """
struct {struct_name} {{
{fields}
}};
""".format(
            struct_name=struct_name,
            fields=str(fmt_fields))

    def print_towire(self, is_header, tlv_name):
        """ prints towire function definition for a TLV message."""
        if is_header:
            return ''
        field_decls = []
        for f in self.fields:
            if f.is_tlv:
                raise TypeError("Nested TLVs aren't allowed!! {}->{}".format(tlv_name, f.name))
            elif f.optional:
                raise TypeError("Optional fields on TLV messages not currently supported. {}->{}".format(tlv_name, f.name))
            if f.is_len_var:
                field_decls.append('\t{0} {1} = tal_count({2}->{3});'.format(
                    f.fieldtype.name, f.name, self.name, f.lenvar_for.name
                ))

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()
            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('towire_pad(p, {});'.format(f.num_elems))
            elif f.is_array():
                self.print_towire_array(subcalls, basetype, f, f.num_elems,
                                        is_tlv=True)
            elif f.is_variable_size():
                self.print_towire_array(subcalls, basetype, f, f.lenvar,
                                        is_tlv=True)
            elif f.is_len_var:
                subcalls.append('towire_{}(p, {});'.format(basetype, f.name))
            else:
                ref = '&' if f.fieldtype.needs_ptr() else ''
                subcalls.append('towire_{}(p, {}{}->{});'.format(basetype, ref, self.name, f.name))
        return tlv_message_towire_stub.format(
            tlv_name=tlv_name,
            name=self.name,
            field_decls='\n'.join(field_decls),
            subcalls=str(subcalls))

    def print_fromwire(self, is_header, tlv_name):
        """ prints fromwire function definition for a TLV message.
        these are significantly different in that they take in a struct
        to populate, instead of fields, as well as a length to read in
        """
        if is_header:
            return ''
        ctx_arg = 'const tal_t *ctx, ' if self.has_variable_fields else ''
        args = 'const u8 **cursor, size_t *plen, const u16 len, struct tlv_msg_{name} *{name}'.format(name=self.name)
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]
        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()
            if f.is_tlv:
                raise TypeError('Nested TLVs arent allowed!!')
            elif f.optional:
                raise TypeError('Optional fields on TLV messages not currently supported')

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('fromwire_pad(cursor, plen, {});'
                                .format(f.num_elems))
            elif f.is_array():
                name = '*{}->{}'.format(self.name, f.name)
                self.print_fromwire_array('ctx', subcalls, basetype, f, name,
                                          f.num_elems, is_embedded=True)
            elif f.is_variable_size():
                subcalls.append("// 2nd case {name}".format(name=f.name))
                typename = f.fieldtype.name
                # If structs are varlen, need array of ptrs to them.
                if basetype in varlen_structs:
                    typename += ' *'
                subcalls.append('{}->{} = {} ? tal_arr(ctx, {}, {}) : NULL;'
                                .format(self.name, f.name, f.lenvar, typename, f.lenvar))

                name = '{}->{}'.format(self.name, f.name)
                # Allocate these off the array itself, if they need alloc.
                self.print_fromwire_array('*' + f.name, subcalls, basetype, f,
                                          name, f.lenvar, is_embedded=True)
            else:
                if f.is_assignable():
                    if f.is_len_var:
                        s = '{} = fromwire_{}(cursor, plen);'.format(f.name, basetype)
                    else:
                        s = '{}->{} = fromwire_{}(cursor, plen);'.format(
                            self.name, f.name, basetype)
                else:
                    ref = '&' if f.fieldtype.needs_ptr() else ''
                    s = 'fromwire_{}(cursor, plen, {}{}->{});'.format(
                        basetype, ref, self.name, f.name)
                subcalls.append(s)

        return fromwire_tlv_impl_templ.format(
            tlv_name=tlv_name,
            name=self.name,
            ctx=ctx_arg,
            args=''.join(args),
            fields=''.join(fields),
            subcalls=str(subcalls)
        )


class Subtype(Message):
    def __init__(self, name, comments):
        super().__init__(name, None, comments, False)

    def print_struct(self):
        return TlvMessage._inner_print_struct(self.name, self.fields)

    def print_towire(self):
        """ prints towire function definition for a subtype"""
        template = subtype_towire_header_stub if options.header else subtype_towire_stub

        field_decls = []
        for f in self.fields:
            if f.optional:
                raise TypeError("Optional fields on subtypes not currently supported. {}".format(f.name))
            if f.is_len_var:
                field_decls.append('\t{0} {1} = tal_count({2}->{3});'.format(
                    f.fieldtype.name, f.name, self.name, f.lenvar_for.name
                ))

        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()
            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('towire_pad(p, {});'.format(f.num_elems))
            elif f.is_array():
                self.print_towire_array(subcalls, basetype, f, f.num_elems,
                                        is_tlv=True)
            elif f.is_variable_size():
                self.print_towire_array(subcalls, basetype, f, f.lenvar,
                                        is_tlv=True)
            elif f.is_len_var:
                subcalls.append('towire_{}(p, {});'.format(basetype, f.name))
            else:
                ref = '&' if f.fieldtype.needs_ptr() else ''
                subcalls.append('towire_{}(p, {}{}->{});'.format(basetype, ref, self.name, f.name))
        return template.format(
            static='' if options.subtypes else 'static ',
            name=self.name,
            field_decls='\n'.join(field_decls),
            subcalls=str(subcalls))

    def print_fromwire(self):
        """ prints fromwire function definition for a subtype.
        these are significantly different in that they take in a struct
        to populate, instead of fields.
        """
        ctx_arg = 'const tal_t *ctx, ' if self.has_variable_fields else ''
        args = 'const u8 **cursor, size_t *plen, struct {name} *{name}'.format(name=self.name)
        fields = ['\t{} {};\n'.format(f.fieldtype.name, f.name) for f in self.fields if f.is_len_var]
        template = fromwire_subtype_header_templ if options.header else fromwire_subtype_impl_templ
        subcalls = CCode()
        for f in self.fields:
            basetype = f.fieldtype.base()
            if f.optional:
                raise TypeError('Optional fields on subtypes not currently supported')

            for c in f.comments:
                subcalls.append('/*{} */'.format(c))

            if f.is_padding():
                subcalls.append('fromwire_pad(cursor, plen, {});'
                                .format(f.num_elems))
            elif f.is_array():
                name = '*{}->{}'.format(self.name, f.name)
                self.print_fromwire_array('ctx', subcalls, basetype, f, name,
                                          f.num_elems, is_embedded=True)
            elif f.is_variable_size():
                subcalls.append("// 2nd case {name}".format(name=f.name))
                typename = f.fieldtype.name
                # If structs are varlen, need array of ptrs to them.
                if basetype in varlen_structs:
                    typename += ' *'
                subcalls.append('{}->{} = {} ? tal_arr(ctx, {}, {}) : NULL;'
                                .format(self.name, f.name, f.lenvar, typename, f.lenvar))

                name = '{}->{}'.format(self.name, f.name)
                # Allocate these off the array itself, if they need alloc.
                self.print_fromwire_array(name, subcalls, basetype, f,
                                          name, f.lenvar, is_embedded=True)
            else:
                if f.is_assignable():
                    if f.is_len_var:
                        s = '{} = fromwire_{}(cursor, plen);'.format(f.name, basetype)
                    else:
                        s = '{}->{} = fromwire_{}(cursor, plen);'.format(
                            self.name, f.name, basetype)
                else:
                    ref = '&' if f.fieldtype.needs_ptr() else ''
                    s = 'fromwire_{}(cursor, plen, {}{}->{});'.format(
                        basetype, ref, self.name, f.name)
                subcalls.append(s)

        return template.format(
            static='' if options.subtypes else 'static ',
            name=self.name,
            ctx=ctx_arg,
            args=''.join(args),
            fields=''.join(fields),
            subcalls=str(subcalls)
        )

    def print_printwire_array(self, subcalls, basetype, f, num_elems, ref):
        return Subtype._inner_print_printwire_array(subcalls, basetype, f, num_elems, '')

    @staticmethod
    def _inner_print_printwire_array(subcalls, basetype, f, num_elems, ref):
        if f.has_array_helper():
            subcalls.append('printwire_{}_array(tal_fmt(NULL, "%s.{}", fieldname), {}cursor, {}plen, {});'
                            .format(basetype, f.name, ref, ref, num_elems))
        else:
            subcalls.append('printf("[");')
            subcalls.append('for (size_t i = 0; i < {}; i++) {{'
                            .format(num_elems))
            subcalls.append('printwire_{}(tal_fmt(NULL, "%s.{}", fieldname), {}cursor, {}plen);'
                            .format(basetype, f.name, ref, ref))
            subcalls.append('}')
            subcalls.append('printf("]");')


tlv_message_towire_stub = """static void towire_{tlv_name}_{name}(u8 **p, struct tlv_msg_{name} *{name}) {{
{field_decls}
{subcalls}
}}
"""

subtype_towire_stub = """{static}void towire_{name}(u8 **p, const struct {name} *{name}) {{
{field_decls}
{subcalls}
}}
"""

subtype_towire_header_stub = """void towire_{name}(u8 **p, const struct {name} *{name});"""

tlv_struct_template = """
struct {tlv_name} {{
{msg_type_structs}
}};
"""

tlv__type_impl_towire_fields = """\tif ({tlv_name}->{name}) {{
\t\ttlv_msg = tal_arr(ctx, u8, 0);
\t\ttowire_u8(p, {enum});
\t\ttowire_{tlv_name}_{name}(&tlv_msg, {tlv_name}->{name});
\t\tmsg_len = tal_count(tlv_msg);
\t\ttowire_var_int(p, msg_len);
\t\ttowire_u8_array(p, tlv_msg, msg_len);
\t\ttal_free(tlv_msg);
\t}}
"""

tlv__type_impl_towire_template = """static void towire__{tlv_name}(const tal_t *ctx, u8 **p, const struct {tlv_name} *{tlv_name}) {{
\tu64 msg_len;
\tu8 *tlv_msg;
{fields}}}
"""

tlv__type_impl_fromwire_template = """static struct {tlv_name} *fromwire__{tlv_name}(const tal_t *ctx, const u8 **p, size_t *plen, const u64 *len) {{
\tu8 msg_type;
\tu64 msg_len;
\tsize_t start_len = *plen;
\tif (*plen < *len)
\t\treturn NULL;

\tstruct {tlv_name} *{tlv_name} = talz(ctx, struct {tlv_name});

\twhile (*plen) {{
\t\tmsg_type = fromwire_u8(p, plen);
\t\tmsg_len = fromwire_var_int(p, plen);
\t\tif (*plen < msg_len) {{
\t\t\tfromwire_fail(p, plen);
\t\t\tbreak;
\t\t}}
\t\tswitch((enum {tlv_name}_type)msg_type) {{
{cases}\t\tdefault:
\t\t\tif (msg_type % 2 == 0) {{ // it's ok to be odd
\t\t\t\tfromwire_fail(p, plen);
\t\t\t\ttal_free({tlv_name});
\t\t\t\treturn NULL;
\t\t\t}}
\t\t\t*p += msg_len;
\t\t\t*plen -= msg_len;
\t\t}}
\t}}
\tif (!*p || start_len - *plen != *len) {{
\t\ttal_free({tlv_name});
\t\treturn NULL;
\t}}
\treturn {tlv_name};
}}
"""

case_tmpl = """\t\tcase {tlv_msg_enum}:
\t\t\tif ({tlv_name}->{tlv_msg_name} != NULL) {{
\t\t\t\tfromwire_fail(p, plen);
\t\t\t\ttal_free({tlv_name});
\t\t\t\treturn NULL;
\t\t\t}}
\t\t\t{tlv_name}->{tlv_msg_name} = tal({tlv_name}, struct tlv_msg_{tlv_msg_name});
\t\t\tif (!fromwire_{tlv_name}_{tlv_msg_name}({ctx_arg}p, plen, msg_len, {tlv_name}->{tlv_msg_name})) {{
\t\t\t\ttal_free({tlv_name});
\t\t\t\treturn NULL;
\t\t\t}}
\t\t\tbreak;
"""

print_tlv_template = """static void printwire_{tlv_name}(const char *fieldname, const u8 *cursor)
{{
\tu8 msg_type;
\tu64 msg_size;
\tsize_t plen = tal_count(cursor);

\twhile (cursor) {{
\t\tmsg_type = fromwire_u8(&cursor, &plen);
\t\tmsg_size = fromwire_var_int(&cursor, &plen);
\t\tif (!cursor)
\t\t\tbreak;
\t\tswitch ((enum {tlv_name}_type)msg_type) {{
\t\t\t{printcases}
\t\t\tdefault:
\t\t\t\tprintf("WARNING:No message matching type %d\\n", msg_type);
\t\t}}
\t}}
\tif (plen != 0)
\t\tprintf("EXTRA: %s\\n", tal_hexstr(NULL, cursor, plen));
}}
"""


def build_tlv_fromwires(tlv_fields):
    fromwires = []
    for field_name, messages in tlv_fields.items():
        fromwires.append(print_tlv_fromwire(field_name, messages))
    return fromwires


def build_tlv_towires(tlv_fields):
    towires = []
    for field_name, messages in tlv_fields.items():
        towires.append(print_tlv_towire(field_name, messages))
    return towires


def print_tlv_towire(tlv_field_name, messages):
    fields = ""
    for m in messages:
        fields += tlv__type_impl_towire_fields.format(
            tlv_name=tlv_field_name,
            enum=m.enum.name,
            name=m.name)
    return tlv__type_impl_towire_template.format(
        tlv_name=tlv_field_name,
        fields=fields)


def print_tlv_fromwire(tlv_field_name, messages):
    cases = ""
    for m in messages:
        ctx_arg = tlv_field_name + ', ' if m.has_variable_fields else ''
        cases += case_tmpl.format(ctx_arg=ctx_arg,
                                  tlv_msg_enum=m.enum.name,
                                  tlv_name=tlv_field_name,
                                  tlv_msg_name=m.name)
    return tlv__type_impl_fromwire_template.format(
        tlv_name=tlv_field_name,
        cases=cases)


def build_tlv_type_struct(name, messages):
    inner_structs = CCode()
    for m in messages:
        inner_structs.append('struct tlv_msg_{} *{};'.format(m.name, m.name))
    return tlv_struct_template.format(
        tlv_name=name,
        msg_type_structs=str(inner_structs))


def build_tlv_type_structs(tlv_fields):
    structs = ''
    for name, messages in tlv_fields.items():
        structs += build_tlv_type_struct(name, messages)
    return structs


def find_message(messages, name):
    for m in messages:
        if m.name == name:
            return m

    return None


def print_tlv_printwire(tlv_name, messages):
    printcases = ''
    for m in messages:
        printcases += 'case {enum.name}: printf("{enum.name} (size %"PRIu64"):\\n", msg_size); printwire_{name}("{name}", &cursor, &plen); break;'.format(
            enum=m.enum, name=m.name, tlv_name=tlv_name)
    return print_tlv_template.format(
        tlv_name=tlv_name,
        printcases=printcases)


def print_tlv_printwires(enumname, tlv_fields):
    decls = []
    switches = ''
    for name, messages in tlv_fields.items():
        # Print each of the message parsers
        decls += [m.print_printwire(options.header, is_embedded=True) for m in messages]

        # Print the TLV body parser
        decls.append(print_tlv_printwire(name, messages))

        # Print the 'master' print_tlv_messages cases
        switches += tlv_switch_template.format(tlv_name=name)
    decls.append(print_master_tlv_template.format(enumname=enumname, tlv_switches=switches))
    return decls


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
parser.add_argument('--subtypes', action='store_true', help="Include subtype parsing function delcarations in header definition. Only active if --header also declared.")
parser.add_argument('--bolt', action='store_true', help="Generate wire-format for BOLT")
parser.add_argument('--printwire', action='store_true', help="Create print routines")
parser.add_argument('headerfilename', help='The filename of the header')
parser.add_argument('enumname', help='The name of the enum to produce')
parser.add_argument('files', nargs='*', help='Files to read in (or stdin)')
options = parser.parse_args()

# Maps message names to messages
messages = []
messages_with_option = []
subtypes = []
comments = []
includes = []
tlv_fields = {}
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

    if len(parts) in [1, 2, 3]:
        # eg: commit_sig,132,(_tlv)
        is_tlv_msg = len(parts) == 3
        if len(parts) == 1:  # this is a subtype, it has no type number.
            subtypes.append(Subtype(parts[0], comments))
        else:
            if is_tlv_msg:
                message = TlvMessage(parts[0],
                                     Enumtype("WIRE_" + parts[0].upper(), parts[1]),
                                     comments)
            else:
                message = Message(parts[0],
                                  Enumtype("WIRE_" + parts[0].upper(), parts[1]),
                                  comments)

            messages.append(message)
            if is_tlv_msg:
                tlv_fields[parts[2]].append(message)

        comments = []
        prevfield = None
    else:
        if len(parts) == 4:
            # eg commit_sig,0,channel-id,8 OR
            #    commit_sig,0,channel-id,u64
            m = find_message(messages + subtypes, parts[0])
        elif len(parts) == 5:
            # eg.
            # channel_reestablish,48,your_last_per_commitment_secret,32,option209
            m = find_message_with_option(messages, messages_with_option, parts[0], parts[4])
        else:
            raise ValueError('Line {} malformed'.format(line.rstrip()))

        if m is None:
            raise ValueError('Unknown message or subtype {}'.format(parts[0]))
        f = Field(m.name, parts[2], parts[3], comments, prevfield, includes)
        m.addField(f)
        # If it used prevfield as lenvar, keep that for next
        # time (multiple fields can use the same lenvar).
        if not f.lenvar:
            prevfield = parts[2]
        comments = []


def construct_hdr_enums(msgs):
    enums = ""
    for m in msgs:
        for c in m.comments:
            enums += '\t/*{} */\n'.format(c)
        enums += '\t{} = {},\n'.format(m.enum.name, m.enum.value)
    return enums


def construct_impl_enums(msgs):
    return '\n\t'.join(['case {enum.name}: return "{enum.name}";'.format(enum=m.enum) for m in msgs])


def enum_header(enums, enumname):
    return format_enums(enum_header_template, enums, enumname)


def enum_impl(enums, enumname):
    return format_enums(enum_impl_template, enums, enumname)


def format_enums(template, enums, enumname):
    return template.format(
        enums=enums,
        enumname=enumname)


def build_hdr_enums(toplevel_enumname, toplevel_messages, tlv_fields):
    enum_set = ""
    if len(toplevel_messages):
        enum_set += enum_header(construct_hdr_enums(toplevel_messages), toplevel_enumname)
    for field_name, tlv_messages in tlv_fields.items():
        enum_set += "\n"
        enum_set += enum_header(construct_hdr_enums(tlv_messages), field_name + '_type')
    return enum_set


def build_impl_enums(toplevel_enumname, toplevel_messages, tlv_fields):
    enum_set = ""
    if len(toplevel_messages):
        enum_set += enum_impl(construct_impl_enums(toplevel_messages), toplevel_enumname)
    for field_name, tlv_messages in tlv_fields.items():
        enum_set += "\n"
        enum_set += enum_impl(construct_impl_enums(tlv_messages), field_name + '_type')
    return enum_set


def build_tlv_structs(tlv_fields):
    structs = ""
    for field_name, tlv_messages in tlv_fields.items():
        for m in tlv_messages:
            structs += m.print_struct()
    return structs


def build_subtype_structs(subtypes):
    structs = ""
    for subtype in reversed(subtypes):
        structs += subtype.print_struct()
    return structs


enum_header_template = """enum {enumname} {{
{enums}
}};
const char *{enumname}_name(int e);
"""

enum_impl_template = """
const char *{enumname}_name(int e)
{{
\tstatic char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

\tswitch ((enum {enumname})e) {{
\t{enums}
\t}}

\tsnprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
\treturn invalidbuf;
}}
"""

header_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#ifndef LIGHTNING_{idem}
#define LIGHTNING_{idem}
#include <ccan/tal/tal.h>
#include <wire/wire.h>
{includes}
{formatted_hdr_enums}{gen_structs}
{func_decls}
#endif /* LIGHTNING_{idem} */
"""

impl_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#include <{headerfilename}>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
{formatted_impl_enums}
{func_decls}
"""

print_tlv_message_printwire_empty = """void print{enumname}_tlv_message(const char *tlv_name, const u8 *msg)
{{
\tprintf("~~ No TLV definition found for %s ~~\\n", tlv_name);
}}
"""

print_header_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#ifndef LIGHTNING_{idem}
#define LIGHTNING_{idem}
#include <ccan/tal/tal.h>
#include <devtools/print_wire.h>
{includes}

void print{enumname}_message(const u8 *msg);

void print{enumname}_tlv_message(const char *tlv_name, const u8 *msg);

{func_decls}
#endif /* LIGHTNING_{idem} */
"""

print_template = """/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
#include "{headerfilename}"
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <inttypes.h>
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

print_master_tlv_template = """
void print{enumname}_tlv_message(const char *tlv_name, const u8 *msg)
{{
\t{tlv_switches}
\tprintf("ERR: Unknown TLV message type: %s\\n", tlv_name);
}}
"""

tlv_switch_template = """
\tif (strcmp(tlv_name, "{tlv_name}") == 0) {{
\t\tprintwire_{tlv_name}("{tlv_name}", msg);
\t\treturn;
\t}}
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

# Print out all the things
toplevel_messages = [m for m in messages if not m.is_tlv]
built_hdr_enums = build_hdr_enums(options.enumname, toplevel_messages, tlv_fields)
built_impl_enums = build_impl_enums(options.enumname, toplevel_messages, tlv_fields)
tlv_structs = build_tlv_structs(tlv_fields)
tlv_structs += build_tlv_type_structs(tlv_fields)
subtype_structs = build_subtype_structs(subtypes)
includes = '\n'.join(includes)
printcases = ['case {enum.name}: printf("{enum.name}:\\n"); printwire_{name}("{name}", msg); return;'.format(enum=m.enum, name=m.name) for m in toplevel_messages]

if options.printwire:
    decls = []
    if not options.header:
        subtype_decls = [m.print_printwire(options.header, is_embedded=True) for m in subtypes]
        subtype_decls.reverse()
        decls += subtype_decls
        if len(tlv_fields):
            decls += print_tlv_printwires(options.enumname, tlv_fields)
        else:
            decls += [print_tlv_message_printwire_empty.format(enumname=options.enumname)]
    decls += [m.print_printwire(options.header) for m in toplevel_messages + messages_with_option]
else:
    towire_decls = []
    fromwire_decls = []

    if not options.header or (options.header and options.subtypes):
        subtype_towires = []
        subtype_fromwires = []
        for subtype in subtypes:
            subtype_towires.append(subtype.print_towire())
            subtype_fromwires.append(subtype.print_fromwire())
        subtype_towires.reverse()
        subtype_fromwires.reverse()
        towire_decls += subtype_towires
        fromwire_decls += subtype_fromwires

    for tlv_field, tlv_messages in tlv_fields.items():
        for m in tlv_messages:
            towire_decls.append(m.print_towire(options.header, tlv_field))
            fromwire_decls.append(m.print_fromwire(options.header, tlv_field))

    if not options.header:
        towire_decls += build_tlv_towires(tlv_fields)
        fromwire_decls += build_tlv_fromwires(tlv_fields)

    towire_decls += [m.print_towire(options.header) for m in toplevel_messages + messages_with_option]
    fromwire_decls += [m.print_fromwire(options.header) for m in toplevel_messages + messages_with_option]
    decls = fromwire_decls + towire_decls

print(template.format(
    headerfilename=options.headerfilename,
    printcases='\n\t'.join(printcases),
    idem=idem,
    includes=includes,
    enumname=options.enumname,
    formatted_hdr_enums=built_hdr_enums,
    formatted_impl_enums=built_impl_enums,
    gen_structs=subtype_structs + tlv_structs,
    func_decls='\n'.join(decls)))
