#! /usr/bin/env python3
# Script to turn JSON schema into markdown documentation and replace in-place.
# Released by Rusty Russell under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
from argparse import ArgumentParser
import json


def json_value(obj):
    """Format obj in the JSON style for a value"""
    if type(obj) is bool:
        if obj:
            return '*true*'
        return '*false*'
    if type(obj) is str:
        return '"' + obj + '"'
    if obj is None:
        return '*null*'
    assert False


def outputs(lines):
    """Add these lines to the final output"""
    print(''.join(lines), end='')


def output(line):
    """Add this line to the final output"""
    print(line, end='')


def output_type(properties, is_optional):
    # FIXME: there's a horrible hack for listpeers' closer which can be NULL
    if type(properties['type']) is list:
        typename = properties['type'][0]
    else:
        typename = properties['type']
    if typename == 'array':
        typename += ' of {}s'.format(properties['items']['type'])
    if is_optional:
        typename += ", optional"
    output(" ({})".format(typename))


def output_range(properties):
    if 'maximum' and 'minimum' in properties:
        output(" ({} to {} inclusive)".format(properties['minimum'],
                                              properties['maximum']))
    elif 'maximum' in properties:
        output(" (max {})".format(properties['maximum']))
    elif 'minimum' in properties:
        output(" (min {})".format(properties['minimum']))

    if 'maxLength' and 'minLength' in properties:
        if properties['minLength'] == properties['maxLength']:
            output(' (always {} characters)'.format(properties['minLength']))
        else:
            output(' ({} to {} characters)'.format(properties['minLength'],
                                                   properties['maxLength']))
    elif 'maxLength' in properties:
        output(' (up to {} characters)'.format(properties['maxLength']))
    elif 'minLength' in properties:
        output(' (at least {} characters)'.format(properties['minLength']))

    if 'enum' in properties:
        if len(properties['enum']) == 1:
            output(" (always {})".format(json_value(properties['enum'][0])))
        else:
            output(' (one of {})'.format(', '.join([json_value(p) for p in properties['enum']])))


def output_member(propname, properties, is_optional, indent, print_type=True, prefix=None):
    """Generate description line(s) for this member"""

    if prefix is None:
        prefix = '- **{}**'.format(propname)
    output(indent + prefix)

    # We make them explicitly note if they don't want a type!
    is_untyped = 'untyped' in properties

    if not is_untyped and print_type:
        output_type(properties, is_optional)

    if 'description' in properties:
        output(": {}".format(properties['description']))

    output_range(properties)

    if not is_untyped and properties['type'] == 'object':
        output(':\n')
        output_members(properties, indent + '  ')
    elif not is_untyped and properties['type'] == 'array':
        output(':\n')
        output_array(properties['items'], indent + '  ')
    else:
        output('\n')


def output_array(items, indent):
    """We've already said it's an array of {type}"""
    if items['type'] == 'object':
        output_members(items, indent)
    elif items['type'] == 'array':
        output(indent + '- {}:\n'.format(items['description']))
        output_array(items['items'], indent + '  ')
    else:
        output(indent + '- {}'.format(items['description']))
        output_range(items)
        output('\n')


def has_members(sub):
    """Does this sub have any properties to print?"""
    for p in list(sub['properties'].keys()):
        if len(sub['properties'][p]) == 0:
            continue
        if 'deprecated' in sub['properties'][p]:
            continue
        return True
    return False


def output_members(sub, indent=''):
    """Generate lines for these properties"""
    warnings = []

    # Remove deprecated and stub properties, collect warnings
    # (Stubs required to keep additionalProperties: false happy)
    for p in list(sub['properties'].keys()):
        if len(sub['properties'][p]) == 0 or 'deprecated' in sub['properties'][p]:
            del sub['properties'][p]
        elif p.startswith('warning'):
            warnings.append(p)

    # First list always-present properties
    for p in sub['properties']:
        if p.startswith('warning'):
            continue
        if p in sub['required']:
            output_member(p, sub['properties'][p], False, indent)

    for p in sub['properties']:
        if p.startswith('warning'):
            continue
        if p not in sub['required']:
            output_member(p, sub['properties'][p], True, indent)

    if warnings != []:
        output(indent + "- the following warnings are possible:\n")
        for w in warnings:
            output_member(w, sub['properties'][w], False, indent + '  ', print_type=False)

    # Not handled.
    assert 'oneOf' not in sub

    # If we have multiple ifs, we have to wrap them in allOf.
    if 'allOf' in sub:
        ifclauses = sub['allOf']
    elif 'if' in sub:
        ifclauses = [sub]
    else:
        ifclauses = []

    # We partially handle if, assuming it depends on particular values of prior properties.
    for ifclause in ifclauses:
        conditions = []

        # "required" are fields that simply must be present
        for r in ifclause['if'].get('required', []):
            conditions.append('**{}** is present'.format(r))

        # "properties" are enums of field values
        for tag, vals in ifclause['if'].get('properties', {}).items():
            # Don't have a description field here, it's not used.
            assert 'description' not in vals
            whichvalues = vals['enum']

            cond = "**{}** is".format(tag)
            if len(whichvalues) == 1:
                cond += " {}".format(json_value(whichvalues[0]))
            else:
                cond += " {} or {}".format(", ".join([json_value(v) for v in whichvalues[:-1]]),
                                           json_value(whichvalues[-1]))
            conditions.append(cond)

        sentence = indent + "If " + ", and ".join(conditions) + ":\n"

        if has_members(ifclause['then']):
            # Prefix with blank line.
            outputs(['\n', sentence])

            output_members(ifclause['then'], indent + '  ')


def generate_from_schema(schema):
    """This is not general, but works for us"""
    if schema['type'] != 'object':
        # 'stop' returns a single string!
        output_member(None, schema, False, '', prefix='On success, returns a single element')
        return

    toplevels = []
    warnings = []
    props = schema['properties']

    # We handle warnings on top-level objects with a separate section,
    # so collect them now and remove them
    for toplevel in list(props.keys()):
        if toplevel.startswith('warning'):
            warnings.append((toplevel, props[toplevel]['description']))
            del props[toplevel]
        else:
            toplevels.append(toplevel)

    # No properties -> empty object.
    if toplevels == []:
        output('On success, an empty object is returned.\n')
        sub = schema
    elif len(toplevels) == 1 and props[toplevels[0]]['type'] == 'object':
        output('On success, an object containing **{}** is returned.  It is an object containing:\n'.format(toplevels[0]))
        # Don't have a description field here, it's not used.
        assert 'description' not in toplevels[0]
        sub = props[toplevels[0]]
    elif len(toplevels) == 1 and props[toplevels[0]]['type'] == 'array':
        output('On success, an object containing **{}** is returned.  It is an array of objects, where each object contains:\n'.format(toplevels[0]))
        # Don't have a description field here, it's not used.
        assert 'description' not in toplevels[0]
        sub = props[toplevels[0]]['items']
    else:
        output('On success, an object is returned, containing:\n')
        sub = schema

    output_members(sub)

    if warnings:
        outputs(['\n', 'The following warnings may also be returned:\n'])
        for w, desc in warnings:
            output("- **{}**: {}\n".format(w, desc))

    # GH markdown rendering gets upset if there isn't a blank line
    # between a list and the end comment.
    output('\n')


def main(schemafile, markdownfile):
    start_marker = '[comment]: # (GENERATE-FROM-SCHEMA-START)\n'
    end_marker = '[comment]: # (GENERATE-FROM-SCHEMA-END)\n'

    if markdownfile is None:
        with open(schemafile, "r") as f:
            schema = json.load(f)
        generate_from_schema(schema)
        return

    with open(markdownfile, "r") as f:
        md = f.readlines()

    suppress_output = False
    for line in md:
        if line == end_marker:
            suppress_output = False

        if not suppress_output:
            print(line, end='')

        if line == start_marker:
            with open(schemafile, "r") as f:
                schema = json.load(f)
            generate_from_schema(schema)
            suppress_output = True


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('schemafile', help='The schema file to use')
    parser.add_argument('--markdownfile', help='The markdown file to read')
    parsed_args = parser.parse_args()

    main(parsed_args.schemafile, parsed_args.markdownfile)
