#! /usr/bin/env python3
# Script to turn JSON schema into markdown documentation and replace in-place.
# Released by Rusty Russell under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
from argparse import ArgumentParser
import json
import re

# To maintain the sequence of the before return value (body) and after return value (footer) sections in the markdown file
BODY_KEY_SEQUENCE = ['reliability', 'usage', 'restriction_format', 'permitted_sqlite3_functions', 'treatment_of_types', 'tables', 'example_usage', 'notes', 'notifications', 'sharing_runes', 'riskfactor_effect_on_routing', 'recommended_riskfactor_values', 'optimality', 'randomization']
FOOTER_KEY_SEQUENCE = ['errors', 'json_example', 'trivia', 'author', 'see_also', 'resources']


def output_title(title, underline='-', num_leading_newlines=1, num_trailing_newlines=2):
    """Add a title to the output"""
    print('\n' * num_leading_newlines + title, end='\n')
    print(underline * len(title) + '\n' * num_trailing_newlines, end='')
    global current_line_width
    current_line_width = 0


def esc_underscores(s):
    """Backslash-escape underscores outside of backtick-enclosed spans"""
    return ''.join(['\\_' if x == '_' else x for x in re.findall(r'[^`_\\]+|`(?:[^`\\]|\\.)*`|\\.|_', s)])


def json_value(obj):
    """Format obj in the JSON style for a value"""
    if type(obj) is bool:
        if obj:
            return '*true*'
        return '*false*'
    if type(obj) is str:
        return '"' + esc_underscores(obj) + '"'
    if obj is None:
        return '*null*'
    assert False


def outputs(lines, separator=''):
    """Add these lines to the final output"""
    print(esc_underscores(separator.join(lines)), end='')


def output(line):
    """Add this line to the final output"""
    print(line, end='')


def search_key_in_conditional_array(request, param):
    """search param in all conditional subarrays/objects and return the condition and found array/obj"""
    one_of_many_array = request.get('oneOfMany', [])
    paired_with_array = request.get('pairedWith', [])

    # Check if the same parameter is in both 'pairedWith' and 'oneOfMany' and throw an error if found
    common_key = next((element_one for subarray_one in one_of_many_array for element_one in subarray_one for subarray_paired in paired_with_array if element_one in subarray_paired), '')
    assert common_key == '', f'The same parameter "{common_key}" cannot be in both "pairedWith" and "oneOfMany"'

    # Search for the parameter in 'oneOfMany' array
    for sub_array_one in one_of_many_array:
        if param in sub_array_one:
            return 'oneOfMany', sub_array_one

    # Search for the parameter in 'pairedWith' array
    for sub_array_paired in paired_with_array:
        if param in sub_array_paired:
            return 'pairedWith', sub_array_paired

    # If param doesn't exist in any of the conditional arrays, return empty condition and None
    return '', None


def output_conditional_params(conditional_sub_array, condition):
    """Output request parameters with appropriate separator based on the separator"""
    # If the request has 'oneOfMany', then print them in one param section with OR (|) sign.
    # 'oneOfMany' example `plugin`: [*plugin|directory*]
    # If the request has 'pairedWith', then print them in one param section separated with space.
    # 'pairedWith' example `delpay`: [*partid* *groupid*]
    # If the request has 'dependentUpon', then print them in one param section separated with space.
    # 'dependentUpon' example `listforwards`: [*index* [*start*] [*limit*]]
    separator = {'oneOfMany': '|', 'pairedWith': '* *', 'dependentUpon': '*] [*'}.get(condition, '')
    # Join all keys with the separator
    keysfoundstr = format(esc_underscores(separator.join(conditional_sub_array)))
    # Print the merged keys
    output('{}{}'.format(fmt_paramname(keysfoundstr, True, False), '' if condition == 'dependentUpon' else ' '))


def output_type(properties, is_optional):
    """Add types for request and reponse parameters"""
    typename = 'one of' if 'oneOf' in properties else esc_underscores(properties['type'])
    if typename == 'array':
        if 'items' in properties and 'type' in properties['items']:
            typename += ' of {}s'.format(esc_underscores(properties['items']['type']))
    if is_optional:
        typename += ', optional'
    output(' ({})'.format(esc_underscores(typename)))


def output_range(properties):
    if 'maximum' and 'minimum' in properties:
        output(' ({} to {} inclusive)'.format(properties['minimum'], properties['maximum']))
    elif 'maximum' in properties:
        output(' (max {})'.format(properties['maximum']))
    elif 'minimum' in properties:
        output(' (min {})'.format(properties['minimum']))

    if 'maxLength' and 'minLength' in properties:
        if properties['minLength'] == properties['maxLength']:
            output(' (always {} characters)'.format(properties['minLength']))
        else:
            output(' ({} to {} characters)'.format(properties['minLength'], properties['maxLength']))
    elif 'maxLength' in properties:
        output(' (up to {} characters)'.format(properties['maxLength']))
    elif 'minLength' in properties:
        output(' (at least {} characters)'.format(properties['minLength']))

    if 'enum' in properties:
        if len(properties['enum']) == 1:
            output(" (always {})".format(json_value(properties['enum'][0])))
        else:
            output(' (one of {})'.format(', '.join([json_value(p) for p in properties['enum']])))


def fmt_propname(propname):
    """Pretty-print format a property name"""
    return '**{}**'.format(esc_underscores(propname))


def fmt_paramname(paramname, is_optional=True, trailing_space=True):
    """Pretty-print format a parameter name"""
    return '[*{}*]{}'.format(esc_underscores(paramname), ' ' if trailing_space else '') if is_optional else '*{}*{}'.format(esc_underscores(paramname), ' ' if trailing_space else '')


def deprecated_to_deleted(vername):
    """We promise a 6 month minumum deprecation period, and versions are every 3 months"""
    assert vername.startswith('v')
    base = [int(s) for s in vername[1:].split('.')[0:2]]
    if base == [0, 12]:
        base = [22, 8]
    base[1] += 9
    if base[1] > 12:
        base[0] += 1
        base[1] -= 12
    # Christian points out versions should sort well lexographically,
    # so we zero-pad single-digits.
    return 'v{}.{:0>2}'.format(base[0], base[1])


def output_member(propname, properties, is_optional, indent, print_type=True, prefix=None):
    """Generate description line(s) for this member"""
    # Skip hidden properties
    if 'hidden' in properties and properties['hidden']:
        return

    if prefix is None:
        prefix = '- ' + fmt_propname(propname) if propname is not None else '-'
    output(indent + prefix)

    # We make them explicitly note if they don't want a type!
    is_untyped = 'untyped' in properties

    if not is_untyped and print_type:
        output_type(properties, is_optional)

    output_range(properties)

    if 'description' in properties:
        for i in range(0, len(properties['description'])):
            output('{} {}{}'.format(':' if i == 0 else '', esc_underscores(properties['description'][i]), '' if i + 1 == len(properties['description']) else '\n'))

    if 'default' in properties:
        output(' The default is {}.'.format(esc_underscores(properties['default']) if isinstance(properties['default'], str) else properties['default']))

    if 'deprecated' in properties:
        output(' **deprecated in {}, removed after {}**'.format(properties['deprecated'][0], properties['deprecated'][1] if len(properties['deprecated']) > 1 else deprecated_to_deleted(properties['deprecated'][0])))

    if 'added' in properties:
        output(' *(added {})*'.format(properties['added']))

    if 'oneOf' in properties and isinstance(properties['oneOf'], list):
        output(':\n')
        output_members(properties, indent + '  ')
    elif not is_untyped and properties['type'] == 'object':
        output(':\n')
        output_members(properties, indent + '  ')
    elif not is_untyped and properties['type'] == 'array':
        output(':\n')
        output_array(properties['items'], indent + '  ')
    else:
        output('\n')


def output_array(items, indent):
    """We've already said it's an array of {type}"""
    if 'oneOf' in items and isinstance(items['oneOf'], list):
        output_members(items, indent + '  ')
    elif items['type'] == 'object':
        output_members(items, indent)
    elif items['type'] == 'array':
        output(indent + '-')
        output_type(items, False)
        output(': {}\n'.format(esc_underscores('\n'.join(items['description']))) if 'description' in items and len(items['description']) > 0 else '\n')
        if 'items' in items:
            output_array(items['items'], indent + '  ')
    else:
        if 'type' in items:
            output_member(None, items, True, indent)


def has_members(sub):
    """Does this sub have any properties to print?"""
    for p in list(sub['properties'].keys()):
        if len(sub['properties'][p]) == 0:
            continue
        if sub['properties'][p].get('deprecated') is True:
            continue
        return True
    return False


def output_members(sub, indent=''):
    """Generate lines for these properties"""
    warnings = []
    if 'properties' in sub:
        for p in list(sub['properties'].keys()):
            if len(sub['properties'][p]) == 0 or sub['properties'][p].get('deprecated') is True:
                del sub['properties'][p]
            elif p.startswith('warning'):
                warnings.append(p)

        # First list always-present properties
        for p in sub['properties']:
            if p.startswith('warning'):
                continue
            if 'required' in sub and p in sub['required']:
                output_member(p, sub['properties'][p], False, indent)

        for p in sub['properties']:
            if p.startswith('warning'):
                continue
            if 'required' not in sub or p not in sub['required']:
                output_member(p, sub['properties'][p], True, indent)

    if warnings != []:
        output(indent + '- the following warnings are possible:\n')
        for w in warnings:
            output_member(w, sub['properties'][w], False, indent + '  ', print_type=False)

    if 'oneOf' in sub:
        for oneOfItem in sub['oneOf']:
            if 'type' in oneOfItem and oneOfItem['type'] == 'array':
                output_array(oneOfItem, indent)
            else:
                output_member(None, oneOfItem, False, indent, False if 'enum' in oneOfItem else True)

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

        # 'required' are fields that simply must be present
        for r in ifclause['if'].get('required', []):
            conditions.append(fmt_propname(r) + ' is present')

        # 'properties' are enums of field values
        for tag, vals in ifclause['if'].get('properties', {}).items():
            # Don't have a description field here, it's not used.
            assert 'description' not in vals
            whichvalues = vals['enum']

            cond = fmt_propname(tag) + ' is'
            if len(whichvalues) == 1:
                cond += ' {}'.format(json_value(whichvalues[0]))
            else:
                cond += ' {} or {}'.format(', '.join([json_value(v) for v in whichvalues[:-1]]),
                                           json_value(whichvalues[-1]))
            conditions.append(cond)

        sentence = indent + 'If ' + ', and '.join(conditions) + ':\n'

        if has_members(ifclause['then']):
            # Prefix with blank line.
            outputs(['\n', sentence])
            output_members(ifclause['then'], indent + '  ')


def create_shell_command(rpc, example):
    """Output shell command for the request example"""
    output('```shell\n')
    shell_command = f'lightning-cli {rpc} '
    if 'params' in example['request']:
        if isinstance(example['request']['params'], list):
            shell_command += ' '.join(f'"{item}"' for item in example['request']['params'])
        elif example['request']['params'].items():
            shell_command += '-k '
            for k, v in example['request']['params'].items():
                # If the value is a string, wrap it in double quotes
                # otherwise, keep the json as is and wrap the whole value in single quotes
                # Example 1: wrap route list in single quotes
                # lightning-cli check -k "command_to_check"="sendpay" "route"='[{"amount_msat": 1011, "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59", "delay": 20, "channel": "1x1x1"}, {"amount_msat": 1000, "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d", "delay": 10, "channel": "2x2x2"}]' "payment_hash"="0000000000000000000000000000000000000000000000000000000000000000"
                # Example 2: keep subcommand value ("slowcmd") in double quotes
                # lightning-cli check -k "command_to_check"="dev" "subcommand"="slowcmd" "msec"=1000
                if isinstance(v, str):
                    shell_command += f'"{k}"="{v}" '
                elif isinstance(v, int):
                    shell_command += f'"{k}"={v} '
                else:
                    shell_command += f'"{k}"=\'' + json.dumps(v) + '\' '
    shell_command = shell_command.strip()
    output(shell_command + '\n')
    output('```\n')


def create_expandable(title, rpc, examples):
    """Output example/s with request and response in collapsible header"""
    output('\n<details>\n')
    output('<summary>\n')
    output(f'<span style="font-size: 1.5em; font-weight: bold;">{title}</span><br><hr>\n')
    output('</summary>\n\n')
    for i, example in enumerate(examples):
        output('{}**Example {}**: {}\n'.format('' if i == 0 else '\n', i + 1, '\n'.join(example.get('description', ''))))
        output('\nRequest:\n')
        output('```json\n')
        output(json.dumps(example['request'], indent=2).strip() + '\n')
        output('```\n')
        create_shell_command(rpc, example)
        output('\nResponse:\n')
        output('```json\n')
        output(json.dumps(example['response'], indent=2).strip() + '\n')
        output('```\n')
    output('</details>')


def generate_header(schema):
    """Generate lines for rpc title and synopsis with request parameters"""
    output_title(esc_underscores(''.join(['lightning-', schema['rpc'], ' -- ', schema['title']])), '=', 0, 1)
    output_title('SYNOPSIS')
    # Add command level warning if exists
    if 'warning' in schema:
        output('**(WARNING: {})**\n\n'.format(esc_underscores(schema['warning'])))
    # generate the rpc command details with request parameters
    request = schema['request']
    properties = request['properties']
    toplevels = list(request['properties'].keys())
    output('{} '.format(fmt_propname(schema['rpc'])))
    i = 0
    while i < len(toplevels):
        # Skip hidden properties
        if 'hidden' in properties[toplevels[i]] and properties[toplevels[i]]['hidden']:
            i += 1
            continue
        # Search for the parameter in 'dependentUpon' array
        dependent_upon_obj = request['dependentUpon'] if 'dependentUpon' in request else []
        if toplevels[i] in dependent_upon_obj:
            # Output parameters with appropriate separator
            output('{}*{}* '.format('' if 'required' in request and toplevels[i] in request['required'] else '[', esc_underscores(toplevels[i])))
            output_conditional_params(dependent_upon_obj[toplevels[i]], 'dependentUpon')
            toplevels = [key for key in toplevels if key not in dependent_upon_obj[toplevels[i]]]
            output('{}'.format('' if 'required' in request and toplevels[i] in request['required'] else ']'))
        else:
            # Search for the parameter in any conditional sub-arrays (oneOfMany, pairedWith)
            condition, foundinsubarray = search_key_in_conditional_array(request, toplevels[i])
            # If param found in the conditional sub-array
            if condition != '' and foundinsubarray is not None:
                # Output parameters with appropriate separator
                output_conditional_params(foundinsubarray, condition)
                # Remove found keys from toplevels array
                toplevels = [key for key in toplevels if key not in foundinsubarray]
                # Reset the cursor to the previous index
                i = i - 1
            else:
                # Print the key as it is if it doesn't exist in conditional array
                output('{}'.format(fmt_paramname(toplevels[i], False if 'required' in request and toplevels[i] in request['required'] else True)))
        i += 1
    # lightning-plugin.json is an exception where all parameters cannot be printed deu to their dependency on different subcommands
    # So, add ... at the end for lightning-plugin schema
    if schema['rpc'] == 'plugin':
        output('...')
    output('\n')


def generate_description(schema):
    """Generate rpc description with request parameter descriptions"""
    request = schema['request']
    output_title('DESCRIPTION')
    # Add deprecated and removal information for the command
    if 'deprecated' in schema:
        output('Command **deprecated in {}, removed after {}**.\n\n'.format(schema['deprecated'][0], schema['deprecated'][1] if len(schema['deprecated']) > 1 else deprecated_to_deleted(schema['deprecated'][0])))
    # Version when the command was added
    if 'added' in schema:
        output('Command *added* in {}.\n\n'.format(schema['added']))
    # Command's detailed description
    outputs(schema['description'], '\n')
    # Request parameter's detailed description
    output('{}'.format('\n\n' if len(request['properties']) > 0 else '\n'))
    output_members(request)


def generate_return_value(schema):
    """This is not general, but works for us"""
    output_title('RETURN VALUE')

    response = schema['response']

    if 'pre_return_value_notes' in response:
        outputs(response['pre_return_value_notes'], '\n')
        output('\n')

    toplevels = []
    warnings = []
    props = response['properties']

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
        # Use pre/post_return_value_notes with empty properties when dynamic generation of the return value section is not required.
        # But to add a custom return value section instead. Example: `commando` commands.
        if "pre_return_value_notes" not in response and "post_return_value_notes" not in response:
            output('On success, an empty object is returned.\n')
        sub = schema
    elif len(toplevels) == 1 and props[toplevels[0]]['type'] == 'object':
        output('On success, an object containing {} is returned. It is an object containing:\n\n'.format(fmt_propname(toplevels[0])))
        # Don't have a description field here, it's not used.
        assert 'description' not in toplevels[0]
        sub = props[toplevels[0]]
    elif len(toplevels) == 1 and props[toplevels[0]]['type'] == 'array' and props[toplevels[0]]['items']['type'] == 'object':
        output('On success, an object containing {} is returned. It is an array of objects, where each object contains:\n\n'.format(fmt_propname(toplevels[0])))
        # Don't have a description field here, it's not used.
        assert 'description' not in toplevels[0]
        sub = props[toplevels[0]]['items']
    else:
        output('On success, an object is returned, containing:\n\n')
        sub = response

    output_members(sub)

    if warnings:
        output('\nThe following warnings may also be returned:\n\n')
        for w, desc in warnings:
            output('- {}: {}\n'.format(fmt_propname(w), ''.join(desc)))

    if 'post_return_value_notes' in response:
        if len(props.keys()) > 0:
            output('\n')
        outputs(response['post_return_value_notes'], '\n')
        output('\n')


def generate_body(schema):
    """Output sections which should be printed after description and before return value"""
    # Insert extra line between description and next section with this flag
    first_matching_key = True
    # Only add a newline if at least there is one body key found
    body_key_found = False
    for key in BODY_KEY_SEQUENCE:
        if key not in schema:
            continue
        body_key_found = True
        output_title(key.replace('_', ' ').upper(), '-', 1 if first_matching_key else 2)
        first_matching_key = False
        outputs(schema[key], '\n')
    if body_key_found:
        output('\n')


def generate_footer(schema):
    """Output sections which should be printed after return value"""
    for key in FOOTER_KEY_SEQUENCE:
        if key not in schema:
            continue
        if key == 'see_also':
            output_title(key.replace('_', ' ').upper(), '-', 1)
            # Wrap see_also list with comma separated values
            output(esc_underscores(', '.join(schema[key])))
        elif key == 'json_example' and len(schema[key]) > 0:
            create_expandable('EXAMPLE', schema['rpc'], schema.get('json_example', []))
        else:
            output_title(key.replace('_', ' ').upper(), '-', 1)
            outputs(schema[key], '\n')
        output('\n')


def main(schemafile, markdownfile):
    with open(schemafile, 'r') as f:
        schema = json.load(f)
    # Outputs rpc title and synopsis with request parameters
    generate_header(schema)
    # Outputs command description with request parameter descriptions
    generate_description(schema)
    # Outputs other remaining sections before return value section
    generate_body(schema)
    # Outputs command response with response parameter descriptions
    generate_return_value(schema)
    # Outputs other remaining sections after return value section
    generate_footer(schema)

    if markdownfile is None:
        return


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('schemafile', help='The schema file to use')
    parser.add_argument('--markdownfile', help='The markdown file to read')
    parsed_args = parser.parse_args()
    main(parsed_args.schemafile, parsed_args.markdownfile)
