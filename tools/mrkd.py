#!/usr/bin/env python3

import argparse
import configparser
import io
import mistune
import os
import re
import sys

lines = lambda *a: '\n'.join(a) + '\n'


REF_PATTERN = (r'([A-Za-z-_.]+)\((\d+)\)')


def parse_ref(inline, m, state):
    return 'reference', m.group(1), m.group(2)


def plugin_reference(md):
    md.inline.register_rule('reference', REF_PATTERN, parse_ref)
    md.inline.rules.append('reference')
    md.renderer.register('reference', md.renderer.reference)


class RoffRenderer(mistune.HTMLRenderer):
    def __init__(self, name, sect, index):
        super(RoffRenderer, self).__init__()
        self.name = name
        self.sect = sect
        self.index = index

    # Used above in parse_ref
    def reference(self, text, section):
        return f'{self.strong(text)}({section})'

    # Inline level.
    def text(self, text):
        return text.replace('\\', '\\\\').replace('.', '\\.')

    def link(self, link, title=None, children=None):
        if 'mailto:' in link or link == title:
            return f'{self.emphasis(title)}'

        if link and title:
            return f'{self.strong(title)} ({self.emphasis(link)})'

        return f'{self.emphasis(link)}'

    def image(self, src, alt="", title=None):
        assert 0

    def emphasis(self, text):
        return f'\\fI{text}\\fR'

    def strong(self, text):
        return f'\\fB{text}\\fR'

    def codespan(self, text):
        return self.strong(text)

    def linebreak(self):
        assert 0

    def newline(self):
        return ''

    def inline_html(self, text):
        return ''

    # Block level.
    def paragraph(self, text):
        return lines('', text, '')

    def heading(self, text, level):
        if level == 1:
            if '--' not in text:
                sys.exit(f'Invalid header: {text}')
            self.description = text.split('--', 1)[1].strip()
            return lines(
                f'.TH "{self.name.upper()}" "{self.sect}" "" "" "{self.name}"',
                '.SH NAME',
                f'{text.replace("--", "-")}',
            )
        else:
            return lines(f'.SH {text}')

    def thematic_break(self):
        return lines('.HL')

    def block_text(self, text):
        return self.paragraph(text)

    def block_code(self, code, info=None):
        return lines(
            '.nf',
            self.block_quote(code.replace('\\', '\\\\')),
            '.fi',
        )

    def block_quote(self, text):
        return lines(
            '.RS',
            text,
            '.RE',
        )

    def block_html(self, html):
        return '\n'

    def block_error(self, html):
        assert 0

    def list(self, text, ordered, level, start=None):
        if ordered:
            count = 1
            buf = io.StringIO()

            assert text[0] == '\0'
            for chunk in text.split('\0')[1:]:
                buf.write(f'.IP {count}\\.')
                buf.write(chunk)
                count += 1

            contents = buf.getvalue()
        else:
            contents = text.replace('\0', '.IP \\[bu]')

        return lines(
            '.RS',
            contents,
            '.RE',
        )

    def list_item(self, text, level):
        return '\0' + text

    def finalize(self, data):
        return ''.join(data)


def main():
    parser = argparse.ArgumentParser(prog='mrkd', allow_abbrev=True)
    parser.add_argument('source', help='The source man page')
    parser.add_argument('output', help='The output file')
    parser.add_argument('-name', help='The name to use for the man page')
    parser.add_argument('-section', help='The section to use for the man page')
    parser.add_argument('-template', help='The HTML template file to use')
    parser.add_argument('-index', help='An index file to use for HTML links')
    parser.add_argument('-format',
                        help='The output format',
                        choices=['roff'],
                        default='roff')

    args = parser.parse_args()

    name = args.name
    section = args.section

    m = re.match(r'(.*).(\d).[^.]+$', os.path.basename(args.source))
    if m is None:
        if name is None or section is None:
            sys.exit('Both -name and -section must be passed for invalid filenames.')
    else:
        if name is None:
            name = m.group(1)
        if section is None:
            section = m.group(2)

    if args.index is not None:
        index_config = configparser.ConfigParser()
        with open(args.index) as fp:
            index_config.read_file(fp)

        try:
            index_data = index_config['Index']
        except KeyError:
            sys.exit('Index file must contain an [Index] section.')
    else:
        index_data = {}

    renderer = RoffRenderer(name, section, index_data)

    with open(args.source) as fp:
        markdown = mistune.create_markdown(renderer=renderer, plugins=[plugin_reference])
        result = markdown(fp.read())

    if args.output == '-':
        print(result)
    else:
        with open(args.output, 'w') as fp:
            fp.write(result)


if __name__ == '__main__':
    main()
