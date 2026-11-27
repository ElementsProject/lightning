#!/usr/bin/env python3
"""Flag added C lines which are indented with spaces.

The C code is indented with TAB characters (see .editorconfig).  Spaces
only align a continuation, under the open paren of the line before:

    static void subtract_received_htlcs(const struct channel *channel,
                                        struct amount_msat *amount)

So a line which starts a new statement -- one after a `;`, `{`, `}` or a
label -- must start with a tab.  Only added lines are checked (see
tools/added-lines.sh).
"""
import os
import re
import subprocess
import sys

PATHSPECS = ['*.c', '*.h', ':(exclude)ccan/', ':(exclude)contrib/']

# Comments, strings and character constants: none of them hold code.
NOT_CODE = re.compile(r'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*' ''', re.S | re.X)

# After one of these a new statement starts: nothing to align under.
BOUNDARY = re.compile(r'[;:{}]$')


def code_only(text):
    """Blank out whatever is not code, keeping every line where it was."""
    return NOT_CODE.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), text)


def problems(code):
    """(line, complaint) for each line which is indented with spaces."""
    previous = ''
    for number, line in enumerate(code.split('\n'), 1):
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith('#'):
            continue
        indent = line[:len(line) - len(line.lstrip())]
        if ' \t' in indent:
            yield number, 'is indented with spaces before a tab: use tabs'
        elif (indent.startswith(' ') and not previous.endswith('\\')
              and BOUNDARY.search(previous)):
            yield number, 'is indented with spaces: use tabs'
        previous = stripped


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'master'
    helper = os.path.join(os.path.dirname(sys.argv[0]), 'added-lines.sh')
    lines = subprocess.run([helper, base] + PATHSPECS,
                           check=True, stdout=subprocess.PIPE, text=True)
    added = {}
    for entry in lines.stdout.splitlines():
        path, line = entry.rsplit(':', 1)
        added.setdefault(path, set()).add(int(line))

    failed = False
    for path in sorted(added):
        with open(path, errors='replace') as f:
            code = code_only(f.read())
        for line, complaint in problems(code):
            if line in added[path]:
                print(f'{path}:{line}: line {complaint}')
                failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
