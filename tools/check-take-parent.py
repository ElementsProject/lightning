#!/usr/bin/env python3
"""Flag take() of something which was allocated off a parent.

take() gives its argument to the function being called.  Something
allocated only to be given away should be allocated off NULL, so it is
clear that nothing else owns it:

    subd_send_msg(sd, take(towire_foo(NULL, ...)));

The generated marshalling code does not support take() at all: a take()
anywhere in the arguments of a towire_ or fromwire_ call leaks what it
was given.

Only added lines are checked (see tools/added-lines.sh).  The allocations
recognised are the ones which name their parent first: anything given
tmpctx, and the towire_ and tal functions.
"""
import os
import re
import subprocess
import sys

PATHSPECS = ['*.c', '*.h', ':(exclude)ccan/', ':(exclude)contrib/', ':(exclude)external/']

# Comments, strings and character constants: none of them hold code.
NOT_CODE = re.compile(r'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*' ''', re.S | re.X)
TAKE = re.compile(r'\btake\(\s*(?:\w+\(\s*(tmpctx)\b|(?:towire_\w+|tal\w*)\(\s*(?!NULL\b)(\w+))')
WIRE_CALL = re.compile(r'\b(?:towire|fromwire)_\w+\(')


def code_only(text):
    """Blank out whatever is not code, keeping every line where it was."""
    return NOT_CODE.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), text)


def wire_takes(code):
    """Offset of each take() inside the arguments of a wire call."""
    for call in WIRE_CALL.finditer(code):
        depth = 1
        for i in range(call.end(), len(code)):
            if code[i] == '(':
                depth += 1
            elif code[i] == ')':
                depth -= 1
                if depth == 0:
                    break
        take = re.compile(r'\btake\(').search(code, call.end(), i)
        if take:
            yield take.start()


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
        for take in TAKE.finditer(code):
            line = code.count('\n', 0, take.start()) + 1
            if line in added[path]:
                parent = take.group(1) or take.group(2)
                print(f'{path}:{line}: take() of something allocated off {parent}:'
                      ' allocate it off NULL, since take() gives it away')
                failed = True
        for offset in wire_takes(code):
            line = code.count('\n', 0, offset) + 1
            if line in added[path]:
                print(f'{path}:{line}: take() in the arguments of a wire call:'
                      ' the generated marshalling never frees it, so it leaks')
                failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
