#!/usr/bin/env python3
"""Flag a `default:` label added to a switch over an enum.

Without a default, the compiler warns about every switch which does not
handle a newly added enumerator.

Only added lines are checked (see tools/added-lines.sh), and only switches
where some case label is an enumerator: one declared in a tracked source
file, or a WIRE_ name, since the wire headers are generated.  A switch over
errno values or address families may keep its default.
"""
import os
import re
import subprocess
import sys

PATHSPECS = ['*.c', '*.h', ':(exclude)ccan/', ':(exclude)contrib/']

# Comments, strings and character constants: none of them hold code.
NOT_CODE = re.compile(r'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*' ''', re.S | re.X)
ENUM = re.compile(r'\benum\b[^;{}()]*\{([^{}]*)\}')
ENUMERATOR = re.compile(r'\s*([A-Za-z_]\w*)')
SWITCH = re.compile(r'\bswitch\s*\(')
CASE = re.compile(r'\bcase\s+([A-Za-z_]\w*)\s*:')
DEFAULT = re.compile(r'\bdefault\s*:')


def code_only(text):
    """Blank out whatever is not code, keeping every line where it was."""
    return NOT_CODE.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), text)


def read(path):
    with open(path, errors='replace') as f:
        return f.read()


def enumerators():
    """Every enumerator declared in a tracked C file."""
    names = set()
    tracked = subprocess.run(['git', 'ls-files', '-z', '--', '*.c', '*.h'],
                             check=True, stdout=subprocess.PIPE, text=True)
    for path in tracked.stdout.split('\0'):
        if not os.path.isfile(path):
            continue
        text = read(path)
        if 'enum' not in text:
            continue
        for body in ENUM.findall(code_only(text)):
            body = re.sub(r'^\s*#.*$', '', body, flags=re.M)
            for item in body.split(','):
                name = ENUMERATOR.match(item)
                if name:
                    names.add(name.group(1))
    return names


def closing(code, start, opener, closer):
    """Offset just past the bracket which closes the one at start."""
    depth = 0
    for i in range(start, len(code)):
        if code[i] == opener:
            depth += 1
        elif code[i] == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def switch_bodies(code):
    """(start, end) offsets of the braces of each switch statement."""
    bodies = []
    for switch in SWITCH.finditer(code):
        after = closing(code, switch.end() - 1, '(', ')')
        if after is None:
            continue
        brace = code.find('{', after)
        if brace == -1 or code[after:brace].strip():
            continue
        end = closing(code, brace, '{', '}')
        if end is not None:
            bodies.append((brace, end))
    return bodies


def innermost(bodies, offset):
    inside = [b for b in bodies if b[0] < offset < b[1]]
    return max(inside, default=None)


def enum_defaults(code, names):
    """(line, enumerator) for each default: in a switch over an enum."""
    bodies = switch_bodies(code)
    for default in DEFAULT.finditer(code):
        body = innermost(bodies, default.start())
        if body is None:
            continue
        for case in CASE.finditer(code, body[0], body[1]):
            label = case.group(1)
            if innermost(bodies, case.start()) != body:
                continue
            if label in names or label.startswith('WIRE_'):
                yield code.count('\n', 0, default.start()) + 1, label
                break


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'master'
    helper = os.path.join(os.path.dirname(sys.argv[0]), 'added-lines.sh')
    lines = subprocess.run([helper, base] + PATHSPECS,
                           check=True, stdout=subprocess.PIPE, text=True)
    added = {}
    for entry in lines.stdout.splitlines():
        path, line = entry.rsplit(':', 1)
        added.setdefault(path, set()).add(int(line))

    names = None
    failed = False
    for path in sorted(added):
        code = code_only(read(path))
        if not DEFAULT.search(code):
            continue
        if names is None:
            names = enumerators()
        for line, label in enum_defaults(code, names):
            if line in added[path]:
                print(f'{path}:{line}: default: in a switch over an enum ({label}, ...):'
                      ' list every case, so the compiler warns when one is added')
                failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
