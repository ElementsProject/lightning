#!/usr/bin/env python3
"""Flag an added function which nothing calls.

Unused code is buggy code: nothing runs it, so nothing shows that it
works.  The compiler says so for a static function; this is the same check
for one which is not static.

Only functions defined on added lines are checked (see
tools/added-lines.sh).  A caller in a unit test counts.  towire_ and
fromwire_ functions are left alone: generated code calls them, and it is
not tracked.

A commit in the middle of a branch may add a function for a later commit
to call.  tools/check-commits.sh sets CHECK_COMMITS_TIP to the last commit
of the branch, and callers are then looked for there.
"""
import os
import re
import subprocess
import sys

PATHSPECS = ['*.c', ':(exclude)ccan/', ':(exclude)contrib/', ':(exclude)external/',
             ':(exclude)tests/', ':(exclude)*/test/*']

# Comments, strings and character constants: none of them hold code.
NOT_CODE = re.compile(r'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*' ''', re.S | re.X)
# A return type and a name at the left margin: a definition or a prototype.
# The name may be on the next line, as it often is for pointer returns.
DECLARATION = re.compile(r'^(?!static\b)(?:\w+[ \t*]+)+(?:\n)?(\w+)\(', re.M)
BODY_OR_END = re.compile(r'[{;]')
GENERATED_CALLERS = ('towire_', 'fromwire_', 'printwire_')


def code_only(text):
    """Blank out whatever is not code, keeping every line where it was."""
    return NOT_CODE.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), text)


def definitions(code):
    """(line, name) of each function which is defined and not static."""
    for declaration in DECLARATION.finditer(code):
        body = BODY_OR_END.search(code, declaration.end())
        if body and body.group() == '{':
            yield code.count('\n', 0, declaration.start(1)) + 1, declaration.group(1)


def is_use(line, name):
    """Does this line of code name the function, other than to declare it?"""
    if not re.search(rf'\b{name}\b', line):
        return False
    if re.match(rf'\s*(?!return\b)[\w*][\w\s*]*\b{name}\(', line):
        return False
    # A pointer-returning definition may put the name at the left margin,
    # with its return type on the line before.
    return not re.match(rf'{name}\(', line)


def used(names):
    """Those of the names which some tracked C file uses."""
    tip = os.environ.get('CHECK_COMMITS_TIP')
    command = ['git', 'grep', '-h', '-w', '-I']
    for name in names:
        command += ['-e', name]
    # Files which git does not know yet are part of the working tree too.
    grep = subprocess.run(command + ([tip] if tip else ['--untracked']) + ['--', '*.c', '*.h'],
                          stdout=subprocess.PIPE, text=True, errors='replace')
    found = set()
    for line in grep.stdout.splitlines():
        # A block comment which this line only starts, or is in the middle of.
        line = re.sub(r'/\*.*', '', code_only(line))
        if line.lstrip().startswith('*'):
            continue
        found.update(name for name in names if is_use(line, name))
    return found


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'master'
    helper = os.path.join(os.path.dirname(sys.argv[0]), 'added-lines.sh')
    lines = subprocess.run([helper, base] + PATHSPECS,
                           check=True, stdout=subprocess.PIPE, text=True)
    added = {}
    for entry in lines.stdout.splitlines():
        path, line = entry.rsplit(':', 1)
        added.setdefault(path, set()).add(int(line))

    new = {}
    for path in sorted(added):
        with open(path, errors='replace') as f:
            code = code_only(f.read())
        for line, name in definitions(code):
            if (line in added[path] and name != 'main'
                    and not name.startswith(GENERATED_CALLERS)):
                new.setdefault(name, []).append((path, line))
    if not new:
        sys.exit(0)

    unused = sorted((path, line, name)
                    for name in set(new) - used(set(new))
                    for path, line in new[name])
    for path, line, name in unused:
        print(f'{path}:{line}: {name}() has no caller:'
              ' unused code is buggy code, so leave it out until something needs it')
    sys.exit(1 if unused else 0)


if __name__ == '__main__':
    main()
