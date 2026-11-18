#!/usr/bin/env python3
"""Flag added comments which are long, or which will go stale.

A comment describes the code beside it, to a reader who has never seen
any other version of the file.  What a change fixed, what the code used to
do, and which pull request or review asked for it belong in the commit
message: in a comment they are out of date as soon as the commit lands.
And a comment which needs many lines usually explains code which should be
simpler.

Only added lines are checked (see tools/added-lines.sh).  BOLT quotes are
left alone, and the /*~ walkthrough comments may be any length.
"""
import io
import os
import re
import subprocess
import sys
import tokenize

PATHSPECS = ['*.c', '*.h', '*.py', ':(exclude)ccan/',
             ':(exclude)*gen.c', ':(exclude)*gen.h',
             ':(exclude)*_pb2*.py', ':(exclude)*grpc2py.py']

# A comment at the left margin documents a function or a type; an indented
# one is in the middle of the code it explains.
MAX_LINES = 8
MAX_INDENTED_LINES = 4

STALE = [
    (re.compile(r'\b(the|this) fix\b|\bthis (commit|pr|patch|change)\b'
                r'|\b(previous|next|earlier|later|follow-?up) (commit|pr|patch)\b', re.I),
     'describes the change, not the code: put that in the commit message'),
    (re.compile(r'\bused to be\b|\b(we|it|they|there|this|that|which|\w+\(\)) used to\b'
                r'|\b(old|previous|former|original|earlier) (code|implementation|behaviou?r|logic)\b'
                r'|\brefactor(ed|ing)?\b|\brenamed (from|to)\b', re.I),
     'describes code which is gone: say what this code does, or what breaks without it'),
    (re.compile(r'github\.com/ElementsProject/lightning/(pull|issues)/\d+'
                r'|\b(pr|mr|pull request|issue)\s*[#!]?\d+\b'
                r'|(?<![\w&#])#\d{3,5}\b', re.I),
     'points at a pull request or issue: say here what the code needs said'),
    (re.compile(r'\breview(er)? (comments?|feedback)\b|\bper review\b'
                r'|\bas (requested|discussed)\b', re.I),
     'refers to a discussion which the reader cannot see'),
    (re.compile(r'\b[\w/.-]+\.(c|h|py|rs|sh|md|json|csv):\d+\b|\b(on|at) line \d+\b', re.I),
     'points at a line number, which moves with the next edit: name the function'),
]

# Comments, and the strings and character constants which could hold "//".
C_TOKEN = re.compile(r'''//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*' ''', re.S | re.X)


def c_comments(text):
    """(first line, lines, indented) of each comment; a run of // lines is one."""
    comments = []
    for token in C_TOKEN.finditer(text):
        body = token.group()
        if body[0] in '"\'':
            continue
        first = text.count('\n', 0, token.start()) + 1
        lines = body.split('\n')
        before = text[text.rfind('\n', 0, token.start()) + 1:token.start()]
        alone = not before.strip()
        prev = comments[-1] if comments else None
        if (body.startswith('//') and alone and prev and prev[3]
                and prev[0] + len(prev[1]) == first):
            prev[1].extend(lines)
            continue
        comments.append([first, lines, before != '', body.startswith('//') and alone])
    return [tuple(comment[:3]) for comment in comments]


def py_comments(text):
    """(first line, lines, indented) of each comment; a run of # lines is one."""
    comments = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return []
    for token in tokens:
        if token.type != tokenize.COMMENT or token.string.startswith('#!'):
            continue
        line = token.start[0]
        alone = not token.line[:token.start[1]].strip()
        prev = comments[-1] if comments else None
        if alone and prev and prev[3] and prev[0] + len(prev[1]) == line:
            prev[1].append(token.string)
            continue
        comments.append([line, [token.string], token.start[1] != 0, alone])
    return [tuple(comment[:3]) for comment in comments]


def problems(path, text, added):
    """(line, complaint) for each added comment line which breaks a rule."""
    comments = py_comments(text) if path.endswith('.py') else c_comments(text)
    for first, lines, indented in comments:
        whole = '\n'.join(lines)
        new = [line for line in range(first, first + len(lines)) if line in added]
        if not new or 'BOLT' in whole:
            continue
        limit = MAX_INDENTED_LINES if indented else MAX_LINES
        if len(lines) > limit and not whole.startswith('/*~'):
            where = 'inside code' if indented else 'at the left margin'
            yield new[0], (f'comment is {len(lines)} lines long (limit {limit} {where}):'
                           ' keep it short, and let simpler code say the rest')
        for line, content in enumerate(lines, first):
            if line not in added:
                continue
            for pattern, complaint in STALE:
                if pattern.search(content):
                    yield line, f'comment {complaint}'
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

    failed = False
    for path in sorted(added):
        with open(path, errors='replace') as f:
            text = f.read()
        for line, complaint in sorted(problems(path, text, added[path])):
            print(f'{path}:{line}: {complaint}')
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
