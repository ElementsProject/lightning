#!/usr/bin/env python3
"""Flag commit messages in BASE..HEAD which are hard to read, or go stale.

Once a commit lands, its message is all that explains it.  The pull request
and its review are not part of the history, and the commit before it is
not the same one after a rebase or a cherry-pick.  So the message has to
stand on its own, as plain wrapped text in paragraphs short enough to
follow.

Indented lines are quoted output, not prose, so logs and backtraces can be
any width and length.  Links and trailers are left alone too.
"""
import re
import subprocess
import sys

MAX_COLUMNS = 80
MAX_PARAGRAPH = 10

TRAILER = re.compile(r'(Changelog-[A-Za-z]+|Signed-off-by|Co-authored-by|Fixes|Closes'
                     r'|Reported-by|Suggested-by|Reviewed-by|Tested-by|Acked-by'
                     r'|Assisted-by|Cc|Link)\s*:|Changelog-None|\(cherry picked from', re.I)
HEADER = re.compile(r'#{1,6} \S')
UNSEEN = re.compile(r'\bthis (pr|mr|pull request)\b|\breview(er)? (comments?|feedback)\b'
                    r'|\bper review\b|\bas (requested|discussed)\b', re.I)
BY_POSITION = re.compile(r'\b(previous|last|earlier|prior|preceding|parent) (commit|patch)(es|s)?\b', re.I)


def is_prose(line):
    return bool(line.strip()
                and not line.startswith(('  ', '\t', '>'))
                and not TRAILER.match(line))


def problems(message):
    lines = message.rstrip('\n').split('\n')
    if len(lines) > 1 and lines[1].strip():
        yield 'needs a blank line after the subject'

    paragraph = longest = 0
    wide = header = unseen = by_position = False
    for line in lines[1:]:
        if not is_prose(line):
            paragraph = 0
            continue
        paragraph += 1
        longest = max(longest, paragraph)
        if len(line) > MAX_COLUMNS and '://' not in line and ' ' in line.strip():
            wide = True
        header = header or bool(HEADER.match(line))
        unseen = unseen or bool(UNSEEN.search(line))
        by_position = by_position or bool(BY_POSITION.search(line))

    if wide:
        yield (f'has text wider than {MAX_COLUMNS} columns:'
               ' wrap what you wrote, and indent any output you quote')
    if longest > MAX_PARAGRAPH:
        yield (f'has a paragraph of {longest} lines (limit {MAX_PARAGRAPH}):'
               ' break it up, and indent any output you quote')
    if header:
        yield 'has markdown headers: commit messages are plain text'
    if unseen:
        yield 'refers to a pull request or review which the reader cannot see'
    if by_position:
        yield ('refers to an earlier commit by its position:'
               ' say what the code does now, so this commit stands on its own')


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else 'master'
    log = subprocess.run(['git', 'log', '--reverse', '--no-merges',
                          '--format=%x01%h %s%x00%B', f'{base}..HEAD'],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if log.returncode != 0:
        print(f"check-commit-msgs: no commits found from '{base}', so none are checked",
              file=sys.stderr)
        sys.exit(0)

    failed = False
    for commit in log.stdout.split('\x01')[1:]:
        name, message = commit.split('\x00')
        for problem in problems(message):
            print(f'{name}: message {problem}')
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
