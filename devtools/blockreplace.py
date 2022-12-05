#!/usr/bin/env python3

# A rather simple script to replace a block of text, delimited by
# markers, with new contents from stdin. Importantly the markers are
# left in the file so future runs can update the file without
# requiring a separate template. The markers are currently for
# reStructuredText only, but more can be added.

from enum import Enum
import argparse
import os
import sys
import textwrap


class Language(str, Enum):
    md = 'md'
    rst = 'rst'
    c = 'c'


comment_style = {
    Language.md: (
        "<!-- block_start {blockname} -->",
        "<!-- block_end {blockname} -->",
    ),
    Language.rst: (
        ".. block_start {blockname}",
        ".. block_end {blockname}",
    ),
    Language.c: (
        "/* block_start {blockname} */",
        "/* block_end {blockname} */",
    ),
}


def replace(filename, blockname, language, content):
    start, stop = comment_style[language]

    tempfile = f"{filename}.tmp"

    with open(filename, 'r') as i, open(tempfile, 'w') as o:
        lines = i.readlines()
        # Read lines up to the marker
        while lines != []:
            l = lines.pop(0)
            o.write(l)
            if l.strip() == start.format(blockname=blockname):
                break

        o.write(content)

        # Skip lines until we get the end marker
        while lines != []:
            l = lines.pop(0)
            if l.strip() == stop.format(blockname=blockname):
                o.write(l)
                break

        # Now flush the rest of the file
        for l in lines:
            o.write(l)

    # Move the temp file over the old one for an atomic replacement
    os.rename(tempfile, filename)


def main(args):
    parser = argparse.ArgumentParser(
        prog='blockreplace'
    )
    parser.add_argument('filename')
    parser.add_argument('blockname')
    parser.add_argument('--language', type=Language)
    parser.add_argument('--indent', dest="indent", default="")
    args = parser.parse_args()
    content = sys.stdin.read()
    content = textwrap.indent(content, args.indent)

    replace(args.filename, args.blockname, args.language, content)


if __name__ == "__main__":
    main(sys.argv)
