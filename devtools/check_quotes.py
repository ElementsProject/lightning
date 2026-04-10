#! /usr/bin/python3
import fileinput
import glob
import re
import sys
from argparse import ArgumentParser, REMAINDER, Namespace
from collections import namedtuple
from typing import Dict, List, Tuple, Optional

Quote = namedtuple("Quote", ["filename", "line", "text"])
whitespace_re = re.compile(r"\s+")


def collapse_whitespace(string: str) -> str:
    return whitespace_re.sub(" ", string)


def add_quote(
    boltquotes: Dict[int, List[Quote]],
    boltnum: int,
    filename: str,
    line: int,
    quote: str,
) -> None:
    if boltnum not in boltquotes:
        boltquotes[boltnum] = []
    boltquotes[boltnum].append(
        Quote(filename, line, collapse_whitespace(quote.strip()))
    )


def included_commit(args: Namespace, boltprefix: str) -> bool:
    for inc in args.include_commit:
        if boltprefix.startswith(inc):
            return True
    return False


# This looks like a BOLT line; return the bolt number and start of
# quote if we shouldn't ignore it.
def get_boltstart(
    args: Namespace, line: str, filename: str, linenum: int
) -> Tuple[Optional[int], Optional[str]]:
    if not line.startswith(args.comment_start + "BOLT"):
        return None, None

    parts = line[len(args.comment_start + "BOLT"):].partition(":")
    boltnum = parts[0].strip()

    # e.g. BOLT-50143e388e16a449a92ed574fc16eb35b51426b9 #11:"
    if boltnum.startswith("-"):
        if not included_commit(args, boltnum[1:]):
            return None, None
        boltnum = boltnum.partition(" ")[2]

    if not boltnum.startswith("#"):
        print(
            "{}:{}:expected # after BOLT in {}".format(filename, linenum, line),
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        boltint = int(boltnum[1:].strip())
    except ValueError:
        print(
            "{}:{}:bad bolt number {}".format(filename, linenum, line), file=sys.stderr
        )
        sys.exit(1)

    return boltint, parts[2]


# We expect lines to start with '# BOLT #NN:'
def gather_quotes(args: Namespace) -> Dict[int, List[Quote]]:
    boltquotes: Dict[int, List[Quote]] = {}
    curquote = None
    # These initializations simply keep flake8 happy
    curbolt = 0
    filestart = ""
    linestart = 0
    for file_line in fileinput.input(args.files):
        line = file_line.strip()
        boltnum, quote = get_boltstart(
            args, line, fileinput.filename(), fileinput.filelineno()
        )
        if boltnum is not None:
            if curquote is not None:
                add_quote(boltquotes, curbolt, filestart, linestart, curquote)

            linestart = fileinput.filelineno()
            filestart = fileinput.filename()
            curbolt = boltnum
            curquote = quote
            # Handle single-line comment: /* BOLT #N: text */
            if args.comment_end is not None:
                stripped = curquote.rstrip()
                if stripped.endswith(args.comment_end):
                    curquote = stripped[: -len(args.comment_end)]
                    add_quote(boltquotes, curbolt, filestart, linestart, curquote)
                    curquote = None
        elif curquote is not None:
            # If this is a continuation (and not an end!), add it.
            if (
                args.comment_end is None or not line.startswith(args.comment_end)
            ) and line.startswith(args.comment_continue):
                # Special case where end marker is on same line.
                if args.comment_end is not None and line.endswith(args.comment_end):
                    curquote += (
                        " " + line[len(args.comment_continue):-len(args.comment_end)]
                    )
                    add_quote(boltquotes, curbolt, filestart, linestart, curquote)
                    curquote = None
                else:
                    curquote += " " + line[len(args.comment_continue):]
            else:
                add_quote(boltquotes, curbolt, filestart, linestart, curquote)
                curquote = None

    # Handle quote at eof.
    if curquote is not None:
        add_quote(boltquotes, curbolt, filestart, linestart, curquote)

    return boltquotes


def load_bolt(boltdir: str, num: int) -> List[str]:
    """Return a list, divided into one-string-per-bolt-section, with
    whitespace collapsed into single spaces.

    """
    boltfile = glob.glob("{}/{}-*md".format(boltdir, str(num).zfill(2)))
    if len(boltfile) == 0:
        print("Cannot find bolt {} in {}".format(num, boltdir), file=sys.stderr)
        sys.exit(1)
    elif len(boltfile) > 1:
        print(
            "More than one bolt {} in {}? {}".format(num, boltdir, boltfile),
            file=sys.stderr,
        )
        sys.exit(1)

    # We divide it into sections, and collapse whitespace.
    boltsections = []
    with open(boltfile[0]) as f:
        sect = ""
        for line in f.readlines():
            if line.startswith("#"):
                # Append with whitespace collapsed.
                boltsections.append(collapse_whitespace(sect))
                sect = ""
            sect += line
        boltsections.append(collapse_whitespace(sect))

    return boltsections


def find_quote(
    text: str, boltsections: List[str]
) -> Tuple[Optional[str], Optional[int]]:
    # '...' means "match anything, but prefer within a single section".
    # When a part is not found in the current section, we try subsequent
    # sections so that quotes can explicitly span a section header.
    textparts = text.split("...")
    for start_si, start_b in enumerate(boltsections):
        cur_si = start_si
        cur_section = start_b
        off = 0
        success = True
        for part in textparts:
            new_off = cur_section.find(part, off)
            if new_off == -1:
                # Try subsequent sections; strip leading whitespace since we're
                # starting fresh at position 0 after a section boundary.
                found = False
                search_part = part.lstrip()
                for next_si in range(cur_si + 1, len(boltsections)):
                    new_off = boltsections[next_si].find(search_part, 0)
                    if new_off != -1:
                        cur_si = next_si
                        cur_section = boltsections[next_si]
                        off = new_off + len(search_part)
                        found = True
                        break
                if not found:
                    success = False
                    break
            else:
                off = new_off + len(part)
        if success:
            return cur_section, off
    return None, None


def find_quote_immediate(
    text: str, section: str, start: int
) -> Tuple[Optional[str], Optional[int]]:
    """Find text in section starting immediately at position start.
    Allows a single space separator (whitespace is already collapsed to single spaces).
    The text may still contain '...' wildcards for its own internal matching.
    """
    textparts = text.split("...")
    off = start
    # Allow for exactly one whitespace separator (already collapsed)
    if off < len(section) and section[off] == " ":
        off += 1
    first_part = textparts[0]
    if not section[off:].startswith(first_part):
        return None, None
    off += len(first_part)
    for part in textparts[1:]:
        new_off = section.find(part, off)
        if new_off == -1:
            return None, None
        off = new_off + len(part)
    return section, off


def main(args: Namespace) -> None:
    boltquotes = gather_quotes(args)
    failed = False
    for bolt in boltquotes:
        boltsections = load_bolt(args.boltdir, bolt)
        last_section: Optional[str] = None
        last_end: int = 0
        last_filename: Optional[str] = None
        for quote in boltquotes[bolt]:
            # Reset per-file tracking when the file changes.
            if quote.filename != last_filename:
                last_section = None
                last_end = 0
                last_filename = quote.filename

            if quote.text.startswith("..."):
                # Leading '...' means this quote must immediately follow the
                # previous quote (in this file) in the BOLT text.
                if last_section is None:
                    print(
                        "{}:{}:'...' at start of quote but no previous BOLT #{} quote in this file".format(
                            quote.filename, quote.line, bolt
                        ),
                        file=sys.stderr,
                    )
                    if not args.keep_going:
                        sys.exit(1)
                    failed = True
                    sect, end = None, None
                else:
                    text_after = quote.text[3:]
                    sect, end = find_quote_immediate(text_after, last_section, last_end)
                    if sect is None:
                        print(
                            "{}:{}:cannot find match (must immediately follow previous quote)".format(
                                quote.filename, quote.line
                            ),
                            file=sys.stderr,
                        )
                        print(
                            "  previous quote ended at: ...{:.45}".format(
                                last_section[last_end:]
                            ),
                            file=sys.stderr,
                        )
                        print(
                            "  but quote expects: {:.45}".format(text_after),
                            file=sys.stderr,
                        )
                        if not args.keep_going:
                            sys.exit(1)
                        failed = True
            else:
                sect, end = find_quote(quote.text, boltsections)
                if sect is None:
                    print(
                        "{}:{}:cannot find match".format(quote.filename, quote.line),
                        file=sys.stderr,
                    )
                    # Reduce the text until we find a match.
                    for n in range(len(quote.text), -1, -1):
                        sect, end = find_quote(quote.text[:n], boltsections)
                        if sect:
                            print(
                                "  common prefix: {}...".format(quote.text[:n]),
                                file=sys.stderr,
                            )
                            print(
                                "  expected ...{:.45}".format(sect[end:]), file=sys.stderr
                            )
                            print(
                                "  but have ...{:.45}".format(quote.text[n:]),
                                file=sys.stderr,
                            )
                            break
                    if not args.keep_going:
                        sys.exit(1)
                    failed = True
                elif args.verbose:
                    print(
                        "{}:{}:Matched {} in {}".format(
                            quote.filename, quote.line, quote.text, sect
                        )
                    )

            if sect is not None:
                last_section = sect
                last_end = end

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Check BOLT quotes in the given files are correct"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-k", "--keep-going", action="store_true",
                        help="Report all errors instead of stopping at first")
    # e.g. for C code these are '/* ', '*' and '*/'
    parser.add_argument(
        "--comment-start", help='marker for start of "BOLT #N" quote', default="# "
    )
    parser.add_argument(
        "--comment-continue", help='marker for continued "BOLT #N" quote', default="#"
    )
    parser.add_argument("--comment-end", help='marker for end of "BOLT #N" quote')
    parser.add_argument(
        "--include-commit",
        action="append",
        help="Also parse BOLT-<commit> quotes",
        default=[],
    )
    parser.add_argument(
        "--boltdir", help="Directory to look for BOLT tests", default="../lightning-rfc"
    )
    parser.add_argument("files", help="Files to read in (or stdin)", nargs=REMAINDER)

    args = parser.parse_args()
    main(args)
