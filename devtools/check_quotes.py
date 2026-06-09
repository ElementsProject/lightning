#! /usr/bin/python3
import fileinput
import glob
import os
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
) -> Tuple[int, int, int]:
    """Search for text (with '...' wildcards) across boltsections.

    Returns (section_idx, start, end) of the match, or (-1, 0, 0) on failure.
    When a '...' part is not found in the current section we try subsequent
    sections, so quotes can explicitly span a section header using '*...'.
    For a cross-section match the start is credited as 0 in the final section.
    """
    textparts = text.split("...")
    for start_si, start_b in enumerate(boltsections):
        cur_si = start_si
        cur_section = start_b
        off = 0
        match_start = -1
        success = True
        for i, part in enumerate(textparts):
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
                        # Cross-section: credit coverage from start of this section.
                        match_start = 0
                        off = new_off + len(search_part)
                        found = True
                        break
                if not found:
                    success = False
                    break
            else:
                if i == 0 and match_start < 0:
                    match_start = new_off
                off = new_off + len(part)
        if success:
            return cur_si, (match_start if match_start >= 0 else 0), off
    return -1, 0, 0


def find_quote_immediate(
    text: str, section: str, start: int
) -> Tuple[int, int]:
    """Find text in section starting immediately at position start.

    Allows a single space separator (whitespace is already collapsed to single
    spaces). The text may still contain '...' wildcards for its own internal
    matching. Returns (match_start, end) or (-1, -1) on failure.
    """
    textparts = text.split("...")
    off = start
    # Allow for exactly one whitespace separator (already collapsed).
    # The quote text itself may also have a leading space (from the comment
    # continuation line joining), so strip both together.
    if off < len(section) and section[off] == " ":
        off += 1
    match_start = off
    first_part = textparts[0].lstrip(" ")
    if not section[off:].startswith(first_part):
        return -1, -1
    off += len(first_part)
    for part in textparts[1:]:
        new_off = section.find(part, off)
        if new_off == -1:
            return -1, -1
        off = new_off + len(part)
    return match_start, off


def write_coverage(filename: str, bolt: int, section_idx: int, start: int, end: int,
                   src_file: str, src_line: int) -> None:
    """Atomically append one coverage record to filename.

    Each record is a single line '{bolt} {si} {start} {end} {src_file} {src_line}\\n',
    written via a single os.write() call so parallel invocations don't
    interleave partial lines.
    """
    record = "{} {} {} {} {} {}\n".format(bolt, section_idx, start, end, src_file, src_line).encode()
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o666)
    try:
        os.write(fd, record)
    finally:
        os.close(fd)


def main(args: Namespace) -> None:
    boltquotes = gather_quotes(args)
    failed = False
    for bolt in boltquotes:
        boltsections = load_bolt(args.boltdir, bolt)
        last_section: Optional[str] = None
        last_section_idx: int = -1
        last_end: int = 0
        last_filename: Optional[str] = None
        for quote in boltquotes[bolt]:
            # Reset per-file tracking when the file changes.
            if quote.filename != last_filename:
                last_section = None
                last_section_idx = -1
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
                    sect, istart, end = None, -1, 0
                else:
                    text_after = quote.text[3:]
                    istart, end = find_quote_immediate(text_after, last_section, last_end)
                    if istart < 0:
                        sect = None
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
                        sect = last_section
                        if args.coverage:
                            write_coverage(args.coverage, bolt, last_section_idx, istart, end,
                                           quote.filename, quote.line)
            else:
                si, start, end = find_quote(quote.text, boltsections)
                sect = boltsections[si] if si >= 0 else None
                if sect is None:
                    print(
                        "{}:{}:cannot find match".format(quote.filename, quote.line),
                        file=sys.stderr,
                    )
                    # Reduce the text until we find a match.
                    for n in range(len(quote.text), -1, -1):
                        si2, _, end2 = find_quote(quote.text[:n], boltsections)
                        if si2 >= 0:
                            s2 = boltsections[si2]
                            print(
                                "  common prefix: {}...".format(quote.text[:n]),
                                file=sys.stderr,
                            )
                            print(
                                "  expected ...{:.45}".format(s2[end2:]), file=sys.stderr
                            )
                            print(
                                "  but have ...{:.45}".format(quote.text[n:]),
                                file=sys.stderr,
                            )
                            break
                    if not args.keep_going:
                        sys.exit(1)
                    failed = True
                else:
                    if args.coverage:
                        write_coverage(args.coverage, bolt, si, start, end,
                                       quote.filename, quote.line)
                    if args.verbose:
                        print(
                            "{}:{}:Matched {} in {}".format(
                                quote.filename, quote.line, quote.text, sect
                            )
                        )
                    last_section_idx = si

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
    parser.add_argument("--coverage", metavar="FILE",
                        help="Append coverage records to FILE (bolt section_idx start end)")
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
