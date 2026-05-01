#!/usr/bin/env python3
"""Report BOLT text (by default, Requirements sections) not quoted by any source comment.

Coverage data is produced by check_quotes.py --coverage=FILE; this tool reads
that file and highlights text that no comment quotes, showing adjacent quoted
text for context.

Output is in compiler-error format so Emacs/Vim can navigate directly:
    src/foo.c:13:...text covered just before the gap...
    .tmp.lightningrfc/02-peer-protocol.md:5:uncovered text here
    src/bar.c:99:text covered just after the gap...

Usage example:
    make check-requirements-coverage
"""

import glob
import re
import sys
from argparse import ArgumentParser
from collections import defaultdict
from typing import Dict, List, Tuple

whitespace_re = re.compile(r"\s+")


def collapse_whitespace(string: str) -> str:
    return whitespace_re.sub(" ", string)


def collapse_with_linemap(raw_lines: List[Tuple[int, str]]) -> Tuple[str, List[int]]:
    """Collapse whitespace across a list of (lineno, text) pairs.

    Returns (collapsed_text, linemap) where linemap[i] is the original line
    number for character i in collapsed_text.  Matches the behaviour of
    collapse_whitespace() so positions are compatible with coverage records.
    """
    result: List[str] = []
    linemap: List[int] = []
    in_ws = False
    ws_lineno = 1

    for lineno, line in raw_lines:
        for ch in line:
            if whitespace_re.match(ch):
                if not in_ws:
                    in_ws = True
                    ws_lineno = lineno
            else:
                if in_ws:
                    result.append(" ")
                    linemap.append(ws_lineno)
                    in_ws = False
                result.append(ch)
                linemap.append(lineno)

    if in_ws:
        result.append(" ")
        linemap.append(ws_lineno)

    return "".join(result), linemap


def load_bolt(boltdir: str, num: int) -> Tuple[str, List[Tuple[str, List[int]]]]:
    """Load a BOLT file, split into sections.

    Returns (boltpath, sections) where sections is a list of
    (collapsed_text, linemap) pairs; linemap[i] is the original line number
    for collapsed_text[i].
    """
    boltfile = glob.glob("{}/{}-*md".format(boltdir, str(num).zfill(2)))
    if not boltfile:
        print("Cannot find bolt {} in {}".format(num, boltdir), file=sys.stderr)
        sys.exit(1)
    if len(boltfile) > 1:
        print("More than one bolt {} in {}? {}".format(num, boltdir, boltfile),
              file=sys.stderr)
        sys.exit(1)

    boltpath = boltfile[0]
    with open(boltpath) as f:
        raw = list(enumerate(f.readlines(), 1))  # [(lineno, line), ...]

    # Split into sections on lines that start with '#'.
    raw_sections: List[List[Tuple[int, str]]] = []
    cur: List[Tuple[int, str]] = []
    for lineno, line in raw:
        if line.startswith("#"):
            raw_sections.append(cur)
            cur = []
        cur.append((lineno, line))
    raw_sections.append(cur)

    sections = [collapse_with_linemap(s) for s in raw_sections]
    return boltpath, sections


def is_requirements_section(text: str) -> bool:
    """True if the section's header names a Requirements section."""
    return bool(re.match(r"#+\s+requirements\b", text.lstrip(), re.IGNORECASE))


# Coverage record: (section_idx, start, end, src_file, src_line)
CovRecord = Tuple[int, int, int, str, int]


def load_coverage(coverage_file: str) -> Dict[int, List[CovRecord]]:
    """Return {bolt: [CovRecord, ...]} from the coverage file."""
    coverage: Dict[int, List[CovRecord]] = defaultdict(list)
    try:
        with open(coverage_file) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 6:
                    print("{}:{}: bad coverage record (expected 6 fields): {!r}".format(
                        coverage_file, lineno, line), file=sys.stderr)
                    continue
                bolt = int(parts[0])
                si, start, end, src_line = int(parts[1]), int(parts[2]), int(parts[3]), int(parts[5])
                src_file = parts[4]
                coverage[bolt].append((si, start, end, src_file, src_line))
    except FileNotFoundError:
        print("Coverage file not found: {}".format(coverage_file), file=sys.stderr)
        sys.exit(1)
    return coverage


def merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping/adjacent [start, end) intervals."""
    merged: List[List[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def section_content_start(text: str) -> int:
    """Offset past the leading '### SectionTitle ' header."""
    m = re.match(r"(#+\s+\S+\s+)", text.lstrip())
    return m.end() if m else 0


def adjacent_before(records: List[CovRecord], gap_start: int) -> List[CovRecord]:
    """All records whose covered range ends closest to (but not after) gap_start."""
    candidates = [r for r in records if r[2] <= gap_start]
    if not candidates:
        return []
    max_end = max(r[2] for r in candidates)
    return [r for r in candidates if r[2] == max_end]


def adjacent_after(records: List[CovRecord], gap_end: int) -> List[CovRecord]:
    """All records whose covered range starts closest to (but not before) gap_end."""
    candidates = [r for r in records if r[1] >= gap_end]
    if not candidates:
        return []
    min_start = min(r[1] for r in candidates)
    return [r for r in candidates if r[1] == min_start]


def snippet(text: str, start: int, end: int, tail: bool = False, maxlen: int = 60) -> str:
    """Return a short excerpt of text[start:end], from the tail or head."""
    s = text[start:end].strip()
    if tail:
        return ("..." + s[-maxlen:]) if len(s) > maxlen else ("..." + s)
    return (s[:maxlen] + "...") if len(s) > maxlen else (s + "...")


def show_gaps(boltpath: str, bolt_num: int, si: int,
              text: str, linemap: List[int],
              section_records: List[CovRecord]) -> bool:
    """Print uncovered gaps in text with adjacent-mention context.

    Returns True if any uncovered text was found.
    """
    content_start = section_content_start(text)

    # Build merged intervals to find gaps, but keep raw records for adjacency.
    merged = merge_intervals([(r[1], r[2]) for r in section_records])

    # Walk the merged intervals and find gaps.
    any_gap = False
    pos = content_start
    for m_start, m_end in merged:
        if m_start > pos:
            gap_text = text[pos:m_start].strip()
            if not gap_text:
                pos = max(pos, m_end)
                continue

            any_gap = True
            bolt_lineno = linemap[pos] if pos < len(linemap) else 1

            before = adjacent_before(section_records, pos)
            after = adjacent_after(section_records, m_start)

            for r in before:
                print("{}:{}:{}".format(r[3], r[4], snippet(text, r[1], r[2], tail=True)))
            print("{}:{}:{}".format(boltpath, bolt_lineno, gap_text[:120]))
            for r in after:
                print("{}:{}:{}".format(r[3], r[4], snippet(text, r[1], r[2], tail=False)))

        pos = max(pos, m_end)

    # Tail gap after last interval.
    if pos < len(text):
        gap_text = text[pos:].strip()
        if gap_text:
            any_gap = True
            bolt_lineno = linemap[pos] if pos < len(linemap) else 1
            before = adjacent_before(section_records, pos)

            for r in before:
                print("{}:{}:{}".format(r[3], r[4], snippet(text, r[1], r[2], tail=True)))
            print("{}:{}:{}".format(boltpath, bolt_lineno, gap_text[:120]))

    return any_gap


def main() -> None:
    parser = ArgumentParser(
        description="Show BOLT text not covered by any source code comment"
    )
    parser.add_argument(
        "--boltdir", default="../lightning-rfc",
        help="Directory containing BOLT spec files (default: ../lightning-rfc)"
    )
    parser.add_argument(
        "--coverage", required=True, metavar="FILE",
        help="Coverage file produced by check_quotes.py --coverage=FILE"
    )
    parser.add_argument(
        "--bolt", type=int, action="append", dest="bolts", metavar="N",
        help="Restrict to BOLT #N (may be repeated; default: all bolts in coverage file)"
    )
    parser.add_argument(
        "--all-sections", action="store_true",
        help="Check all sections, not just Requirements sections"
    )
    args = parser.parse_args()

    coverage = load_coverage(args.coverage)
    bolts_to_check = sorted(args.bolts if args.bolts else coverage.keys())

    any_uncovered = False
    for bolt_num in bolts_to_check:
        try:
            boltpath, sections = load_bolt(args.boltdir, bolt_num)
        except SystemExit:
            continue

        # Group records by section index.
        by_section: Dict[int, List[CovRecord]] = defaultdict(list)
        for rec in coverage.get(bolt_num, []):
            si = rec[0]
            if 0 <= si < len(sections):
                by_section[si].append(rec)

        for si, (text, linemap) in enumerate(sections):
            if not text.strip():
                continue
            if not args.all_sections and not is_requirements_section(text):
                continue

            records = by_section.get(si, [])
            if show_gaps(boltpath, bolt_num, si, text, linemap, records):
                any_uncovered = True

    sys.exit(1 if any_uncovered else 0)


if __name__ == "__main__":
    main()
