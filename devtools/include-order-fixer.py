#!/usr/bin/env python3
"""
Fix include directive ordering in C source and header files.

This script analyzes Core Lightning C source and header files, ensuring
include directives are sorted according to the Coding Style Guidelines.

Includes ending in "_gen.h" or with any leading whitespace are preserved
in their original positions. Comments and blank lines are also preserved.
Includes found more than once are de-duplicated.
"""

import locale
import os
import re
import subprocess
import sys
import tempfile

# Set C locale for sorting to match Makefile behavior
locale.setlocale(locale.LC_ALL, "C")


def parse_makefile_output(output):
    """Parse Makefile output, handling the 'Building version' line."""
    lines = output.splitlines()
    # Skip "Building version" line if present
    if lines and lines[0].startswith("Building version"):
        if len(lines) > 1:
            file_list = lines[1]
        else:
            file_list = ""
    else:
        file_list = lines[0] if lines else ""

    # Split by spaces and filter out empty strings
    files = [f for f in file_list.split() if f]
    return files


def get_files_to_check():
    """Get lists of C source and header files from Makefile targets."""
    # Get C source files
    result = subprocess.run(
        ["make", "print-src-to-check"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    if result.returncode != 0:
        print(
            f"Error running 'make print-src-to-check': {result.stderr}", file=sys.stderr
        )
        sys.exit(1)

    src_files = parse_makefile_output(result.stdout)

    # Get header files
    result = subprocess.run(
        ["make", "print-hdr-to-check"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    if result.returncode != 0:
        print(
            f"Error running 'make print-hdr-to-check': {result.stderr}", file=sys.stderr
        )
        sys.exit(1)

    hdr_files = parse_makefile_output(result.stdout)

    # Return files with their types
    files_with_types = []
    for f in src_files:
        files_with_types.append((f, "c"))
    for f in hdr_files:
        files_with_types.append((f, "h"))

    return files_with_types


def extract_includes(content):
    """
    Extract include directives from file content, preserving comments and whitespace.

    Returns:
        tuple: (main_items, trailing_items, include_start_line, blank_line_index, include_end_line)
        main_items: List of (type, line) tuples in main block where type is 'include', 'comment', or 'blank'
        trailing_items: List of (type, line) tuples after blank line (to be preserved)
        include_start_line: Line number where includes start (0-indexed)
        blank_line_index: Line number of blank line separator (None if no blank line)
        include_end_line: Line number after last include (0-indexed)
    """
    lines = content.splitlines(keepends=True)
    main_items = []
    trailing_items = []
    include_start = None
    include_end = None
    blank_line_index = None
    in_trailing_block = False

    # Pattern to match include directives (with optional leading whitespace)
    include_pattern = re.compile(r'^\s*#include\s+[<"].*[>"]\s*$')
    # Pattern to match comments (single-line or start of multi-line)
    comment_pattern = re.compile(r'^\s*/\*|^\s*//')
    # Pattern to match continuation lines of multi-line comments
    comment_continuation_pattern = re.compile(r'^\s*\*|.*\*/')

    in_multiline_comment = False

    for i, line in enumerate(lines):
        # Check if this line is an include
        if include_pattern.match(line):
            in_multiline_comment = False
            if include_start is None:
                include_start = i
            # Preserve the line as-is (including leading whitespace)
            if in_trailing_block:
                trailing_items.append(('include', line))
            else:
                main_items.append(('include', line))
            include_end = i + 1
        elif include_start is not None:
            # We've seen includes, but this line is not an include
            if line.strip():
                # Check if it's a comment start or continuation
                if comment_pattern.match(line):
                    # Start of a comment
                    in_multiline_comment = True
                    # Check if it's a single-line comment (ends with */)
                    if '*/' in line:
                        in_multiline_comment = False
                    # Preserve comments
                    if in_trailing_block:
                        trailing_items.append(('comment', line))
                    else:
                        main_items.append(('comment', line))
                    include_end = i + 1
                elif in_multiline_comment and comment_continuation_pattern.match(line):
                    # Continuation of multi-line comment
                    if in_trailing_block:
                        trailing_items.append(('comment', line))
                    else:
                        main_items.append(('comment', line))
                    include_end = i + 1
                    # Check if this line ends the comment
                    if '*/' in line:
                        in_multiline_comment = False
                else:
                    # Non-blank, non-include, non-comment line - stop here
                    in_multiline_comment = False
                    break
            else:
                # Blank line
                # Only treat as separator if we haven't seen one yet
                # and we'll continue to look for trailing includes
                if blank_line_index is None:
                    blank_line_index = i
                    in_trailing_block = True
                    # Add this separator blank line to trailing_items
                    trailing_items.append(('blank', line))
                    include_end = i + 1
                elif in_trailing_block:
                    # We're in trailing block, preserve blank lines here
                    trailing_items.append(('blank', line))
                    include_end = i + 1
                else:
                    # Blank line in main block (before separator) - preserve it
                    main_items.append(('blank', line))
                    include_end = i + 1
        # If we haven't started collecting includes yet, continue

    if include_start is None:
        # No includes found
        return [], [], None, None, None

    # If we marked a blank line as separator but found no trailing includes,
    # those blank lines should not be treated as trailing - they're just
    # normal blank lines after the includes that should remain in after_lines
    if blank_line_index is not None:
        # Check if we actually have trailing includes (not just blank lines/comments)
        has_trailing_includes = any(item_type == 'include' for item_type, _ in trailing_items)
        if not has_trailing_includes:
            # No trailing includes found, so blank lines aren't a separator
            # Reset to treat them as normal file content
            blank_line_index = None
            trailing_items = []
            # Recalculate include_end to point to the last include/comment in main_items
            # Count how many lines we've processed in main_items
            include_end = include_start + len(main_items)

    return (
        main_items,
        trailing_items,
        include_start,
        blank_line_index,
        include_end,
    )


def sort_includes(items, file_type):
    """
    Sort includes according to Core Lightning rules.

    For .c files: all includes in alphabetical order
    For .h files: config.h first (if present), then others alphabetically

    Includes ending in "_gen.h" or with any leading whitespace are preserved
    in their original positions. Comments and blank lines are also preserved.
    """
    if not items:
        return items

    # Track includes that should be preserved at their positions
    preserved_positions = {}  # position -> (type, line)
    regular_includes = []  # list of (position, include_line) tuples to sort

    for pos, (item_type, line) in enumerate(items):
        if item_type != 'include':
            # Preserve comments and blank lines at their positions
            preserved_positions[pos] = (item_type, line)
        else:
            # Check if this include should be preserved
            # (has any leading whitespace, or ends in "_gen.h")
            stripped = line.lstrip()
            has_leading_whitespace = line != stripped
            is_gen_h = '_gen.h"' in line or "_gen.h>" in line

            if has_leading_whitespace or is_gen_h:
                # Preserve at original position
                preserved_positions[pos] = (item_type, line)
            else:
                # Regular include to be sorted
                regular_includes.append((pos, line))

    # Separate config.h from other regular includes for header files
    config_h_pos = None
    config_h_include = None
    other_regular = []

    for pos, inc in regular_includes:
        if file_type == "h" and '"config.h"' in inc:
            config_h_pos = pos
            config_h_include = inc
        else:
            other_regular.append((pos, inc))

    # Sort other regular includes using C locale (by the include content, not position)
    other_regular_sorted = sorted(other_regular, key=lambda x: locale.strxfrm(x[1]))

    # Build sorted list of regular includes
    sorted_regular = []
    if config_h_include:
        sorted_regular.append((config_h_pos, config_h_include))
    sorted_regular.extend(other_regular_sorted)

    # Build result: preserved items at original positions, sorted regular includes elsewhere
    result = []
    regular_idx = 0

    for pos in range(len(items)):
        if pos in preserved_positions:
            # Use preserved item at its original position
            result.append(preserved_positions[pos])
        else:
            # Use next sorted regular include
            if regular_idx < len(sorted_regular):
                _, sorted_inc = sorted_regular[regular_idx]
                result.append(('include', sorted_inc))
                regular_idx += 1

    return result


def dedupe_include_items(items, seen):
    """Remove duplicate include lines, keeping the first occurrence.

    Duplicate detection uses a canonical form of include lines (`lstrip()`),
    so leading whitespace differences do not prevent matching.
    Non-include items (comments/blanks) are always preserved.
    """
    deduped = []
    for item_type, line in items:
        if item_type != "include":
            deduped.append((item_type, line))
            continue

        key = line.lstrip()
        if key in seen:
            continue
        seen.add(key)
        deduped.append((item_type, line))
    return deduped


def fix_file_includes(filepath, file_type):
    """
    Fix include ordering in a file.

    Returns:
        bool: True if file was modified, False otherwise
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except IOError as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return False

    # Extract includes
    main_items, trailing_items, include_start, blank_line_index, include_end = extract_includes(
        content
    )

    if include_start is None:
        # No includes to sort
        return False

    # Sort only the main includes block (preserving comments, blanks, and whitespace-prefixed includes)
    sorted_main_items = sort_includes(main_items, file_type)

    # De-duplicate includes across main and trailing blocks, preserving the first occurrence
    seen_includes = set()
    sorted_main_items = dedupe_include_items(sorted_main_items, seen_includes)
    trailing_items = dedupe_include_items(trailing_items, seen_includes)

    # Reconstruct file content
    lines = content.splitlines(keepends=True)
    before_lines = lines[:include_start] if include_start > 0 else []
    after_lines = lines[include_end:] if include_end < len(lines) else []

    # Build the include section: main sorted items + trailing items
    # Note: blank lines are already included in main_items/trailing_items, and
    # blank_line_index is just a marker, so we don't need to add it separately
    include_section = "".join(line for _, line in sorted_main_items)
    if trailing_items:
        # Add trailing items (blank line separator is already in trailing_items if present)
        include_section += "".join(line for _, line in trailing_items)

    # Combine: before + include section + after
    new_content = "".join(before_lines) + include_section + "".join(after_lines)

    # Check if content actually changed
    if new_content == content:
        return False

    # Write back atomically using temp file
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=os.path.dirname(filepath),
            delete=False,
            suffix=".tmp",
        ) as tmp:
            tmp.write(new_content)
            tmp_path = tmp.name

        # Atomic rename
        os.replace(tmp_path, filepath)
        return True
    except IOError as e:
        print(f"Error writing {filepath}: {e}", file=sys.stderr)
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return False


def main():
    """Main entry point."""
    files_with_types = get_files_to_check()

    modified_files = []

    for filepath, file_type in files_with_types:
        if not os.path.exists(filepath):
            # File might not exist (generated files, etc.)
            continue

        if fix_file_includes(filepath, file_type):
            modified_files.append(filepath)

    # Exit with appropriate code
    if modified_files:
        # Files were modified - exit 1 so pre-commit shows the diff
        sys.exit(1)
    else:
        # No changes needed
        sys.exit(0)


if __name__ == "__main__":
    main()
