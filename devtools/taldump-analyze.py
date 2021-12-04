#! /usr/bin/env python3
import sys
import re

# If you have names on their own lines, it's an old tal_dump which
# put a \n after children:
# awk '/CHILDREN/ { SAVED=$0 } !/CHILDREN/ { print SAVED$0; SAVED="" }' < lightningd-tal_dump > lightningd-tal_dump-children-on-same-line

# Dict of paths -> [total size,count]
by_path = {}
by_name = {}

SIZE_THRESHOLD = 1000000


def process(path, name, indent, bytelen):
    # Finish any previous entries.
    while indent < len(path):
        # Don't track little ones
        if by_path[','.join(path)][0] < SIZE_THRESHOLD:
            del by_path[','.join(path)]
        path = path[:-1]

    # Add new child
    assert indent == len(path)

    # Parents must exist!  Add bytes to all their tallies
    for i in range(0, len(path)):
        by_path[','.join(path[:i])][0] += bytelen
    path += [name]
    # Might already exist
    prev = by_path.get(','.join(path), (0, 0))
    by_path[','.join(path)] = [prev[0] + bytelen, prev[1] + 1]
    prev = by_name.get(name, (0, 0))
    by_name[name] = (prev[0] + bytelen, prev[1] + 1)

    return path


cur_path = []

infile = open(sys.argv[1], 'rt')
while True:
    line = infile.readline()
    if not line:
        break

    stripped = line.lstrip(' ')
    indent = (len(line) - len(stripped)) // 2
    if not stripped.startswith('0x'):
        print("Ignoring {}".format(line), end='')
        continue

    bytelen = int(re.search('len=([0-9]*)', line).group(1))
    name = re.search('"(.*)"', line)
    if not name:
        # This can only happen at the root!
        assert cur_path == []
        name = ''
    else:
        name = name.group(1)
    cur_path = process(cur_path, name, indent, bytelen)


print("Top sizes by name")
for k, v in sorted(by_name.items(), key=lambda x: -x[1][0]):
    if v[0] < SIZE_THRESHOLD:
        break
    print("{}: {} bytes, {} items".format(k, v[0], v[1]))

print("Top sizes by path")
for k, v in sorted(by_path.items(), key=lambda x: -x[1][0]):
    print("{}: {} bytes, {} items".format(k.split(','), v[0], v[1]))
