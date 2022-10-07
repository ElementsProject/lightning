"""Generate javascript exports for #defined symbols in header files.

Takes a single command line arg which is the root source directory
"""
import glob
import os
import sys


def generate(root_dir, hash_define='#define '):
    lines = []
    headers_pattern = os.path.join(root_dir, 'include', 'wally_*.h')
    for header_file in glob.glob(headers_pattern):
        for line in open(header_file).readlines():
            if line.startswith(hash_define):
                line = line.split('/*')[0]
                toks = line.split(hash_define)[1:][0].split()
                if len(toks) > 1:
                    name = toks[0]
                    value = ' '.join(toks[1:])
                    lines.append('_export("{}", {});'.format(name, value))
    return '\n'.join(lines)


if __name__ == "__main__":
    root_dir = sys.argv[1]
    print(generate(root_dir))
