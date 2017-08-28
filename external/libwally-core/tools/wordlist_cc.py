from binascii import b2a_hex
import sys

def as_hex(s):
    return ','.join([hex(c) for c in s.encode('utf8')])

if __name__ == "__main__":

    bits = { 2 ** x : x for x in range(12) } # Up to 4k words
    wordlist = sys.argv[1]
    struct_name = '%s_words' % sys.argv[2]
    string_name = '%s' % sys.argv[2]

    with open(wordlist, 'r') as f:

        words = [l.strip() for l in f.readlines()]
        is_sorted = sorted(words) == words
        assert len(words) >= 2
        assert len(words) in bits

        lengths = [ 0 ];
        for w in words:
            lengths.append(lengths[-1] + len(w.encode('utf-8')) + 1)
        idxs = ['{0}+{1}'.format(string_name, n) for n in lengths]

        print('/* Generated file - do not edit! */')
        print('#include <wordlist.h>')
        print()

        print('static const unsigned char %s_[] = {' % string_name)
        grouped = [words[i : i + 4] for i in range(0, len(words), 4)]
        for w in words:
            print('    %s,0,' % as_hex(w))
        print('};')

        print('#define %s ((const char*)%s_)' % (string_name, string_name))

        print('static const char *%s_i[] = {' % (string_name))
        grouped = [idxs[i : i + 6] for i in range(0, len(idxs), 6)]
        for g in grouped:
            print('    %s,' % (', '.join(g)))
        print('   };')
        print('#undef %s' % string_name)

        print()
        print('static const struct words %s = {' % struct_name)
        print('    {0},'.format(len(words)))
        print('    {0},'.format(bits[len(words)]))
        print('    {0},'.format(str(is_sorted).lower()))
        print('    (const char *)%s_,' % string_name)
        print('    0, /* Constant string */')
        print('    %s_i' % string_name)
        print('};')
