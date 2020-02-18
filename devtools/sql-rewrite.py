#!/usr/bin/env python3

from mako.template import Template

import re
import sys


DEBUG = False


def eprint(*args, **kwargs):
    if not DEBUG:
        return
    print(*args, file=sys.stderr, **kwargs)


class Rewriter(object):

    def rewrite_types(self, query, mapping):
        for old, new in mapping.items():
            query = re.sub(old, new, query)
        return query

    def rewrite_single(self, query):
        return query

    def rewrite(self, queries):
        for i, q in enumerate(queries):
            org = q['query']
            queries[i]['query'] = self.rewrite_single(org)
            eprint("Rewritten statement\n\tfrom {}\n\t  to {}".format(org, q['query']))
        return queries


class Sqlite3Rewriter(Rewriter):
    def rewrite_single(self, query):
        typemapping = {
            r'BIGINT': 'INTEGER',
            r'BIGINTEGER': 'INTEGER',
            r'BIGSERIAL': 'INTEGER',
            r'CURRENT_TIMESTAMP\(\)': "strftime('%s', 'now')",
            r'INSERT INTO[ \t]+(.*)[ \t]+ON CONFLICT.*DO NOTHING;': 'INSERT OR IGNORE INTO \\1;',
            # Rewrite "decode('abcd', 'hex')" to become "x'abcd'"
            r'decode\((.*),\s*[\'\"]hex[\'\"]\)': 'x\\1',
        }
        return self.rewrite_types(query, typemapping)


class PostgresRewriter(Rewriter):
    def rewrite_single(self, q):
        # Let's start by replacing any eventual '?' placeholders
        q2 = ""
        count = 1
        for c in q:
            if c == '?':
                c = "${}".format(count)
                count += 1
            q2 += c
        query = q2

        typemapping = {
            r'BLOB': 'BYTEA',
            r'CURRENT_TIMESTAMP\(\)': "EXTRACT(epoch FROM now())",
        }

        query = self.rewrite_types(query, typemapping)
        return query


rewriters = {
    "sqlite3": Sqlite3Rewriter(),
    "postgres": PostgresRewriter(),
}

template = Template("""#ifndef LIGHTNINGD_WALLET_GEN_DB_${f.upper()}
#define LIGHTNINGD_WALLET_GEN_DB_${f.upper()}

#include <config.h>
#include <wallet/db_common.h>

#if HAVE_${f.upper()}

struct db_query db_${f}_queries[] = {

% for elem in queries:
    {
         .name = "${elem['name']}",
         .query = "${elem['query']}",
         .placeholders = ${elem['placeholders']},
         .readonly = ${elem['readonly']},
    },
% endfor
};

#define DB_${f.upper()}_QUERY_COUNT ${len(queries)}

#endif /* HAVE_${f.upper()} */

#endif /* LIGHTNINGD_WALLET_GEN_DB_${f.upper()} */
""")


def extract_queries(pofile):
    # Given a po-file, extract all queries and their associated names, and
    # return them as a list.

    def chunk(pofile):
        # Chunk a given file into chunks separated by an empty line
        with open(pofile, 'r') as f:
            chunk = []
            for line in f:
                line = line.strip()
                if line.strip() == "":
                    yield chunk
                    chunk = []
                else:
                    chunk.append(line.strip())
            if chunk != []:
                yield chunk

    queries = []
    for c in chunk(pofile):

        # Skip other comments
        i = 1
        while c[i][0] == '#':
            i += 1

        # Strip header and surrounding quotes
        query = c[i][7:][:-1]

        queries.append({
            'name': query,
            'query': query,
            'placeholders': query.count('?'),
            'readonly': "true" if query.upper().startswith("SELECT") else "false",
        })
    return queries


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n\t{} <statements.po-file> <output-dialect>".format(sys.argv[0]))
        sys.exit(1)

    dialect = sys.argv[2]

    if dialect not in rewriters:
        print("Unknown dialect {}. The following are available: {}".format(
            dialect,
            ", ".join(rewriters.keys())
        ))
        sys.exit(1)

    rewriter = rewriters[dialect]

    queries = extract_queries(sys.argv[1])
    queries = rewriter.rewrite(queries)

    print(template.render(f=dialect, queries=queries))
