#!/usr/bin/env python3

from mako.template import Template

import sys


class Sqlite3Rewriter(object):
    def rewrite(self, query):
        return query


rewriters = {
    "sqlite3": Sqlite3Rewriter(),
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
         .placeholders = ${elem['placeholders']}
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
        name = c[0][3:]

        # Skip other comments
        i = 1
        while c[i][0] == '#':
            i += 1

        # Strip header and surrounding quotes
        query = c[i][7:][:-1]

        queries.append({
            'name': name,
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
