#!/usr/bin/env python3

from clang import cindex
from mako.template import Template


class Sqlite3Rewriter(object):
    def rewrite(self, query):
        return query


queries = []
counter = 0


# Depending on whether the header is included or not we might see the SQL call
# as one of the types below
call_types = [
    cindex.CursorKind.MACRO_INSTANTIATION,
    cindex.CursorKind.CALL_EXPR
]


def extract_queries(filename):
    counter = 0

    def extract(node):
        global counter
        tokens = [t for t in node.get_tokens()]
        name = "{}:{}:{}".format(filename, node.extent.end.line, counter)
        literals = [t.spelling for t in tokens if t.kind == cindex.TokenKind.LITERAL]
        query = "".join([l[1:-1] for l in literals])
        counter += 1
        return {
            "name": name,
            "query": query,
            "placeholders": query.count("?"),
        }

    def extract_all(node):
        queries = []
        if node.kind in call_types and node.spelling == "SQL":
            queries.append(extract(node))

        for c in node.get_children():
            queries.extend(extract_all(c))
        return queries

    index = cindex.Index.create()
    tu = index.parse(filename, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    return extract_all(tu.cursor)


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

files = [
    'wallet/db.c',
    'wallet/wallet.c',
    'wallet/test/run-db.c',
    'wallet/test/run-wallet.c',
]

if __name__ == "__main__":
    f = 'sqlite3'
    queries = []
    for ff in files:
        queries.extend(extract_queries(ff))

    rewriter = rewriters[f]
    queries = rewriter.rewrite(queries)

    print(template.render(f=f, queries=queries))
