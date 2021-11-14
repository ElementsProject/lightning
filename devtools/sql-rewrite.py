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
            if q['name'] is None:
                continue
            org = q['query']
            queries[i]['query'] = self.rewrite_single(org)
            eprint("Rewritten statement\n\tfrom {}\n\t  to {}".format(org, q['query']))
        return queries


class Sqlite3Rewriter(Rewriter):
    def rewrite_single(self, query):
        # Replace DB specific queries with a no-op
        if "/*PSQL*/" in query:
            return "UPDATE vars SET intval=1 WHERE name='doesnotexist'"  # Return a no-op

        typemapping = {
            r'BIGINT': 'INTEGER',
            r'BIGINTEGER': 'INTEGER',
            r'BIGSERIAL': 'INTEGER',
            r'CURRENT_TIMESTAMP\(\)': "strftime('%s', 'now')",
            r'INSERT INTO[ \t]+(.*)[ \t]+ON CONFLICT.*DO NOTHING;': 'INSERT OR IGNORE INTO \\1;',
            # Rewrite "decode('abcd', 'hex')" to become "x'abcd'"
            r'decode\((.*),\s*[\'\"]hex[\'\"]\)': 'x\\1',
            # GREATEST() of multiple columns is simple MAX in sqlite3.
            r'GREATEST\(([^)]*)\)': "MAX(\\1)",
        }
        return self.rewrite_types(query, typemapping)


class PostgresRewriter(Rewriter):
    def rewrite_single(self, q):
        # Replace DB specific queries with a no-op
        if "/*SQLITE*/" in q:
            return "UPDATE vars SET intval=1 WHERE name='doesnotexist'"  # Return a no-op

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


# djb2 is simple and effective: see http://www.cse.yorku.ca/~oz/hash.html
def hash_djb2(string):
    val = 5381
    for s in string:
        val = ((val * 33) & 0xFFFFFFFF) ^ ord(s)
    return val


def colname_htable(query):
    assert query.upper().startswith("SELECT")
    colquery = query[6:query.upper().index(" FROM ")]
    colnames = colquery.split(',')

    # If split caused unbalanced brackets, it's complex: assume
    # a single field!
    if any([colname.count('(') != colname.count(')') for colname in colnames]):
        return [('"' + colquery.strip() + '"', 0)]

    # 50% density htable
    tablesize = len(colnames) * 2 - 1
    table = [("NULL", -1)] * tablesize
    for colnum, colname in enumerate(colnames):
        colname = colname.strip()
        # SELECT xxx AS yyy -> Y
        as_clause = colname.upper().find(" AS ")
        if as_clause != -1:
            colname = colname[as_clause + 4:].strip()

        pos = hash_djb2(colname) % tablesize
        while table[pos][0] != "NULL":
            pos = (pos + 1) % tablesize
        table[pos] = ('"' + colname + '"', colnum)
    return table


template = Template("""#ifndef LIGHTNINGD_WALLET_GEN_DB_${f.upper()}
#define LIGHTNINGD_WALLET_GEN_DB_${f.upper()}

#include <config.h>
#include <ccan/array_size/array_size.h>
#include <wallet/db_common.h>

#if HAVE_${f.upper()}
% for colname, table in colhtables.items():
static const struct sqlname_map ${colname}[] = {
% for t in table:
    { ${t[0]}, ${t[1]} },
% endfor
};

% endfor

const struct db_query db_${f}_queries[] = {

% for elem in queries:
    {
% if elem['name'] is not None:
         .name = "${elem['name']}",
         .query = "${elem['query']}",
         .placeholders = ${elem['placeholders']},
         .readonly = ${elem['readonly']},
% if elem['colnames'] is not None:
         .colnames = ${elem['colnames']},
         .num_colnames = ARRAY_SIZE(${elem['colnames']}),
% endif
% endif
    },
% endfor
};

#endif /* HAVE_${f.upper()} */

#endif /* LIGHTNINGD_WALLET_GEN_DB_${f.upper()} */
""")


def queries_htable(queries):
    # Converts a list of queries into a hash table.
    tablesize = len(queries) * 2 - 1
    htable = [{'name': None}] * tablesize

    for q in queries:
        pos = hash_djb2(q['name']) % tablesize
        while htable[pos]['name'] is not None:
            pos = (pos + 1) % tablesize
        htable[pos] = q

    return htable


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

    colhtables = {}
    queries = []
    for c in chunk(pofile):

        # Skip other comments
        i = 1
        while c[i][0] == '#':
            i += 1

        # Strip header and surrounding quotes
        query = c[i][7:][:-1]

        is_select = query.upper().startswith("SELECT")
        if is_select:
            colnames = 'col_table{}'.format(len(queries))
            colhtables[colnames] = colname_htable(query)
        else:
            colnames = None

        queries.append({
            'name': query,
            'query': query,
            'placeholders': query.count('?'),
            'readonly': "true" if is_select else "false",
            'colnames': colnames,
        })
    return colhtables, queries_htable(queries)


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

    colhtables, queries = extract_queries(sys.argv[1])
    queries = rewriter.rewrite(queries)

    print(template.render(f=dialect, queries=queries, colhtables=colhtables))
