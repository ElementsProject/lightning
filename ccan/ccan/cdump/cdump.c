/* MIT (BSD) license - see LICENSE file for details */
#include "cdump.h"
#include <ccan/tal/str/str.h>
#include <assert.h>

struct token {
	const char *p;
	size_t len;
};

static void add_token(struct token **toks, const char *p, size_t len)
{
	size_t n = tal_count(*toks);
	tal_resize(toks, n+1);
	(*toks)[n].p = p;
	(*toks)[n].len = len;
}

static size_t to_eol(const char *p)
{
	size_t len = strcspn(p, "\n");

	/* And any \ continuations. */
	while (p[len] && p[len-1] == '\\')
		len += strcspn(p+len+1, "\n") + 1;
	return len;
}

/* Simplified tokenizer: comments and preproc directives removed,
   identifiers are a token, others are single char tokens. */
static struct token *tokenize(const void *ctx, const char *code)
{
	unsigned int i, len, tok_start = -1;
	bool start_of_line = true;
	struct token *toks = tal_arr(ctx, struct token, 0);

	for (i = 0; code[i]; i += len) {
		if (code[i] == '#' && start_of_line) {
			/* Preprocessor line. */
			len = to_eol(code + i);
		} else if (code[i] == '/' && code[i+1] == '/') {
			/* One line comment. */
			len = to_eol(code + i);
			if (tok_start != -1U) {
				add_token(&toks, code+tok_start, i - tok_start);
				tok_start = -1U;
			}
		} else if (code[i] == '/' && code[i+1] == '*') {
			/* Multi-line comment. */
			const char *end = strstr(code+i+2, "*/");
			len = (end + 2) - (code + i);
			if (!end)
				len = strlen(code + i);
			if (tok_start != -1U) {
				add_token(&toks, code+tok_start, i - tok_start);
				tok_start = -1U;
			}
		} else if (cisalnum(code[i]) || code[i] == '_') {
			/* Identifier or part thereof */
			if (tok_start == -1U)
				tok_start = i;
			len = 1;
		} else if (!cisspace(code[i])) {
			/* Punctuation: treat as single char token. */
			if (tok_start != -1U) {
				add_token(&toks, code+tok_start, i - tok_start);
				tok_start = -1U;
			}
			add_token(&toks, code+i, 1);
			len = 1;
		} else {
			/* Whitespace. */
			if (tok_start != -1U) {
				add_token(&toks, code+tok_start, i - tok_start);
				tok_start = -1U;
			}
			len = 1;
		}
		if (code[i] == '\n')
			start_of_line = true;
		else if (!cisspace(code[i]))
			start_of_line = false;
	}

	/* Add terminating NULL. */
	tal_resizez(&toks, tal_count(toks) + 1);
	return toks;
}

struct parse_state {
	const char *code;
	const struct token *toks;
	struct cdump_definitions *defs;
	char *complaints;
};

static const struct token *tok_peek(const struct token **toks)
{
	/* Ignore removed tokens (eg. comments) */
	while (toks[0]->len == 0) {
		if (!toks[0]->p)
			return NULL;
		(*toks)++;
	}
	return toks[0];
}

static bool tok_is(const struct token **toks, const char *target)
{
	const struct token *t = tok_peek(toks);
	return (t && t->len == strlen(target)
		&& memcmp(t->p, target, t->len) == 0);
}

static const struct token *tok_take(const struct token **toks)
{
	const struct token *t = tok_peek(toks);
	if (t)
		(*toks)++;

	return t;
}

static const struct token *tok_take_if(const struct token **toks,
				       const char *target)
{
	if (tok_is(toks, target))
		return tok_take(toks);
	return NULL;
}

static const char *tok_take_ident(const tal_t *ctx, const struct token **toks)
{
	const struct token *t = tok_peek(toks);

	if (!t)
		return NULL;

	if (strspn(t->p, "_0123456789"
		   "abcdefghijklmnopqrstuvwxyz"
		   "ABCDEFGHIJKLMNOPQRSTUVWXYZ") < t->len)
		return NULL;

	t = tok_take(toks);
	return tal_strndup(ctx, t->p, t->len);
}

static char *string_of_toks(const tal_t *ctx,
			    const struct token *first,
			    const struct token *until)
{
	char *str, *p;

	/* Careful to skip erased tokens (eg. comments) */
	str = p = tal_arr(ctx, char, until->p - first->p + 1);
	while (first != until) {
		const struct token *next = first + 1;

		if (first->len) {
			memcpy(p, first->p, first->len);
			p += first->len;
			/* Insert space if they weren't adjacent, unless last */
			if (next != until) {
				if (first->p + first->len != next->p)
					*(p++) = ' ';
			}
		}
		first = next;
	}
	*p = '\0';

	return str;
}

static char *tok_take_until(const tal_t *ctx,
			    const struct token **toks,
			    const char *delims)
{
	const struct token *t, *start;

	start = tok_peek(toks);
	while ((t = tok_peek(toks)) != NULL) {
		/* If this contains a delimiter, copy up to prev token. */
		if (strcspn(t->p, delims) < t->len)
			return string_of_toks(ctx, start, t);
		tok_take(toks);
	};

	/* EOF without finding delimiter */
	return NULL;
}

static bool type_defined(const struct cdump_type *t)
{
	switch (t->kind) {
	case CDUMP_STRUCT:
	case CDUMP_UNION:
		return (t->u.members != NULL);
	case CDUMP_ENUM:
		return (t->u.enum_vals != NULL);

	/* These shouldn't happen; we don't try to define them. */
	case CDUMP_UNKNOWN:
	case CDUMP_ARRAY:
	case CDUMP_POINTER:
		break;
	}
	abort();
}

/* May allocate a new type if not already found (steals @name) */
static struct cdump_type *get_type(struct cdump_definitions *defs,
				   enum cdump_type_kind kind,
				   const char *name)
{
	cdump_map_t *m = (void *)0x1L; /* Shouldn't be used */
	struct cdump_type *t;

	switch (kind) {
	case CDUMP_STRUCT:
		m = &defs->structs;
		break;
	case CDUMP_UNION:
		m = &defs->unions;
		break;
	case CDUMP_ENUM:
		m = &defs->enums;
		break;
	case CDUMP_UNKNOWN:
	case CDUMP_ARRAY:
	case CDUMP_POINTER:
		m = NULL;
	}

	/* Do we already have it? */
	if (m) {
		t = strmap_get(m, name);
		if (t)
			return t;
	}

	t = tal(defs, struct cdump_type);
	t->kind = kind;
	t->name = name ? tal_steal(t, name) : NULL;
	/* These are actually the same, but be thorough */
	t->u.members = NULL;
	t->u.enum_vals = NULL;
	if (m)
		strmap_add(m, t->name, t);

	return t;
}

static void complain(struct parse_state *ps, const char *complaint)
{
	unsigned int linenum;
	const char *p = ps->code;

	for (linenum = 1; p < ps->toks[0].p; linenum++) {
		p = strchr(p+1, '\n');
		if (!p)
			break;
	}

	tal_append_fmt(&ps->complaints,
		       "Line %u: '%.*s': %s\n",
		       linenum, (int)ps->toks[0].len,
		       ps->toks[0].p, complaint);
}

static void tok_take_unknown_statement(struct parse_state *ps)
{
	complain(ps, "Ignoring unknown statement until next semicolon");
	tal_free(tok_take_until(NULL, &ps->toks, ";"));
	tok_take_if(&ps->toks, ";");
}

static bool tok_take_expr(struct parse_state *ps, const char *term)
{
	while (!tok_is(&ps->toks, term)) {
		if (tok_take_if(&ps->toks, "(")) {
			if (!tok_take_expr(ps, ")"))
				return false;
		} else if (tok_take_if(&ps->toks, "[")) {
			if (!tok_take_expr(ps, "]"))
				return false;
		} else if (!tok_take(&ps->toks))
			return false;
	}
	return tok_take(&ps->toks);
}

static char *tok_take_expr_str(const tal_t *ctx,
			       struct parse_state *ps,
			       const char *term)
{
	const struct token *start = tok_peek(&ps->toks);

	if (!tok_take_expr(ps, term))
		return NULL;

	return string_of_toks(ctx, start, ps->toks - 1);
}

/* [ ... */
static bool tok_take_array(struct parse_state *ps, struct cdump_type **type)
{
	/* This will be some arbitrary expression! */
	struct cdump_type *arr = get_type(ps->defs, CDUMP_ARRAY, NULL);

	arr->u.arr.size = tok_take_expr_str(arr, ps, "]");
	if (!arr->u.arr.size) {
		complain(ps, "Could not find closing array size ]");
		return false;
	}

	arr->u.arr.type = *type;
	*type = arr;

	return true;
}

static struct cdump_type *ptr_of(struct parse_state *ps,
				 const struct cdump_type *ptr_to)
{
	struct cdump_type *ptr = get_type(ps->defs, CDUMP_POINTER, NULL);
	ptr->u.ptr = ptr_to;
	return ptr;
}

static bool tok_take_type(struct parse_state *ps, struct cdump_type **type)
{
	const char *name;
	const struct token *types;
	enum cdump_type_kind kind;

	/* Ignoring weird typedefs, only these can be combined. */
	types = ps->toks;
	while (tok_take_if(&ps->toks, "int")
	       || tok_take_if(&ps->toks, "long")
	       || tok_take_if(&ps->toks, "short")
	       || tok_take_if(&ps->toks, "double")
	       || tok_take_if(&ps->toks, "float")
	       || tok_take_if(&ps->toks, "char")
	       || tok_take_if(&ps->toks, "signed")
	       || tok_take_if(&ps->toks, "unsigned"));

	/* Did we get some? */
	if (ps->toks != types) {
		name = string_of_toks(NULL, types, tok_peek(&ps->toks));
		kind = CDUMP_UNKNOWN;
	} else {
		/* Try normal types (or simple typedefs, etc). */
		if (tok_take_if(&ps->toks, "struct")) {
			kind = CDUMP_STRUCT;
		} else if (tok_take_if(&ps->toks, "union")) {
			kind = CDUMP_UNION;
		} else if (tok_take_if(&ps->toks, "enum")) {
			kind = CDUMP_ENUM;
		} else
			kind = CDUMP_UNKNOWN;

		name = tok_take_ident(ps->defs, &ps->toks);
		if (!name) {
			complain(ps, "Invalid typename");
			return false;
		}
	}

	*type = get_type(ps->defs, kind, name);
	return true;
}

/* CDUMP */
static bool tok_maybe_take_cdump_note(const tal_t *ctx,
				      struct parse_state *ps, const char **note)
{
	*note = NULL;
	if (tok_take_if(&ps->toks, "CDUMP")) {
		if (!tok_take_if(&ps->toks, "(")) {
			complain(ps, "Expected ( after CDUMP");
			return false;
		}
		*note = tok_take_expr_str(ctx, ps, ")");
		if (!*note) {
			complain(ps, "Expected ) after CDUMP(");
			return false;
		}
	}
	return true;
}

/* __attribute__((...)) */
static bool tok_ignore_attribute(struct parse_state *ps)
{
	if (!tok_take_if(&ps->toks, "__attribute__"))
		return true;

	if (!tok_take_if(&ps->toks, "(") || !tok_take_if(&ps->toks, "(")) {
		complain(ps, "Expected (( after __attribute__");
		return false;
	}

	if (!tok_take_expr(ps, ")")) {
		complain(ps, "Expected expression after __attribute__((");
		return false;
	}
	if (!tok_take_if(&ps->toks, ")")) {
		complain(ps, "Expected )) __attribute__((");
		return false;
	}
	return true;
}

/* struct|union ... */
static bool tok_take_conglom(struct parse_state *ps,
			     enum cdump_type_kind conglom_kind)
{
	struct cdump_type *e;
	const char *name;
	size_t n;

	assert(conglom_kind == CDUMP_STRUCT || conglom_kind == CDUMP_UNION);

	name = tok_take_ident(ps->defs, &ps->toks);
	if (!name) {
		complain(ps, "Invalid struct/union name");
		return false;
	}

	e = get_type(ps->defs, conglom_kind, name);
	if (type_defined(e)) {
		complain(ps, "Type already defined");
		return false;
	}

	if (!tok_maybe_take_cdump_note(e, ps, &e->note))
		return false;

	if (!tok_ignore_attribute(ps))
		return false;

	if (!tok_take_if(&ps->toks, "{")) {
		complain(ps, "Expected { for struct/union");
		return false;
	}

	e->u.members = tal_arr(e, struct cdump_member, n = 0);
	while (!tok_is(&ps->toks, "}")) {
		struct cdump_type *basetype;
		const struct token *quals;
		unsigned int num_quals = 0;

		if (!tok_ignore_attribute(ps))
			return false;

		/* Anything can have these prepended. */
		quals = ps->toks;
		while (tok_take_if(&ps->toks, "const")
		       || tok_take_if(&ps->toks, "volatile"))
			num_quals++;

		/* eg. "struct foo" or "varint_t" */
		if (!tok_take_type(ps, &basetype)) {
			complain(ps, "Expected typename inside struct/union");
			return false;
		}

		do {
			struct cdump_member *m;

			tal_resize(&e->u.members, n+1);
			m = &e->u.members[n++];
			m->type = basetype;
			if (num_quals) {
				m->qualifiers
					= string_of_toks(e, quals,
							 quals + num_quals);
			} else
				m->qualifiers = NULL;

			/* May have multiple asterisks. */
			while (tok_take_if(&ps->toks, "*"))
				m->type = ptr_of(ps, m->type);

			if (!tok_ignore_attribute(ps))
				return false;

			m->name = tok_take_ident(e, &ps->toks);
			if (!m->name) {
				complain(ps, "Expected name for member");
				return false;
			}

			/* May be an array. */
			while (tok_take_if(&ps->toks, "[")) {
				if (!tok_take_array(ps, &m->type))
					return false;
			}

			/* CDUMP() */
			if (!tok_maybe_take_cdump_note(e->u.members,
						       ps, &m->note))
				return false;

			if (!tok_ignore_attribute(ps))
				return false;
		} while (tok_take_if(&ps->toks, ","));

		if (!tok_take_if(&ps->toks, ";")) {
			complain(ps, "Expected ; at end of member");
			return false;
		}
	}

	if (!tok_take_if(&ps->toks, "}")) {
		complain(ps, "Expected } at end of struct/union");
		return false;
	}

	if (!tok_ignore_attribute(ps))
		return false;

	if (!tok_take_if(&ps->toks, ";")) {
		complain(ps, "Expected ; at end of struct/union");
		return false;
	}
	return true;
}

/* enum ... */
static bool tok_take_enum(struct parse_state *ps)
{
	size_t n = 0;
	struct cdump_type *e;
	const char *name;

	name = tok_take_ident(ps->defs, &ps->toks);
	if (!name) {
		complain(ps, "Expected enum name");
		return false;
	}

	e = get_type(ps->defs, CDUMP_ENUM, name);

	/* Duplicate name? */
	if (type_defined(e)) {
		complain(ps, "enum already defined");
		return false;
	}

	/* CDUMP() */
	if (!tok_maybe_take_cdump_note(e, ps, &e->note))
		return false;

	if (!tok_ignore_attribute(ps))
		return false;

	if (!tok_take_if(&ps->toks, "{")) {
		complain(ps, "Expected { after enum name");
		return false;
	}

	e->u.enum_vals = tal_arr(e, struct cdump_enum_val, n);
	do {
		struct cdump_enum_val *v;

		/* GCC extension: comma and end of enum */
		if (tok_is(&ps->toks, "}"))
			break;

		tal_resize(&e->u.enum_vals, n+1);
		v = &e->u.enum_vals[n++];

		v->name = tok_take_ident(e, &ps->toks);
		if (!v->name) {
			complain(ps, "Expected enum value name");
			return false;
		}

		/* CDUMP() */
		if (!tok_maybe_take_cdump_note(e->u.enum_vals, ps, &v->note))
			return false;

		if (tok_take_if(&ps->toks, "=")) {
			v->value = tok_take_until(e, &ps->toks, ",}");
			if (!v->value) {
				complain(ps, "Expected , or } to end value");
				return false;
			}
		} else
			v->value = NULL;
	} while (tok_take_if(&ps->toks, ","));

	if (!tok_take_if(&ps->toks, "}")) {
		complain(ps, "Expected } at end of enum");
		return false;
	}

	if (!tok_ignore_attribute(ps))
		return false;

	if (!tok_take_if(&ps->toks, ";")) {
		complain(ps, "Expected ; at end of enum");
		return false;
	}
	return true;
}

static bool gather_undefines(const char *name,
			     struct cdump_type *t,
			     cdump_map_t *undefs)
{
	if (!type_defined(t))
		strmap_add(undefs, name, t);
	return true;
}

static bool remove_from_map(const char *name,
			    struct cdump_type *t,
			    cdump_map_t *map)
{
	strmap_del(map, name, NULL);
	return true;
}

static void remove_undefined(cdump_map_t *map)
{
	cdump_map_t undefs;

	/* We can't delete inside iterator, so gather all the undefs
	 * then remove them. */
	strmap_init(&undefs);

	strmap_iterate(map, gather_undefines, &undefs);
	strmap_iterate(&undefs, remove_from_map, map);
	strmap_clear(&undefs);
}

static void destroy_definitions(struct cdump_definitions *defs)
{
	strmap_clear(&defs->enums);
	strmap_clear(&defs->structs);
	strmap_clear(&defs->unions);
}

/* Simple LL(1) parser, inspired by Tridge's genstruct.pl. */
struct cdump_definitions *cdump_extract(const tal_t *ctx, const char *code,
					char **complaints)
{
	struct parse_state ps;
	const struct token *toks;

	ps.defs = tal(ctx, struct cdump_definitions);
	ps.complaints = tal_strdup(ctx, "");
	ps.code = code;

	strmap_init(&ps.defs->enums);
	strmap_init(&ps.defs->structs);
	strmap_init(&ps.defs->unions);
	tal_add_destructor(ps.defs, destroy_definitions);

	toks = ps.toks = tokenize(ps.defs, code);
	while (tok_peek(&ps.toks)) {
		if (!tok_ignore_attribute(&ps))
			goto fail;
		if (tok_take_if(&ps.toks, "struct")) {
			if (!tok_take_conglom(&ps, CDUMP_STRUCT))
				goto fail;
		} else if (tok_take_if(&ps.toks, "union")) {
			if (!tok_take_conglom(&ps, CDUMP_UNION))
				goto fail;
		} else if (tok_take_if(&ps.toks, "enum")) {
			if (!tok_take_enum(&ps))
				goto fail;
		} else
			tok_take_unknown_statement(&ps);
	}

	/* Now, remove any undefined types! */
	remove_undefined(&ps.defs->enums);
	remove_undefined(&ps.defs->structs);
	remove_undefined(&ps.defs->unions);
	tal_free(toks);

out:
	if (streq(ps.complaints, ""))
		ps.complaints = tal_free(ps.complaints);

	if (complaints)
		*complaints = ps.complaints;
	else
		tal_free(ps.complaints);
	return ps.defs;

fail:
	ps.defs = tal_free(ps.defs);
	goto out;
}
