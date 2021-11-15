/* MIT (BSD) license - see LICENSE file for details */
#include "graphql.h"

#include "ccan/tal/str/str.h"
#include "ccan/utf8/utf8.h"


/* GraphQL character classes
 *
 * These definitions are meant to reflect the GraphQL specification as
 * literally as possible.
 */
#define SOURCE_CHAR(c) ((c) == '\t' || (c) == '\n' || (c) == '\r' || ((c) >= 32 && (c) <= 65535))
#define WHITE_SPACE(c) ((c) == '\t' || (c) == ' ')
#define LINE_TERMINATOR(c) ((c) == '\n' || (c) == '\r')
#define COMMENT(c) ((c) == '#')
#define COMMENT_CHAR(c) (SOURCE_CHAR(c) && !LINE_TERMINATOR(c))
#define STRING_CHAR(c) (SOURCE_CHAR(c) && !LINE_TERMINATOR(c) && (c)!='"' && (c)!='\\')
#define BLOCK_STRING_CHAR(c) (SOURCE_CHAR(c))
#define COMMA(c) ((c) == ',')
#define EOF_CHAR(c) ((c) == 0 || (c) == 4)
#define PUNCTUATOR(c) (strchr("!$&().:=@[]{|}", c))
#define HEX_DIGIT(c) (DIGIT(c) || ((c) >= 'a' && (c) <= 'f') || ((c) >= 'A' && (c) <= 'F'))
#define DIGIT(c) ((c) >= '0' && (c) <= '9')
#define NAME_START(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') || (c) == '_')
#define NAME_CONTINUE(c) (NAME_START(c) || DIGIT(c))

// Helper for copying an overlapping string, since strcpy() is not safe for that
#define cpystr(d,s) { char *cpystr_p; char *cpystr_q; for(cpystr_p = (s), cpystr_q = (d); *cpystr_p;) *cpystr_q++ = *cpystr_p++; *cpystr_q++ = *cpystr_p++; }

/* Parser shorthands
 *
 * These shorthands are motivated by the parser functions, so they can be
 * written in a format that corresponds closely to the specification.
 */
#define RET static void *
#define PARAMS struct list_head *tokens, struct list_head *used, const char **err
#define ARGS tokens, used, err
#define INIT(type) \
	struct graphql_token *rollback_top = list_top(tokens, struct graphql_token, node); \
	struct graphql_##type *obj = talz(tokens, struct graphql_##type); \
	(void)rollback_top; /* avoids unused variable warning */ \

#define EXIT \
	goto exit_label; /* avoids unused label warning */ \
	exit_label: \
	if (*err) obj = tal_free(obj); \
	return obj; \

#define CONSUME_ONE list_add(used, &list_pop(tokens, struct graphql_token, node)->node);
#define RESTORE_ONE list_add(tokens, &list_pop(used, struct graphql_token, node)->node);
#define ROLLBACK(args) while (list_top(tokens, struct graphql_token, node) != rollback_top) { RESTORE_ONE; }
#define OR if (!*err) goto exit_label; *err = NULL;
#define REQ if (*err) { ROLLBACK(args); goto exit_label; }
#define OPT *err = NULL;
#define WHILE_OPT while(!*err); *err = NULL;
#define LOOKAHEAD(args, tok) struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
#define MSG(msg) if (*err) *err = msg;


/* The following parser functions are written in a way that corresponds to the
 * grammar defined in the GraphQL specification. The code is not intended to
 * look like normal C code; it's designed for parsing clarity rather than C
 * style. Think of it as something generated rather than something to read.
 * For that reason, the functions follow special rules:
 *
 *	- The declaration is standardized with RET and PARAMS
 *	- The "err" argument is assumed to be NULL upon entrance
 *	- The "err" argument is set on failure
 *	- If the function fails to parse, then "tokens" shall be as it was upon entrance
 *	- INIT and EXIT macros are used
 *	- Macros such as REQ and OPT facilitate readability and conciseness
 */

/* The following functions construct the "leaves" of the abstract syntax tree. */

RET parse_keyword(PARAMS, const char *keyword, const char *errmsg) {
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != 'a') {
		*err = errmsg; return NULL;
	}
	if (!streq(tok->token_string, keyword)) {
		*err = errmsg; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

// Note: a static buffer is used here.
RET parse_punct(PARAMS, int punct) {
	static char punctbuf[16];
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != punct) {
		if (punct == PUNCT_SPREAD)
			sprintf(punctbuf, "expected: '...'");
		else
			sprintf(punctbuf, "expected: '%c'", punct);
		*err = punctbuf; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

RET parse_name(PARAMS) {
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != 'a') {
		*err = "name expected"; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

RET parse_int(PARAMS) {
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != 'i') {
		*err = "integer expected"; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

RET parse_float(PARAMS) {
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != 'f') {
		*err = "float expected"; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

RET parse_string(PARAMS) {
	struct graphql_token *tok = list_top(tokens, struct graphql_token, node);
	if (!tok || tok->token_type != 's') {
		*err = "string expected"; return NULL;
	}
	CONSUME_ONE;
	return tok;
}

// The following functions create the branches of the AST.

/*
RET parse_non_null_type_2(PARAMS) {
	INIT(non_null_type);
	parse_list_type(ARGS); REQ;
	parse_punct(ARGS, '!'); REQ;
	EXIT;
}

RET parse_non_null_type_1(PARAMS) {
	INIT(non_null_type);
	parse_named_type(ARGS); REQ;
	parse_punct(ARGS, '!'); REQ;
	EXIT;
}

RET parse_non_null_type(PARAMS) {
	INIT(non_null_type);
	parse_non_null_type_1(ARGS); OR
	parse_non_null_type_2(ARGS);
	EXIT;
}

RET parse_list_type(PARAMS) {
	INIT(list_type);
	parse_punct(ARGS, '['); REQ
	parse_type(ARGS); REQ
	parse_punct(ARGS, ']'); REQ
	EXIT;
}
*/

RET parse_named_type(PARAMS) {
	INIT(named_type);
	obj->name = parse_name(ARGS);
	EXIT;
}

RET parse_type(PARAMS) {
	INIT(type);
	obj->named = parse_named_type(ARGS);
/*
	OR
	obj->list = parse_list_type(ARGS); OR
	obj->non_null = parse_non_null_type(ARGS);
*/
	EXIT;
}

RET parse_variable(PARAMS) {
	INIT(variable);
	parse_punct(ARGS, '$'); REQ
	obj->name = parse_name(ARGS); REQ
	EXIT;
}

RET parse_value(PARAMS);

RET parse_list_value(PARAMS) {
	INIT(list_value);
	parse_punct(ARGS, '['); REQ
	parse_punct(ARGS, ']');
	while (*err) {
		*err = NULL;
		parse_value(ARGS); MSG("expected: value or ']'"); REQ
		parse_punct(ARGS, ']');
	}
	EXIT;
}

RET parse_enum_value(PARAMS) {
	INIT(enum_value);
	obj->val = parse_name(ARGS); REQ
	struct graphql_token *tok = list_top(used, struct graphql_token, node);
	if (streq(tok->token_string, "true")
	 || streq(tok->token_string, "false")
	 || streq(tok->token_string, "null")) {
		*err = "enum value cannot be true, false, or null";
		ROLLBACK(ARGS);
	}
	EXIT;
}

RET parse_null_value(PARAMS) {
	INIT(null_value);
	obj->val = parse_keyword(ARGS, "null", "null expected");
	EXIT;
}

RET parse_string_value(PARAMS) {
	INIT(string_value);
	obj->val = parse_string(ARGS);
	EXIT;
}

RET parse_boolean_value(PARAMS) {
	INIT(boolean_value);
	obj->val = parse_keyword(ARGS, "true", "invalid boolean value"); OR
	obj->val = parse_keyword(ARGS, "false", "invalid boolean value");
	EXIT;
}

RET parse_float_value(PARAMS) {
	INIT(float_value);
	obj->val = parse_float(ARGS);
	EXIT;
}

RET parse_int_value(PARAMS) {
	INIT(int_value);
	obj->val = parse_int(ARGS);
	EXIT;
}

RET parse_object_field(PARAMS) {
	INIT(object_field);
	obj->name = parse_name(ARGS); REQ
	parse_punct(ARGS, ':'); REQ
	obj->val = parse_value(ARGS); REQ
	EXIT;
}

RET parse_object_value(PARAMS) {
	INIT(object_value);
	parse_punct(ARGS, '{'); REQ
	parse_punct(ARGS, '}');
	struct graphql_object_field *p = NULL;
	while (*err) {
		*err = NULL;
		if (!p) {
			obj->first = p = parse_object_field(ARGS); MSG("expected: object field or '}'"); REQ
		} else {
			p->next = parse_object_field(ARGS); MSG("expected: object field or '}'"); REQ
			p = p->next;
		}
		parse_punct(ARGS, '}');
	}
	EXIT;
}

RET parse_default_value(PARAMS) {
	INIT(default_value);
	parse_punct(ARGS, '='); REQ
	obj->val = parse_value(ARGS); REQ
	EXIT;
}

RET parse_value(PARAMS) {
	INIT(value);
	obj->var = parse_variable(ARGS); // FIXME: if not const
	OR
	obj->int_val = parse_int_value(ARGS); OR
	obj->float_val = parse_float_value(ARGS); OR
	obj->str_val = parse_string_value(ARGS); OR
	obj->bool_val = parse_boolean_value(ARGS); OR
	obj->null_val = parse_null_value(ARGS); OR
	obj->enum_val = parse_enum_value(ARGS); OR
	obj->list_val = parse_list_value(ARGS); OR
	obj->obj_val = parse_object_value(ARGS);
	EXIT;
}

RET parse_type_condition(PARAMS) {
	INIT(type_condition);
	parse_keyword(ARGS, "on", "expected: 'on'"); REQ
	obj->named_type = parse_named_type(ARGS); REQ
	EXIT;
}

RET parse_fragment_name(PARAMS) {
	INIT(fragment_name);
	obj->name = parse_name(ARGS); REQ
	struct graphql_token *tok = list_top(used, struct graphql_token, node);
	if (streq(tok->token_string, "on")) {
		*err = "invalid fragment name";
		ROLLBACK(ARGS);
	}
	EXIT;
}

RET parse_alias(PARAMS) {
	INIT(alias);
	obj->name = parse_name(ARGS); REQ
	parse_punct(ARGS, ':'); REQ
	EXIT;
}

RET parse_argument(PARAMS) {
	INIT(argument);
	obj->name = parse_name(ARGS); REQ
	parse_punct(ARGS, ':'); REQ
	obj->val = parse_value(ARGS); REQ
	EXIT;
}

RET parse_arguments(PARAMS) {
	INIT(arguments);
	parse_punct(ARGS, '('); REQ
	obj->first = parse_argument(ARGS); REQ
	struct graphql_argument *p = obj->first;
	parse_punct(ARGS, ')');
	while (*err) {
		*err = NULL;
		p->next = parse_argument(ARGS); MSG("expected: argument or ')'"); REQ;
		p = p->next;
		parse_punct(ARGS, ')');
	}
	EXIT;
}

RET parse_directive(PARAMS) {
	INIT(directive);
	parse_punct(ARGS, '@'); REQ
	obj->name = parse_name(ARGS); REQ
	obj->args = parse_arguments(ARGS); OPT
	EXIT;
}

RET parse_directives(PARAMS) {
	INIT(directives);
	obj->first = parse_directive(ARGS); REQ
	struct graphql_directive *p = obj->first;
	do {
		p->next = parse_directive(ARGS);
		p = p->next;
	} WHILE_OPT;
	EXIT;
}

RET parse_fragment_spread(PARAMS) {
	INIT(fragment_spread);
	parse_punct(ARGS, PUNCT_SPREAD); REQ
	obj->name = parse_fragment_name(ARGS); REQ
	obj->directives = parse_directives(ARGS); OPT
	EXIT;
}

RET parse_variable_definition(PARAMS) {
	INIT(variable_definition);
	obj->var = parse_variable(ARGS); REQ
	parse_punct(ARGS, ':'); REQ
	obj->type = parse_type(ARGS); REQ
	obj->default_val = parse_default_value(ARGS); OPT
	obj->directives = parse_directives(ARGS); OPT
	EXIT;
}

RET parse_variable_definitions(PARAMS) {
	INIT(variable_definitions);
	parse_punct(ARGS, '('); REQ
	obj->first = parse_variable_definition(ARGS); REQ
	struct graphql_variable_definition *p = obj->first;
	parse_punct(ARGS, ')');
	while (*err) {
		*err = NULL;
		p->next = parse_variable_definition(ARGS); MSG("expected: variable definition or ')'"); REQ
		p = p->next;
		parse_punct(ARGS, ')');
	}
	EXIT;
}

RET parse_selection_set(PARAMS);

RET parse_fragment_definition(PARAMS) {
	INIT(fragment_definition);
	parse_keyword(ARGS, "fragment", "fragment expected"); REQ
	obj->name = parse_fragment_name(ARGS); REQ
	obj->type_cond = parse_type_condition(ARGS); REQ
	obj->directives = parse_directives(ARGS); OPT
	obj->sel_set = parse_selection_set(ARGS); REQ
	EXIT;
}

RET parse_inline_fragment(PARAMS) {
	INIT(inline_fragment);
	parse_punct(ARGS, PUNCT_SPREAD); REQ
	obj->type_cond = parse_type_condition(ARGS); OPT
	obj->directives = parse_directives(ARGS); OPT
	obj->sel_set = parse_selection_set(ARGS); REQ
	EXIT;
}

RET parse_field(PARAMS) {
	INIT(field);
	obj->alias = parse_alias(ARGS); OPT
	obj->name = parse_name(ARGS); REQ
	obj->args = parse_arguments(ARGS); OPT
	obj->directives = parse_directives(ARGS); OPT
	obj->sel_set = parse_selection_set(ARGS); OPT
	EXIT;
}

RET parse_selection(PARAMS) {
	INIT(selection);
	obj->field = parse_field(ARGS); OR
	obj->frag_spread = parse_fragment_spread(ARGS); OR
	obj->inline_frag = parse_inline_fragment(ARGS);
	MSG("expected: field, fragment spread, or inline fragment");
	EXIT;
}

RET parse_selection_set(PARAMS) {
	INIT(selection_set);
	parse_punct(ARGS, '{'); REQ;
	obj->first = parse_selection(ARGS); REQ;
	struct graphql_selection *p = obj->first;
	parse_punct(ARGS, '}');
	while (*err) {
		*err = NULL;
		p->next = parse_selection(ARGS); MSG("expected: selection or '}'"); REQ;
		p = p->next;
		parse_punct(ARGS, '}');
	}
	EXIT;
}

RET parse_operation_type(PARAMS) {
	INIT(operation_type);
	const char *errmsg = "expected: query, mutation, or subscription";
	obj->op_type = parse_keyword(ARGS, "query", errmsg); OR
	obj->op_type = parse_keyword(ARGS, "mutation", errmsg); OR
	obj->op_type = parse_keyword(ARGS, "subscription", errmsg);
	EXIT;
}

RET parse_operation_definition(PARAMS) {
	INIT(operation_definition);
	obj->op_type = parse_operation_type(ARGS);
	if (!*err) {
		obj->op_name = parse_name(ARGS); OPT
		obj->vars = parse_variable_definitions(ARGS); OPT
		obj->directives = parse_directives(ARGS); OPT
	} else
		*err = NULL;
	obj->sel_set = parse_selection_set(ARGS);
	if (*err) ROLLBACK(ARGS);
	EXIT;
}

RET parse_executable_definition(PARAMS) {
	INIT(executable_definition);
	obj->op_def = parse_operation_definition(ARGS); MSG("invalid operation or fragment definition"); OR
	obj->frag_def = parse_fragment_definition(ARGS); MSG("invalid operation or fragment definition"); 
	EXIT;
}

RET parse_executable_document(PARAMS) {
	INIT(executable_document);
	obj->first_def = parse_executable_definition(ARGS); REQ
	struct graphql_executable_definition *p = obj->first_def;
	do {
		p->next_def = parse_executable_definition(ARGS);
		p = p->next_def;
	} WHILE_OPT;
	EXIT;
}

RET parse_definition(PARAMS) {
	INIT(definition);
	obj->executable_def = parse_executable_definition(ARGS);
/*	OR
	obj->type_system_def = parse_type_system_definition_or_extension(ARGS);
	// NOTE: Optional type system is not (yet) implemented.
*/
	EXIT;
}

RET parse_document(PARAMS) {
	INIT(document);
	obj->first_def = parse_definition(ARGS); REQ
	struct graphql_definition *p = obj->first_def;
	do {
		p->next_def = parse_definition(ARGS);
		p = p->next_def;
	} WHILE_OPT;
	EXIT;
}
void *currently_unused = parse_document; // to hide the warning till this is used

/* Convert input string into tokens.
 *
 * All data (i.e. the list and the tokens it contains) are allocated to the
 * specified tal context.
 */
const char *graphql_lex(const tal_t *ctx, const char *input, struct list_head **tokens) {

	unsigned int c;
	const char *p, *line_beginning;
	unsigned int line_num = 1;
	struct list_head *tok_list;
	struct graphql_token *tok;

	// Initialize token output list.
	tok_list = tal(ctx, struct list_head);
	if (tokens)
		*tokens = tok_list;
	list_head_init(tok_list);

	// Note: label and goto are used here like a continue statement except that
        // it skips iteration, for when characters are fetched in the loop body.
	p = input;
	line_beginning = p;
	do {
		c = *p++;
newchar:
		// Consume line terminators and increment line counter.
		if (LINE_TERMINATOR(c)) {
			unsigned int c0 = c;
			c = *p++;
			if (c0 == 10 || c0 == 13)
				line_num++;
			if (c0 == 13 && c == 10)
				c = *p++;
			line_beginning = p - 1;
			goto newchar;
		}

		// Consume other ignored tokens.
		if (COMMA(c) || WHITE_SPACE(c)) {
			c = *p++;
			goto newchar;
		}
		if (COMMENT(c)) {
			while (!EOF_CHAR(c) && COMMENT_CHAR(c))
				c = *p++;
			goto newchar;
		}

		// Return success when end is reached.
		if (EOF_CHAR(c))
			return GRAPHQL_SUCCESS;

		// Punctuator tokens.
		if (PUNCTUATOR(c)) {

			// Note beginning of token in input.
			const char *start = p - 1;

			// Handle the ... multi-character case.
			if (c == '.') {
				c = *p++;
				if (c != '.')
					return "unrecognized punctuator";
				c = *p++;
				if (c != '.')
					return "unrecognized punctuator";
				c = PUNCT_SPREAD;
			}

			tok = talz(tok_list, struct graphql_token);
			list_add_tail(tok_list, &tok->node);
			tok->token_type = c;
			tok->token_string = NULL;
			tok->source_line = line_num;
			tok->source_column = start - line_beginning + 1;
			tok->source_offset = start - input;
			tok->source_len = p - start;

		} else if (NAME_START(c)) {

			// Name/identifier tokens.
			tok = talz(tok_list, struct graphql_token);
			list_add_tail(tok_list, &tok->node);
			tok->token_type = 'a';
			// tok->token_string updated below.
			tok->source_line = line_num;
			tok->source_column = p - line_beginning;
			// tok->source_len updated below.

			// Note the beginning of the name.
			const char *name_begin = p - 1;
			const char *name_end;
			int name_len;

			// Consume the rest of the token.
			do {
				c = *p++;
			} while (NAME_CONTINUE(c));

			// Note the end of the name and calculate the length.
			name_end = p - 1;
			name_len = name_end - name_begin;
			tok->source_offset = name_begin - input;
			tok->source_len = name_len;

			// Copy the token string.
			tok->token_string = tal_strndup(tok, name_begin, name_len);

			goto newchar;

		} else if (DIGIT(c) || c == '-') {

			// Number tokens.
			const char *num_start = p - 1;
			char type = 'i';

			if (c == '-') {
				c = *p++;
				if (!DIGIT(c))
					return "negative sign must precede a number";
			}

			if (c == '0') {
				c = *p++;
				if (DIGIT(c))
					return "leading zeros are not allowed";
			} else {
				do {
					c = *p++;
				} while(DIGIT(c));
			}

			if (c == '.') {
				type = 'f';
				if (!DIGIT(*p))
					return "invalid float value fractional part";
				do {
					c = *p++;
				} while(DIGIT(c));
			}

			if (c == 'e' || c == 'E') {
				type = 'f';
				c = *p++;
				if (c == '+' || c == '-')
					c = *p++;
				if (!DIGIT(*p))
					return "invalid float value exponent part";
				do {
					c = *p++;
				} while(DIGIT(c));
			}

			if (c == '.' || NAME_START(c))
				return "invalid numeric value";

			const char *num_end = p - 1;
			int num_len = num_end - num_start;

			tok = talz(tok_list, struct graphql_token);
			list_add_tail(tok_list, &tok->node);
			tok->token_type = type;
			tok->token_string = tal_strndup(tok, num_start, num_len);
			tok->source_line = line_num;
			tok->source_column = num_start - line_beginning + 1;
			tok->source_offset = num_start - input;
			tok->source_len = num_len;

			goto newchar;

		} else if (c == '"') {

			// String tokens.
			c = *p++;
			const char *str_begin = p - 1;
			const char *str_end;
			bool str_block = false;
			if (c == '"') {
				c = *p++;
				if (c == '"') {
					// block string
					str_block = true;
					str_begin += 2;
					int quotes = 0;
					do {
						c = *p++;
						if (c == '\"') quotes++; else quotes = 0;
						if (quotes == 3 && *(p-4) == '\\') quotes = 0;
					} while (BLOCK_STRING_CHAR(c) && quotes < 3);
					if (quotes == 3) {
						c = *--p;
						c = *--p;
					}
					str_end = p - 1;
					if (c != '"')
						return "unterminated string or invalid character";
					c = *p++;
					if (c != '"')
						return "invalid string termination";
					c = *p++;
					if (c != '"')
						return "invalid string termination";
				} else {
					// empty string
					str_end = str_begin;
					--p;
				}
			} else {
				// normal string
				--p;
				do {
					c = *p++;
					if (c == '\\') {
						c = *p++;
						if (strchr("\"\\/bfnrtu", c)) {
							if (c == 'u') {
								c = *p++;
								if (!HEX_DIGIT(c))
									return "invalid unicode escape sequence";
								c = *p++;
								if (!HEX_DIGIT(c))
									return "invalid unicode escape sequence";
								c = *p++;
								if (!HEX_DIGIT(c))
									return "invalid unicode escape sequence";
								c = *p++;
								if (!HEX_DIGIT(c))
									return "invalid unicode escape sequence";
							} else {
								c = 'a'; // anything besides a quote to let the loop continue
							}
						} else {
							return "invalid string escape sequence";
						}
					}
				} while (STRING_CHAR(c));
				if (c != '"')
					return "unterminated string or invalid character";
				str_end = p - 1;
			}
			int str_len = str_end - str_begin;

			tok = talz(tok_list, struct graphql_token);
			list_add_tail(tok_list, &tok->node);
			tok->token_type = 's';
			tok->token_string = tal_strndup(tok, str_begin, str_len);
			tok->source_line = line_num;
			tok->source_column = str_begin - line_beginning + 1;
			tok->source_offset = str_begin - input;
			tok->source_len = str_len;

			// Process escape sequences. These always shorten the string (so the memory allocation is always enough).
			char d;
			char *q = tok->token_string;
			char *rewrite_dest;
			int quotes = 0;
			while ((d = *q++)) {
				if (str_block) {
					if (d == '\"') quotes++; else quotes = 0;
					if (quotes == 3 && *(q-4) == '\\') {
						quotes = 0;
						rewrite_dest = q - 4;
						cpystr(rewrite_dest, q - 3);
					}
				} else {
					if (d == '\\') {
						rewrite_dest = q - 1;
						d = *q++;
						switch (d) {
						case '\"':
							*rewrite_dest++ = '\"';
							cpystr(rewrite_dest, q--);
							break;
						case 'b':
							*rewrite_dest++ = '\b';
							cpystr(rewrite_dest, q--);
							break;
						case 'f':
							*rewrite_dest++ = '\f';
							cpystr(rewrite_dest, q--);
							break;
						case 'n':
							*rewrite_dest++ = '\n';
							cpystr(rewrite_dest, q--);
							break;
						case 'r':
							*rewrite_dest++ = '\r';
							cpystr(rewrite_dest, q--);
							break;
						case 't':
							*rewrite_dest++ = '\t';
							cpystr(rewrite_dest, q--);
							break;
						case 'u': {
								// Insert escaped character using UTF-8 multi-byte encoding.
								char buf[5], *b = buf;
								for (int i = 0; i < 4; i++)
									*b++ = *q++;
								*b = 0;
								int code_point = strtol(buf, 0, 16);
								int bytes = utf8_encode(code_point, rewrite_dest);
								// note: if bytes == 0
								// due to encoding failure,
								// the following will safely
								// eliminate the invalid char.
								rewrite_dest += bytes;
								cpystr(rewrite_dest, q--);
							}
							break;
						default:
							cpystr(rewrite_dest, --q);
						}
					}
				}
			}
			if (str_block) {
				// Strip leading lines.
				q = tok->token_string;
				for (;;) {
					d = *q++;
					while (WHITE_SPACE(d))
						d = *q++;
					if (LINE_TERMINATOR(d)) {
						while (LINE_TERMINATOR(d))
							d = *q++;
						cpystr(tok->token_string, q - 1);
						q = tok->token_string;
					} else
						break;
				}

				// Strip trailing lines.
				q = tok->token_string + strlen(tok->token_string);
				for (;;) {
					d = *--q;
					while (WHITE_SPACE(d))
						d = *--q;
					if (LINE_TERMINATOR(d)) {
						while (LINE_TERMINATOR(d))
							d = *--q;
						*++q = 0;
					} else
						break;
				}

				// Look for common indentation.
				char *this_indent_start;
				const char *this_indent_end;
				const char *common_indent_start = NULL;
				const char *common_indent_end = common_indent_start;
				const char *r;
				q = tok->token_string;
				do {
					d = *q++;
					this_indent_start = q - 1;
					while (WHITE_SPACE(d))
						d = *q++;
					this_indent_end = q - 1;
					if (LINE_TERMINATOR(d)) {
						while (LINE_TERMINATOR(d))
							d = *q++;
						continue;
					}
					if (EOF_CHAR(d))
						continue;

					if (common_indent_start == NULL) {
						common_indent_start = this_indent_start;
						common_indent_end = this_indent_end;
					}
					for (r = this_indent_start; r < this_indent_end && (r - this_indent_start + common_indent_start < common_indent_end); r++) {
						if (*r != *(r - this_indent_start + common_indent_start))
							break;
					}
					common_indent_end = r - this_indent_start + common_indent_start;

					while (!LINE_TERMINATOR(d) && !EOF_CHAR(d))
						d = *q++;
					while (LINE_TERMINATOR(d))
						d = *q++;
					--q;

				} while (d);

				// Remove common indentation.
				int common_indent_len = common_indent_end - common_indent_start;
				if (common_indent_len > 0) {
					q = tok->token_string;
					do {
						d = *q++;
						this_indent_start = q - 1;
						while (WHITE_SPACE(d))
							d = *q++;
						this_indent_end = q - 1;
						if (LINE_TERMINATOR(d)) {
							while (LINE_TERMINATOR(d))
								d = *q++;
							continue;
						}
						if (EOF_CHAR(d))
							continue;

						while (!LINE_TERMINATOR(d) && !EOF_CHAR(d))
							d = *q++;
						--q;

						cpystr(this_indent_start, this_indent_start + common_indent_len);
						q -= common_indent_len;
						d = *q++;

						while (LINE_TERMINATOR(d))
							d = *q++;
						--q;

					} while (d);
				}
			}
			c = *p++;
			goto newchar;

		} else {
			return "invalid source character encountered";
		}

	} while (!EOF_CHAR(c));

	return "unexpected end-of-input encountered";
}

// Convert lexed tokens into AST.
const char *graphql_parse(struct list_head *tokens, struct graphql_executable_document **doc) {
	struct list_head used = LIST_HEAD_INIT(used);
	const char *err = NULL;
	*doc = parse_executable_document(tokens, &used, &err);
	return err;
}

// Convert input string into AST.
const char *graphql_lexparse(const tal_t *ctx, const char *input, struct list_head **tokens, struct graphql_executable_document **doc) {
	const char *err = graphql_lex(ctx, input, tokens);
	if (!err)
		err = graphql_parse(*tokens, doc);
	return err;
}



