/* MIT (BSD) license - see LICENSE file for details */
#ifndef __GRAPHQL_H__
#define __GRAPHQL_H__ 1

#include <stdio.h>

#include <ccan/list/list.h>
#include <ccan/tal/tal.h>

// Coding constants
#define GRAPHQL_SUCCESS ((const char *)NULL)

// The following structures constitute the AST returned by the parser.

struct graphql_directive {
	struct graphql_directive *next;
	struct graphql_token *name;
	struct graphql_arguments *args;
	void *data; // for application use
};

struct graphql_directives {
	struct graphql_directive *first;
	void *data; // for application use
};

struct graphql_named_type {
	struct graphql_token *name;
	void *data; // for application use
};

struct graphql_type {
	struct graphql_named_type *named;
//	struct graphql_list_type *list;
//	struct graphql_non_null_type *non_null;
	void *data; // for application use
};

struct graphql_default_value {
	struct graphql_value *val;
	void *data; // for application use
};

struct graphql_variable_definition {
	struct graphql_variable_definition *next;
	struct graphql_variable *var;
	struct graphql_type *type;
	struct graphql_default_value *default_val;
	struct graphql_directives *directives;
	void *data; // for application use
};

struct graphql_variable_definitions {
	struct graphql_variable_definition *first;
	void *data; // for application use
};

struct graphql_variable {
	struct graphql_token *name;
	void *data; // for application use
};

struct graphql_object_field {
	struct graphql_object_field *next;
	struct graphql_token *name;
	struct graphql_value *val;
	void *data; // for application use
};

struct graphql_object_value {
	struct graphql_object_field *first;
	void *data; // for application use
};

struct graphql_list_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_enum_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_null_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_string_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_boolean_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_float_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_int_value {
	struct graphql_token *val;
	void *data; // for application use
};

struct graphql_value {
	struct graphql_variable *var;
	struct graphql_int_value *int_val;
	struct graphql_float_value *float_val;
	struct graphql_boolean_value *bool_val;
	struct graphql_string_value *str_val;
	struct graphql_null_value *null_val;
	struct graphql_enum_value *enum_val;
	struct graphql_list_value *list_val;
	struct graphql_object_value *obj_val;
	void *data; // for application use
};

struct graphql_inline_fragment {
	struct graphql_type_condition *type_cond;
	struct graphql_directives *directives;
	struct graphql_selection_set *sel_set;
	void *data; // for application use
};

struct graphql_type_condition {
	struct graphql_named_type *named_type;
	void *data; // for application use
};

struct graphql_fragment_name {
	struct graphql_token *name;
	void *data; // for application use
};

struct graphql_fragment_definition {
	struct graphql_fragment_name *name;
	struct graphql_type_condition *type_cond;
	struct graphql_directives *directives;
	struct graphql_selection_set *sel_set;
	void *data; // for application use
};

struct graphql_fragment_spread {
	struct graphql_fragment_name *name;
	struct graphql_directives *directives;
	void *data; // for application use
};

struct graphql_alias {
	struct graphql_token *name;
	void *data; // for application use
};

struct graphql_argument {
	struct graphql_argument *next;
	struct graphql_token *name;
	struct graphql_value *val;
	void *data; // for application use
};

struct graphql_arguments {
	struct graphql_argument *first;
	void *data; // for application use
};

struct graphql_field {
	struct graphql_alias *alias;
	struct graphql_token *name;
	struct graphql_arguments *args;
	struct graphql_directives *directives;
	struct graphql_selection_set *sel_set;
	void *data; // for application use
};

struct graphql_selection {
	struct graphql_selection *next;
	struct graphql_field *field;
	struct graphql_fragment_spread *frag_spread;
	struct graphql_inline_fragment *inline_frag;
	void *data; // for application use
};

struct graphql_selection_set {
	struct graphql_selection *first;
	void *data; // for application use
};

struct graphql_operation_type {
	struct graphql_token *op_type;
	void *data; // for application use
};

struct graphql_operation_definition {
	struct graphql_operation_type *op_type;
	struct graphql_token *op_name;
	struct graphql_variable_definitions *vars;
	struct graphql_directives *directives;
	struct graphql_selection_set *sel_set;
	void *data; // for application use
};

struct graphql_executable_definition {
	struct graphql_executable_definition *next_def;
	struct graphql_operation_definition *op_def;
	struct graphql_fragment_definition *frag_def;
	void *data; // for application use
};

struct graphql_executable_document {
	struct graphql_executable_definition *first_def;
	void *data; // for application use
};

struct graphql_definition {
	struct graphql_definition *next_def;
	struct graphql_executable_definition *executable_def;
	struct graphql_type_system_definition_or_extension *type_system_def;
	void *data; // for application use
};

struct graphql_document {
	struct graphql_definition *first_def;
	void *data; // for application use
};

enum token_type_enum {
	NAME		= 'a',
	INTEGER		= 'i',
	FLOAT		= 'f',
	STRING		= 's',
	PUNCT_BANG	= '!',
	PUNCT_SH__	= '$',
	PUNCT_AMP	= '&',
	PUNCT_LPAR	= '(',
	PUNCT_RPAR	= ')',
	PUNCT_COLON	= ':',
	PUNCT_EQ	= '=',
	PUNCT_AT	= '@',
	PUNCT_LBRACKET	= '[',
	PUNCT_RBRACKET	= ']',
	PUNCT_LBRACE	= '{',
	PUNCT_PIPE	= '|',
	PUNCT_RBRACE	= '}',
	PUNCT_SPREAD	= 0x2026, // spread operator (triple dot)
};

struct graphql_token {
	struct list_node node;
	enum token_type_enum token_type;
	char *token_string;
	unsigned int source_line;
	unsigned int source_column;
	unsigned int source_offset;
	unsigned int source_len;
	void *data; // for application use
};

/* The lexer.
 * INPUTS:
 *	input - string to parse
 *	ctx - parent tal context or NULL
 *	tokens - a variable to receive the resulting token list
 * RETURN:
 *	GRAPHQL_SUCCESS or an error string.
 */
const char *graphql_lex(const tal_t *ctx, const char *input, struct list_head **tokens);

/* The parser.
 * INPUTS:
 *	tokens - the list produced by the lexer
 *	doc - a variable to receive the resulting abstract syntax tree (AST)
 * OPERATION:
 *	The token list is emptied during parsing, so far as the parsing
 *	succeeds. This allows the caller to inspect the line/char position
 *	of the next token (where the error likely is) and report that hint to
 *	the user in the form of an error message.
 * RETURN:
 *	GRAPHQL_SUCCESS or an error string.
 */
const char *graphql_parse(struct list_head *tokens, struct graphql_executable_document **doc);

/* The lexer and parser in one function, for convenience. */
const char *graphql_lexparse(const tal_t *ctx, const char *input, struct list_head **tokens, struct graphql_executable_document **doc);

#endif

