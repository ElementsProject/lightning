/* Include the C files directly. */
#include "ccan/graphql/graphql.c"
#include "ccan/str/str.h"

/* TEST POINT MACROS
 *
 * The idea here is to run each test case silently, and if any test point
 * fails, that test case is re-run verbosely to pinpoint the failure.
 *
 * RUN macros run a whole test case function.
 *
 * Different TEST_xxxx macros are provided for different test point types as
 * follows:
 *
 *  TEST_CONT - Test and continue testing regardless of failure (the failure
 *		will still be printed).
 *  TEST_ABRT - Test and abort the test case, used when testing pointer
 *		validity to avoid subsequent dereference errors.
 *  TEST_STRG - Test a string value, which includes the convenience of testing
 *		for a null pointer.
 */

#define RUN(test) { prev_fail = fail; test(source); if (fail != prev_fail) { mute = false; test(source); mute = true; } }
#define RUN1(test,arg) { prev_fail = fail; test(source,arg); if (fail != prev_fail) { mute = false; test(source,arg); mute = true; } }
#define RUN2(test,arg1,arg2) { prev_fail = fail; test(source,arg1,arg2); if (fail != prev_fail) { mute = false; test(source,arg1,arg2); mute = true; } }

#define TEST_CONT(expr) { bool c = (expr); if (mute) c? pass++ : fail++; else printf("%s: %s\033[0m\n", c? "passed" : "\033[91mfailed", stringify(expr)); }
#define TEST_ABRT(expr) { bool c = (expr); if (mute) c? pass++ : fail++; else printf("%s: %s\033[0m\n", c? "passed" : "\033[91mfailed", stringify(expr)); if (!c) return; }
#define TEST_STRG(str,expr) { bool c = ((str) && streq((str),(expr))); if (mute) c? pass++ : fail++; else printf("%s: %s == %s\033[0m\n", c? "passed" : "\033[91mfailed", stringify(str), stringify(expr)); if (!c) return; }

// Global variables to track overall results.
int pass = 0, fail = 0;
bool mute = 1;

// Helper function.
int listlen(struct list_head *tokens);
int listlen(struct list_head *tokens) {
	struct graphql_token *tok;
	int n=0;
	list_for_each(tokens, tok, node) {
		n++;
	}
	return n;
}

/* Test case function prototypes */

void check_example_3(const char *source);
void check_example_5(char *source);
void check_example_6(char *source);
void check_example_7(char *source);
void check_example_8(char *source);
void check_example_9(char *source);
void check_example_10(char *source);
void check_example_11(char *source);
void check_example_12_and_13(const char *source);
void check_example_14(char *source);
void check_example_16(char *source);
void check_example_18(char *source);
void check_example_19(char *source);
void check_example_20(char *source);
void check_example_21(char *source);
void check_example_23(char *source);
void check_example_24(char *source);
void check_int_value(char *source, int int_value);
void check_invalid_int_values(char *source);
void check_float_value(char *source, float float_value, const char *format);
void check_valid_float_values(char *source);
void check_invalid_float_values(char *source);
void check_boolean_values(char *source);
void check_string_value(char *source, const char *test_value, const char *expected_result);
void check_example_25_and_26(const char *source);
void check_example_29(char *source);
void check_example_30_and_31(const char *source);
void check_example_32(char *source);
void check_example_34(char *source);
void check_example_35(char *source);

/* Test case functions begin here, called by main().
 * Note: Memory should be freed correctly in the success case, but if there
 * are errors, all bets are off.
 */

void check_example_3(const char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 3\n");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 11);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	TEST_CONT(tok->source_line == 1);
	TEST_CONT(tok->source_column == 1);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 4);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '(');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 7);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 8);
	TEST_CONT(tok->source_len == 2);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == ':');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 10);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 12);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == ')');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 13);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 15);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	TEST_CONT(tok->source_line == 3);
	TEST_CONT(tok->source_column == 5);
	TEST_CONT(tok->source_len == 4);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	TEST_CONT(tok->source_line == 4);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	TEST_CONT(tok->source_line == 5);
	TEST_CONT(tok->source_column == 1);
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "name");
	tokens = tal_free(tokens);
}

void check_example_5(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 5\n");

	sprintf(source, "\
mutation {\n\
  likeStory(storyID: 12345) {\n\
    story {\n\
      likeCount\n\
    }\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 15);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "mutation");
	TEST_CONT(tok->source_line == 1);
	TEST_CONT(tok->source_column == 1);
	TEST_CONT(tok->source_len == 8);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "likeStory");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 9);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "storyID");
	TEST_CONT(tok->source_line == 2);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "12345");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 22);
	TEST_CONT(tok->source_len == 5);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "story");
	TEST_CONT(tok->source_line == 3);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "likeCount");
	TEST_CONT(tok->source_line == 4);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_ABRT(doc->first_def->op_def->op_type != NULL);
	TEST_ABRT(doc->first_def->op_def->op_type->op_type != NULL);
	TEST_CONT(doc->first_def->op_def->op_type->op_type->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->op_type->op_type->token_string, "mutation");
	TEST_ABRT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "likeStory");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "storyID");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "12345");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "story");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field->name->token_string, "likeCount");
	tokens = tal_free(tokens);
}

void check_example_6(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 6\n");

	sprintf(source, "\
{\n\
  field\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 3);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "field");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 5);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_ABRT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "field");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set == NULL);
	tokens = tal_free(tokens);
}

void check_example_7(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 7\n");

	sprintf(source, "\
{\n\
  id\n\
  firstName\n\
  lastName\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 5);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 2);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "firstName");
	TEST_CONT(tok->source_line == 3);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 9);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "lastName");
	TEST_CONT(tok->source_line == 4);
	TEST_CONT(tok->source_column == 3);
	TEST_CONT(tok->source_len == 8);
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node);
	TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_ABRT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->next->field->name->token_string, "firstName");
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->next->next->field->name->token_string, "lastName");
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_8(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 8\n");

	sprintf(source, "\
{\n\
  me {\n\
    id\n\
    firstName\n\
    lastName\n\
    birthday {\n\
      month\n\
      day\n\
    }\n\
    friends {\n\
      name\n\
    }\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 17);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "me");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "firstName");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "lastName");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "birthday");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "month");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "day");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "friends");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_ABRT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "me");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "firstName");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_string, "lastName");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name->token_string, "birthday");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->name->token_string, "month");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->name->token_string, "day");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set->first->next->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->name->token_string, "friends");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->field->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_9(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 9\n");

	sprintf(source, "\
# `me` could represent the currently logged in viewer.\n\
{\n\
  me {\n\
    name\n\
  }\n\
}\n\
\n\
# `user` represents one of many users in a graph of data, referred to by a\n\
# unique identifier.\n\
{\n\
  user(id: 4) {\n\
    name\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 17);
	// NOTE: Comments are ignored.
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "me");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->next_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_ABRT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "me");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->next_def->next_def == NULL);
	TEST_CONT(doc->first_def->next_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->next_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "name");
	tokens = tal_free(tokens);
}

void check_example_10(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 10\n");

	sprintf(source, "\
{\n\
  user(id: 4) {\n\
    id\n\
    name\n\
    profilePic(size: 100)\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 18);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profilePic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "size");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "100");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_string, "profilePic");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_string, "size");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_string, "100");
	tokens = tal_free(tokens);
}

void check_example_11(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 11\n");

	sprintf(source, "\
{\n\
  user(id: 4) {\n\
    id\n\
    name\n\
    profilePic(width: 100, height: 50)\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 21);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profilePic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "width");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "100");
	// NOTE: Comma is ignored.
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "height");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "50");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_string, "profilePic");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_string, "width");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_string, "100");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->name->token_string, "height");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next->val->int_val->val->token_string, "50");
	tokens = tal_free(tokens);
}

void check_example_12_and_13(const char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example Nos. 12 and 13\n");

	// Test the lexer.
	const char *param;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 11);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "picture");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_ABRT(tok->token_string != NULL && (streq(tok->token_string, "width") || streq(tok->token_string, "height")));
	param = tok->token_string;
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_CONT(tok->token_string != NULL && ((streq(param, "width") && streq(tok->token_string, "200")) || (streq(param, "height") && streq(tok->token_string, "100"))));
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_CONT(tok->token_string != NULL && (streq(tok->token_string, "width") || streq(tok->token_string, "height")));
	param = tok->token_string;
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_CONT(tok->token_string != NULL && ((streq(param, "width") && streq(tok->token_string, "200")) || (streq(param, "height") && streq(tok->token_string, "100"))));
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_argument *arg;
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "picture");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next->next == NULL);
	arg = doc->first_def->op_def->sel_set->first->field->args->first;
	if (!streq(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "width")) arg = arg->next;
	TEST_ABRT(arg->name != NULL);
	TEST_CONT(arg->name->token_type == 'a');
	TEST_STRG(arg->name->token_string, "width");
	TEST_ABRT(arg->val != NULL);
	TEST_ABRT(arg->val->int_val != NULL);
	TEST_ABRT(arg->val->int_val->val != NULL);
	TEST_CONT(arg->val->int_val->val->token_type == 'i');
	TEST_STRG(arg->val->int_val->val->token_string, "200");
	arg = doc->first_def->op_def->sel_set->first->field->args->first;
	if (!streq(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "height")) arg = arg->next;
	TEST_ABRT(arg->name != NULL);
	TEST_CONT(arg->name->token_type == 'a');
	TEST_STRG(arg->name->token_string, "height");
	TEST_ABRT(arg->val != NULL);
	TEST_ABRT(arg->val->int_val != NULL);
	TEST_ABRT(arg->val->int_val->val != NULL);
	TEST_CONT(arg->val->int_val->val->token_type == 'i');
	TEST_STRG(arg->val->int_val->val->token_string, "100");
	tokens = tal_free(tokens);
}

void check_example_14(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 14\n");

	sprintf(source, "\
{\n\
  user(id: 4) {\n\
    id\n\
    name\n\
    smallPic: profilePic(size: 64)\n\
    bigPic: profilePic(size: 1024)\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 28);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "smallPic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profilePic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "size");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "64");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "bigPic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profilePic");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "size");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "1024");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias->name->token_string, "smallPic");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_string, "profilePic");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_string, "size");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->int_val->val->token_string, "64");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->alias != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->alias->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->alias->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->alias->name->token_string, "bigPic");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->name->token_string, "profilePic");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->name->token_string, "size");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->val->int_val->val->token_string, "1024");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next->field->args->first->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_16(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 16\n");

	sprintf(source, "\
{\n\
  zuck: user(id: 4) {\n\
    id\n\
    name\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 14);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "zuck");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, "4");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->alias != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->alias->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->alias->name->token_string, "zuck");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_18(char *source) {
	struct list_head *tokens;

	if (!mute) printf("// Example No. 18\n");

	sprintf(source, "\
query noFragments {\n\
  user(id: 4) {\n\
    friends(first: 10) {\n\
      id\n\
      name\n\
      profilePic(size: 50)\n\
    }\n\
    mutualFriends(first: 10) {\n\
      id\n\
      name\n\
      profilePic(size: 50)\n\
    }\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 44);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_19(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 19\n");

	sprintf(source, "\
query withFragments {\n\
  user(id: 4) {\n\
    friends(first: 10) {\n\
      ...friendFields\n\
    }\n\
    mutualFriends(first: 10) {\n\
      ...friendFields\n\
    }\n\
  }\n\
}\n\
\n\
fragment friendFields on User {\n\
  id\n\
  name\n\
  profilePic(size: 50)\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 46);
	for (int i=0; i<17; i++)
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 0x2026);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "friendFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	for (int i=0; i<7; i++)
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 0x2026);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "friendFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	const char *e;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT((e = graphql_parse(tokens, &doc)) == NULL);
	if (e) printf("%s\n", e);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name->token_string, "friendFields");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name->token_string, "friendFields");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next == NULL);
	TEST_ABRT(doc->first_def->next_def != NULL);
	TEST_CONT(doc->first_def->next_def->next_def == NULL);
	TEST_CONT(doc->first_def->next_def->op_def == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->name->name->token_string, "friendFields");
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_string, "User");
	TEST_CONT(doc->first_def->next_def->frag_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_20(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 20\n");

	sprintf(source, "\
query withNestedFragments {\n\
  user(id: 4) {\n\
    friends(first: 10) {\n\
      ...friendFields\n\
    }\n\
    mutualFriends(first: 10) {\n\
      ...friendFields\n\
    }\n\
  }\n\
}\n\
\n\
fragment friendFields on User {\n\
  id\n\
  name\n\
  ...standardProfilePic\n\
}\n\
\n\
fragment standardProfilePic on User {\n\
  profilePic(size: 50)\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 54);
	for (int i=0; i<17; i++)
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 0x2026);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "friendFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	for (int i=0; i<7; i++)
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 0x2026);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "friendFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	const char *e;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT((e = graphql_parse(tokens, &doc)) == NULL);
	if (e) printf("%s\n", e);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set->first->frag_spread->name->name->token_string, "friendFields");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set->first->frag_spread->name->name->token_string, "friendFields");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next == NULL);
	TEST_ABRT(doc->first_def->next_def != NULL);
	TEST_CONT(doc->first_def->next_def->op_def == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->name->name->token_string, "friendFields");
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_string, "User");
	TEST_CONT(doc->first_def->next_def->frag_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->next->next->field == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->next->frag_spread != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next->next->next == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->next_def == NULL);
	TEST_CONT(doc->first_def->next_def->next_def->op_def == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->name != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->name->name != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->next_def->frag_def->name->name->token_string, "standardProfilePic");
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name->token_string, "User");
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->sel_set->first->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_21(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 21\n");

	sprintf(source, "\
query FragmentTyping {\n\
  profiles(handles: [\"zuck\", \"coca-cola\"]) {\n\
    handle\n\
    ...userFragment\n\
    ...pageFragment\n\
  }\n\
}\n\
\n\
fragment userFragment on User {\n\
  friends {\n\
    count\n\
  }\n\
}\n\
\n\
fragment pageFragment on Page {\n\
  likers {\n\
    count\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 40);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "query");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "FragmentTyping");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profiles");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "handles");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '[');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	TEST_STRG(tok->token_string, "zuck");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	TEST_STRG(tok->token_string, "coca-cola");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ']');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	const char *e;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT((e = graphql_parse(tokens, &doc)) == NULL);
	if (e) printf("%s\n", e);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread->name->name->token_string, "userFragment");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread->name != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread->name->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread->name->name->token_string, "pageFragment");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_ABRT(doc->first_def->next_def != NULL);
	TEST_CONT(doc->first_def->next_def->op_def == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->name->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->name->name->token_string, "userFragment");
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->frag_def->type_cond->named_type->name->token_string, "User");
	TEST_CONT(doc->first_def->next_def->frag_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->next_def->frag_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->next_def->frag_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->next_def == NULL);
	TEST_CONT(doc->first_def->next_def->next_def->op_def == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->name != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->name->name != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->name->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->next_def->frag_def->name->name->token_string, "pageFragment");
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->next_def->next_def->frag_def->type_cond->named_type->name->token_string, "Page");
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->directives == NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->next_def->next_def->frag_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->next_def->next_def->frag_def->sel_set->first->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_23(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 23\n");

	sprintf(source, "\
query inlineFragmentTyping {\n\
  profiles(handles: [\"zuck\", \"coca-cola\"]) {\n\
    handle\n\
    ... on User {\n\
      friends {\n\
        count\n\
      }\n\
    }\n\
    ... on Page {\n\
      likers {\n\
        count\n\
      }\n\
    }\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 34);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "query");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "inlineFragmentTyping");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "profiles");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "handles");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '[');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	TEST_STRG(tok->token_string, "zuck");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	TEST_STRG(tok->token_string, "coca-cola");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ']');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	const char *e;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT((e = graphql_parse(tokens, &doc)) == NULL);
	if (e) printf("%s\n", e);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->type_cond != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->type_cond->named_type->name->token_string, "User");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->type_cond != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->type_cond->named_type->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->type_cond->named_type->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->type_cond->named_type->name->token_string, "Page");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	tokens = tal_free(tokens);
}

void check_example_24(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 24\n");

	sprintf(source, "\
query inlineFragmentNoType($expandedInfo: Boolean) {\n\
  user(handle: \"zuck\") {\n\
    id\n\
    name\n\
    ... @include(if: $expandedInfo) {\n\
      firstName\n\
      lastName\n\
      birthday\n\
    }\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 34);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "query");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "inlineFragmentNoType");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '$');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "expandedInfo");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "Boolean");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "user");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "handle");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	TEST_STRG(tok->token_string, "zuck");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "id");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "name");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 0x2026);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '@');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "include");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "if");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '$');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "expandedInfo");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "firstName");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "lastName");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "birthday");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->type_cond == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->name->token_string, "include");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->name->token_string, "if");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->int_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->float_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->bool_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->str_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->null_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->enum_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->list_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->obj_val == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->var != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->var->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->var->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->directives->first->args->first->val->var->name->token_string, "expandedInfo");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->next->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	tokens = tal_free(tokens);
}

void check_int_value(char *source, int int_value) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Int Value Range Check on %d\n", int_value);

	sprintf(source, "\
{\n\
  user(id: %d) {\n\
    name\n\
  }\n\
}\n\
	", int_value);

	char buf[20];
	sprintf(buf, "%d", int_value);

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 11);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	TEST_STRG(tok->token_string, buf);
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 12);
	TEST_CONT(tok->source_len == strlen(buf));
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 12 + strlen(buf));
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, buf);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	tokens = tal_free(tokens);
}

void check_invalid_int_values(char *source) {
	struct list_head *tokens;

	if (!mute) printf("// Invalid Int Values\n");

	const char *bad_values[] = {"00", "-00", "+1", "1.", "1a", "1e", "0x123", "123L", 0};

	for (int i=0; bad_values[i]; i++) {
		sprintf(source, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
		", bad_values[i]);

		// Test the lexer.
		TEST_CONT(graphql_lex(NULL, source, &tokens) != NULL);
		TEST_ABRT(listlen(tokens) == 5);
		tokens = tal_free(tokens);

		// No need to test parser when lexer fails.
	}
}

void check_float_value(char *source, float float_value, const char *format) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Float Value Range Check on %f\n", float_value);

	char buf[100];
	sprintf(buf, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
	", format);
	sprintf(source, buf, float_value);
	sprintf(buf, format, float_value);

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 11);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'f');
	TEST_STRG(tok->token_string, buf);
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 12);
	TEST_CONT(tok->source_len == strlen(buf));
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	TEST_CONT(tok->source_line == 2);
	TEST_CONT(tok->source_column == 12 + strlen(buf));
	TEST_CONT(tok->source_len == 1);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val->token_type == 'f');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val->token_string, buf);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	tokens = tal_free(tokens);
}

void check_valid_float_values(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Valid Float Values\n");

	const char *good_values[] = {"1.0", "1e50", "6.0221413e23", "1.23", 0};

	for (int i=0; good_values[i]; i++) {
		sprintf(source, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
		", good_values[i]);

		// Test the lexer.
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_ABRT(listlen(tokens) == 11);
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'f');
		TEST_STRG(tok->token_string, good_values[i]);
		TEST_CONT(tok->source_line == 2);
		TEST_CONT(tok->source_column == 12);
		TEST_CONT(tok->source_len == strlen(good_values[i]));
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
		TEST_CONT(tok->source_line == 2);
		TEST_CONT(tok->source_column == 12 + strlen(good_values[i]));
		TEST_CONT(tok->source_len == 1);
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
		tokens = tal_free(tokens);

		// Test the parser.
		struct graphql_executable_document *doc;
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_CONT(graphql_parse(tokens, &doc) == NULL);
		TEST_ABRT(doc != NULL);
		TEST_ABRT(doc->first_def != NULL);
		TEST_ABRT(doc->first_def->op_def != NULL);
		TEST_CONT(doc->first_def->next_def == NULL);
		TEST_CONT(doc->first_def->frag_def == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val->token_type == 'f');
		TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val->val->token_string, good_values[i]);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
		tokens = tal_free(tokens);
	}
}

void check_invalid_float_values(char *source) {
	struct list_head *tokens;

	if (!mute) printf("// Invalid Float Values\n");

	const char *bad_values[] = {"00.0", "-00.0", "00e1", "1.23.4", "0x1.2p3", 0};

	for (int i=0; bad_values[i]; i++) {
		sprintf(source, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
		", bad_values[i]);

		// Test the lexer.
		TEST_CONT(graphql_lex(NULL, source, &tokens) != NULL);
		TEST_ABRT(listlen(tokens) == 5);
		tokens = tal_free(tokens);

		// No need to test parser when lexer fails.
	}
}

void check_boolean_values(char *source) {
	struct list_head *tokens;

	if (!mute) printf("// Boolean Values\n");

	const char *good_values[] = {"true", "false", 0};

	for (int i=0; good_values[i]; i++) {
		sprintf(source, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
		", good_values[i]);

		// Test the lexer.
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_ABRT(listlen(tokens) == 11);
		tokens = tal_free(tokens);

		// Test the parser.
		struct graphql_executable_document *doc;
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_CONT(graphql_parse(tokens, &doc) == NULL);
		TEST_ABRT(doc != NULL);
		TEST_ABRT(doc->first_def != NULL);
		TEST_ABRT(doc->first_def->op_def != NULL);
		TEST_CONT(doc->first_def->next_def == NULL);
		TEST_CONT(doc->first_def->frag_def == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val->val->token_type == 'a');
		TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val->val->token_string, good_values[i]);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
		tokens = tal_free(tokens);
	}

	const char *bad_values[] = {"True", "False", "TRUE", "FALSE", 0};

	for (int i=0; bad_values[i]; i++) {
		sprintf(source, "\
{\n\
  user(id: %s) {\n\
    name\n\
  }\n\
}\n\
		", bad_values[i]);

		// Test the lexer.
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_ABRT(listlen(tokens) == 11);
		tokens = tal_free(tokens);

		// Test the parser (it will succeed in parsing the bad values as enum values, not boolean values).
		struct graphql_executable_document *doc;
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_CONT(graphql_parse(tokens, &doc) == NULL);
		TEST_ABRT(doc != NULL);
		TEST_ABRT(doc->first_def != NULL);
		TEST_ABRT(doc->first_def->op_def != NULL);
		TEST_CONT(doc->first_def->next_def == NULL);
		TEST_CONT(doc->first_def->frag_def == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->var == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->list_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val->val->token_type == 'a');
		TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val->val->token_string, bad_values[i]);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
		tokens = tal_free(tokens);
	}
}

void check_string_value(char *source, const char *test_value, const char *expected_result) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// String Value Test: %s\n", test_value);

	sprintf(source, "\
{\n\
  user(id:%s) {\n\
    name\n\
  }\n\
}\n\
	", test_value);

	bool block = (test_value[0]=='\"' && test_value[1]=='\"' && test_value[2]=='\"')? true: false;
	if (expected_result) {
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_ABRT(listlen(tokens) == 11);
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
		TEST_STRG(tok->token_string, expected_result);
		TEST_CONT(tok->source_line == 2);
		TEST_CONT(tok->source_column == 11 + (block? 3: 1));
		TEST_CONT(tok->source_len == strlen(test_value) - (block? 6: 2));
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
		TEST_CONT(tok->source_line == 2);
		TEST_CONT(tok->source_column == 11 + strlen(test_value));
		TEST_CONT(tok->source_len == 1);
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
		tokens = tal_free(tokens);

		// Test the parser (it will succeed in parsing the bad values as enum values, not boolean values).
		struct graphql_executable_document *doc;
		TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
		TEST_CONT(graphql_parse(tokens, &doc) == NULL);
		TEST_ABRT(doc != NULL);
		TEST_ABRT(doc->first_def != NULL);
		TEST_ABRT(doc->first_def->op_def != NULL);
		TEST_CONT(doc->first_def->next_def == NULL);
		TEST_CONT(doc->first_def->frag_def == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->var == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->list_val == NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val->val != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val->val->token_type == 's');
		TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val->val->token_string, expected_result);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
		TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next == NULL);
		TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
		tokens = tal_free(tokens);
	} else {
		TEST_CONT(graphql_lex(NULL, source, &tokens) != NULL);
		tokens = tal_free(tokens);
	}
}

void check_example_25_and_26(const char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 25 and 26\n");

	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	while ((tok = list_pop(tokens, struct graphql_token, node)) && tok->token_type != 's') { }
	if (tok) {
		TEST_STRG(tok->token_string, "Hello,\n  World!\n\nYours,\n  GraphQL.");
	}

	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	tokens = tal_free(tokens);
}

void check_example_29(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 29\n");

	sprintf(source, "\
{\n\
  field(arg: null)\n\
  field\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 9);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "null");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "field");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "arg");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->var == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->list_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val->val->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val->val->token_string, "null");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->next->field->name->token_string, "field");
	TEST_CONT(doc->first_def->op_def->sel_set->first->next->field->args == NULL);
	tokens = tal_free(tokens);
}

void check_example_30_and_31(const char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 30 and 31\n");

	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 15);
	while ((tok = list_pop(tokens, struct graphql_token, node)) && !(tok->token_type == 'a' && tok->token_string != NULL && streq(tok->token_string, "lat"))) { }
	TEST_CONT(tok);
	if (tok) {
		TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'f');
		TEST_STRG(tok->token_string, "-53.211");
	}
	tokens = tal_free(tokens);

	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	while ((tok = list_pop(tokens, struct graphql_token, node)) && !(tok->token_type == 'a' && tok->token_string != NULL && streq(tok->token_string, "lon"))) { }
	TEST_CONT(tok);
	if (tok) {
		TEST_CONT(tok->token_type == 'a');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
		tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'f');
		TEST_STRG(tok->token_string, "12.43");
	}
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	const char *e;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT((e = graphql_parse(tokens, &doc)) == NULL);
	if (e) printf("%s\n", e);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_CONT(doc->first_def->op_def->op_type == NULL);
	TEST_CONT(doc->first_def->op_def->op_name == NULL);
	TEST_CONT(doc->first_def->op_def->vars == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "nearestThing");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "location");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->var == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->float_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->bool_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->enum_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->list_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->null_val == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->str_val == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->name->token_type == 'a');
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->val->float_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->val->float_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->val->float_val->val->token_type == 'f');
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->name->token_type == 'a');
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->val->float_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->val->float_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->val->float_val->val->token_type == 'f');
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->obj_val->first->next->next == NULL);
	tokens = tal_free(tokens);
}

void check_example_32(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 32\n");

	sprintf(source, "\
query getZuckProfile($devicePicSize: Int) {\n\
  user(id: 4) {\n\
    id\n\
    name\n\
    profilePic(size: $devicePicSize)\n\
  }\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 27);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '$');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'i');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '$');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// Test the parser.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(graphql_parse(tokens, &doc) == NULL);
	TEST_ABRT(doc != NULL);
	TEST_ABRT(doc->first_def != NULL);
	TEST_CONT(doc->first_def->next_def == NULL);
	TEST_CONT(doc->first_def->frag_def == NULL);
	TEST_ABRT(doc->first_def->op_def != NULL);
	TEST_ABRT(doc->first_def->op_def->op_type != NULL);
	TEST_ABRT(doc->first_def->op_def->op_type->op_type != NULL);
	TEST_CONT(doc->first_def->op_def->op_type->op_type->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->op_type->op_type->token_string, "query");
	TEST_CONT(doc->first_def->op_def->op_name != NULL);
	TEST_CONT(doc->first_def->op_def->op_name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->op_name->token_string, "getZuckProfile");
	TEST_ABRT(doc->first_def->op_def->vars != NULL);
	TEST_ABRT(doc->first_def->op_def->vars->first != NULL);
	TEST_CONT(doc->first_def->op_def->vars->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->vars->first->var != NULL);
	TEST_ABRT(doc->first_def->op_def->vars->first->var->name != NULL);
	TEST_CONT(doc->first_def->op_def->vars->first->var->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->vars->first->var->name->token_string, "devicePicSize");
	TEST_ABRT(doc->first_def->op_def->vars->first->type != NULL);
//	TEST_CONT(doc->first_def->op_def->vars->first->type->list == NULL);
//	TEST_CONT(doc->first_def->op_def->vars->first->type->non_null == NULL);
	TEST_ABRT(doc->first_def->op_def->vars->first->type->named != NULL);
	TEST_ABRT(doc->first_def->op_def->vars->first->type->named->name != NULL);
	TEST_CONT(doc->first_def->op_def->vars->first->type->named->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->vars->first->type->named->name->token_string, "Int");
	TEST_CONT(doc->first_def->op_def->vars->first->default_val == NULL);
	TEST_CONT(doc->first_def->op_def->vars->first->directives == NULL);
	TEST_CONT(doc->first_def->op_def->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->name->token_string, "user");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->name->token_string, "id");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_type == 'i');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->args->first->val->int_val->val->token_string, "4");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->directives == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->name->token_string, "id");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->name->token_string, "name");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->args == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->next == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->frag_spread == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->inline_frag == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->alias == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->name->token_string, "profilePic");
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->directives == NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->sel_set == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->next == NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->name->token_string, "size");
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->var != NULL);
	TEST_ABRT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->var->name != NULL);
	TEST_CONT(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->var->name->token_type == 'a');
	TEST_STRG(doc->first_def->op_def->sel_set->first->field->sel_set->first->next->next->field->args->first->val->var->name->token_string, "devicePicSize");
	tokens = tal_free(tokens);
}

void check_example_34(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 34\n");

	sprintf(source, "\
type Person\n\
  @addExternalFields(source: \"profiles\")\n\
  @excludeField(name: \"photo\") {\n\
  name: String\n\
}\n\
	");

	// Test the lexer.
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 21);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '@');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "addExternalFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '@');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "excludeField");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// The type system is not yet implemented, so parsing will fail here.
	// This could be "phase 2" of this project.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) != NULL);
	tokens = tal_free(tokens);
}

void check_example_35(char *source) {
	struct list_head *tokens;
	struct graphql_token *tok;

	if (!mute) printf("// Example No. 35\n");

	sprintf(source, "\
type Person\n\
  @excludeField(name: \"photo\")\n\
  @addExternalFields(source: \"profiles\") {\n\
  name: String\n\
}\n\
	");

	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_ABRT(listlen(tokens) == 21);
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '@');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "excludeField");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '@');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	TEST_STRG(tok->token_string, "addExternalFields");
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '(');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 's');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ')');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '{');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == ':');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == 'a');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok->token_type == '}');
	tok = list_pop(tokens, struct graphql_token, node); TEST_CONT(tok == NULL);
	tokens = tal_free(tokens);

	// The type system is not yet implemented, so parsing will fail here.
	// This could be "phase 2" of this project.
	struct graphql_executable_document *doc;
	TEST_CONT(graphql_lex(NULL, source, &tokens) == NULL);
	TEST_CONT(graphql_parse(tokens, &doc) != NULL);
	tokens = tal_free(tokens);
}

/* End of test case functions. */

/* Beginning of main() test run to run all test cases. */

int main(void)
{
	printf("\nTesting GraphQL lexer/parser...\n");

	char source[1024];
	int prev_fail; // Used by RUNx macros.

	// Check the lexer with all valid line terminators.
	const char *new_line = "\n";
	const char *carriage_return = "\r";
	const char *carriage_return_new_line = "\r\n";
	const char *line_terminators[] = { new_line, carriage_return, carriage_return_new_line };
	for (int i=0; i<3; i++) {
		sprintf(source, "\
{%s\
  user(id: 4) {%s\
    name%s\
  }%s\
}%s\
		", line_terminators[i], line_terminators[i], line_terminators[i], line_terminators[i], line_terminators[i]);

		RUN(check_example_3);
	}

	RUN(check_example_5); // Parse a mutation operation and check results.

	RUN(check_example_6); // Parse an unnamed query and check results.

	RUN(check_example_7); // Parse multiple fields in a selection set and check results.
	RUN(check_example_8); // Parse complex data structure and check results.
	RUN(check_example_9); // Parse example of top-level fields and check results.
	RUN(check_example_10); // Parse example with parameterized field and check results.
	RUN(check_example_11); // Parse example with multiple field arguments and check results.

	// Parse examples of different parameter order and check for identical results.
	sprintf(source, "\
{\n\
  picture(width: 200, height: 100)\n\
}\n\
	");
	RUN(check_example_12_and_13);
	sprintf(source, "\
{\n\
  picture(height: 100, width: 200)\n\
}\n\
	");
	RUN(check_example_12_and_13);

	RUN(check_example_14); // Parse alias example and check results.
	RUN(check_example_16); // Parse a top-level-field alias example and check results.

	RUN(check_example_18); // Parse example and check results.

	RUN(check_example_19); // Parse fragment example and check results.
	RUN(check_example_20); // Parse another fragment example and check results.
	RUN(check_example_21); // Parse fragment typing example and check results.
	RUN(check_example_23); // Parse fragment typing example and check results.
	RUN(check_example_24); // Parse fragment typing example and check results.

	// Parse various int values and check results.
	for (int i=        -15; i<=         15; i++) { RUN1(check_int_value, i); }
	for (int i=     -32770; i<=     -32765; i++) { RUN1(check_int_value, i); }
	for (int i=      32765; i<=      32770; i++) { RUN1(check_int_value, i); }
	for (int i=-2147483648; i<=-2147483645; i++) { RUN1(check_int_value, i); }
	for (int i= 2147483647; i>= 2147483645; i--) { RUN1(check_int_value, i); }
	RUN(check_invalid_int_values);

	// Parse various float values and check results.
	for (float i=   -1.0; i<=    1.0; i+=    0.1) { RUN2(check_float_value, i, "%1.1f"); }
	for (float i=-327.70; i<=-327.65; i+=   0.01) { RUN2(check_float_value, i, "%1.2f"); }
	for (float i= 327.65; i<= 327.70; i+=   0.01) { RUN2(check_float_value, i, "%1.2f"); }
	for (float i= -5e-20; i<= -1e-20; i+=  1e-20) { RUN2(check_float_value, i, "%1.0e"); }
	for (float i=  5e-20; i>=  1e-20; i-=  1e-20) { RUN2(check_float_value, i, "%1.0e"); }
	for (float i=  5E+20; i>=  1E+20; i-=  1E+20) { RUN2(check_float_value, i, "%1.2E"); }
	for (float i=1.5E+20; i>=1.1E+20; i-=0.1E+20) { RUN2(check_float_value, i, "%1.1E"); }
	RUN(check_valid_float_values);
	RUN(check_invalid_float_values);

	RUN(check_boolean_values); // Parse boolean values and check results.

	// Parse various string values and check results.
	RUN2(check_string_value, "te^st",                    NULL         ); // Missing quotes (the caret makes it an invalid token for testing purposes).
	RUN2(check_string_value, "\"te^st\"",                "te^st"      ); // A valid string.
	RUN2(check_string_value, "\"\"",                     ""           ); // An empty string is valid.
	RUN2(check_string_value, "\"\"\"te^st\"\"\"",        "te^st"      ); // A block string.
	RUN2(check_string_value, "\"te\\st\"",               NULL         ); // Backslashes are normally invalid.
	RUN2(check_string_value, "\"te\nst\"",               NULL         ); // New-line characters are invalid except in block strings.
	RUN2(check_string_value, "\"te\rst\"",               NULL         ); // New-line characters are invalid except in block strings.
	RUN2(check_string_value, "\"\"\"te\nst\"\"\"",       "te\nst"     ); // New-line characters are valid in block strings.
	RUN2(check_string_value, "\"\"\"te\rst\"\"\"",       "te\rst"     ); // New-line characters are valid in block strings.
	RUN2(check_string_value, "\"te\"st\"",               NULL         ); // A quote in a string is invalid.
	RUN2(check_string_value, "\"te\\\"st\"",             "te\"st"     ); // ...unless it is escaped.
	RUN2(check_string_value, "\"\"\"te\"st\"\"\"",       "te\"st"     ); // A quote in a block string is valid.
	RUN2(check_string_value, "\"\"\"te\"\"st\"\"\"",     "te\"\"st"   ); // It is even valid to have two quotes in a block string.
	RUN2(check_string_value, "\"\"\"te\"\"\"st\"\"\"",   NULL         ); // Three quotes in a row are not allowed in a block string.
	RUN2(check_string_value, "\"\"\"te\\\"\"\"st\"\"\"", "te\"\"\"st" ); // ...unless escaped.
	RUN2(check_string_value, "\"te\\\"st\"",             "te\"st"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\\\st\"",             "te\\st"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\/st\"",              "te/st"      ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\bst\"",              "te\bst"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\fst\"",              "te\fst"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\nst\"",              "te\nst"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\rst\"",              "te\rst"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\tst\"",              "te\tst"     ); // Check escape sequence.
	RUN2(check_string_value, "\"te\\vst\"",              NULL         ); // Invalid escape sequence.
	RUN2(check_string_value, "\"te\\033st\"",            NULL         ); // Invalid escape sequence.
	// Note: Unicode excape sequence is tested below.

	// This block string and this string should result in identical tokens.
	sprintf(source, "\
mutation {\n\
  sendEmail(message: \"\"\"\n\
    Hello,\n\
      World!\n\
\n\
    Yours,\n\
      GraphQL.\n\
  \"\"\")\n\
}\n\
	");
	RUN(check_example_25_and_26);
	sprintf(source, "\
mutation {\n\
  sendEmail(message: \"Hello,\\n  World!\\n\\nYours,\\n  GraphQL.\")\n\
}\n\
	");
	RUN(check_example_25_and_26);

	// Check block string example.
	RUN2(check_string_value,
"\"\"\"\n\
This starts with and ends with an empty line,\n\
which makes it easier to read.\n\
\"\"\"",
		"This starts with and ends with an empty line,\nwhich makes it easier to read.");

	// Check block string counter example.
	RUN2(check_string_value,
"\"\"\"This does not start with or end with any empty lines,\n\
which makes it a little harder to read.\"\"\"",
		"This does not start with or end with any empty lines,\nwhich makes it a little harder to read.");

	RUN2(check_string_value, "\"te\\u001bst\"",         "te\033st"        ); // Check unicode escape sequence.
	RUN2(check_string_value, "\"te\\u001Bst\"",         "te\033st"        ); // Check again with other case.
	RUN2(check_string_value, "\"\"\"te\\u001bst\"\"\"", "te\\u001bst"     ); // Escape sequences are ignored in block strings (except for the triple quote).
	RUN2(check_string_value, "\"\"\"te\\nst\"\"\"",     "te\\nst"         ); // Escape sequences are ignored in block strings (except for the triple quote).
	RUN2(check_string_value, "\"te\\u2026st\"",         "te\xe2\x80\xa6st"); // Check a unicode escape sequence.

	RUN(check_example_29); // Parse null value and check result.

	// These two input objects should have the same result.
	sprintf(source, "\
{\n\
  nearestThing(location: { lon: 12.43, lat: -53.211 })\n\
}\n\
	");
	RUN(check_example_30_and_31);
	sprintf(source, "\
{\n\
  nearestThing(location: { lat: -53.211, lon: 12.43 })\n\
}\n\
	");
	RUN(check_example_30_and_31);

	RUN(check_example_32); // Parse an example with a variable and check result.

	RUN(check_example_34); // Parse directives and check result.
	RUN(check_example_35); // Parse directives and check result.

	RUN(check_example_35); // Parse directives and check result.

	printf("total passed: %d\n%stotal failed: %d\033[0m\n", pass, fail?"\033[91m":"", fail);

	return fail==0? 0: 1;
}

