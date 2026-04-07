#include "config.h"
#include <assert.h>
#include <bitcoin/base58.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/json_parse.h>
#include <common/splice_script.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#define SCRIPT_DUMP_TOKENS 0
#define SCRIPT_DUMP_SEGMENTS 0

/* Basic primitives */
#define ARROW_SYMBOL "->"
#define PIPE_SYMBOL '|'
#define AT_SYMBOL '@'
#define COLON_SYMBOL ':'
#define Q_SYMBOL '?'
#define WILD_SYMBOL '*'
#define PLUS_SYMBOL '+'
#define MINUS_SYMBOL '-'
#define FEE_SYMBOL "fee"
#define OPAREN_SYMBOL '('
#define CPAREN_SYMBOL ')'
#define DOT_SYMBOL '.'

/* Script keywords */
#define BALANCE_SYMBOL "balance"
#define PEER_SYMBOL "peer"
#define CHAN_SYMBOL "chan"
#define NEW_SYMBOL "new"
#define PRIVATE_SYMBOL "private"
#define CLOSE_TO_SYMBOL "close_to"
#define COMMIT_FEERATE_SYMBOL "commit_feerate"
#define LEASE_SYMBOL "lease"

/* Complex primitve regexes */
#define PERCENT_REGEX "^([0-9]*)[.]?([0-9]*)%$"
#define Q_REGEX "^\\?|any|first|one$"
#define WILD_REGEX "^\\*|all$"
#define CHANID_REGEX "^[0-9A-Fa-f]{64}$"
#define NODEID_REGEX "^0[23][0-9A-Fa-f]{62}$"
#define WALLET_REGEX "^wallet$"
#define FEE_REGEX "^" FEE_SYMBOL "$"
#define SATM_REGEX "^([0-9]*)[.]?([0-9]*)[Mm]$"
#define SATK_REGEX "^([0-9]*)[.]?([0-9]*)[Kk]$"

/* Terminal width of debug output */
#define CODE_SNIPPET_PADDING 80

/* Minimum # of matching charaters to autocomplete nodeid or chanid */
#define NODEID_MIN_CHARS 4
#define CHANID_MIN_CHARS 4

/* Shorthand for failing if `parameter` is set. */
#define CHECK_ASSIGN_TOKEN(token, parameter, error, section) \
	do { \
		if (token->parameter) \
			return new_error(ctx, error, token, section); \
	} while(0)

#define CHECK_ASSIGN_LEFT(token, section) \
	CHECK_ASSIGN_TOKEN(token, left, LEFT_ALREADY_SET, section)
#define CHECK_ASSIGN_MIDDLE(token, section) \
	CHECK_ASSIGN_TOKEN(token, middle, MIDDLE_ALREADY_SET, section)
#define CHECK_ASSIGN_RIGHT(token, section) \
	CHECK_ASSIGN_TOKEN(token, right, RIGHT_ALREADY_SET, section)

/* Token types from simplest to most complex. */
enum token_type {

	TOK_CHAR, /* Everything starts as a char */
	TOK_DELIMITER, /* Newline or semicolon. Guaranteed one at end. */

	/* Basic primitives */
	TOK_ARROW,
	TOK_STR,
	TOK_PIPE, /* lease separator "|", ex 5M|3M (add 5M, lease 3M) */
	TOK_COLON, /* node query separator ":", ex nodeid:0 */
	TOK_ATSYM, /* lease rate separator "@", ex 3M@2% */
	TOK_PLUS,
	TOK_MINUS,

	/* Complex primitives */
	TOK_PERCENT, /* ie "80%" */
	TOK_SATS, /* ie 8M or 0 */
	TOK_NUMBER, /* Floating point number (stored as double) */
	TOK_OPAREN, /* open parentheses */
	TOK_CPAREN, /* close parentheses */
	TOK_DOT,
	TOK_QUESTION, /* ie "?" */
	TOK_WILDCARD, /* ie "*" */
	TOK_FEE, /* ie the word "fee" */
	TOK_CHANID,
	TOK_WALLET,
	TOK_FEERATE, /* The fee rate */
	TOK_NODEID,
	TOK_BTCADDR,

	/* Script keywords */
	TOK_BALANCE,
	TOK_PEER,
	TOK_CHAN,
	TOK_NEW,
	TOK_PRIVATE,
	TOK_CLOSE_TO,
	TOK_COMMIT_FEERATE,
	TOK_LEASE,

	/* Compiler introduced types */
	TOK_CHANQUERY, /* ie nodeid:? */
	TOK_MULTI_CHANID, /* Matches stored in ->right */
	TOK_LEASEREQ,
	TOK_LEASERATE, /* ie @2% */
	TOK_SEGMENT, /* An entire line or semicolon separated segment */
};

#define TOKEN_FLAG_FEERATE_NEGATIVE 0x01

/* We turn the script into an array of tokens. The intial parse creates an array
 * of tokens of type TOK_CHAR with `c` set. As we progress in proccessing the
 * script we shrink the token array into less tokens where each token is
 * logically more descriptive tokens.
 *
 * While the array trends smaller, some operations do actually increase the
 * array size. For example TOK_MULTI_CHANID can match multiple channels, which
 * results in more tokens being added.
 *
 * Eventually tokens will start getting attached to other tokens. For example
 * a 'feerate' will get attached to an `amount`, which will itself get attached
 * to a 'channel'. In these cases the most significant token stays in the token
 * array and the detail tokens get attached as children via `left`, `middle` and
 * `right`.
 *
 * Finally the tokens get compressed all the way down into TOK_SEGMENT which
 * represents a single action (ie. splice, open channel, send funds to X).
 *
 * Each TOK_SEGMENT is turned into a splice_script_result which describes to the
 * caller the specific actions to be performed.
 */
struct token {
	enum token_type type;
	size_t script_index; /* For error messages */

	/* Generally one of the values below will be set. Sometimes extra values
	 * are left set to ease in debugging. `type` will tell you which value
	 * to expect to be filled. */
	char c;
	char *str;
	u32 ppm;
	struct amount_sat amount_sat;
	struct node_id *node_id;
	struct channel_id *chan_id;
	double number;

	/* Tokens can refer to other tokens. For example "a.b" will result in:
	 * a.right = b
	 *
	 * "a(b)" will result in
	 * a.middle = b
	 *
	 * "a -> b -> c" will result in:
	 * b.left = a
	 * b.right = c
	 *
	 * These relationships can have arbitrary depth, for instance:
	 * a.b.c.d(e) results in:
	 * a.right = b
	 *  b.right = c
	 *   c.right = d
	 *    d.middle = e
	 *
	 * Whenever a token takes another as any of these fields it *must* take
	 * over it's memory (ie. `tal_steal`).
	 *
	 * Circular token reference are not allowed (ie. KISS).
	 */
	struct token *left, *middle, *right;

	/* Currently only used for tracking negative feerate values. Available
	 * for future use. */
	u32 flags;
};

static struct token *new_token(const tal_t *ctx, enum token_type token_type,
			       size_t script_index)
{
	struct token *token = tal(ctx, struct token);

	token->type = token_type;
	token->script_index = script_index;
	token->c = 0;
	token->str = NULL;
	token->ppm = 0;
	token->amount_sat = AMOUNT_SAT(0);
	token->number = 0;
	token->node_id = NULL;
	token->chan_id = NULL;
	token->left = NULL;
	token->middle = NULL;
	token->right = NULL;
	token->flags = 0;

	return token;
}

static const char *token_type_str(enum token_type type)
{
	switch (type) {
	case TOK_CHAR: return "TOK_CHAR";
	case TOK_DELIMITER: return "TOK_DELIMITER";
	case TOK_ARROW: return "TOK_ARROW";
	case TOK_STR: return "TOK_STR";
	case TOK_PIPE: return "TOK_PIPE";
	case TOK_ATSYM: return "TOK_ATSYM";
	case TOK_PLUS: return "TOK_PLUS";
	case TOK_MINUS: return "TOK_MINUS";
	case TOK_COLON: return "TOK_COLON";
	case TOK_SATS: return "TOK_SATS";
	case TOK_NUMBER: return "TOK_NUMBER";
	case TOK_PERCENT: return "TOK_PERCENT";
	case TOK_OPAREN: return "TOK_OPAREN";
	case TOK_CPAREN: return "TOK_CPAREN";
	case TOK_DOT: return "TOK_DOT";
	case TOK_QUESTION: return "TOK_QUESTION";
	case TOK_WILDCARD: return "TOK_WILDCARD";
	case TOK_FEE: return "TOK_FEE";
	case TOK_CHANID: return "TOK_CHANID";
	case TOK_WALLET: return "TOK_WALLET";
	case TOK_FEERATE: return "TOK_FEERATE";
	case TOK_NODEID: return "TOK_NODEID";
	case TOK_BTCADDR: return "TOK_BTCADDR";
	case TOK_BALANCE: return "TOK_BALANCE";
	case TOK_PEER: return "TOK_PEER";
	case TOK_CHAN: return "TOK_CHAN";
	case TOK_NEW: return "TOK_NEW";
	case TOK_PRIVATE: return "TOK_PRIVATE";
	case TOK_CLOSE_TO: return "TOK_CLOSE_TO";
	case TOK_COMMIT_FEERATE: return "TOK_COMMIT_FEERATE";
	case TOK_LEASE: return "TOK_LEASE";
	case TOK_CHANQUERY: return "TOK_CHANQUERY";
	case TOK_MULTI_CHANID: return "TOK_MULTI_CHANID";
	case TOK_LEASEREQ: return "TOK_LEASEREQ";
	case TOK_LEASERATE: return "TOK_LEASERATE";
	case TOK_SEGMENT: return "TOK_SEGMENT";
	}

	return NULL;
}

#if SCRIPT_DUMP_TOKENS || SCRIPT_DUMP_SEGMENTS
static void dump_token_shallow(char **str, struct token *token, char *prefix)
{
	const char *tmp;

	tal_append_fmt(str, "%s%zu:%s", prefix, token->script_index,
		       token_type_str(token->type));

	if (token->c) {
		tal_append_fmt(str, " char:");
		if (token->c == '\n')
			tal_append_fmt(str, "'\\n'");
		else if (token->c == '\r')
			tal_append_fmt(str, "'\\r'");
		else if (token->c == '\t')
			tal_append_fmt(str, "'\\t'");
		else if (token->c < ' ')
			tal_append_fmt(str, "0x%02x", token->c);
		else
			tal_append_fmt(str, "'%c'", token->c);
	}

	if (token->str)
		tal_append_fmt(str, " str:\"%s\"", token->str);

	if (token->node_id)
		tal_append_fmt(str, " node_id:%s",
			       fmt_node_id(tmpctx, token->node_id));

	if (token->chan_id)
		tal_append_fmt(str, " chan_id:%s",
			       tal_hexstr(tmpctx, token->chan_id,
			       sizeof(struct channel_id)));

	if (token->ppm)
		tal_append_fmt(str, " ppm:%u", token->ppm);

	if (!amount_sat_is_zero(token->amount_sat) || token->type == TOK_SATS) {
		tmp = fmt_amount_sat(tmpctx, token->amount_sat);
		tal_append_fmt(str, " amnt:%s", tmp);
		tal_free(tmp);
	}

	if (token->type == TOK_NUMBER)
		tal_append_fmt(str, " number:%g", token->number);

	if (token->flags)
		tal_append_fmt(str, " flags:%u", token->flags);
}
#endif /* SCRIPT_DUMP_TOKENS || SCRIPT_DUMP_SEGMENTS */

#if SCRIPT_DUMP_TOKENS
/* Returns the indent used */
static int dump_token(char **str, struct token *token, int indent, char *prefix)
{
	if (token->left)
		indent = dump_token(str, token->left, indent, "l ") + 1;

	for (int i = 0; i < indent; i++)
		tal_append_fmt(str, " ");

	dump_token_shallow(str, token, prefix);

	tal_append_fmt(str, "\n");

	if (token->middle)
		dump_token(str, token->middle, indent + 1, "m ");

	if (token->right)
		dump_token(str, token->right, indent + 1, "r ");

	return indent;
}

static struct splice_script_error *debug_dump(const tal_t *ctx,
					      struct token **tokens)
{
	struct splice_script_error *error = tal(ctx,
						struct splice_script_error);

	error->type = DEBUG_DUMP;
	error->script_index = 0;
	error->message = tal_strdup(error, "");

	for (size_t i = 0; i < tal_count(tokens); i++)
		dump_token(&error->message, tokens[i], 0, "- ");

	return error;
}
#endif /* SCRIPT_DUMP_TOKENS */

#if SCRIPT_DUMP_SEGMENTS
static void append_token_modifiers(char **str, struct token *token)
{
	if (!token)
		return;

	if (token->middle)
		tal_append_fmt(str, "(%s)", token->middle->str ?: "");

	if (token->right) {
		tal_append_fmt(str, ".%s", token->right->str ?: "");
		append_token_modifiers(str, token->right);
	}
}

static struct splice_script_error *dump_segments(const tal_t *ctx,
						 struct token **tokens)
{
	struct splice_script_error *error = tal(ctx,
						struct splice_script_error);

	error->type = DEBUG_DUMP;
	error->script_index = 0;
	error->message = tal_strdup(error, "");

	for (size_t i = 0; i < tal_count(tokens); i++) {
		if (tokens[i]->type == TOK_SEGMENT) {
			dump_token_shallow(&error->message, tokens[i]->left,
					   "");
			append_token_modifiers(&error->message,
					       tokens[i]->left);
			dump_token_shallow(&error->message, tokens[i]->middle,
					   " -> ");
			append_token_modifiers(&error->message,
					       tokens[i]->middle);
			if (tokens[i]->right) {
				dump_token_shallow(&error->message,
						   tokens[i]->right, " -> ");
				append_token_modifiers(&error->message,
						       tokens[i]->right);
			}
		}
		else {
			tal_append_fmt(&error->message, "Invalid token!! ");
			dump_token_shallow(&error->message, tokens[i], "");
		}
		tal_append_fmt(&error->message, "\n");
	}

	return error;
}
#endif /* SCRIPT_DUMP_SEGMENTS */

static struct splice_script_error *new_error_offset(const tal_t *ctx,
						    enum splice_script_error_type type,
						    struct token *token,
						    const char *phase,
						    int index_offset)
{
	struct splice_script_error *error = tal(ctx, struct splice_script_error);

	error->type = type;
	error->script_index = token->script_index + index_offset;
	error->message = tal_fmt(error, "%s",
				 type == INVALID_TOKEN
				 	? token_type_str(token->type)
				 	: "");
	error->phase = phase;

	return error;
}

static struct splice_script_error *new_error(const tal_t *ctx,
					     enum splice_script_error_type type,
					     struct token *token,
					     const char *phase)
{
	return new_error_offset(ctx, type, token, phase, 0);
}

static struct splice_script_error *new_error_msg(const tal_t *ctx,
						 enum splice_script_error_type type,
						 struct token *token,
						 const char *phase,
						 char *msg)
{
	struct splice_script_error *error = new_error(ctx, type, token, phase);

	tal_append_fmt(&error->message, "%s", msg);

	return error;
}

static char *context_snippet(const tal_t *ctx,
			     const char *script,
			     struct splice_script_error *error)
{
	const char *start = script + error->script_index;
	const char *last = start;
	const char *end = script + strlen(script);
	char *str;

	for (size_t i = 0; i < CODE_SNIPPET_PADDING && start-1 >= script && start[-1] >= ' '; i++)
		start--;

	for (size_t i = 0; i < CODE_SNIPPET_PADDING && last < end && last[0] >= ' '; i++)
		last++;

	str = tal_strndup(ctx, start, last - start);

	tal_append_fmt(&str, "\n");

	for (const char *ptr = start; ptr < script + error->script_index; ptr++)
		tal_append_fmt(&str, " ");

	tal_append_fmt(&str, "^\n");

	if (error->message && strlen(error->message))
		tal_append_fmt(&str, "%s\n", error->message);

	if (error->phase)
		tal_append_fmt(&str, "Compiler phase: %s\n", error->phase);

	return str;
}

char *fmt_splice_script_compiler_error(const tal_t *ctx,
				       const char *script,
				       struct splice_script_error *error)
{
	switch (error->type) {
	case INTERNAL_ERROR:
		return tal_fmt(ctx, "Internal error\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_TOKEN:
		return tal_fmt(ctx, "Invalid token error\n%s",
			       context_snippet(ctx, script, error));
	case UNRECOGNIZED_TOKEN:
		return tal_fmt(ctx, "Unrecognized keyword or value\n%s",
			       context_snippet(ctx, script, error));
	case DEBUG_DUMP:
		return tal_fmt(ctx, "Token Dump:\n%s", error->message);
	case TOO_MANY_PIPES:
		return tal_fmt(ctx, "Too many '%c' symbols near here\n%s",
			       PIPE_SYMBOL,
			       context_snippet(ctx, script, error));
	case TOO_MANY_ATS:
		return tal_fmt(ctx, "Too many '%c' symbols near here\n%s",
			       AT_SYMBOL,
			       context_snippet(ctx, script, error));
	case TOO_MANY_COLONS:
		return tal_fmt(ctx, "Too many '%c' symbols near here\n%s",
			       COLON_SYMBOL,
			       context_snippet(ctx, script, error));
	case TOO_MANY_PLUS:
		return tal_fmt(ctx, "Too many '%c' symbols near here\n%s",
			       PLUS_SYMBOL,
			       context_snippet(ctx, script, error));
	case TOO_MANY_MINUS:
		return tal_fmt(ctx, "Too many '%c' symbols near here\n%s",
			       MINUS_SYMBOL,
			       context_snippet(ctx, script, error));
	case INVALID_NODEID:
		return tal_fmt(ctx, "Invalid node id\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_CHANID:
		return tal_fmt(ctx, "Invalid channel id\n%s",
			       context_snippet(ctx, script, error));
	case WRONG_NUM_SEGMENT_CHUNKS:
		return tal_fmt(ctx, "Segments must have one or two \""
			       ARROW_SYMBOL "\" symbols\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_ARROW:
		return tal_fmt(ctx, "Segments elements must be separated by \""
			       ARROW_SYMBOL "\" symbols\n%s",
			       context_snippet(ctx, script, error));
	case NO_MATCHING_NODES:
		return tal_fmt(ctx, "No matching nodes for node query\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_INDEX:
		return tal_fmt(ctx, "Valid index must be only number digits"
			       " and no other characters\n%s",
			       context_snippet(ctx, script, error));
	case CHAN_INDEX_ON_WILDCARD_NODE:
		return tal_fmt(ctx, "Node wildcard matches must use an index,"
			       " '%c', or '%c' after the '%c'\n%s",
			       Q_SYMBOL, WILD_SYMBOL, COLON_SYMBOL,
			       context_snippet(ctx, script, error));
	case CHANQUERY_TYPEERROR:
		return tal_fmt(ctx, "Channel query has invalid type(s)\n%s",
			       context_snippet(ctx, script, error));
	case CHANQUERY_PEERID_IS_CHANID:
		return tal_fmt(ctx, "Invalid peer id (this query matches a"
			       " channel but we expect a peer)\n%s",
			       context_snippet(ctx, script, error));
	case CHAN_INDEX_NOT_FOUND:
		return tal_fmt(ctx, "Channel index not found for node\n%s",
			       context_snippet(ctx, script, error));
	case NODE_ID_MULTIMATCH:
		return tal_fmt(ctx, "Node id matched multiple nodes, specify"
			       " more characters to be more specific\n%s",
			       context_snippet(ctx, script, error));
	case NODE_ID_CHAN_OVERMATCH:
		return tal_fmt(ctx, "Node id matched a channel id, specify"
			       " more characters to be more specific\n%s",
			       context_snippet(ctx, script, error));
	case CHAN_ID_MULTIMATCH:
		return tal_fmt(ctx, "Channel id matched multiple channels,"
			       " specify more characters to be more specific"
			       "\n%s",
			       context_snippet(ctx, script, error));
	case CHAN_ID_NODE_OVERMATCH:
		return tal_fmt(ctx, "Channel id matched a node id, specify"
			       " more characters to be more specific\n%s",
			       context_snippet(ctx, script, error));
	case NODE_ID_NO_UNUSED:
		return tal_fmt(ctx, "No unused channels for node id. Other"
			       " channel queries already claimed all channels"
			       "\n%s",
			       context_snippet(ctx, script, error));
	case DOUBLE_MIDDLE_OP:
		return tal_fmt(ctx, "Duplicate channel or address equivalent."
			       " Each line must contain only one\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_MIDDLE_OP:
		return tal_fmt(ctx, "Missing channel or address equivalent."
			       " Each line must contain one\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_AMOUNT_OP:
		return tal_fmt(ctx, "Missing amount. An amount is required here"
			       "\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_AMOUNT_OR_WILD_OP:
		return tal_fmt(ctx, "Missing sat amount. A sat amount or '%c'"
			       " is required here\n%s", WILD_SYMBOL,
			       context_snippet(ctx, script, error));
	case CANNOT_PARSE_SAT_AMNT:
		return tal_fmt(ctx, "Failed to parse sat amount\n%s",
			       context_snippet(ctx, script, error));
	case ZERO_AMOUNTS:
		return tal_fmt(ctx, "Each line must specify a non-zero amount,"
			       "lease request, or pay the onchain fee. This"
			       " line specifies none of these\n%s",
			       context_snippet(ctx, script, error));
	case IN_AND_OUT_AMOUNTS:
		return tal_fmt(ctx, "Can't specify funds going into and out of"
			       " in the same segment\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_PERCENT:
		return tal_fmt(ctx, "A percentage value is required here (ie."
			       " 1.5%%)\n%s",
			       context_snippet(ctx, script, error));
	case LEASE_AMOUNT_ZERO:
		return tal_fmt(ctx, "Lease specified without a non-zero amount."
			       " Must specify a non-zero amount.\n%s",
			       context_snippet(ctx, script, error));
	case CHANNEL_ID_UNRECOGNIZED:
		return tal_fmt(ctx, "Channel id not one of our channels.\n%s",
			       context_snippet(ctx, script, error));
	case DUPLICATE_CHANID:
		return tal_fmt(ctx, "Channel referenced on multiple lines. Each"
			       " channel id must appear only once.\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_MIDDLE_OP:
		return tal_fmt(ctx, "Unrecognized channel query. Must be"
			       " channel id query, bitcoin address, or"
			       " \"wallet\"\n%s",
			       context_snippet(ctx, script, error));
	case INSUFFICENT_FUNDS:
		return tal_fmt(ctx, "Script as written has insufficent funds to"
			       " be completed\n%s",
			       context_snippet(ctx, script, error));
	case PERCENT_IS_ZERO:
		return tal_fmt(ctx, "Percentage channel input will result in"
			       " zero\n%s",
			       context_snippet(ctx, script, error));
	case WILDCARD_IS_ZERO:
		return tal_fmt(ctx, "Wildcard channel input will result in zero"
			       "\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_PERCENT:
		return tal_fmt(ctx, "Percentage value invalid. Percentages must"
			       " be in range 0%% to 100%%.\n%s",
			       context_snippet(ctx, script, error));
	case LEFT_PERCENT_OVER_100:
		return tal_fmt(ctx, "Left operand percentage total out of"
			       " range. Left percentages must add up to 100%%"
			       " or less\n%s",
			       context_snippet(ctx, script, error));
	case LEFT_FEE_NOT_NEGATIVE:
		return tal_fmt(ctx, "Fees on the left operand must be negative"
			       " as they subtract from the amount\n%s",
			       context_snippet(ctx, script, error));
	case RIGHT_FEE_NOT_POSITIVE:
		return tal_fmt(ctx, "Fees on the right operand must be positive"
			       " as they pull out extra to cover the fee\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_FEESTR:
		return tal_fmt(ctx, "Must have \"%s\" token here\n%s",
			       FEE_SYMBOL,
			       context_snippet(ctx, script, error));
	case DUPLICATE_FEESTR:
		return tal_fmt(ctx, "Duplicate \"%s\" token here. Only one"
			       " channel or location may pay the fee\n%s",
			       FEE_SYMBOL,
			       context_snippet(ctx, script, error));
	case TOO_MUCH_DECIMAL:
		return tal_fmt(ctx, "Too many digits after the decimal. This"
			       " type does not support this many\n%s",
			       context_snippet(ctx, script, error));
	case INVALID_FEERATE:
		return tal_fmt(ctx, "Valid feerate must be only number digits"
			       " and no other characters\n%s",
			       context_snippet(ctx, script, error));
	case DOUBLE_CPAREN:
		return tal_fmt(ctx, "Not allowed to nest parentheses\n%s",
			       context_snippet(ctx, script, error));
	case MULTI_ITEMS_IN_PAREN:
		return tal_fmt(ctx, "Only one item allowed between"
			       " parentheses\n%s",
			       context_snippet(ctx, script, error));
	case MISSING_CLOSE_PAREN:
		return tal_fmt(ctx, "Missing an closing parentheses\n%s",
			       context_snippet(ctx, script, error));
	case PAREN_ON_NOTHING:
		return tal_fmt(ctx, "Parentheses must come after something\n%s",
			       context_snippet(ctx, script, error));
	case PAREN_ON_DOT:
		return tal_fmt(ctx, "Parentheses can't come after a dot\n%s",
			       context_snippet(ctx, script, error));
	case DOT_ON_DOT:
		return tal_fmt(ctx, "Dot can't come after another dot\n%s",
			       context_snippet(ctx, script, error));
	case UNOPENED_PAREN:
		return tal_fmt(ctx, "Parentheses was never opened\n%s",
			       context_snippet(ctx, script, error));
	case DOT_ON_NOTHING:
		return tal_fmt(ctx, "Dot operator must come after something\n%s",
			       context_snippet(ctx, script, error));
	case DOT_OF_NOTHING:
		return tal_fmt(ctx, "Dot operator must have something after"
			       " it\n%s", context_snippet(ctx, script, error));
	case LEFT_ALREADY_SET:
		return tal_fmt(ctx, "Trying to left attach an element that"
			       " already has something attached there.\n%s",
			       context_snippet(ctx, script, error));
	case MIDDLE_ALREADY_SET:
		return tal_fmt(ctx, "Trying to middle attach an element that"
			       " already has something attached there.\n%s",
			       context_snippet(ctx, script, error));
	case RIGHT_ALREADY_SET:
		return tal_fmt(ctx, "Trying to right attach an element that"
			       " already has something attached there.\n%s",
			       context_snippet(ctx, script, error));
	case NODEID_NOT_FOUND:
		return tal_fmt(ctx, "Unable to resolve node id for node query"
			       "\n%s", context_snippet(ctx, script, error));
	case NODE_NEEDS_RIGHT:
		return tal_fmt(ctx, "Node query needs to be modified by adding"
			       " something to the right, for example .chan() or"
			       " .new()\n%s",
			       context_snippet(ctx, script, error));
	case NODE_UNRECOGNIZED_RIGHT:
		return tal_fmt(ctx, "Node is followed by unrecognized modifier."
			       "\n%s", context_snippet(ctx, script, error));
	}

	return NULL;
}

static bool is_whitespace(char c)
{
	return cisspace(c);
}

static bool is_digit(char c)
{
	return cisdigit(c);
}

/* Removes all whitespace */
static struct splice_script_error *clean_whitespace(const tal_t *ctx,
						    struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++)
		if (input[i]->type != TOK_CHAR || !is_whitespace(input[i]->c))
			tokens[n++] = tal_steal(tokens, input[i]);

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

/* Returns point in str that starts match of suffix. */
static char *find_suffix(char *str, char *suffix)
{
	char *ptr;

	if (strlen(str) < strlen(suffix))
		return false;

	ptr = str + strlen(str) - strlen(suffix);

	if (streq(ptr, suffix))
		return ptr;

	return NULL;
}

/* Eats all "->"s, and CHARs, turning them into TOK_STRs.
 * Input must end in a TOK_DELIMITER
 *
 * Result:
 *  TOK_STR TOK_ARROW TOK_STR TOK_DELIMITER
 *  TOK_STR TOK_ARROW TOK_STR TOK_DELIMITER...
 */
static struct splice_script_error *find_arrows_and_strs(const tal_t *ctx,
							struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	struct token *token = NULL;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_DELIMITER:
			if (token)
				tokens[n++] = token;
			token = NULL;
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_CHAR:
			if (!token) {
				token = new_token(tokens, TOK_STR,
						  input[i]->script_index);
				token->str = tal_strdup(token, "");
			}
			tal_append_fmt(&token->str, "%c", input[i]->c);

			if (find_suffix(token->str, ARROW_SYMBOL)) {

				/* Terminmate the string at the arrow */
				*find_suffix(token->str, ARROW_SYMBOL) = 0;

				if (*token->str)
					tokens[n++] = token;
				else
					tal_free(token);
				token = NULL;

				tokens[n++] = new_token(tokens,
							TOK_ARROW,
							input[i]->script_index);
			}
			break;
		case TOK_ARROW:
		case TOK_STR:
		case TOK_PIPE:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "arrows");
		}
	}

	/* Script should always end in a delimiter which NULLS token */
	assert(!token);

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

/* Eats all "|:" turning them into tokens.
 *
 * Result:
 *  TOK_STR TOK_PIPE TOK_STR TOK_COLON...
 */
static struct splice_script_error *process_top_separators(const tal_t *ctx,
							  struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *,
					tal_count(input) * 3);
	char *split_point;
	size_t script_index;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "top_separators");
		case TOK_DELIMITER:
		case TOK_ARROW:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_STR:
			if ((split_point = strchr(input[i]->str,
						  PIPE_SYMBOL))) {
				if (split_point != strrchr(input[i]->str,
							   PIPE_SYMBOL))
					return new_error_offset(ctx,
								TOO_MANY_PIPES,
								input[i],
								"top_separators",
								split_point - input[i]->str);

				*split_point = 0;
				tokens[n++] = tal_steal(tokens, input[i]);

				script_index = input[i]->script_index;
				script_index += (split_point - input[i]->str);

				tokens[n++] = new_token(tokens, TOK_PIPE,
							script_index);

				script_index++;

				tokens[n] = new_token(tokens, TOK_STR,
						      script_index);
				tokens[n++]->str = split_point + 1;

			} else if ((split_point = strchr(input[i]->str,
						       COLON_SYMBOL))) {
				if (split_point != strrchr(input[i]->str,
							   COLON_SYMBOL))
					return new_error_offset(ctx,
								TOO_MANY_COLONS,
								input[i],
								"top_separators",
								split_point - input[i]->str);

				*split_point = 0;
				tokens[n++] = tal_steal(tokens, input[i]);

				script_index = input[i]->script_index;
				script_index += (split_point - input[i]->str);

				tokens[n++] = new_token(tokens, TOK_COLON,
							script_index);

				script_index++;

				tokens[n] = new_token(tokens, TOK_STR,
						      script_index);
				tokens[n++]->str = split_point + 1;
			} else {
				tokens[n++] = tal_steal(tokens, input[i]);
			}
			break;
		case TOK_PIPE:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "top_separators");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *process_2nd_separators(const tal_t *ctx,
							  struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *,
					tal_count(input) * 3);
	char *split_point;
	size_t script_index;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "2nd_separators");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_COLON:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_STR:
			if ((split_point = strchr(input[i]->str,
							 PLUS_SYMBOL))) {
				if (split_point != strrchr(input[i]->str,
							   PLUS_SYMBOL))
					return new_error_offset(ctx,
								TOO_MANY_PLUS,
								input[i],
								"2nd_separators",
								split_point - input[i]->str);

				*split_point = 0;
				tokens[n++] = tal_steal(tokens, input[i]);

				script_index = input[i]->script_index;
				script_index += (split_point - input[i]->str);

				tokens[n++] = new_token(tokens, TOK_PLUS,
							script_index);

				script_index++;

				tokens[n] = new_token(tokens, TOK_STR,
						      script_index);
				tokens[n++]->str = split_point + 1;
			} else if ((split_point = strchr(input[i]->str,
							 MINUS_SYMBOL))) {
				if (split_point != strrchr(input[i]->str,
							   MINUS_SYMBOL))
					return new_error_offset(ctx,
								TOO_MANY_MINUS,
								input[i],
								"2nd_separators",
								split_point - input[i]->str);

				*split_point = 0;
				tokens[n++] = tal_steal(tokens, input[i]);

				script_index = input[i]->script_index;
				script_index += (split_point - input[i]->str);

				tokens[n++] = new_token(tokens, TOK_MINUS,
							script_index);

				script_index++;

				tokens[n] = new_token(tokens, TOK_STR,
						      script_index);
				tokens[n++]->str = split_point + 1;
			} else {
				tokens[n++] = tal_steal(tokens, input[i]);
			}
			break;
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "2nd_separators");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *process_3rd_separators(const tal_t *ctx,
							  struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *,
					tal_count(input) * 3);
	char *split_point;
	size_t script_index;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "3rd_separators");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_COLON:
		case TOK_PLUS:
		case TOK_MINUS:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_STR:
			if ((split_point = strchr(input[i]->str,
						  AT_SYMBOL))) {
				if (split_point != strrchr(input[i]->str,
							   AT_SYMBOL))
					return new_error_offset(ctx,
								TOO_MANY_ATS,
								input[i],
								"3rd_separators",
								split_point - input[i]->str);

				*split_point = 0;
				tokens[n++] = tal_steal(tokens, input[i]);

				script_index = input[i]->script_index;
				script_index += (split_point - input[i]->str);

				tokens[n++] = new_token(tokens, TOK_ATSYM,
							script_index);

				script_index++;

				tokens[n] = new_token(tokens, TOK_STR,
						      script_index);
				tokens[n++]->str = split_point + 1;
			} else {
				tokens[n++] = tal_steal(tokens, input[i]);
			}
			break;
		case TOK_ATSYM:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "3rd_separators");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static const char *segwit_addr_net_decode(int *witness_version,
					  uint8_t *witness_program,
					  size_t *witness_program_len,
					  const char *addrz,
					  const struct chainparams *chainparams)
{
	if (segwit_addr_decode(witness_version, witness_program,
			       witness_program_len, chainparams->onchain_hrp,
			       addrz))
		return chainparams->onchain_hrp;
	else
		return NULL;
}

static bool is_bitcoin_address(const char *address)
{
	struct ripemd160 addr;
	int witness_version;
	/* segwit_addr_net_decode requires a buffer of size 40, and will
	 * not write to the buffer if the address is too long, so a buffer
	 * of fixed size 40 will not overflow. */
	uint8_t witness_program[40];
	size_t witness_program_len;

	const char *bech32;

	u8 addr_version;

	if (ripemd160_from_base58(&addr_version, &addr,
				  address, strlen(address))) {
		if (addr_version == chainparams->p2pkh_version) {
			return true;
		} else if (addr_version == chainparams->p2sh_version) {
			return true;
		}
		return false;
	}

	bech32 = segwit_addr_net_decode(&witness_version, witness_program,
					&witness_program_len, address,
					chainparams);
	if (bech32) {
		bool witness_ok;

		/* Only V0 has restricted lengths of witness programs */
		if (witness_version == 0) {
			witness_ok = (witness_program_len == 20 ||
				       witness_program_len == 32);
		} else if (witness_version == 1) {
			witness_ok = (witness_program_len == 32);
		} else {
			witness_ok = true;
		}

		if (!witness_ok)
			return false;

		return true;
	}

	return false;
}

/* Checks token->str for a short node id and auto completes it. */
static bool autocomplete_node_id(struct token *token,
				 struct splice_script_chan **channels,
				 bool *multiple_nodes,
				 bool *chan_id_overmatch)
{
	struct node_id *match;
	struct node_id candidate;
	size_t len = strlen(token->str) / 2;

	*multiple_nodes = false;
	*chan_id_overmatch = false;

	if (strlen(token->str) < NODEID_MIN_CHARS)
		return false;
	if (len > PUBKEY_CMPR_LEN)
		return false;
	if (!hex_decode(token->str, len * 2,
			candidate.k, len))
		return false;

	match = NULL;
	for (size_t i = 0; i < tal_count(channels); i++) {
		if (len <= sizeof(channels[i]->node_id.k)
		    && memeq(candidate.k, len, channels[i]->node_id.k, len)) {
			/* must not match multiple node ids */
			if (match && !node_id_eq(match, &channels[i]->node_id)) {
				*multiple_nodes = true;
				return true;
			}
			match = &channels[i]->node_id;
		}
		/* nodeid query must *not* match any channel ids */
		if (channels[i]->chan_id
		    && len <= sizeof(channels[i]->chan_id->id)
		    && memeq(candidate.k, len, channels[i]->chan_id->id, len))
			*chan_id_overmatch = true;
	}

	if (!match)
		return false;

	assert(!token->node_id);
	token->node_id = tal_dup(token, struct node_id, match);

	return true;
}

static bool autocomplete_chan_id(struct token *token,
				 struct splice_script_chan **channels,
				 bool *multiple_chans,
				 bool *node_id_overmatch)
{
	struct channel_id *match;
	struct channel_id candidate;
	size_t len = strlen(token->str) / 2;

	*multiple_chans = false;
	*node_id_overmatch = false;

	if (strlen(token->str) < NODEID_MIN_CHARS)
		return false;
	if (len > PUBKEY_CMPR_LEN)
		return false;
	if (!hex_decode(token->str, len * 2,
			candidate.id, len))
		return false;

	match = NULL;
	for (size_t i = 0; i < tal_count(channels); i++) {
		if (channels[i]->chan_id
		    && len <= sizeof(channels[i]->chan_id->id)
		    && memeq(candidate.id, len, channels[i]->chan_id->id, len)) {
			/* must not match multiple channel ids */
			if (match && !channel_id_eq(match, channels[i]->chan_id)) {
				*multiple_chans = true;
				return true;
			}
			match = channels[i]->chan_id;
		}
		/* nodeid query must *not* match any node ids */
		if (len <= sizeof(channels[i]->node_id.k)
		    && memeq(candidate.id, len, channels[i]->node_id.k, len))
			*node_id_overmatch = true;
	}

	if (!match)
		return false;

	assert(!token->chan_id);
	token->chan_id = tal_dup(token, struct channel_id, match);

	return true;
}

/* Eats all "()." turning them into tokens.
 *
 * Example: new.feerate(1.1)
 *  TOK_STR TOK_DOT TOK_STR TOK_OPAREN TOK_SATS TOK_CPAREN
 */
static struct splice_script_error *process_paren_dot_separators(const tal_t *ctx,
								struct token ***tokens_inout)
{
	const int tokenmap[] =
	{
		OPAREN_SYMBOL, TOK_OPAREN,
		CPAREN_SYMBOL, TOK_CPAREN,
		DOT_SYMBOL, TOK_DOT,
	};
	const int tokencount = sizeof(tokenmap) / sizeof(tokenmap[0]);
	enum token_type token_type, last_token;
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, 0);
	struct token *token;
	size_t script_index;
	char *start, *itr;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "paren_dot_separators");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_COLON:
		case TOK_ATSYM:
			tal_arr_expand(&tokens,
				       tal_steal(tokens, input[i]));
			break;
		case TOK_STR:
			start = itr = input[i]->str;
			last_token = TOK_CHAR;
			while (*itr) {
				token_type = TOK_CHAR;
				for (size_t j = 0; j < tokencount; j += 2) {
					if (*itr == tokenmap[j])
						token_type = tokenmap[j + 1];
				}
				if (token_type == TOK_CHAR) {
					itr++;
					continue;
				}
				/* Turn off dot parsing inside parens */
				if (token_type == TOK_DOT
				    && last_token == TOK_OPAREN) {
				    	itr++;
					continue;
				}
				/* Turn off dot parsing on numbers */
				if (token_type == TOK_DOT
				    && itr > start
				    && is_digit(itr[-1])) {
					itr++;
					continue;
				}
				last_token = token_type;

				/* Calc script_index for `str` */
				script_index = input[i]->script_index;
				script_index += (start - input[i]->str);

				/* Add any string before the token to result */
				if (itr > start) {
					*itr = 0;
					token = new_token(tokens,
							  TOK_STR,
							  script_index);
					token->str = tal_strdup(token, start);
					tal_arr_expand(&tokens, token);
				}

				/* One character forward for matching token */
				script_index++;

				/* Add the matching token */
				tal_arr_expand(&tokens,
					       new_token(tokens,
					       		 token_type,
							 script_index));

				/* Adjust start to be just after the token */
				start = ++itr;
			}

			/* Add any remaining string to result */
			if (itr > start) {
				token = new_token(tokens,
						  TOK_STR,
						  script_index);
				token->str = tal_strdup(token, start);
				tal_arr_expand(&tokens, token);
			}
			break;
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_FEERATE:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "paren_dot_separators");
		}
	}

	tal_free(input);
	*tokens_inout = tokens;
	return NULL;
}

/* Eats all script keyword methods turning them into tokens.
 *
 * Example: new.commit_feerate(1.1)
 *  TOK_NEW TOK_DOT TOK_COMMIT_FEERATE TOK_OPAREN TOK_SATS TOK_CPAREN
 */
static struct splice_script_error *process_keywords(const tal_t *ctx,
						   struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "type_data");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_COLON:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_STR:
			if (0 == strcmp(input[i]->str, BALANCE_SYMBOL))
				input[i]->type = TOK_BALANCE;
			if (0 == strcmp(input[i]->str, PEER_SYMBOL))
				input[i]->type = TOK_PEER;
			if (0 == strcmp(input[i]->str, CHAN_SYMBOL))
				input[i]->type = TOK_CHAN;
			if (0 == strcmp(input[i]->str, NEW_SYMBOL))
				input[i]->type = TOK_NEW;
			if (0 == strcmp(input[i]->str, PRIVATE_SYMBOL))
				input[i]->type = TOK_PRIVATE;
			if (0 == strcmp(input[i]->str, CLOSE_TO_SYMBOL))
				input[i]->type = TOK_CLOSE_TO;
			if (0 == strcmp(input[i]->str, COMMIT_FEERATE_SYMBOL))
				input[i]->type = TOK_COMMIT_FEERATE;
			if (0 == strcmp(input[i]->str, LEASE_SYMBOL))
				input[i]->type = TOK_LEASE;
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "type_data");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *type_data(const tal_t *ctx,
					      struct splice_script_chan **channels,
					      struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	char *whole, *decimal;
	char *sat_candidate;
	char *endptr;
	double number;
	struct amount_sat amount_sat;
	bool multiple = false;
	bool overmatch = false;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "type_data");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_COLON:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_STR:
			if (tal_strreg(ctx, input[i]->str, PERCENT_REGEX,
				       &whole, &decimal)) {
				if (atoll(whole) < 0 || atoll(decimal) < 0)
					return new_error(ctx, INVALID_PERCENT,
							 input[i],
							 "type_data");
				while (strlen(decimal) < 4)
					tal_append_fmt(&decimal, "0");
				if (decimal[4])
					return new_error(ctx, TOO_MUCH_DECIMAL,
							 input[i],
							 "type_data");

				input[i]->ppm = (u32)(10000 * atoll(whole)
						      + atoll(decimal));
				input[i]->type = TOK_PERCENT;
				if (input[i]->ppm > 1000000)
					return new_error(ctx, INVALID_PERCENT,
							 input[i],
							 "type_data");
			} else if (tal_strreg(ctx, input[i]->str, Q_REGEX)) {
				input[i]->type = TOK_QUESTION;
			} else if (tal_strreg(ctx, input[i]->str, WILD_REGEX)) {
				input[i]->type = TOK_WILDCARD;
			} else if (tal_strreg(ctx, input[i]->str,
					      NODEID_REGEX)) {
				input[i]->type = TOK_NODEID;
				input[i]->node_id = tal(input[i],
						    struct node_id);
				/* Rare corner case where channel begins with
				 * prefix of 02 or 03 */
				if (autocomplete_chan_id(input[i], channels,
							 &multiple,
							 &overmatch)) {
					if (multiple)
						return new_error(ctx,
								 CHAN_ID_MULTIMATCH,
								 input[i],
								 "type_data");
					if (overmatch)
						return new_error(ctx,
								 CHAN_ID_NODE_OVERMATCH,
								 input[i],
								 "type_data");
					input[i]->type = TOK_CHANID;
					input[i]->node_id = tal_free(input[i]->node_id);
				} else if (!node_id_from_hexstr(input[i]->str,
							 strlen(input[i]->str),
							 input[i]->node_id)) {
					return new_error(ctx, INVALID_NODEID,
							 input[i],
							 "type_data");
				}
			} else if (is_bitcoin_address(input[i]->str)) {
				input[i]->type = TOK_BTCADDR;
			} else if (tal_strreg(ctx, input[i]->str,
					      CHANID_REGEX)) {
				input[i]->type = TOK_CHANID;
				input[i]->chan_id = tal(input[i],
							struct channel_id);
				if (!hex_decode(input[i]->str,
						strlen(input[i]->str),
						input[i]->chan_id,
						32))
					return new_error(ctx, INVALID_CHANID,
							 input[i],
							 "type_data");
			} else if (tal_strreg(ctx, input[i]->str,
					      WALLET_REGEX)) {
				input[i]->type = TOK_WALLET;
			} else if (tal_strreg(ctx, input[i]->str, FEE_REGEX)) {
				input[i]->type = TOK_FEE;
			} else if (autocomplete_node_id(input[i], channels,
							&multiple,
							&overmatch)) {
				if (multiple)
					return new_error(ctx,
							 NODE_ID_MULTIMATCH,
							 input[i],
							 "type_data");

				if (overmatch)
					return new_error(ctx,
							 NODE_ID_CHAN_OVERMATCH,
							 input[i],
							 "type_data");
				input[i]->type = TOK_NODEID;
			} else if (autocomplete_chan_id(input[i], channels,
							&multiple,
							&overmatch)) {
				if (multiple)
					return new_error(ctx,
							 CHAN_ID_MULTIMATCH,
							 input[i],
							 "type_data");

				if (overmatch)
					return new_error(ctx,
							 CHAN_ID_NODE_OVERMATCH,
							 input[i],
							 "type_data");
				input[i]->type = TOK_CHANID;
			} else {
				/* Parse shorthand sat formats */
				sat_candidate = input[i]->str;

				if (tal_strreg(ctx, sat_candidate, SATM_REGEX,
					       &whole, &decimal)) {
					while (strlen(decimal) < 6)
						tal_append_fmt(&decimal, "0");
					if (decimal[6])
						return new_error(ctx,
								 TOO_MUCH_DECIMAL,
								 input[i],
								 "type_data");

					sat_candidate = tal_fmt(input[i],
								"%"PRIu64,
								(u64)(1000000 * atoll(whole)
								      + atoll(decimal)));
				} else if (tal_strreg(ctx, sat_candidate, SATK_REGEX,
					       &whole, &decimal)) {
					while (strlen(decimal) < 3)
						tal_append_fmt(&decimal, "0");
					if (decimal[3])
						return new_error(ctx,
								 TOO_MUCH_DECIMAL,
								 input[i],
								 "type_data");

					sat_candidate = tal_fmt(input[i],
								"%"PRIu64,
								(u64)(1000 * atoll(whole)
								      + atoll(decimal)));
				}

				errno = 0;
				number = strtod(input[i]->str, &endptr);

				/* Try to parse it as a sat first */
				if (parse_amount_sat(&amount_sat, sat_candidate,
						    strlen(sat_candidate))) {
					input[i]->type = TOK_SATS;
					input[i]->amount_sat = amount_sat;
				} else if(!sat_candidate || !strlen(sat_candidate)) {
					input[i]->type = TOK_SATS;
					input[i]->amount_sat = AMOUNT_SAT(0);
				} else if (endptr != input[i]->str
					   && *endptr == '\0' && !errno) {

					/* Fall back to a double if it couldnt
					 * be parsed as a sat */
					input[i]->type = TOK_NUMBER;
					input[i]->number = number;
				}

				if (sat_candidate != input[i]->str)
					tal_free(sat_candidate);
			}

			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "type_data");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *compress_top_operands(const tal_t *ctx,
							 struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "operands");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_NODEID:
		case TOK_BTCADDR:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_ATSYM:
			if (!n || i + 1 >= tal_count(input))
				return new_error(ctx, INVALID_TOKEN, input[i],
						 "operands");
			input[i]->type = tokens[n-1]->type == TOK_FEE
						? TOK_FEERATE
						: TOK_LEASERATE;
			CHECK_ASSIGN_RIGHT(input[i], "operands");
			CHECK_ASSIGN_RIGHT(tokens[n-1], "operands");

			input[i]->right = tal_steal(input[i], input[i+1]);
			tokens[n-1]->right = tal_steal(tokens[n-1], input[i]);
			i++;
			break;
		case TOK_COLON:
			if (!n || i + 1 >= tal_count(input))
				return new_error(ctx, INVALID_TOKEN, input[i],
						 "operands");
			CHECK_ASSIGN_LEFT(input[i], "operands");
			CHECK_ASSIGN_RIGHT(input[i], "operands");

			input[i]->type = TOK_CHANQUERY;
			input[i]->left = tal_steal(input[i], tokens[n-1]);
			input[i]->right = tal_steal(input[i], input[i+1]);
			tokens[n-1] = tal_steal(tokens, input[i]);
			i++;
			break;
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_FEERATE:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "operands");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *compress_2nd_operands(const tal_t *ctx,
							 struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_COLON:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "2nd_operands");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASERATE:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_MINUS:
		case TOK_PLUS:
			if (i + 1 >= tal_count(input)
				|| input[i+1]->type != TOK_FEE)
				return new_error(ctx, MISSING_FEESTR, input[i],
						 "2nd_operands");

			/* This token is consumed. If negative, add flag to next
			 * token */
			if (input[i]->type == TOK_MINUS)
				input[i+1]->flags |= TOKEN_FLAG_FEERATE_NEGATIVE;
			break;
		case TOK_FEE:
			if (!n)
				return new_error(ctx, INVALID_TOKEN, input[i],
						 "2nd_operands");
			CHECK_ASSIGN_MIDDLE(tokens[n-1], "2nd_operands");

			/* We put FEE on the middle spot of the amount */
			tokens[n-1]->middle = tal_steal(tokens[n-1], input[i]);
			break;
		case TOK_PIPE:
			if (!n || i + 1 >= tal_count(input))
				return new_error(ctx, INVALID_TOKEN, input[i],
						 "2nd_operands");
			CHECK_ASSIGN_RIGHT(input[i], "2nd_operands");
			CHECK_ASSIGN_RIGHT(tokens[n-1], "2nd_operands");

			input[i]->type = TOK_LEASEREQ;
			input[i]->right = tal_steal(input[i], input[i+1]);

			/* We put LEASEREQ on the right spot of the amount */
			tokens[n-1]->right = tal_steal(tokens[n-1], input[i]);
			i++;
			break;
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "2nd_operands");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static bool matches_chan_id(struct token *token, struct channel_id *chan_id)
{
	if (!chan_id)
		return false;

	if (token->chan_id && channel_id_eq(token->chan_id, chan_id))
		return true;

	if (token->left && matches_chan_id(token->left, chan_id))
		return true;

	if (token->middle && matches_chan_id(token->middle, chan_id))
		return true;

	if (token->right && matches_chan_id(token->right, chan_id))
		return true;

	return false;
}

/* Searches through both tokensA and tokensB. */
static struct node_id *first_node_with_unused_chan(const tal_t *ctx,
						   struct splice_script_chan **channels,
						   struct token **tokensA,
						   size_t a_size,
						   struct token **tokensB,
						   size_t b_size)
{
	for (size_t i = 0; i < tal_count(channels); i++) {
		bool used = false;
		for (size_t j = 0; j < a_size; j++)
			if (matches_chan_id(tokensA[j], channels[i]->chan_id))
				used = true;
		for (size_t k = 0; k < b_size; k++)
			if (matches_chan_id(tokensB[k], channels[i]->chan_id))
				used = true;
		if (!used)
			return tal_dup(ctx, struct node_id,
				       &channels[i]->node_id);
	}

	return NULL;
}

/* Searches through channels looking at just node_ids, return the `at_index`th
 * unique node id. */
static struct node_id *node_at_index(const tal_t *ctx,
				     struct splice_script_chan **channels,
				     int at_index)
{
	struct node_id *last_node_id = NULL;
	if (at_index < 0)
		return NULL;

	for (size_t i = 0; i < tal_count(channels); i++) {
		if (at_index == 0)
			return tal_dup(ctx, struct node_id,
				       &channels[i]->node_id);

		if (!last_node_id || !node_id_eq(last_node_id,
						 &channels[i]->node_id)) {
			at_index--;
			last_node_id = &channels[i]->node_id;
		}
	}

	return NULL;
}

static struct channel_id *chan_for_node_index(const tal_t *ctx,
					      struct splice_script_chan **channels,
					      struct node_id node_id,
					      size_t channel_index)
{
	for (size_t i = 0; i < tal_count(channels); i++)
		if (node_id_eq(&node_id, &channels[i]->node_id))
			if (channels[i]->chan_id && channel_index-- == 0)
				return tal_dup(ctx, struct channel_id,
					       channels[i]->chan_id);
	return NULL;
}

static struct channel_id **unused_chans(const tal_t *ctx,
					struct splice_script_chan **channels,
					struct token **tokensA,
					size_t a_size,
					struct token **tokensB,
					size_t b_size)
{
	struct channel_id **result = tal_arr(ctx, struct channel_id*, 0);

	for (size_t i = 0; i < tal_count(channels); i++) {
		bool used = false;
		for (size_t j = 0; j < a_size; j++)
			if (matches_chan_id(tokensA[j], channels[i]->chan_id))
				used = true;
		for (size_t k = 0; k < b_size; k++)
			if (matches_chan_id(tokensB[k], channels[i]->chan_id))
				used = true;
		if (!used)
			tal_arr_expand(&result, tal_dup(result,
							struct channel_id,
							channels[i]->chan_id));
	}

	if (!tal_count(result))
		result = tal_free(result);

	return result;
}

static struct channel_id **unused_chans_for_node(const tal_t *ctx,
						 struct splice_script_chan **channels,
						 struct token **tokensA,
						 size_t a_size,
						 struct token **tokensB,
						 size_t b_size,
						 struct node_id node_id)
{
	struct channel_id **result = tal_arr(ctx, struct channel_id*, 0);

	for (size_t i = 0; i < tal_count(channels); i++) {
		bool used = false;
		if (!node_id_eq(&node_id, &channels[i]->node_id))
			continue;
		for (size_t j = 0; j < a_size; j++)
			if (matches_chan_id(tokensA[j], channels[i]->chan_id))
				used = true;
		for (size_t k = 0; k < b_size; k++)
			if (matches_chan_id(tokensB[k], channels[i]->chan_id))
				used = true;
		if (!used)
			tal_arr_expand(&result, tal_dup(result,
							struct channel_id,
							channels[i]->chan_id));
	}

	if (!tal_count(result))
		result = tal_free(result);

	return result;
}

static bool parse_channel_index(struct token *token, size_t *channel_index)
{
	long long result;
	char *endptr;
	if (!token->str || !strlen(token->str))
		return false;

	errno = 0;
	result = strtoll(token->str, &endptr, 10);
	if (errno || *endptr)
		return false;

	*channel_index = result;
	return true;
}

static bool parse_feerate(struct token *token, u32 *feerate)
{
	long long result;
	char *endptr;
	if (!token->str)
		return false;

	/* zero length feerate is valid and implies 0 */
	if (0 == strlen(token->str)) {
		*feerate = 0;
		return true;
	}

	/* If no feerate was found, str wont contain feerate */
	if (0 == strcmp(token->str, FEE_SYMBOL)) {
		*feerate = 0;
		return true;
	}

	errno = 0;
	result = strtoll(token->str, &endptr, 10);
	if (errno || *endptr)
		return false;

	*feerate = result;
	return true;
}

static struct splice_script_error *resolve_channel_ids(const tal_t *ctx,
						       struct splice_script_chan **channels,
						       struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	struct node_id *node_id;
	struct channel_id *chan_id;
	struct channel_id **chan_ids;
	struct token *token_itr;
	size_t channel_index;
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_FEE:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "resolve_channel_ids");
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		case TOK_CHANQUERY:
			if (!input[i]->left || !input[i]->right)
				return new_error(ctx, INVALID_TOKEN, input[i],
						 "resolve_channel_ids");

			/* If user specifies *:? it is same as ?:? */
			if (input[i]->left->type == TOK_WILDCARD
				&& input[i]->right->type == TOK_QUESTION)
				input[i]->left->type = TOK_QUESTION;

			/* If user specifies *:# it is same as ?:# */
			if (input[i]->left->type == TOK_WILDCARD
				&& input[i]->right->type == TOK_SATS)
				input[i]->left->type = TOK_QUESTION;

			if (input[i]->left->type == TOK_QUESTION) {
				node_id = first_node_with_unused_chan(ctx,
								      channels,
								      input,
								      tal_count(input),
								      tokens,
								      n);
				if (!node_id)
					return new_error(ctx, NO_MATCHING_NODES,
							 input[i],
							 "resolve_channel_ids");
				input[i]->left->type = TOK_NODEID;
				input[i]->left->node_id = tal_steal(input[i]->left,
								    node_id);
			}

			if (input[i]->left->type == TOK_NODEID
				&& input[i]->right->type == TOK_SATS) {
				if (!parse_channel_index(input[i]->right,
							 &channel_index))
					return new_error(ctx, INVALID_INDEX,
							 input[i],
							 "resolve_channel_ids");
				chan_id = chan_for_node_index(ctx, channels,
							      *input[i]->left->node_id,
							      channel_index);
				if (!chan_id)
					return new_error(ctx,
							 CHAN_INDEX_NOT_FOUND,
							 input[i],
							 "resolve_channel_ids");

				input[i]->type = TOK_CHANID;
				input[i]->chan_id = tal_steal(input[i],
							      chan_id);
				input[i]->left = tal_free(input[i]->left);
				input[i]->right = tal_free(input[i]->right);
				tokens[n++] = tal_steal(tokens, input[i]);

			} else if (input[i]->left->type == TOK_NODEID) {
				chan_ids = unused_chans_for_node(ctx, channels,
								 input,
								 tal_count(input),
								 tokens, n,
								 *input[i]->left->node_id);
				if (!tal_count(chan_ids))
					return new_error(ctx, NODE_ID_NO_UNUSED,
							 input[i],
							 "resolve_channel_ids");
				if (input[i]->right->type == TOK_QUESTION) {
					input[i]->type = TOK_CHANID;
					input[i]->chan_id = tal_steal(input[i],
								      chan_ids[0]);
					tokens[n++] = tal_steal(tokens,
								input[i]);
				} else if (input[i]->right->type == TOK_WILDCARD) {
					input[i]->type = TOK_MULTI_CHANID;
					token_itr = input[i];

					input[i]->right = tal_free(input[i]->right);
					for (size_t j = 0; j < tal_count(chan_ids); j++) {
						CHECK_ASSIGN_RIGHT(token_itr, "resolve_channel_ids");

						token_itr->right = new_token(token_itr,
									     TOK_CHANID,
									     token_itr->script_index);
						token_itr->right->chan_id = tal_dup(token_itr->right,
										    struct channel_id,
										    chan_ids[j]);
						token_itr = token_itr->right;
					}
					tokens[n++] = tal_steal(tokens, input[i]);
				} else {
					return new_error(ctx,
							 CHAN_INDEX_ON_WILDCARD_NODE,
							 input[i],
							 "resolve_channel_ids");
				}
				tal_free(chan_ids);

			} else if (input[i]->left->type == TOK_WILDCARD) {
				if (input[i]->right->type != TOK_WILDCARD)
					return new_error(ctx,
							 CHAN_INDEX_ON_WILDCARD_NODE,
							 input[i],
							 "resolve_channel_ids");

				chan_ids = unused_chans(ctx, channels,
							input,
							tal_count(input),
							tokens, n);
				input[i]->type = TOK_MULTI_CHANID;
				input[i]->right = tal_free(input[i]->right);
				token_itr = input[i];
				for (size_t j = 0; j < tal_count(chan_ids); j++) {
					CHECK_ASSIGN_RIGHT(token_itr, "resolve_channel_ids");

					token_itr->right = new_token(token_itr,
								     TOK_CHANID,
								     token_itr->script_index);
					token_itr->right->chan_id = tal_dup(token_itr->right,
									    struct channel_id,
									    chan_ids[j]);
					token_itr = token_itr->right;
				}
				tokens[n++] = tal_steal(tokens, input[i]);
				tal_free(chan_ids);
			} else if (input[i]->left->type == TOK_CHANID) {
				return new_error(ctx,
						 CHANQUERY_PEERID_IS_CHANID,
						 input[i],
						 "resolve_channel_ids");
			} else {
				return new_error(ctx,
						 CHANQUERY_TYPEERROR,
						 input[i],
						 "resolve_channel_ids");
			}
			break;
		case TOK_SEGMENT:
		case TOK_MULTI_CHANID:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "resolve_channel_ids");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *process_peer_token(const tal_t *ctx,
						      struct splice_script_chan **channels,
						      struct token **token_inout)
{
	struct token *chan;
	struct token *token = *token_inout;
	struct token *old_token_right;

	if (!token->right)
		return new_error(ctx, NODE_NEEDS_RIGHT, token,
				 "process_peer_token");

	if (token->right->type == TOK_CHAN) {
		chan = token->right;

		CHECK_ASSIGN_LEFT(token, "process_peer_token");

		token->type = TOK_CHANQUERY;

		/* TOK_CHANQUERY takes nodeid on left and query on the right */

		token->left = token->middle;
		token->middle = NULL;

		if (chan->middle && token->right) {
			old_token_right = token->right;
			token->right = tal_steal(token, chan->middle);
			token->right->right = tal_steal(token->right,
							old_token_right);
		}
		chan->middle = NULL;

		/* Modifying the token in place so we dont have to use
		 * token_inout */
		return NULL;
	}

	if (token->middle && token->middle->type == TOK_QUESTION)
			token->node_id = node_at_index(token, channels, 0);

	/* node().new will be handled later after node id processing phase */
	if (token->right->type == TOK_NEW)
		return NULL;

	return new_error(ctx, NODE_UNRECOGNIZED_RIGHT, token,
		"process_peer_token");
}

static struct splice_script_error *process_chan_token(const tal_t *ctx,
						      struct splice_script_chan **channels,
						      struct token **token_inout)
{
	struct token *token = *token_inout;

	if (!token->middle)
		return new_error(ctx, NODE_NEEDS_RIGHT, token,
				 "process_chan_token");

	*token_inout = token->middle;
	(*token_inout)->right = tal_steal(*token_inout, token->right);
	return NULL;
}

static struct splice_script_error *resolve_peer_and_chan(const tal_t *ctx,
							 struct splice_script_chan **channels,
							 struct token ***tokens_inout)
{
	struct splice_script_error *error;
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		struct token *token = input[i];
		switch(token->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_FEE:
		case TOK_NODEID:
			return new_error(ctx, INVALID_TOKEN, token,
					 "resolve_peer_and_chan.");
		case TOK_CHANID:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_BTCADDR:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			tokens[n++] = tal_steal(tokens, token);
			break;
		case TOK_PEER:
			error = process_peer_token(ctx, channels, &token);
			if (error)
				return error;
			tokens[n++] = tal_steal(tokens, token);
			break;
		case TOK_CHAN:
			error = process_chan_token(ctx, channels, &token);
			if (error)
				return error;
			tokens[n++] = tal_steal(tokens, token);
			break;
		case TOK_MULTI_CHANID:
		case TOK_SEGMENT:
		case TOK_CHANQUERY:
			return new_error(ctx, INVALID_TOKEN, token,
					 "resolve_peer_and_chan..");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *check_for_unparsed_tokens(const tal_t *ctx,
							     struct token *input)
{
	struct splice_script_error *error;

	error = NULL;
	if (input->type == TOK_STR)
		error = new_error_msg(ctx, UNRECOGNIZED_TOKEN, input,
				      "check_for_unparsed_tokens",
				      tal_fmt(tmpctx, "'%s' unrecognized",
				      	      input->str ?: "NULL"));

	if (!error && input->left)
		error = check_for_unparsed_tokens(ctx, input->left);

	if (!error && input->middle)
		error = check_for_unparsed_tokens(ctx, input->middle);

	if (!error && input->right)
		error = check_for_unparsed_tokens(ctx, input->right);

	return error;
}

static struct splice_script_error *error_on_strings(const tal_t *ctx,
						    struct token **input)
{
	struct splice_script_error *error;
	for (size_t i = 0; i < tal_count(input); i++) {
		error = check_for_unparsed_tokens(ctx, input[i]);
		if (error)
			return error;
	}

	return NULL;
}

static bool is_valid_middle(struct token *token)
{
	switch(token->type) {
		case TOK_CHANID:
			if (!token->chan_id)
				return false;
			return true;
		case TOK_MULTI_CHANID:
		case TOK_BTCADDR:
		case TOK_WALLET:
			return true;
		case TOK_PEER:
			return token->node_id
			       && token->right
			       && token->right->type == TOK_NEW;
		case TOK_FEERATE:
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_NODEID:
		case TOK_CHANQUERY:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
		case TOK_SEGMENT:
			return false;
	}

	return false;
}

static struct splice_script_error *make_segments(const tal_t *ctx,
						 struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;
	size_t next_consumable = 0;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_FEE:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_STR:
		case TOK_CHANQUERY:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "segments");
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_WILDCARD:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
			break;
		case TOK_DELIMITER:
			if (i == 0 || input[i-1]->type == TOK_SEGMENT
				 || input[i-1]->type == TOK_DELIMITER) {
				next_consumable = i+1;
				break;
			}
			if (i - next_consumable == 3) {
				if (input[next_consumable+1]->type != TOK_ARROW)
					return new_error(ctx, MISSING_ARROW,
							 input[next_consumable+1],
							 "segments");
				CHECK_ASSIGN_LEFT(input[i], "segments.");
				CHECK_ASSIGN_MIDDLE(input[i], "segments");
				CHECK_ASSIGN_RIGHT(input[i], "segments");

				input[i]->type = TOK_SEGMENT;
				input[i]->left = tal_steal(input[i],
							   input[next_consumable]);
				input[i]->middle = tal_steal(input[i],
							     input[next_consumable+2]);
				tokens[n++] = tal_steal(tokens, input[i]);
				next_consumable = i+1;
			}
			else if (i - next_consumable == 5) {
				if (input[next_consumable+1]->type != TOK_ARROW)
					return new_error(ctx, MISSING_ARROW,
							 input[next_consumable+1],
							 "segments");
				if (input[next_consumable+3]->type != TOK_ARROW)
					return new_error(ctx, MISSING_ARROW,
							 input[next_consumable+3],
							 "segments");
				CHECK_ASSIGN_LEFT(input[i], "segments..");
				CHECK_ASSIGN_MIDDLE(input[i], "segments");
				CHECK_ASSIGN_RIGHT(input[i], "segments");

				input[i]->type = TOK_SEGMENT;
				input[i]->left = tal_steal(input[i],
							   input[next_consumable]);
				input[i]->middle = tal_steal(input[i],
							     input[next_consumable+2]);
				input[i]->right = tal_steal(input[i],
							    input[next_consumable+4]);
				tokens[n++] = tal_steal(tokens, input[i]);
				next_consumable = i+1;
			}
			else {
				return new_error(ctx, WRONG_NUM_SEGMENT_CHUNKS,
						 input[i], "segments");
			}

			/* Move middle OP to middle and validate */
			if (!tokens[n-1]->right) {
				if (is_valid_middle(tokens[n-1]->left)) {
					if (is_valid_middle(tokens[n-1]->middle))
						return new_error(ctx,
								 DOUBLE_MIDDLE_OP,
								 tokens[n-1]->middle,
								 "make_segments");
					CHECK_ASSIGN_RIGHT(tokens[n-1], "segments");

					tokens[n-1]->right = tokens[n-1]->middle;
					tokens[n-1]->middle = tokens[n-1]->left;
					tokens[n-1]->left = new_token(tokens[n-1],
								      TOK_SATS,
								      tokens[n-1]->script_index);
					tokens[n-1]->left->amount_sat = AMOUNT_SAT(0);

				} else if (is_valid_middle(tokens[n-1]->middle)) {
					CHECK_ASSIGN_RIGHT(tokens[n-1], "segments");

					tokens[n-1]->right = new_token(tokens[n-1],
								       TOK_SATS,
								       tokens[n-1]->script_index);
					tokens[n-1]->right->amount_sat = AMOUNT_SAT(0);
				} else {
					return new_error(ctx, MISSING_MIDDLE_OP,
							 tokens[n-1]->middle,
							 "make_segments");
				}
			}
			if (tokens[n-1]->left->type == TOK_STR
				&& !strlen(tokens[n-1]->left->str)) {
				tokens[n-1]->left->type = TOK_SATS;
				tokens[n-1]->left->amount_sat = AMOUNT_SAT(0);
			}
			if (tokens[n-1]->right->type == TOK_STR
				&& !strlen(tokens[n-1]->right->str)) {
				tokens[n-1]->right->type = TOK_SATS;
				tokens[n-1]->right->amount_sat = AMOUNT_SAT(0);
			}
			break;
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "segments");
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

/* Goes through the tokens and eats all OPAREN, CPAREN, and DOT tokens.
 * Parens will be attached to the token just left of them on the `middle` ptr.
 * Dots will attach the trailing token onto the token before it on the `right`.
 *
 * Example: "peer(0234).private"
 * Input tokens:
 *   STR OPAREN STR CPAREN DOT STR 
 * Output tokens:
 *   STR "peer"
 *     ->middle:
 *         STR "0234"
 *     ->right:
 *         STR "private"
 *
 * Example: "peer.private(0234)"
 * Input tokens:
 *   STR DOT STR OPAREN STR CPAREN
 * Output tokens:
 *   STR "peer"
 *     ->right:
 *         STR "private"
 *           ->middle:
 *               STR "0234"
 */
static struct splice_script_error *compress_parens_and_dots(const tal_t *ctx,
							    struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;
	struct token *last_token = NULL;
	struct token *close_paren = NULL;
	struct token *paren_content = NULL;

	/* Parens and dots are special in that they can be chained. In order to
	 * keep our `right` assignment checks working correctly, we have to
	 * process these tokens in reverse order. */
	for (int i = tal_count(input) - 1; i >= 0; i--) {
		switch(input[i]->type) {
		case TOK_CHAR:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "parens_and_dots");
		case TOK_DELIMITER:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_WILDCARD:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_CHANID:
		case TOK_FEE:
		case TOK_WALLET:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
			if (close_paren) {
				/* If we're inside parens, save this token for 
				 * processing when we get to the final paren */
				if (paren_content)
					return new_error(ctx,
							 MULTI_ITEMS_IN_PAREN,
							 input[i],
							 "parens_and_dots");
				paren_content = input[i];
			} else {
				/* Otherwise, just push it onto the result as
				 * normal */
				last_token = input[i];
				tokens[n++] = tal_steal(tokens, input[i]);
			}
			break;
		case TOK_CPAREN:
			/* NOTE: Don't forget we're looping backwards. */

			/* When we see close paren we just store a reference to
			 * it for later. */
			if (close_paren)
				return new_error(ctx, DOUBLE_CPAREN, input[i],
						 "parens_and_dots");
			close_paren = input[i];
			paren_content = NULL;
			break;
		case TOK_OPAREN:
			/* NOTE: Don't forget we're looping backwards. */

			/* On opening paren, take the contents of paren pair
			 * and attach them to the next token as `middle` */
			if (!close_paren)
				return new_error(ctx, MISSING_CLOSE_PAREN,
						 input[i], "parens_and_dots");
			if (i < 1)
				return new_error(ctx, PAREN_ON_NOTHING,
						 input[i], "parens_and_dots");
			if (input[i-1]->type == TOK_DOT)
				return new_error(ctx, PAREN_ON_DOT,
						 input[i], "parens_and_dots");
			CHECK_ASSIGN_MIDDLE(input[i-1], "parens_and_dots");

			input[i-1]->middle = tal_steal(input[i-1],
						       paren_content);

			/* Take this example: "peer(abc).new"
			 * 'new' will be attached to the close paren.
			 * We must foward this attachment onto 'peer' */
			if (close_paren->right) {
				CHECK_ASSIGN_RIGHT(input[i-1], "parens_and_dots.");
				input[i-1]->right = tal_steal(input[i-1],
							      close_paren->right);
			}
			/* Fees must be at the end of the paren chain. We put
			 * them on the right even though theyre coming from
			 * middle. */
			if (close_paren->middle
			    && close_paren->middle->type == TOK_FEE) {
				CHECK_ASSIGN_RIGHT(input[i-1], "parens_and_dots.");
				input[i-1]->right = tal_steal(input[i-1],
							      close_paren->middle);
			}
			close_paren = NULL;
			paren_content = NULL;
			break;
		case TOK_DOT:
			/* NOTE: Don't forget we're looping backwards. */

			/* On dot, attach last token onto the next token as
			 * `right` */
			if (i < 1)
				return new_error(ctx, DOT_ON_NOTHING,
						 input[i], "parens_and_dots");
			if (input[i-1]->type == TOK_DOT)
				return new_error(ctx, DOT_ON_DOT,
						 input[i], "parens_and_dots");
			if (!last_token)
				return new_error(ctx, DOT_OF_NOTHING,
						 input[i], "parens_and_dots");
			CHECK_ASSIGN_RIGHT(input[i-1], "parens_and_dots");

			/* Steal next token and attach it to the last token */
			input[i-1]->right = tal_steal(input[i-1], last_token);

			/* Remove `last_token` from results */
			tokens[n] = NULL;
			n--;
			break;
		case TOK_ATSYM:
		case TOK_COLON:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_FEERATE:
		case TOK_LEASERATE:
		case TOK_LEASEREQ:
		case TOK_SEGMENT:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "parens_and_dots");
		}
	}

	if (close_paren)
		return new_error(ctx, UNOPENED_PAREN,
				 close_paren, "parens_and_dots");

	tal_free(input);
	tal_resize(&tokens, n);

	/* Now reverse the array back and put it into *tokens_inout */
	*tokens_inout = tal_arr(ctx, struct token *, tal_count(tokens));
	n = 0;
	for (int i = tal_count(tokens) - 1; i >= 0; i--)
		(*tokens_inout)[n++] = tal_steal(*tokens_inout, tokens[i]);

	return NULL;
}

static void steal_sub_tokens(const tal_t *ctx, struct token *token)
{
	tal_steal(token, token->left);
	tal_steal(token, token->middle);
	tal_steal(token, token->right);
}

static struct splice_script_error *expand_multichans(const tal_t *ctx,
						     struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, 0);
	struct token *token_itr;
	struct token *token;
	size_t chan_count;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "expand_multichans");
		case TOK_SEGMENT:
			if (input[i]->middle->type == TOK_MULTI_CHANID) {
				token_itr = input[i]->middle->right;
				/* First we count how many chan_ids */
				chan_count = 0;
				while (token_itr) {
					chan_count++;
					token_itr = token_itr->right;
				}
				/* Now we loop through each chan_id */
				token_itr = input[i]->middle->right;
				while (token_itr) {
					/* Duplicate the SEGMENT token */
					token = tal_dup(tokens, struct token,
							input[i]);

					token->left = tal_dup(token,
							      struct token,
							      token->left);

					token->right = tal_dup(token,
							       struct token,
							       token->right);
					/* token_itr is already a CHANID */

					token->middle = tal_steal(token,
								  token_itr);

					steal_sub_tokens(token->left,
							 token->left);
					steal_sub_tokens(token->middle,
							 token->middle);
					steal_sub_tokens(token->right,
							 token->right);

					/* Divide percentage between chans */
					if (input[i]->left->type == TOK_PERCENT) {
						token->left->ppm = input[i]->left->ppm / chan_count;
					}

					/* Add modified copy to token array */
					tal_arr_expand(&tokens, token);

					token_itr = token_itr->right;

					/* Any remainder points to go the last
					 * destination in script */
					if (!token_itr)
						token->left->ppm += input[i]->left->ppm % chan_count;
				}
			} else {
				tal_arr_expand(&tokens,
					       tal_steal(tokens, input[i]));
			}
			break;
		}
	}

	tal_free(input);
	*tokens_inout = tokens;
	return NULL;
}

static bool is_valid_sat_amount(struct token *token)
{
	switch(token->type) {
		case TOK_SATS:
		case TOK_WILDCARD:
		case TOK_PERCENT:
		case TOK_FEE:
		case TOK_BALANCE:
			return true;
		case TOK_NUMBER:
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
		case TOK_SEGMENT:
			return false;
	}

	return false;
}

static bool is_valid_nonzero_sat_amount(struct token *token)
{
	if (token->type == TOK_SATS && amount_sat_is_zero(token->amount_sat))
		return false;

	return is_valid_sat_amount(token);
}

static bool valid_channel_id(struct channel_id *chan_id,
			     struct splice_script_chan **channels)
{
	for (size_t i = 0; i < tal_count(channels); i++)
		if (channel_id_eq(chan_id, channels[i]->chan_id))
			return true;

	return false;
}

static struct token *find_on_right(struct token *token, enum token_type type)
{
	if (!token)
		return NULL;
	if (token && token->type == type)
		return token;
	return find_on_right(token->right, type);
}

static struct splice_script_error *validate_and_clean(const tal_t *ctx,
						      struct splice_script_chan **channels,
						      struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens = tal_arr(ctx, struct token *, tal_count(input));
	size_t n = 0;
	struct channel_id *chan_ids = tal_arr(ctx, struct channel_id, 0);
	struct token *lease, *leaserate, *fee, *leftfee, *rightfee, *feerate;
	bool pay_fee_found = false;

	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
			/* Balance is invalid on a newchan query */
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "validate_and_clean");
		case TOK_SEGMENT:
			if (!is_valid_sat_amount(input[i]->left))
				return new_error(ctx, MISSING_AMOUNT_OR_WILD_OP,
						 input[i]->left,
						 "validate_and_clean");
			if (!is_valid_sat_amount(input[i]->right))
				return new_error(ctx, MISSING_AMOUNT_OR_WILD_OP,
						 input[i]->right,
						 "validate_and_clean");

			/* Process lease & lease rate.
			 * ex: "0|10M@1% -> chan_id"
			 * ex: "0 -> chan(chan_id).lease(10M @ 1%)"
			 */

			/* Splice in amounts on the left side of a segment can have leases
	 		 * attached or they can be found in channel identifeir
	 		 * in the segment's middle segment. */
			lease = find_on_right(input[i]->left, TOK_LEASE)
				?: find_on_right(input[i]->middle, TOK_LEASE);
			leaserate = NULL;
			if (lease && lease->type == TOK_LEASEREQ) {
				if (!lease->right
				    || lease->right->type != TOK_SATS)
					return new_error(ctx, LEASE_AMOUNT_ZERO,
							 lease,
							 "validate_and_clean");
				lease->amount_sat = lease->right->amount_sat;
				if (amount_sat_is_zero(lease->amount_sat))
					return new_error(ctx, LEASE_AMOUNT_ZERO,
							 lease->right,
							 "validate_and_clean");
				leaserate = lease->right->right;
			} else if(lease && lease->type == TOK_LEASE) {
				if (!lease->middle
				    || lease->middle->type != TOK_SATS)
					return new_error(ctx, LEASE_AMOUNT_ZERO,
							 lease,
							 "validate_and_clean");
				lease->amount_sat = lease->middle->amount_sat;
				if (amount_sat_is_zero(lease->amount_sat))
					return new_error(ctx, LEASE_AMOUNT_ZERO,
							 lease->right,
							 "validate_and_clean");
				leaserate = lease->middle->right;
			} else if(lease) {
				return new_error(ctx, INTERNAL_ERROR,
						 input[i],
						 "validate_and_clean");
			}

			if (leaserate) {
				if (leaserate->type != TOK_LEASERATE)
					return new_error(ctx, INTERNAL_ERROR,
							 leaserate,
							 "validate_and_clean");
				if (leaserate->right->type != TOK_PERCENT)
					return new_error(ctx, MISSING_PERCENT,
							 leaserate,
							 "validate_and_clean");
				lease->ppm = leaserate->right->ppm;
			}

			/* Process fee & fee rate.
			 * ex: "10M-fee@4k -> chan_id" (splice in 10M less fee) */
			leftfee = find_on_right(input[i]->left->middle, TOK_FEE)
				  ?: find_on_right(input[i]->left, TOK_FEE);
			rightfee = find_on_right(input[i]->right->middle, TOK_FEE)
				  ?: find_on_right(input[i]->right, TOK_FEE);
			if (leftfee && rightfee)
				return new_error(ctx, DUPLICATE_FEESTR,
						 leftfee,
						 "validate_and_clean");
			fee = leftfee ?: rightfee;
			feerate = NULL;
			if (fee) {
				if (leftfee && !(leftfee->flags
						 & TOKEN_FLAG_FEERATE_NEGATIVE))
					return new_error(ctx,
							 LEFT_FEE_NOT_NEGATIVE,
							 leftfee,
							 "validate_and_clean");
				if (rightfee && (rightfee->flags
						 & TOKEN_FLAG_FEERATE_NEGATIVE))
					return new_error(ctx,
							 RIGHT_FEE_NOT_POSITIVE,
							 rightfee,
							 "validate_and_clean");
				if (pay_fee_found)
					return new_error(ctx, DUPLICATE_FEESTR,
							 fee,
							 "validate_and_clean");
				pay_fee_found = true;
				feerate = fee->right;
			}
			if (feerate) {
				if (feerate->type != TOK_FEERATE)
					return new_error(ctx, INTERNAL_ERROR,
							 feerate,
							 "validate_and_clean");
				if (feerate->right->type != TOK_SATS)
					return new_error(ctx, MISSING_AMOUNT_OP,
							 feerate,
							 "validate_and_clean'");
				fee->amount_sat = feerate->right->amount_sat;
				fee->str = feerate->right->str;
			}

			if (!is_valid_nonzero_sat_amount(input[i]->left)
				&& !is_valid_nonzero_sat_amount(input[i]->right)
				&& !lease
				&& !fee)
				return new_error(ctx, ZERO_AMOUNTS,
						 input[i]->left,
						 "validate_and_clean");
			/* Can't specify funds going into and out of into the
			 * same segment. User should simply subtract one amount
			 * from the other. */
			if (is_valid_nonzero_sat_amount(input[i]->left)
				&& is_valid_nonzero_sat_amount(input[i]->right))
				return new_error(ctx, IN_AND_OUT_AMOUNTS,
						 input[i]->left,
						 "validate_and_clean");
			/* Check the channel id is one of our channels */
			if (input[i]->middle->type == TOK_CHANID
				&& !valid_channel_id(input[i]->middle->chan_id,
						     channels))
				return new_error(ctx, CHANNEL_ID_UNRECOGNIZED,
						 input[i]->middle,
						 "validate_and_clean");
			/* Check for duplicate channel ids */
			for (size_t j = 0; j < tal_count(chan_ids); j++)
				if (input[i]->middle->type == TOK_CHANID
					&& channel_id_eq(&chan_ids[j],
							 input[i]->middle->chan_id))
					return new_error(ctx, DUPLICATE_CHANID,
							 input[i]->middle,
							 "validate_and_clean");

			/* Now add our channel id to the array */
			if (input[i]->middle->type == TOK_CHANID)
				tal_arr_expand(&chan_ids,
					       *input[i]->middle->chan_id);
			if (!is_valid_middle(input[i]->middle))
				return new_error(ctx, INVALID_MIDDLE_OP,
						 input[i]->middle,
						 "validate_and_clean");
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		}
	}

	tal_free(chan_ids);
	tal_free(input);
	tal_resize(&tokens, n);
	*tokens_inout = tokens;
	return NULL;
}

static struct splice_script_error *calculate_amounts(const tal_t *ctx,
						     struct token ***tokens_inout)
{
	struct token **input = *tokens_inout;
	struct token **tokens;
	size_t n, left_wild_index, left_wilds, right_wilds;
	u32 left_used_ppm;
	bool right_used_ppm;
	struct amount_sat left_total, right_total;
	struct token *left_wildcard_token, *left_percent_token, *wallet_token;

	left_wilds = 0;
	right_wilds = 0;
	left_used_ppm = 0;
	right_used_ppm = false;
	left_total = AMOUNT_SAT(0);
	right_total = AMOUNT_SAT(0);
	left_wildcard_token = NULL;
	left_percent_token = NULL;
	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "calculate_amounts");
		case TOK_SEGMENT:
			if (input[i]->left->type == TOK_WILDCARD) {
				left_wildcard_token = input[i]->left;
				left_wilds++;
			}
			if (input[i]->right->type == TOK_WILDCARD)
				right_wilds++;
			if (input[i]->left->type == TOK_SATS)
				if (!amount_sat_add(&left_total, left_total,
						    input[i]->left->amount_sat))
					return new_error(ctx, INTERNAL_ERROR,
							 input[i]->left,
							 "calculate_amounts");
			if (input[i]->right->type == TOK_SATS)
				if (!amount_sat_add(&right_total, right_total,
						    input[i]->right->amount_sat))
					return new_error(ctx, INTERNAL_ERROR,
							 input[i]->right,
							 "calculate_amounts");
			if (input[i]->left->type == TOK_PERCENT) {
				left_percent_token = input[i]->left;
				left_used_ppm += input[i]->left->ppm;
				if (left_used_ppm > 1000000)
					return new_error(ctx,
							 LEFT_PERCENT_OVER_100,
							 input[i]->left,
							 "calculate_amounts");
			}
			if (input[i]->right->type == TOK_PERCENT)
				right_used_ppm = true;
			break;
		}
	}

	/* Do we know precisely how much we're getting? */
	if (!right_wilds && !right_used_ppm) {
		/* Then we can give sat amount errors */
		if (amount_sat_greater(left_total, right_total)) {
			return new_error_msg(ctx, INSUFFICENT_FUNDS,
					     left_wildcard_token ?: input[0],
					     "calculate_amounts",
					     tal_fmt(tmpctx, "required: %s,"
						     " provided: %s",
						     fmt_amount_sat(tmpctx, left_total),
						     fmt_amount_sat(tmpctx, right_total)));
		}
		if (left_used_ppm && amount_sat_eq(left_total, right_total))
			return new_error(ctx, PERCENT_IS_ZERO,
					 left_percent_token ?: input[0],
					 "calculate_amounts");
		if (left_wilds && amount_sat_eq(left_total, right_total))
			return new_error(ctx, WILDCARD_IS_ZERO,
					 left_wildcard_token ?: input[0],
					 "calculate_amounts");
	}

	tokens = tal_arr(ctx, struct token *, tal_count(input));
	n = 0;

	left_wild_index = 0;
	for (size_t i = 0; i < tal_count(input); i++) {
		switch(input[i]->type) {
		case TOK_CHAR:
		case TOK_ATSYM:
		case TOK_PLUS:
		case TOK_MINUS:
		case TOK_COLON:
		case TOK_LEASERATE:
		case TOK_ARROW:
		case TOK_PIPE:
		case TOK_STR:
		case TOK_SATS:
		case TOK_NUMBER:
		case TOK_PERCENT:
		case TOK_QUESTION:
		case TOK_OPAREN:
		case TOK_CPAREN:
		case TOK_DOT:
		case TOK_WILDCARD:
		case TOK_FEE:
		case TOK_CHANID:
		case TOK_WALLET:
		case TOK_FEERATE:
		case TOK_NODEID:
		case TOK_BTCADDR:
		case TOK_BALANCE:
		case TOK_PEER:
		case TOK_CHAN:
		case TOK_NEW:
		case TOK_PRIVATE:
		case TOK_CLOSE_TO:
		case TOK_COMMIT_FEERATE:
		case TOK_LEASE:
		case TOK_CHANQUERY:
		case TOK_MULTI_CHANID:
		case TOK_LEASEREQ:
		case TOK_DELIMITER:
			return new_error(ctx, INVALID_TOKEN, input[i],
					 "calculate_amounts");
		case TOK_SEGMENT:
			if (input[i]->left->type == TOK_WILDCARD) {
				input[i]->left->ppm = (1000000 - left_used_ppm) / left_wilds;

				/* Place remainder points into the last wildcard
				 * spot */
				if (++left_wild_index == left_wilds)
					input[i]->left->ppm += (1000000 - left_used_ppm) % left_wilds;

			}
			if (input[i]->right->type == TOK_WILDCARD)
				input[i]->right->ppm = 1000000;
			tokens[n++] = tal_steal(tokens, input[i]);
			break;
		}
	}

	tal_free(input);
	tal_resize(&tokens, n);

	/* Are there potential unclaimed funds? Typically we will have right
	 * side funds but in some channel lease situations and / or user
	 * provided funds (via user provided PSBT) we may have 0 funds coming
	 * in aka 'on the right side'. */
	if (!amount_sat_is_zero(right_total) || right_wilds || right_used_ppm) {
		/* Are they not already claimed by a % or wildcard? */
		if (!left_wilds && left_used_ppm < 1000000) {
			wallet_token = new_token(tokens, TOK_SEGMENT, 0);
			wallet_token->left = new_token(wallet_token,
						       TOK_WILDCARD, 0);
			wallet_token->middle = new_token(wallet_token,
							 TOK_WALLET, 0);
			wallet_token->right = new_token(wallet_token,
							TOK_SATS, 0);
			wallet_token->left->ppm = 1000000 - left_used_ppm;
			tal_arr_expand(&tokens, wallet_token);
		}
	}

	*tokens_inout = tokens;
	return NULL;
}

static bool is_delimiter(char c)
{
	return c == '\n' || c == ';';
}

struct splice_script_error *parse_splice_script(const tal_t *ctx,
						const char *script,
						struct splice_script_chan **channels,
						struct splice_script_result ***result)
{
	struct splice_script_error *error;
	struct token **tokens = tal_arr(ctx, struct token *,
					strlen(script) + 1);

	for (size_t i = 0; i < strlen(script); i++) {
		tokens[i] = new_token(tokens, is_delimiter(script[i])
						? TOK_DELIMITER
						: TOK_CHAR, i);
		tokens[i]->c = script[i];
	}

	/* We add a delimiter on the end to make life simple. */
	tokens[strlen(script)] = new_token(tokens, TOK_DELIMITER,
					   strlen(script));

	if ((error = clean_whitespace(ctx, &tokens)))
		return error;

	if ((error = find_arrows_and_strs(ctx, &tokens)))
		return error;

	if ((error = process_top_separators(ctx, &tokens)))
		return error;

	if ((error = process_2nd_separators(ctx, &tokens)))
		return error;

	if ((error = process_3rd_separators(ctx, &tokens)))
		return error;

	if ((error = process_paren_dot_separators(ctx, &tokens)))
		return error;

	if ((error = process_keywords(ctx, &tokens)))
		return error;

	if ((error = type_data(ctx, channels, &tokens)))
		return error;

	if ((error = error_on_strings(ctx, tokens)))
		return error;

	if ((error = compress_top_operands(ctx, &tokens)))
		return error;

	if ((error = compress_2nd_operands(ctx, &tokens)))
		return error;

	if ((error = compress_parens_and_dots(ctx, &tokens)))
		return error;

	if ((error = resolve_peer_and_chan(ctx, channels, &tokens)))
		return error;

	if ((error = resolve_channel_ids(ctx, channels, &tokens)))
		return error;

	if ((error = make_segments(ctx, &tokens)))
		return error;

	if ((error = expand_multichans(ctx, &tokens)))
		return error;

	if ((error = validate_and_clean(ctx, channels, &tokens)))
		return error;

	if ((error = calculate_amounts(ctx, &tokens)))
		return error;

#if SCRIPT_DUMP_TOKENS
	// return debug_dump(ctx, tokens);
#endif
#if SCRIPT_DUMP_SEGMENTS
	return dump_segments(ctx, tokens);
#endif

	*result = tal_arr(ctx, struct splice_script_result*, tal_count(tokens));

	for (size_t i = 0; i < tal_count(tokens); i++) {
		(*result)[i] = talz(*result, struct splice_script_result);
		struct splice_script_result *itr = (*result)[i];
		struct token *lease = tokens[i]->left->right;
		struct token *fee = tokens[i]->left->middle
					? tokens[i]->left->middle
					: tokens[i]->right->middle;
		struct token *itr_r;

		if (lease) {
			itr->lease_sat = lease->amount_sat;
			itr->lease_max_ppm = lease->ppm;
		}

		itr->in_sat = tokens[i]->left->amount_sat;
		itr->in_ppm = tokens[i]->left->ppm;

		if (tokens[i]->middle->type == TOK_CHANID) {
			itr->channel_id = tal_dup(itr, struct channel_id,
						  tokens[i]->middle->chan_id);
			itr_r = find_on_right(tokens[i]->middle, TOK_LEASE);
			if (itr_r) {
				itr->lease_sat = itr_r->amount_sat;
				itr->lease_max_ppm = itr_r->ppm;
			}
		}
		else if (tokens[i]->middle->type == TOK_BTCADDR) {
			itr->bitcoin_address = tal_strdup(itr,
							 tokens[i]->middle->str);
		}
		else if (tokens[i]->middle->type == TOK_WALLET){
			itr->onchain_wallet = true;
		}
		else if (tokens[i]->middle->type == TOK_PEER
			 && tokens[i]->middle->right
			 && tokens[i]->middle->right->type == TOK_NEW) {
			itr->peer_id = tal_dup(itr, struct node_id,
					       tokens[i]->middle->node_id);
			itr_r = tokens[i]->middle->right;
			for (; itr_r; itr_r = itr_r->right) {
				if (itr_r->type == TOK_PRIVATE)
					itr->private_channel = true;
				if (itr_r->type == TOK_CLOSE_TO
				    && itr_r->middle)
					itr->close_to_address = tal_strdup(itr, itr_r->middle->str);
				if (itr_r->type == TOK_COMMIT_FEERATE
				    && itr_r->middle) {
					if (!parse_feerate(itr_r->middle, &itr->commit_feerate_per_kw))
						return new_error(ctx, INVALID_FEERATE,
								 itr_r,
								 "splice_script_result");
				}
				if (itr_r->type == TOK_LEASE) {
					itr->lease_sat = itr_r->amount_sat;
					itr->lease_max_ppm = itr_r->ppm;
				}
			}
		}
		else {
			return new_error(ctx, INTERNAL_ERROR, tokens[i],
					 "splice_script_result");
		}

		itr->out_sat = tokens[i]->right->amount_sat;
		itr->out_ppm = tokens[i]->right->ppm;

		if (tokens[i]->right->type == TOK_WILDCARD)
			itr->out_ppm = UINT32_MAX;

		if (fee) {
			itr->pays_fee = true;
			if (!parse_feerate(fee, &itr->feerate_per_kw))
				return new_error(ctx, INVALID_FEERATE,
						 fee->right ? fee->right->right
						 ?: fee->right : fee,
						 "splice_script_result");
		}
	}

	return NULL;
}

void splice_to_json(const tal_t *ctx,
		    struct splice_script_result **splice,
		    struct json_stream *js)
{
	json_object_start(js, NULL);
	json_array_start(js, "splice");
	for (size_t i = 0; i < tal_count(splice); i++) {
		json_object_start(js, NULL);

		if (!amount_sat_is_zero(splice[i]->lease_sat)) {
			json_object_start(js, "lease_request");
			json_add_amount_sat_msat(js, "amount_msat",
						 splice[i]->lease_sat);
			json_add_u32(js, "max_ppm", splice[i]->lease_max_ppm);
			json_object_end(js);
		}

		if (!amount_sat_is_zero(splice[i]->in_sat) || splice[i]->in_ppm) {
			json_object_start(js, "into_destination");
			if (!amount_sat_is_zero(splice[i]->in_sat))
				json_add_amount_sat_msat(js, "amount_msat",
							 splice[i]->in_sat);
			if (splice[i]->in_ppm)
				json_add_u32(js, "ppm", splice[i]->in_ppm);
			json_object_end(js);
		}

		json_object_start(js, "destination");
		if (splice[i]->channel_id)
			json_add_channel_id(js, "channel_id",
					    splice[i]->channel_id);
		if (splice[i]->peer_id)
			json_add_node_id(js, "peer_id", splice[i]->peer_id);
		if (splice[i]->bitcoin_address)
			json_add_string(js, "bitcoin_address",
					splice[i]->bitcoin_address);
		if (splice[i]->onchain_wallet)
			json_add_bool(js, "onchain_wallet", true);
		json_object_end(js);

		if (!amount_sat_is_zero(splice[i]->out_sat)
			|| splice[i]->out_ppm) {
			json_object_start(js, "outof_destination");
			if (!amount_sat_is_zero(splice[i]->out_sat))
				json_add_amount_sat_msat(js, "amount_msat",
							 splice[i]->out_sat);
			if (splice[i]->out_ppm)
				json_add_u32(js, "ppm", splice[i]->out_ppm);
			json_object_end(js);
		}

		if (splice[i]->balance_ppm)
			json_add_u32(js, "balance_ppm", splice[i]->balance_ppm);

		if (splice[i]->peer_id) {
			json_object_start(js, "new_chan_params");
			if (splice[i]->commit_feerate_per_kw)
				json_add_u32(js, "commit_feerate_per_kw",
					     splice[i]->commit_feerate_per_kw);

			if (splice[i]->private_channel)
				json_add_bool(js, "private_channel", true);

			if (splice[i]->close_to_address)
				json_add_string(js, "close_to_address",
						splice[i]->close_to_address);
			json_object_end(js);
		}

		if (splice[i]->pays_fee || splice[i]->feerate_per_kw) {
			json_object_start(js, "fee");
			if (splice[i]->pays_fee)
				json_add_bool(js, "pays_fee",
					      splice[i]->pays_fee);
			if (splice[i]->feerate_per_kw)
				json_add_u32(js, "feerate_per_kw",
					     splice[i]->feerate_per_kw);
			json_object_end(js);
		}

		json_object_end(js);
	}
	json_array_end(js);
	json_object_end(js);
}

static bool json_to_msat_to_sat(const char *buffer, const jsmntok_t *tok,
				struct amount_sat *sat)
{
	struct amount_msat msat;

	if (!json_to_msat(buffer, tok, &msat))
		return false;
	return amount_msat_to_sat(sat, msat);
}

bool json_to_splice(const tal_t *ctx, const char *buffer, const jsmntok_t *tok,
		    struct splice_script_result ***result)
{
	const jsmntok_t *splice;
	const jsmntok_t *itr;
	size_t i;

	splice = json_get_member(buffer, tok, "splice");
	if (!splice || splice->type != JSMN_ARRAY)
		return false;

	*result = tal_arr(ctx, struct splice_script_result*, 0);
	json_for_each_arr(i, itr, splice) {
		const jsmntok_t *lease, *in, *dest, *out, *bal, *chan, *fee, *obj;
		struct splice_script_result *ele = talz(*result, struct splice_script_result);

		if ((lease = json_get_member(buffer, itr, "lease_request"))) {
			if ((obj = json_get_member(buffer, lease,
						   "amount_msat"))) {
				if (!json_to_msat_to_sat(buffer, obj,
							 &ele->lease_sat))
					return false;
			}
			if ((obj = json_get_member(buffer, lease, "max_ppm"))) {
				if (!json_to_u32(buffer, obj,
						 &ele->lease_max_ppm))
					return false;
			}
		}

		if ((in = json_get_member(buffer, itr, "into_destination"))) {
			if ((obj = json_get_member(buffer, in,
						   "amount_msat"))) {
				if (!json_to_msat_to_sat(buffer, obj,
							 &ele->in_sat))
					return false;
			}
			if ((obj = json_get_member(buffer, in, "ppm"))) {
				if (!json_to_u32(buffer, obj, &ele->in_ppm))
					return false;
			}
		}

		if ((dest = json_get_member(buffer, itr, "destination"))) {
			if ((obj = json_get_member(buffer, dest,
						   "channel_id"))) {
				ele->channel_id = tal(ele, struct channel_id);
				if (!json_to_channel_id(buffer, obj,
							ele->channel_id))
					return false;
			}
			if ((obj = json_get_member(buffer, dest, "peer_id"))) {
				ele->peer_id = tal(ele, struct node_id);
				if (!json_to_node_id(buffer, obj, ele->peer_id))
					return false;
			}
			if ((obj = json_get_member(buffer, dest,
						   "bitcoin_address"))) {
				ele->bitcoin_address = json_strdup(ele, buffer,
								   obj);
				if (!ele->bitcoin_address)
					return false;
			}
			if ((obj = json_get_member(buffer, dest,
						   "onchain_wallet"))) {
				if (!json_to_bool(buffer, obj,
						  &ele->onchain_wallet))
					return false;
			}
		}

		if ((out = json_get_member(buffer, itr, "outof_destination"))) {
			if ((obj = json_get_member(buffer, out,
						   "amount_msat"))) {
				if (!json_to_msat_to_sat(buffer, obj,
							 &ele->out_sat))
					return false;
			}
			if ((obj = json_get_member(buffer, out, "ppm"))) {
				if (!json_to_u32(buffer, obj, &ele->out_ppm))
					return false;
			}
		}

		if ((bal = json_get_member(buffer, itr, "balance_ppm")))
			if (!json_to_u32(buffer, bal, &ele->balance_ppm))
				return false;

		if ((chan = json_get_member(buffer, itr, "new_chan_params"))) {
			if ((obj = json_get_member(buffer, chan,
						   "commit_feerate_per_kw"))) {
				if (!json_to_u32(buffer, obj,
						 &ele->commit_feerate_per_kw))
					return false;
			}
			if ((obj = json_get_member(buffer, chan,
						   "private_channel"))) {
				if (!json_to_bool(buffer, obj,
						 &ele->private_channel))
					return false;
			}
			if ((obj = json_get_member(buffer, chan,
						   "close_to_address"))) {
				ele->close_to_address = json_strdup(ele, buffer,
								    obj);
				if (!ele->close_to_address)
					return false;
			}
		}

		if ((fee = json_get_member(buffer, itr, "fee"))) {
			if ((obj = json_get_member(buffer, fee, "pays_fee"))) {
				if (!json_to_bool(buffer, obj, &ele->pays_fee))
					return false;
			}
			if ((obj = json_get_member(buffer, fee,
						   "feerate_per_kw"))) {
				if (!json_to_u32(buffer, obj,
						 &ele->feerate_per_kw))
					return false;
			}
		}

		tal_arr_expand(result, ele);
	}

	return true;
}

static char *ppm_to_str(const tal_t *ctx, u32 ppm)
{
	if (ppm == UINT_MAX)
		return tal_fmt(ctx, "max");

	if (ppm % 10000)
		return tal_fmt(ctx, "%u.%04u%%", ppm / 10000, ppm % 10000);

	return tal_fmt(ctx, "%u%%", ppm / 10000);
}

char *splice_to_string(const tal_t *ctx,
		       struct splice_script_result *result)
{
	const char *into_prefix, *fee_str;
	char *str = tal_strdup(ctx, "");

	into_prefix = "";
	fee_str = "";
	if (!amount_sat_is_zero(result->lease_sat)) {
		into_prefix = "and ";
		tal_append_fmt(&str, "lease %s ",
			       fmt_amount_sat(ctx,
			       result->lease_sat));
		if (result->lease_max_ppm)
			tal_append_fmt(&str, "(max fee %s) ",
				       ppm_to_str(ctx, result->lease_max_ppm));
	}

	if (result->pays_fee)
		fee_str = " less fee";
	if (result->feerate_per_kw)
		fee_str = tal_fmt(tmpctx, " less fee (%u/kw)",
				  result->feerate_per_kw);

	if (!amount_sat_is_zero(result->in_sat))
		tal_append_fmt(&str, "%sput %s%s %s ", into_prefix,
			       fmt_amount_sat(ctx, result->in_sat),
			       fee_str,
			       result->in_ppm ? "and" : "into");
	if (result->in_ppm)
		tal_append_fmt(&str, "%s%s%s%s of rest into ", into_prefix,
			       amount_sat_is_zero(result->in_sat) ? "put " : "",
			       ppm_to_str(ctx, result->in_ppm),
			       fee_str);
	if (result->balance_ppm)
		tal_append_fmt(&str, "%senough to %s balance channel%s into ",
			       into_prefix,
			       ppm_to_str(ctx, result->balance_ppm),
			       fee_str);

	if (result->channel_id)
		tal_append_fmt(&str, "%s%s%s",
			       result->peer_id ? "new(" : "",
			       tal_hexstr(tmpctx, result->channel_id, sizeof(struct channel_id)),
			       result->peer_id ? ")" : "");
	else if (result->peer_id)
		tal_append_fmt(&str, "new channel with %s",
			       fmt_node_id(ctx, result->peer_id));
	if (result->bitcoin_address)
		tal_append_fmt(&str, "%s", result->bitcoin_address);
	if (result->onchain_wallet)
		tal_append_fmt(&str, "wallet");

	fee_str = "";
	if (result->pays_fee)
		fee_str = " plus fee";
	if (result->feerate_per_kw)
		fee_str = tal_fmt(tmpctx, " plus fee (%u/kw, %.02f"
				  " sat/vB) ",
				  result->feerate_per_kw,
				  4 * result->feerate_per_kw / 1000.0f);

	if (!amount_sat_is_zero(result->out_sat))
		tal_append_fmt(&str, " withdraw %s%s",
			       fmt_amount_sat(ctx, result->out_sat),
			       fee_str);
	if (result->out_ppm)
		tal_append_fmt(&str, " %s %s%s",
			       amount_sat_is_zero(result->out_sat)
			       	 ? "withdraw" : "and",
			       ppm_to_str(ctx, result->out_ppm),
			       fee_str);

	if (amount_sat_is_zero(result->in_sat) && !result->in_ppm
		&& amount_sat_is_zero(result->out_sat)
		&& !result->out_ppm
		&& result->pays_fee) {

		tal_append_fmt(&str, " withdraw fee");
		if (result->feerate_per_kw)
			tal_append_fmt(&str, " (%u/kw, %.02f sat/vB)",
				       result->feerate_per_kw,
				       4 * result->feerate_per_kw / 1000.0f);
	}

	return str;
}

char *splicearr_to_string(const tal_t *ctx,
			  struct splice_script_result **result)
{
	char *str = tal_strdup(ctx, "");

	for (size_t i = 0; i < tal_count(result); i++)
		tal_append_fmt(&str, "%s\n", splice_to_string(str, result[i]));

	return str;
}
