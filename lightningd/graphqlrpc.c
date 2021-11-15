/* Code for GraphQL layer on top of JSON_RPC API.
 *
 * Only one GraphQL RPC method is needed per binary executable/plugin.
 * The RPC method for lightningd is "graphql" and is defined here.
 * It takes a single string argument, fully JSON-escaped, which is a
 * GraphQL "executable document" per the GraphQL spec, e.g.:
 *	{ info { id }, peers { id, log(level: UNUSUAL), channels { state } } }
 */
#include "ccan/config.h"
#include <ccan/graphql/graphql.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/graphql_util.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <lightningd/graphqlrpc.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/peer_control.h>

static void json_add_op(struct json_stream *js,
			struct command *cmd,
			const struct graphql_operation_definition *op)
{
	const struct graphql_selection *sel;
	struct gqlcb_data *cbd;

	if (!op->op_type && op->sel_set) {
		for (sel = op->sel_set->first; sel; sel = sel->next) {
			cbd = (struct gqlcb_data *)sel->field->data;
			cbd->fieldspec->json_emitter(js, cbd, cmd->ld);
		}
	}
}

extern struct gqlcb_fieldspec peer_control_top_fields[];

static struct command_result *
prep_op(struct command *cmd, const char *buffer,
	const struct graphql_operation_definition *op)
{
	const struct graphql_selection *sel;
	struct command_result *err;

	if (!op->op_type && op->sel_set) {
		for (sel = op->sel_set->first; sel; sel = sel->next) {
			err = field_prep(cmd, buffer, sel->field,
					 (struct gqlcb_fieldspec *)peer_control_top_fields,
					 NULL);
			if (err)
				return err;
		}
	}
	return NULL;
}

static struct command_result *json_graphql(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	const char *querystr, *queryerr;
	struct list_head *toks;
	struct graphql_executable_document *doc;
	struct graphql_executable_definition *def;
	struct command_result *err;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("operation", param_escaped_string, &querystr),
		   NULL))
		return command_param_failed();

	/* Parse the GraphQL syntax */
	if ((queryerr = graphql_lexparse(cmd, querystr, &toks, &doc)))
		return command_fail(cmd, GRAPHQL_INVALID_SYNTAX, "%s", queryerr);

	/* Traverse the AST to check for errors and prepare for outputting */
	for (def = doc->first_def; def; def = def->next_def)
		if (def->op_def)
			if ((err = prep_op(cmd, querystr, def->op_def)))
				return err;

	/* Traverse the prepared AST to output the JSON data */
	response = json_stream_success(cmd);
	for (def = doc->first_def; def; def = def->next_def)
		if (def->op_def)
			json_add_op(response, cmd, def->op_def);

	return command_success(cmd, response);
}

static const struct json_command graphql_command = {
        "graphql",
        "system",
        json_graphql,
        "Perform GraphQL {operation} and return the selected fields"
};
AUTODATA(json_command, &graphql_command);

