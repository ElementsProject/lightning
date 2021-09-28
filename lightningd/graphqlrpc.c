/* Code for GraphQL layer on top of JSON_RPC API.
 *
 * Only one GraphQL RPC command is needed per binary executable/plugin.
 * The RPC command for lightningd is "graphql" and is defined here.
 * It takes a single string argument, fully JSON-escaped, which is a
 * GraphQL "executable document" per the GraphQL spec.
 *
 * Plugins may register their own top-level GraphQL fields, allowing plugins
 * to extend the GraphQL query mechanism.
 */
/* eg: { peers { id, log(level: "broken"), channels { state } }, pluginA { field1, field2 } } */
#include "ccan/config.h"
#include <ccan/graphql/graphql.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <lightningd/graphqlrpc.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/peer_control.h>

static void json_add_toplevel_field(struct json_stream *js,
				    struct command *cmd,
				    const struct graphql_selection *sel)
{
	const char *name, *alias;

	name = alias = sel->field->name->token_string;
	if (sel->field->alias && sel->field->alias->name &&
	    sel->field->alias->name->token_type == 'a' &&
	    sel->field->alias->name->token_string)
		alias = sel->field->alias->name->token_string;

	if (streq(name, "peers")) {
		json_add_peers(js, cmd, alias, sel->field);
	} else {
		json_add_null(js, alias);
	}
}

static void json_add_op(struct json_stream *js,
			struct command *cmd,
			const struct graphql_operation_definition *op)
{
	const struct graphql_selection *sel;

	if (!op->op_type && op->sel_set)
		for (sel = op->sel_set->first; sel; sel = sel->next) {
			json_add_toplevel_field(js, cmd, sel);
		}
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
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("operation", param_escaped_string, &querystr),
		   NULL))
		return command_param_failed();

	if ((queryerr = graphql_lexparse(querystr, cmd, &toks, &doc)))
		return command_fail_badparam(cmd, "operation", buffer, params,
					     queryerr);

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
        "Execute GraphQL {query} and return the selected fields"
};
/* Comment added to satisfice AUTODATA */
AUTODATA(json_command, &graphql_command);

