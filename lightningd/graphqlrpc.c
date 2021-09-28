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
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <lightningd/graphqlrpc.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/peer_control.h>

static struct list_head warnings = LIST_HEAD_INIT(warnings);

struct graphqlrpc_warning {
	struct list_node node;
	struct json_stream *stream;
	const char *message;
};

void graphqlrpc_add_warning(struct json_stream *js, const char *fmt, ...)
{
	va_list ap;
	struct graphqlrpc_warning *w;

	va_start(ap, fmt);
	w = tal(NULL, struct graphqlrpc_warning);
	w->stream = js;
	w->message = tal_vfmt(w, fmt, ap);
	va_end(ap);

	/* Don't add the same message twice */
	struct graphqlrpc_warning *v;
	list_for_each(&warnings, v, node)
		if (streq(v->message, w->message)) {
			w = tal_free(w);
			return;
		}

	list_add(&warnings, &w->node);
}

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
		graphqlrpc_add_warning(js, "field not found '%s'", name);
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

static void json_add_warnings(struct json_stream *js)
{
	struct list_head temp = LIST_HEAD_INIT(temp);
	struct list_head todo = LIST_HEAD_INIT(todo);
	struct graphqlrpc_warning *w;

	while ((w = list_pop(&warnings, struct graphqlrpc_warning, node))) {
		if (w->stream == js)
			list_add(&todo, &w->node);
		else
			list_add(&temp, &w->node);
	}
	while ((w = list_pop(&temp, struct graphqlrpc_warning, node))) {
		list_add(&warnings, &w->node);
	}

	if (list_top(&todo, struct graphqlrpc_warning, node)) {
		json_array_start(js, "warnings");
		while ((w = list_pop(&todo, struct graphqlrpc_warning, node))) {
			json_add_string(js, NULL, w->message);
			w = tal_free(w);
		}
		json_array_end(js);
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

	json_add_warnings(response);

	return command_success(cmd, response);
}

static const struct json_command graphql_command = {
        "graphql",
        "system",
        json_graphql,
        "Perform GraphQL {operation} and return the selected fields"
};
/* Comment added to satisfice AUTODATA */
AUTODATA(json_command, &graphql_command);

