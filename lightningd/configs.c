#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/configvar.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/version.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/options.h>
#include <lightningd/plugin.h>

static void json_add_source(struct json_stream *result,
			    const char *fieldname,
			    const struct configvar *cv)
{
	const char *source;

	if (!cv) {
		source = "default";
	} else {
		source = NULL;
		switch (cv->src) {
		case CONFIGVAR_CMDLINE:
		case CONFIGVAR_CMDLINE_SHORT:
			source = "cmdline";
			break;
		case CONFIGVAR_EXPLICIT_CONF:
		case CONFIGVAR_BASE_CONF:
		case CONFIGVAR_NETWORK_CONF:
			source = tal_fmt(tmpctx, "%s:%u", cv->file, cv->linenum);
			break;
		case CONFIGVAR_PLUGIN_START:
			source = "pluginstart";
			break;
		}
	}
	json_add_string(result, fieldname, source);
}

static const char *configval_fieldname(const struct opt_table *ot)
{
	bool multi = (ot->type & OPT_MULTI);
	if (ot->type & OPT_SHOWBOOL)
		return multi ? "values_bool" : "value_bool";
	if (ot->type & OPT_SHOWINT)
		return multi ? "values_int" : "value_int";
	if (ot->type & OPT_SHOWMSATS)
		return multi ? "values_msat" : "value_msat";
	return multi ? "values_str" : "value_str";
}

#define CONFIG_SHOW_BUFSIZE 4096

static const char *get_opt_val(const struct opt_table *ot,
			       char buf[],
			       const struct configvar *cv)
{
	if (ot->show == (void *)opt_show_charp) {
		/* Don't truncate or quote! */
		return *(char **)ot->u.carg;
	}
	if (ot->show) {
		/* Plugins options' show only shows defaults, so show val if
		 * we have it */
		if (is_plugin_opt(ot) && cv)
			return cv->optarg;
		strcpy(buf + CONFIG_SHOW_BUFSIZE, "...");
		if (ot->show(buf, CONFIG_SHOW_BUFSIZE, ot->u.carg))
			return buf;
		return NULL;
	}

	/* For everything else we only display if it's set,
	 * BUT we check here to make sure you've handled
	 * everything! */
	if (is_known_opt_cb_arg(ot->cb_arg)
	    || is_restricted_print_if_nonnull(ot->cb_arg)) {
		/* Only if set! */
		if (cv)
			return cv->optarg;
		else
			return NULL;
	}

	/* Insert more decodes here! */
	errx(1, "Unknown decode for %s", ot->names);
}

static void check_literal(const char *name, const char *val)
{
	if (streq(val, "true") || streq(val, "false"))
		return;
	if (!streq(val, "") && strspn(val, "-0123456789.") == strlen(val))
		return;
	errx(1, "Bad literal for %s: %s", name, val);
}

static void json_add_configval(struct json_stream *result,
			       const char *fieldname,
			       const struct opt_table *ot,
			       const char *str)
{
	if (ot->type & OPT_SHOWBOOL) {
		json_add_bool(result, fieldname, opt_canon_bool(str));
	} else if (ot->type & (OPT_SHOWMSATS|OPT_SHOWINT)) {
		check_literal(ot->names, str);
		json_add_primitive(result, fieldname, str);
	} else
		json_add_string(result, fieldname, str);
}

/* Config vars can have multiple names ("--large-channels|--wumbo"), but first
 * is preferred */
static void json_add_config(struct lightningd *ld,
			    struct json_stream *response,
			    bool always_include,
			    const struct opt_table *ot,
			    const char **names)
{
	char buf[CONFIG_SHOW_BUFSIZE + sizeof("...")];
	const char *val;
	struct configvar *cv;

	/* This tells us if they actually set the option */
	cv = configvar_first(ld->configvars, names);

	/* Ignore dev/hidden options (deprecated) unless they actually used it */
	if (!cv
	    && (ot->desc == opt_hidden || (ot->type & OPT_DEV))
	    && !always_include) {
		return;
	}

	/* Ignore options which simply exit */
	if (ot->type & OPT_EXITS)
		return;

	if (ot->type & OPT_NOARG) {
		json_object_start(response, names[0]);
		json_add_bool(response, "set", cv != NULL);
		json_add_source(response, "source", cv);
		json_add_config_plugin(response, ld->plugins, "plugin", ot);
		if (ot->type & OPT_DYNAMIC)
			json_add_bool(response, "dynamic", true);
		json_object_end(response);
		return;
	}

	assert(ot->type & OPT_HASARG);
	if (ot->type & OPT_MULTI) {
		json_object_start(response, names[0]);
		json_array_start(response, configval_fieldname(ot));
		while (cv) {
			val = get_opt_val(ot, buf, cv);
			json_add_configval(response, NULL, ot, val);
			cv = configvar_next(ld->configvars, cv, names);
		}
		json_array_end(response);

		/* Iterate again, for sources */
		json_array_start(response, "sources");
		for (cv = configvar_first(ld->configvars, names);
		     cv;
		     cv = configvar_next(ld->configvars, cv, names)) {
			json_add_source(response, NULL, cv);
		}
		json_array_end(response);
		json_add_config_plugin(response, ld->plugins, "plugin", ot);
		if (ot->type & OPT_DYNAMIC)
			json_add_bool(response, "dynamic", true);
		json_object_end(response);
		return;
	}

	/* Returns NULL if we don't want to print it */
	val = get_opt_val(ot, buf, cv);
	if (!val)
		return;

	json_object_start(response, names[0]);
	json_add_configval(response, configval_fieldname(ot), ot, val);
	json_add_source(response, "source", cv);
	json_add_config_plugin(response, ld->plugins, "plugin", ot);
	if (ot->type & OPT_DYNAMIC)
		json_add_bool(response, "dynamic", true);
	json_object_end(response);
}

static struct command_result *param_opt_config(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       const struct opt_table **config)
{
	const char *name0 = json_strdup(tmpctx, buffer, tok);
	*config = opt_find_long(name0, NULL);
	if (*config)
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "Unknown config option");
}

/* FIXME: This is a hack!  Expose somehow in ccan/opt.*/
/* Returns string after first '-'. */
static const char *first_name(const char *names, unsigned *len)
{
	*len = strcspn(names + 1, "|= ");
	return names + 1;
}

static const char *next_name(const char *names, unsigned *len)
{
	names += *len;
	if (names[0] == ' ' || names[0] == '=' || names[0] == '\0')
		return NULL;
	return first_name(names + 1, len);
}

static struct command_result *json_listconfigs(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct json_stream *response = NULL;
	const struct opt_table *config;

	if (!param(cmd, buffer, params,
		   p_opt("config", param_opt_config, &config),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);

	if (!deprecated_apis)
		goto modern;

	if (!config)
		json_add_string(response, "# version", version());

	for (size_t i = 0; i < opt_count; i++) {
		unsigned int len;
		const char *name;

		/* FIXME: Print out comment somehow? */
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;

		for (name = first_name(opt_table[i].names, &len);
		     name;
		     name = next_name(name, &len)) {
			/* Skips over first -, so just need to look for one */
			if (name[0] != '-')
				continue;

			if (!config || config == &opt_table[i]) {
				add_config_deprecated(cmd->ld, response, &opt_table[i],
						      name+1, len-1);
			}
			/* If we have more than one long name, first
			 * is preferred */
			break;
		}
	}

modern:
	json_object_start(response, "configs");
	for (size_t i = 0; i < opt_count; i++) {
		unsigned int len;
		const char *name;
		const char **names;

		/* FIXME: Print out comment somehow? */
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;

		if (config && config != &opt_table[i])
			continue;

		names = tal_arr(tmpctx, const char *, 0);
		for (name = first_name(opt_table[i].names, &len);
		     name;
		     name = next_name(name, &len)) {
			/* Skips over first -, so just need to look for one */
			if (name[0] != '-')
				continue;
			tal_arr_expand(&names,
				       tal_strndup(names, name+1, len-1));
		}
		/* We don't usually print dev or deprecated options, unless
		 * they explicitly ask, or they're set. */
		json_add_config(cmd->ld, response, config != NULL,
				&opt_table[i], names);
	}
	json_object_end(response);

	return command_success(cmd, response);
}

static const struct json_command listconfigs_command = {
	"listconfigs",
	"utility",
	json_listconfigs,
	"List all configuration options, or with [config], just that one.",
	.verbose = "listconfigs [config]\n"
	"Outputs an object, with each field a config options\n"
	"(Option names which start with # are comments)\n"
	"With [config], object only has that field"
};
AUTODATA(json_command, &listconfigs_command);
