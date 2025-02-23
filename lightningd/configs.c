#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/configvar.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/version.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/options.h>
#include <lightningd/plugin.h>
#include <unistd.h>

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
		case CONFIGVAR_SETCONFIG_TRANSIENT:
			source = "setconfig transient";
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
	if (ot->type & OPT_CONCEAL)
		return "...";

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
 * is preferred.
 * wrap_object means we wrap json in an object of that name, otherwise outputs
 * raw fields.
 */
static void json_add_config(struct lightningd *ld,
			    struct json_stream *response,
			    bool always_include,
			    bool wrap_object,
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
		if (wrap_object)
			json_object_start(response, names[0]);
		json_add_bool(response, "set", cv != NULL);
		json_add_source(response, "source", cv);
		json_add_config_plugin(response, ld->plugins, "plugin", ot);
		if (ot->type & OPT_DYNAMIC)
			json_add_bool(response, "dynamic", true);
		if (wrap_object)
			json_object_end(response);
		return;
	}

	assert(ot->type & OPT_HASARG);
	if (ot->type & OPT_MULTI) {
		if (wrap_object)
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
		if (wrap_object)
			json_object_end(response);
		return;
	}

	/* Returns NULL if we don't want to print it */
	val = get_opt_val(ot, buf, cv);
	if (!val)
		return;

	if (wrap_object)
		json_object_start(response, names[0]);
	json_add_configval(response, configval_fieldname(ot), ot, val);
	json_add_source(response, "source", cv);
	json_add_config_plugin(response, ld->plugins, "plugin", ot);
	if (ot->type & OPT_DYNAMIC)
		json_add_bool(response, "dynamic", true);
	if (wrap_object)
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

static const char **opt_names_arr(const tal_t *ctx,
				  const struct opt_table *ot)
{
	const char **names = tal_arr(ctx, const char *, 0);
	const char *name;
	unsigned len;

	for (name = first_name(ot->names, &len);
	     name;
	     name = next_name(name, &len)) {
		/* Skips over first -, so just need to look for one */
		if (name[0] != '-')
			continue;
		tal_arr_expand(&names,
			       tal_strndup(names, name+1, len-1));
	}
	return names;
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

	if (!command_deprecated_out_ok(cmd, "configlist", "v23.08", "v24.08"))
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
		const char **names;

		/* FIXME: Print out comment somehow? */
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;

		if (config && config != &opt_table[i])
			continue;

		names = opt_names_arr(tmpctx, &opt_table[i]);
		/* We don't usually print dev or deprecated options, unless
		 * they explicitly ask, or they're set. */
		json_add_config(cmd->ld, response, config != NULL, true,
				&opt_table[i], names);
	}
	json_object_end(response);

	return command_success(cmd, response);
}

static const struct json_command listconfigs_command = {
	"listconfigs",
	json_listconfigs,
};
AUTODATA(json_command, &listconfigs_command);

static struct command_result *param_opt_dynamic_config(struct command *cmd,
						       const char *name,
						       const char *buffer,
						       const jsmntok_t *tok,
						       const struct opt_table **config)
{
	struct command_result *ret;

	ret = param_opt_config(cmd, name, buffer, tok, config);
	if (ret)
		return ret;

	if (!((*config)->type & OPT_DYNAMIC))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Not a dynamic config option");
	return NULL;
}

static void configvar_updated(struct lightningd *ld,
			      enum configvar_src src,
			      const char *fname,
			      size_t linenum,
			      const char *confline)
{
	struct configvar *cv;

	cv = configvar_new(ld->configvars, src, fname, linenum, confline);
	configvar_unparsed(cv);

	log_info(ld->log, "setconfig: %s %s (updated %s:%u)",
		 cv->optvar, cv->optarg ? cv->optarg : "SET",
		 cv->file ? cv->file : "NULL", cv->linenum);

	tal_arr_expand(&ld->configvars, cv);
	configvar_finalize_overrides(ld->configvars);
}

static size_t append_to_file(struct lightningd *ld,
			     const char *fname,
			     const char *str,
			     bool must_exist)
{
	int fd;
	const char *buffer;

	fd = open(fname, O_RDWR|O_APPEND);
	if (fd < 0) {
		if (errno != ENOENT || must_exist)
			fatal("Could not write to config %s: %s",
			      fname, strerror(errno));
		fd = open(fname, O_RDWR|O_APPEND|O_CREAT, 0644);
		if (fd < 0)
			fatal("Could not create config file %s: %s",
			      fname, strerror(errno));
	}

	/* Note: always nul terminates */
	buffer = grab_fd(tmpctx, fd);
	if (!buffer)
		fatal("Error reading %s: %s", fname, strerror(errno));

	/* If there's a last character and it's not \n, add one */
	if (tal_bytelen(buffer) > 1
	    && buffer[tal_bytelen(buffer)-2] != '\n')
		str = tal_strcat(tmpctx, "\n", str);

	/* Always append a \n ourselves */
	str = tal_strcat(tmpctx, str, "\n");
	if (write(fd, str, strlen(str)) != strlen(str))
		fatal("Could not write to config file %s: %s",
		      fname, strerror(errno));
	if (fsync(fd) != 0)
		fatal("Syncing %s: %s", fname, strerror(errno));
	close(fd);

	/* 1-based counter of where new stuff appeared */
	return strcount(buffer, "\n") + 1;
}

/* This comments out the config file entry or maybe replace one */
static void configfile_replace_var(struct lightningd *ld,
				   const struct configvar *cv,
				   const char *replace)
{
	char *contents, **lines, *template;
	int outfd;

	switch (cv->src) {
	case CONFIGVAR_CMDLINE:
	case CONFIGVAR_CMDLINE_SHORT:
	case CONFIGVAR_PLUGIN_START:
	case CONFIGVAR_SETCONFIG_TRANSIENT:
		/* These can't be commented out */
		abort();
	case CONFIGVAR_EXPLICIT_CONF:
	case CONFIGVAR_BASE_CONF:
	case CONFIGVAR_NETWORK_CONF:
		break;
	}

	contents = grab_file(tmpctx, cv->file);
	if (!contents)
		fatal("Could not load configfile %s: %s",
		      cv->file, strerror(errno));

	lines = tal_strsplit(contents, contents, "\r\n", STR_EMPTY_OK);
	if (cv->linenum - 1 >= tal_count(lines))
		fatal("Configfile %s no longer has %u lines!",
		      cv->file, cv->linenum);

	if (!streq(lines[cv->linenum - 1], cv->configline))
		fatal("Configfile %s line %u changed from %s to %s!",
		      cv->file, cv->linenum,
		      cv->configline,
		      lines[cv->linenum - 1]);

	if (replace)
		lines[cv->linenum - 1] = cast_const(char *, replace);
	else
		lines[cv->linenum - 1] = tal_fmt(lines, "# setconfig commented out (see config.setconfig): %s",
						 lines[cv->linenum - 1]);

	log_info(ld->log, "setconfig: %s line %u of %s (%s)",
		 replace ? "replaced" : "commented out",
		 cv->linenum, cv->file, cv->configline);

	template = tal_fmt(tmpctx, "%s.setconfig.XXXXXX", cv->file);
	outfd = mkstemp(template);
	if (outfd < 0)
		fatal("Creating %s: %s", template, strerror(errno));

	contents = tal_strjoin(tmpctx, take(lines), "\n", STR_TRAIL);
	if (!write_all(outfd, contents, strlen(contents)))
		fatal("Writing %s: %s", template, strerror(errno));
	if (fsync(outfd) != 0)
		fatal("Syncing %s: %s", template, strerror(errno));

	if (rename(template, cv->file) != 0)
		fatal("Renaming %s over %s: %s",
		      template, cv->file, strerror(errno));
	close(outfd);
}

static const char *base_conf_file(const tal_t *ctx,
				  struct lightningd *ld,
				  bool *must_exist)
{
	/* Explicit --conf?  Edit that, otherwise network-specific config. */
	if (ld->config_filename) {
		if (must_exist)
			*must_exist = true;
		return ld->config_filename;
	} else {
		if (must_exist)
			*must_exist = false;
		return path_join(ctx, ld->config_netdir, "config");
	}
}

static void create_setconfig_include(struct lightningd *ld)
{
	const char *lines;
	time_t now = time(NULL);
	const char *fname;
	bool must_exist;

	/* Usually config.setconfig, but could be different with --conf */
	fname = base_conf_file(tmpctx, ld, &must_exist);
	ld->setconfig_file = tal_fmt(ld, "%s.setconfig", fname);

	/* We want to use a relative path here (ctime() includes \n!). */
	lines = tal_fmt(tmpctx,
			"# Inserted by setconfig %sinclude %s.setconfig",
			ctime(&now), path_basename(tmpctx, fname));
	append_to_file(ld, fname, lines, must_exist);

	/* This creates the file */
	append_to_file(ld, ld->setconfig_file,
		       "# Created and update by setconfig, but you can edit this manually when node is stopped.",
		       false);
}

static void configvar_save(struct lightningd *ld,
			   const char **names,
			   const char *confline)
{
	/* Simple case: set in a config file. */
	struct configvar *oldcv;
	size_t linenum;

	/* If we don't already have "include config.setconfig" add it */
	if (!ld->setconfig_file)
		create_setconfig_include(ld);

	/* Is it already set in the config? */
	oldcv = configvar_first(ld->configvars, names);
	if (oldcv && oldcv->file) {
		/* If it's already in config.setconfig, replace */
		if (streq(oldcv->file, ld->setconfig_file)) {
			configfile_replace_var(ld, oldcv, confline);
			linenum = oldcv->linenum;
			goto replaced;
		}
		configfile_replace_var(ld, oldcv, NULL);
	}

	linenum = append_to_file(ld, ld->setconfig_file, confline, true);

replaced:
	configvar_updated(ld, CONFIGVAR_NETWORK_CONF,
			  ld->setconfig_file, linenum, confline);
}

static struct command_result *setconfig_success(struct command *cmd,
						const struct opt_table *ot,
						const char *val,
						bool transient)
{
	struct json_stream *response;
	const char **names, *confline;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	names = opt_names_arr(tmpctx, ot);

	if (val)
		confline = tal_fmt(tmpctx, "%s=%s", names[0], val);
	else
		confline = names[0];

	if (!transient)
		configvar_save(cmd->ld, names, confline);
	else
		configvar_updated(cmd->ld, CONFIGVAR_SETCONFIG_TRANSIENT, NULL, 0, confline);


	response = json_stream_success(cmd);
	json_object_start(response, "config");
	json_add_string(response, "config", names[0]);
	json_add_config(cmd->ld, response, true, false, ot, names);
	json_object_end(response);
	return command_success(cmd, response);
}

static struct command_result *json_setconfig(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	const struct opt_table *ot;
	const char *val;
	char *err;
	void *arg;
	bool *transient;

	if (!param_check(cmd, buffer, params,
			 p_req("config", param_opt_dynamic_config, &ot),
			 p_opt("val", param_string, &val),
			 p_opt_def("transient", param_bool, &transient, false),
			 NULL))
		return command_param_failed();

	log_debug(cmd->ld->log, "setconfig!");

	/* We don't handle DYNAMIC MULTI, at least yet! */
	assert(!(ot->type & OPT_MULTI));

	/* We use arg = NULL to tell callback it's only for testing */
	if (command_check_only(cmd))
		arg = NULL;
	else
		arg = ot->u.arg;

	if (ot->type & OPT_NOARG) {
		if (val)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s does not take a value",
					    ot->names + 2);
		if (is_plugin_opt(ot))
			return plugin_set_dynamic_opt(cmd, ot, NULL, *transient,
						      setconfig_success);
		err = ot->cb(arg);
	} else {
		assert(ot->type & OPT_HASARG);
		if (!val)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s requires a value",
					    ot->names + 2);
		if (is_plugin_opt(ot))
			return plugin_set_dynamic_opt(cmd, ot, val, *transient,
						      setconfig_success);
		err = ot->cb_arg(val, arg);
	}

	if (err) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Error setting %s: %s", ot->names + 2, err);
	}

	return setconfig_success(cmd, ot, val, *transient);
}

static const struct json_command setconfig_command = {
	"setconfig",
	json_setconfig,
};
AUTODATA(json_command, &setconfig_command);
