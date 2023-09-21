#ifndef LIGHTNING_COMMON_CONFIGDIR_H
#define LIGHTNING_COMMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Unless overridden, we exit with status 1 when option parsing fails */
extern int opt_exitcode;

/* Helper for options which are tal() strings. */
char *opt_set_talstr(const char *arg, char **p);

/* Initial options setup */
void setup_option_allocators(void);

/* Minimal config parsing for tools: use opt_early_parse/opt_parse after */
void minimal_config_opts(const tal_t *ctx,
			 int argc, char *argv[],
			 char **config_filename,
			 char **basedir,
			 char **config_netdir,
			 char **rpc_filename);

/* Parse initial config options and files */
struct configvar **initial_config_opts(const tal_t *ctx,
				       int *argc, char *argv[],
				       bool remove_args,
				       char **config_filename,
				       char **config_basedir,
				       char **config_netdir,
				       char **rpc_filename);

/* This is called before we know all the options. */
void parse_configvars_early(struct configvar **cvs, bool developer);

/* This is called once, after we know all the options (if full_knowledge
 * is false, ignore unknown non-cmdline options). */
void parse_configvars_final(struct configvar **cvs,
			    bool full_knowledge, bool developer);

/* For listconfigs to detect. */
bool is_restricted_ignored(const void *fn);
bool is_restricted_print_if_nonnull(const void *fn);

#endif /* LIGHTNING_COMMON_CONFIGDIR_H */
